// Package provider implements the Stripe reference provider agent for Codefly.
//
// It speaks the codefly.provider/v0 protocol: the host drives it through the
// Provider service (GetProviderInformation, Validate, Observe, Plan,
// ApplyAction, Doctor, UpgradeState) and the provider reaches Stripe only
// through the host broker's ProviderHost callbacks. Raw credentials and the
// webhook signing secret never enter this process; they are opaque handles and
// references. This package implements the offline surface (information,
// validate, plan, upgrade); the broker-driven surface lands with the host
// broker (F2) and coordinator (F3).
package provider

import (
	"fmt"

	providerv0 "github.com/codefly-dev/core/generated/go/codefly/services/provider/v0"
	"github.com/codefly-dev/core/provider/manifest"
	"github.com/codefly-dev/core/provider/sdk"
)

// Identity is the verified artifact identity of the running provider, taken
// from the installed provider.artifact.json descriptor. It binds the binary to
// its manifest and is echoed back to the host in GetProviderInformation.
type Identity struct {
	Publisher      string
	Name           string
	Version        string
	ArtifactDigest string
	ManifestDigest string
}

// Server implements providerv0.ProviderServer. The offline methods are
// implemented here; GetProviderInformation is served by the embedded sdk.Base,
// and the broker-driven methods (Observe, ApplyAction, Doctor) remain
// unimplemented until the host broker and coordinator are available.
type Server struct {
	*sdk.Base
	manifest       *manifest.Manifest
	catalog        *providerv0.RuntimeCatalog
	artifactDigest string
	manifestDigest string
	catalogDigest  string
}

var _ providerv0.ProviderServer = (*Server)(nil)

// NewServer builds a provider server from the packaged manifest bytes and the
// verified artifact identity. It fails closed when the identity does not match
// the packaged manifest, so a tampered manifest or mismatched descriptor can
// never be advertised as authentic.
func NewServer(manifestBytes []byte, id Identity) (*Server, error) {
	m, err := manifest.Load(manifestBytes)
	if err != nil {
		return nil, fmt.Errorf("packaged manifest is invalid: %w", err)
	}
	manifestDigest, err := m.Digest()
	if err != nil {
		return nil, err
	}
	if id.ManifestDigest != manifestDigest {
		return nil, fmt.Errorf("artifact manifest digest does not match packaged manifest")
	}
	if id.Publisher != m.Agent.Publisher || id.Name != m.Agent.Name || id.Version != m.Agent.Version {
		return nil, fmt.Errorf("artifact identity does not match packaged manifest agent")
	}
	catalog, err := buildCatalog(m)
	if err != nil {
		return nil, err
	}
	information := &providerv0.GetProviderInformationResponse{
		Artifact: &providerv0.AgentArtifactIdentity{
			Publisher:      id.Publisher,
			Name:           id.Name,
			Version:        id.Version,
			ArtifactDigest: id.ArtifactDigest,
			ManifestDigest: id.ManifestDigest,
		},
		Catalog: catalog,
		Capabilities: &providerv0.ProviderCapabilities{
			SupportsImport:       true,
			SupportsReplace:      true,
			SupportsDelete:       true,
			SupportsStateUpgrade: false,
		},
		// v0.1 observes production and mutates only sandbox/test accounts;
		// production mutation is a separate, not-yet-granted readiness gate.
		Readiness: &providerv0.ProviderReadiness{
			ProductionObserve:  true,
			ProductionMutation: false,
		},
	}
	base, err := sdk.NewBase(information)
	if err != nil {
		return nil, err
	}
	return &Server{
		Base:           base,
		manifest:       m,
		catalog:        catalog,
		artifactDigest: id.ArtifactDigest,
		manifestDigest: id.ManifestDigest,
		catalogDigest:  catalog.GetDigest(),
	}, nil
}
