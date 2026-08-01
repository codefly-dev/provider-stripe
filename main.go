// Command provider-stripe is the Codefly Stripe reference provider agent.
//
// It is spawned by the Codefly host as a codefly:provider leaf agent, serves
// the codefly.provider/v0 Provider service over the host-provided transport,
// and reaches Stripe only through the host broker. It holds no Stripe
// credentials and never sees the webhook signing secret.
package main

import (
	_ "embed"
	"fmt"
	"os"

	"github.com/codefly-dev/core/agents"
	"github.com/codefly-dev/core/provider/artifact"
	"github.com/codefly-dev/provider-stripe/internal/provider"
)

//go:embed provider.codefly.yaml
var manifestBytes []byte

func main() {
	server, err := newServer()
	if err != nil {
		fmt.Fprintln(os.Stderr, "provider-stripe:", err)
		os.Exit(1)
	}
	agents.Serve(agents.PluginRegistration{Provider: server})
}

func newServer() (*provider.Server, error) {
	identity, err := discoverIdentity()
	if err != nil {
		return nil, err
	}
	return provider.NewServer(manifestBytes, identity)
}

// discoverIdentity reads the verified artifact descriptor installed alongside
// this executable. The provider only advertises an identity the host already
// verified against the binary and manifest digests.
func discoverIdentity() (provider.Identity, error) {
	executable, err := os.Executable()
	if err != nil {
		return provider.Identity{}, err
	}
	data, err := os.ReadFile(executable + artifact.InstalledDescriptorSuffix)
	if err != nil {
		return provider.Identity{}, fmt.Errorf("provider must run from an installed artifact layout: %w", err)
	}
	descriptor, err := artifact.ParseDescriptor(data)
	if err != nil {
		return provider.Identity{}, err
	}
	return provider.Identity{
		Publisher:      descriptor.Publisher,
		Name:           descriptor.Name,
		Version:        descriptor.Version,
		ArtifactDigest: descriptor.ArtifactDigest,
		ManifestDigest: descriptor.ManifestDigest,
	}, nil
}
