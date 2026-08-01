package provider

import (
	"fmt"

	providerv0 "github.com/codefly-dev/core/generated/go/codefly/services/provider/v0"
	"github.com/codefly-dev/core/provider/manifest"
)

// Diagnostic codes advertised by the runtime catalog. Every code is strictly
// prefixed by the manifest diagnostic namespace and maps a bounded Stripe
// failure class; no raw Stripe error body is ever surfaced through them.
const (
	diagNamespace          = "provider.stripe."
	DiagInvalidInput       = diagNamespace + "invalid-input"
	DiagAuthentication     = diagNamespace + "authentication"
	DiagPermission         = diagNamespace + "permission"
	DiagWrongMode          = diagNamespace + "wrong-mode"
	DiagNotFound           = diagNamespace + "not-found"
	DiagAmbiguous          = diagNamespace + "ambiguous"
	DiagEndpointQuota      = diagNamespace + "endpoint-quota"
	DiagIdempotency        = diagNamespace + "idempotency-mismatch"
	DiagRateLimit          = diagNamespace + "rate-limit"
	DiagTimeoutBeforeSend  = diagNamespace + "timeout-before-send"
	DiagOutcomeUnknown     = diagNamespace + "outcome-unknown"
	DiagValidation         = diagNamespace + "permanent-validation"
	DiagUnmanagedConflict  = diagNamespace + "unmanaged-conflict"
	DiagModeMismatch       = diagNamespace + "mode-mismatch"
	DiagProjectionDeferred = diagNamespace + "projection-deferred"
)

// diagnosticCodes is the exact, ordered set of codes the runtime advertises. It
// must remain a subset of the packaged manifest namespace.
var diagnosticCodes = []string{
	DiagInvalidInput, DiagAuthentication, DiagPermission, DiagWrongMode,
	DiagNotFound, DiagAmbiguous, DiagEndpointQuota, DiagIdempotency,
	DiagRateLimit, DiagTimeoutBeforeSend, DiagOutcomeUnknown, DiagValidation,
	DiagUnmanagedConflict, DiagModeMismatch, DiagProjectionDeferred,
}

// buildCatalog derives the runtime catalog from the packaged manifest. The
// catalog advertises the full manifest surface (a valid subset of itself) and
// is digest-bound so the host rejects any binary/manifest mismatch before
// admitting a request.
func buildCatalog(m *manifest.Manifest) (*providerv0.RuntimeCatalog, error) {
	local := &manifest.Catalog{
		SchemaVersion:       m.SchemaVersion,
		ProtocolVersion:     m.ProtocolVersion,
		StateSchemaVersions: append([]uint32(nil), m.StateSchemaVersions...),
		ProjectionContracts: make([]string, 0, len(m.Projections)),
		DiagnosticCodes:     append([]string(nil), diagnosticCodes...),
	}
	runtime := &providerv0.RuntimeCatalog{
		ProtocolVersion:       m.ProtocolVersion,
		ManifestSchemaVersion: m.SchemaVersion,
		StateSchemaVersions:   append([]uint32(nil), m.StateSchemaVersions...),
		ProjectionContracts:   make([]string, 0, len(m.Projections)),
		DiagnosticCodes:       append([]string(nil), diagnosticCodes...),
	}
	for _, descriptor := range m.Requests {
		d, err := manifest.RequestDescriptorDigest(descriptor)
		if err != nil {
			return nil, err
		}
		local.Requests = append(local.Requests, manifest.CatalogRequest{ID: descriptor.ID, Digest: d})
		runtime.Requests = append(runtime.Requests, &providerv0.RuntimeCatalogRequest{Id: descriptor.ID, Digest: d})
	}
	for _, resourceType := range m.ResourceTypes {
		actions := append([]string(nil), resourceType.Actions...)
		local.ResourceTypes = append(local.ResourceTypes, manifest.CatalogResource{ID: resourceType.ID, Actions: actions})
		runtime.ResourceTypes = append(runtime.ResourceTypes, &providerv0.RuntimeCatalogResource{Id: resourceType.ID, Actions: actions})
	}
	for _, projection := range m.Projections {
		local.ProjectionContracts = append(local.ProjectionContracts, projection.Contract)
		runtime.ProjectionContracts = append(runtime.ProjectionContracts, projection.Contract)
	}

	// Bind the runtime digest to the local catalog digest so the host's
	// AdmitRuntimeCatalog (which recomputes it) accepts exactly this surface.
	digest, err := local.Digest()
	if err != nil {
		return nil, err
	}
	runtime.Digest = digest

	// Fail closed if the derived catalog is not admissible against the manifest.
	if _, err := m.AdmitRuntimeCatalog(runtime); err != nil {
		return nil, fmt.Errorf("derived runtime catalog is not admissible: %w", err)
	}
	return runtime, nil
}
