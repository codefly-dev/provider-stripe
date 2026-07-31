package provider

import (
	"strings"
	"testing"

	providerv0 "github.com/codefly-dev/core/generated/go/codefly/services/provider/v0"
	"github.com/codefly-dev/core/provider/manifest"
)

func TestManifestValidatesAndCatalogIsAdmissible(t *testing.T) {
	m, err := manifest.Load(loadManifestBytes(t))
	if err != nil {
		t.Fatalf("manifest is invalid: %v", err)
	}
	catalog, err := buildCatalog(m)
	if err != nil {
		t.Fatalf("catalog build: %v", err)
	}
	if _, err := m.AdmitRuntimeCatalog(catalog); err != nil {
		t.Fatalf("catalog is not admissible against manifest: %v", err)
	}
	// The billing contract must be projected.
	found := false
	for _, contract := range catalog.GetProjectionContracts() {
		if contract == "codefly.dev/configuration/billing@1" {
			found = true
		}
	}
	if !found {
		t.Fatal("catalog does not project billing@1")
	}
}

func TestGetProviderInformationMatchesArtifactIdentity(t *testing.T) {
	server := testServer(t)
	response, err := server.GetProviderInformation(t.Context(), &providerv0.GetProviderInformationRequest{
		Artifact: &providerv0.AgentArtifactIdentity{
			Publisher:      "codefly.dev",
			Name:           "stripe",
			Version:        "0.1.0",
			ArtifactDigest: "sha256:" + strings.Repeat("a", 64),
			ManifestDigest: server.manifestDigest,
		},
	})
	if err != nil {
		t.Fatalf("information: %v", err)
	}
	if response.GetCatalog().GetDigest() != server.catalogDigest {
		t.Fatal("catalog digest mismatch")
	}
	if !response.GetCapabilities().GetSupportsReplace() || !response.GetCapabilities().GetSupportsDelete() || !response.GetCapabilities().GetSupportsImport() {
		t.Fatal("capabilities must advertise import, replace, and delete")
	}
	if response.GetReadiness().GetProductionMutation() {
		t.Fatal("v0.1 must not advertise production mutation readiness")
	}
}

func TestGetProviderInformationRejectsMismatchedIdentity(t *testing.T) {
	server := testServer(t)
	_, err := server.GetProviderInformation(t.Context(), &providerv0.GetProviderInformationRequest{
		Artifact: &providerv0.AgentArtifactIdentity{
			Publisher: "codefly.dev", Name: "stripe", Version: "9.9.9",
			ArtifactDigest: "sha256:" + strings.Repeat("a", 64), ManifestDigest: server.manifestDigest,
		},
	})
	if err == nil {
		t.Fatal("expected identity mismatch to be rejected")
	}
}

func TestNewServerRejectsManifestDigestMismatch(t *testing.T) {
	_, err := NewServer(loadManifestBytes(t), Identity{
		Publisher: "codefly.dev", Name: "stripe", Version: "0.1.0",
		ArtifactDigest: "sha256:" + strings.Repeat("a", 64),
		ManifestDigest: "sha256:" + strings.Repeat("b", 64),
	})
	if err == nil {
		t.Fatal("expected manifest digest mismatch to fail closed")
	}
}
