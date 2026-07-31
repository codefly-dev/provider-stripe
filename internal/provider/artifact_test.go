package provider

import (
	"testing"

	"github.com/codefly-dev/core/provider/artifact"
)

// TestPackagedArtifactIdentityBootstrapsServer proves that the identity built
// by the real artifact packaging (the same descriptor the release produces)
// is accepted by NewServer, binding the binary to this manifest.
func TestPackagedArtifactIdentityBootstrapsServer(t *testing.T) {
	manifestBytes := loadManifestBytes(t)
	// A stand-in binary; BuildDescriptor binds its digest, name, and manifest.
	descriptor, err := artifact.BuildDescriptor("provider-stripe", []byte("stand-in-binary"), manifestBytes)
	if err != nil {
		t.Fatalf("build descriptor: %v", err)
	}
	server, err := NewServer(manifestBytes, Identity{
		Publisher:      descriptor.Publisher,
		Name:           descriptor.Name,
		Version:        descriptor.Version,
		ArtifactDigest: descriptor.ArtifactDigest,
		ManifestDigest: descriptor.ManifestDigest,
	})
	if err != nil {
		t.Fatalf("packaged identity must bootstrap the server: %v", err)
	}
	if server.artifactDigest != descriptor.ArtifactDigest {
		t.Fatal("server must advertise the packaged artifact digest")
	}
}
