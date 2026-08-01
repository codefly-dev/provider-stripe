// Command package assembles the verified provider artifact layout: the built
// binary, the packaged provider.codefly.yaml manifest, and a digest-bound
// provider.artifact.json descriptor. The layout is what the host installs and
// verifies before spawning the provider.
package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/codefly-dev/core/provider/artifact"
)

func main() {
	binary := flag.String("binary", "provider-stripe", "path to the built provider binary")
	manifestPath := flag.String("manifest", "provider.codefly.yaml", "path to the provider manifest")
	out := flag.String("out", "dist", "output layout directory")
	flag.Parse()

	if err := run(*binary, *manifestPath, *out); err != nil {
		fmt.Fprintln(os.Stderr, "package:", err)
		os.Exit(1)
	}
}

func run(binaryPath, manifestPath, out string) error {
	binaryName := filepath.Base(binaryPath)
	binaryBytes, err := os.ReadFile(binaryPath)
	if err != nil {
		return fmt.Errorf("read binary: %w", err)
	}
	manifestBytes, err := os.ReadFile(manifestPath)
	if err != nil {
		return fmt.Errorf("read manifest: %w", err)
	}
	descriptor, err := artifact.BuildDescriptor(binaryName, binaryBytes, manifestBytes)
	if err != nil {
		return fmt.Errorf("build descriptor: %w", err)
	}
	descriptorBytes, err := artifact.MarshalDescriptor(descriptor)
	if err != nil {
		return fmt.Errorf("marshal descriptor: %w", err)
	}
	if err := os.MkdirAll(out, 0o755); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(out, binaryName), binaryBytes, 0o755); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(out, "provider.codefly.yaml"), manifestBytes, 0o644); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(out, "provider.artifact.json"), descriptorBytes, 0o644); err != nil {
		return err
	}
	fmt.Printf("packaged %s\n  artifact_digest: %s\n  manifest_digest: %s\n", binaryName, descriptor.ArtifactDigest, descriptor.ManifestDigest)
	return nil
}
