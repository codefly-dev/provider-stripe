GOFLAGS ?= -mod=mod
export GOPRIVATE = github.com/codefly-dev/*

BINARY := provider-stripe
DIST := dist

.PHONY: build test vet package clean

build:
	go build $(GOFLAGS) -o $(BINARY) .

test:
	go test $(GOFLAGS) ./...

vet:
	go vet $(GOFLAGS) ./...

# package produces the verified artifact layout (binary + manifest + descriptor)
# under $(DIST). The host installs and re-verifies this layout before spawning.
package: build
	go run $(GOFLAGS) ./cmd/package -binary $(BINARY) -manifest provider.codefly.yaml -out $(DIST)

clean:
	rm -rf $(BINARY) $(DIST)
