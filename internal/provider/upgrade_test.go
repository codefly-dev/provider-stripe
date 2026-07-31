package provider

import (
	"testing"

	providerv0 "github.com/codefly-dev/core/generated/go/codefly/services/provider/v0"
)

func TestUpgradeStateFailsClosed(t *testing.T) {
	_, err := testServer(t).UpgradeState(t.Context(), &providerv0.UpgradeStateRequest{FromVersion: 1, ToVersion: 2})
	if err == nil {
		t.Fatal("v0.1 defines no state upgrade; UpgradeState must fail closed")
	}
}
