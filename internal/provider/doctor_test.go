package provider

import (
	"net/http"
	"strings"
	"testing"

	providerv0 "github.com/codefly-dev/core/generated/go/codefly/services/provider/v0"
)

func doctorRequest(t *testing.T) *providerv0.DoctorRequest {
	t.Helper()
	return &providerv0.DoctorRequest{
		Context: brokerContext(t, "op-doctor", "action-doctor", validInput(), providerv0.HostMode_HOST_MODE_DEVELOPMENT, ""),
	}
}

func TestDoctor_HealthyWhenReadyAndEndpointPresent(t *testing.T) {
	host := newFakeHost(t, true)
	server := fakeServer(t, host)
	events := []string{"customer.subscription.updated"}
	routes := map[string]http.HandlerFunc{
		"GET /v1/account": func(w http.ResponseWriter, _ *http.Request) {
			writeJSON(w, http.StatusOK, accountJSON("acct_test_123", true, true))
		},
		"GET /v1/webhook_endpoints": func(w http.ResponseWriter, _ *http.Request) {
			writeJSON(w, http.StatusOK, webhookListJSON(false,
				webhookJSON("we_owned", "https://app.example.com/v1/billing/webhook", "2024-06-20", statusEnabled, events, false, true, false)))
		},
	}
	stub := stripeStub(t, routes)
	host.record(stub)
	response, err := server.Doctor(t.Context(), doctorRequest(t))
	if err != nil {
		t.Fatalf("doctor: %v", err)
	}
	if !response.GetHealthy() {
		t.Fatalf("expected healthy, diagnostics = %v", response.GetDiagnostics())
	}
}

func TestDoctor_AccountNotReadyAndNoEndpoint(t *testing.T) {
	host := newFakeHost(t, true)
	server := fakeServer(t, host)
	routes := map[string]http.HandlerFunc{
		"GET /v1/account": func(w http.ResponseWriter, _ *http.Request) {
			writeJSON(w, http.StatusOK, accountJSON("acct_test_123", false, false))
		},
		"GET /v1/webhook_endpoints": func(w http.ResponseWriter, _ *http.Request) {
			writeJSON(w, http.StatusOK, webhookListJSON(false))
		},
	}
	stub := stripeStub(t, routes)
	host.record(stub)
	response, err := server.Doctor(t.Context(), doctorRequest(t))
	if err != nil {
		t.Fatalf("doctor: %v", err)
	}
	// An account that cannot yet transact is a warning, and a missing endpoint an
	// info: neither is a hard error, so the provider stays healthy.
	if !response.GetHealthy() {
		t.Fatalf("expected healthy with advisories, diagnostics = %v", response.GetDiagnostics())
	}
	if len(response.GetDiagnostics()) != 2 {
		t.Fatalf("expected readiness and presence advisories, got %v", response.GetDiagnostics())
	}
}

func TestDoctor_CredentialUnreachableIsUnhealthy(t *testing.T) {
	host := newFakeHost(t, true)
	server := fakeServer(t, host)
	routes := map[string]http.HandlerFunc{
		"GET /v1/account": func(w http.ResponseWriter, _ *http.Request) {
			writeJSON(w, http.StatusUnauthorized, `{"error":{"type":"authentication_error"}}`)
		},
	}
	stub := stripeStub(t, routes)
	host.record(stub)
	response, err := server.Doctor(t.Context(), doctorRequest(t))
	if err != nil {
		t.Fatalf("doctor: %v", err)
	}
	if response.GetHealthy() {
		t.Fatal("an unreachable credential must be unhealthy")
	}
	if len(response.GetDiagnostics()) != 1 || response.GetDiagnostics()[0].GetCode() != DiagAuthentication {
		t.Fatalf("expected an authentication diagnostic, got %v", response.GetDiagnostics())
	}
}

func TestDoctor_WithoutHostFailsClosed(t *testing.T) {
	server := testServer(t)
	_, err := server.Doctor(t.Context(), doctorRequest(t))
	if err == nil || !strings.Contains(err.Error(), "host callback channel") {
		t.Fatalf("expected a fail-closed error without a host, got %v", err)
	}
}
