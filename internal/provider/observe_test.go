package provider

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	providerv0 "github.com/codefly-dev/core/generated/go/codefly/services/provider/v0"
)

// observeRecordThenReplay runs Observe once against the live Stripe stand-in to
// record, then again against the loaded cassette with no network, and returns
// the replayed response. It asserts the two runs agree so a cassette is proven
// enforcement-identical to live.
func observeRecordThenReplay(t *testing.T, host *fakeHost, server *Server, routes map[string]http.HandlerFunc, input map[string]*providerv0.PublicValue, mode providerv0.HostMode) (*providerv0.ObserveResponse, error) {
	t.Helper()
	stub := stripeStub(t, routes)
	host.record(stub)
	recorded, recErr := server.Observe(t.Context(), &providerv0.ObserveRequest{
		Context: brokerContext(t, "op-observe", "action-observe", input, mode, ""),
	})
	if recErr != nil {
		return recorded, recErr
	}
	host.replay()
	return server.Observe(t.Context(), &providerv0.ObserveRequest{
		Context: brokerContext(t, "op-observe", "action-observe", input, mode, ""),
	})
}

func TestObserve_AccountAndOwnedWebhook(t *testing.T) {
	host := newFakeHost(t, true)
	server := fakeServer(t, host)
	events := []string{"customer.subscription.created", "customer.subscription.updated"}
	routes := map[string]http.HandlerFunc{
		"GET /v1/account": func(w http.ResponseWriter, _ *http.Request) {
			writeJSON(w, http.StatusOK, accountJSON("acct_test_123", true, true))
		},
		"GET /v1/webhook_endpoints": func(w http.ResponseWriter, _ *http.Request) {
			writeJSON(w, http.StatusOK, webhookListJSON(false,
				webhookJSON("we_owned", "https://app.example.com/v1/billing/webhook", "2024-06-20", statusEnabled, events, false, true, false)))
		},
	}
	response, err := observeRecordThenReplay(t, host, server, routes, validInput(), providerv0.HostMode_HOST_MODE_DEVELOPMENT)
	if err != nil {
		t.Fatalf("observe: %v", err)
	}

	material := response.GetMaterial()
	if material.GetAccountIdentity() != "acct_test_123" {
		t.Fatalf("account identity = %q", material.GetAccountIdentity())
	}
	if material.GetMode() != providerv0.HostMode_HOST_MODE_DEVELOPMENT {
		t.Fatalf("mode = %v", material.GetMode())
	}
	if !material.GetComplete() {
		t.Fatal("observation must be complete")
	}
	webhooks := observedWebhooks(material)
	if len(webhooks) != 1 {
		t.Fatalf("expected 1 webhook, got %d", len(webhooks))
	}
	owned := webhooks[0]
	if owned.RemoteID != "we_owned" || owned.Ownership != providerv0.Ownership_OWNERSHIP_OWNED {
		t.Fatalf("owned webhook = %+v", owned)
	}
	if !eventsEqual(owned.EnabledEvents, normalizeEvents(events)) {
		t.Fatalf("events = %v", owned.EnabledEvents)
	}
	// The account resource carries the safe subset only and never a livemode claim.
	for _, resource := range material.GetResources() {
		if resource.GetIdentity().GetResourceType() == resourceAccount {
			if _, present := resource.GetProviderOwnedFields()["livemode"]; present {
				t.Fatal("the account projection must not claim livemode")
			}
		}
	}
}

func TestObserve_PaginatedListAndRetrieve(t *testing.T) {
	host := newFakeHost(t, true)
	server := fakeServer(t, host)
	events := []string{"customer.subscription.updated"}
	page1 := webhookJSON("we_owned", "https://app.example.com/v1/billing/webhook", "2024-06-20", statusEnabled, events, false, true, false)
	page2 := webhookJSON("we_unmanaged", "https://other.example.com/hook", "2024-06-20", statusEnabled, events, false, false, false)
	existing := webhookJSON("we_existing", "https://legacy.example.com/hook", "2024-06-20", statusEnabled, events, false, false, false)
	routes := map[string]http.HandlerFunc{
		"GET /v1/account": func(w http.ResponseWriter, _ *http.Request) {
			writeJSON(w, http.StatusOK, accountJSON("acct_test_123", true, true))
		},
		"GET /v1/webhook_endpoints": func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Query().Get("starting_after") == "we_owned" {
				writeJSON(w, http.StatusOK, webhookListJSON(false, page2))
				return
			}
			writeJSON(w, http.StatusOK, webhookListJSON(true, page1))
		},
		"GET /v1/webhook_endpoints/{id}": func(w http.ResponseWriter, _ *http.Request) {
			writeJSON(w, http.StatusOK, existing)
		},
	}
	input := validInput()
	input["callback_mode"] = str("existing")
	input["existing_webhook_id"] = str("we_existing")
	delete(input, "callback_url")

	response, err := observeRecordThenReplay(t, host, server, routes, input, providerv0.HostMode_HOST_MODE_DEVELOPMENT)
	if err != nil {
		t.Fatalf("observe: %v", err)
	}
	remotes := map[string]providerv0.Ownership{}
	for _, webhook := range observedWebhooks(response.GetMaterial()) {
		remotes[webhook.RemoteID] = webhook.Ownership
	}
	for _, id := range []string{"we_owned", "we_unmanaged", "we_existing"} {
		if _, ok := remotes[id]; !ok {
			t.Fatalf("expected %q in observation, got %v", id, remotes)
		}
	}
	if remotes["we_owned"] != providerv0.Ownership_OWNERSHIP_OWNED {
		t.Fatalf("we_owned ownership = %v", remotes["we_owned"])
	}
	if remotes["we_unmanaged"] != providerv0.Ownership_OWNERSHIP_UNMANAGED {
		t.Fatalf("we_unmanaged ownership = %v", remotes["we_unmanaged"])
	}
}

func TestObserve_PaginationWithoutCursorFailsClosed(t *testing.T) {
	host := newFakeHost(t, true)
	server := fakeServer(t, host)
	listCalls := 0
	routes := map[string]http.HandlerFunc{
		"GET /v1/account": func(w http.ResponseWriter, _ *http.Request) {
			writeJSON(w, http.StatusOK, accountJSON("acct_test_123", true, true))
		},
		"GET /v1/webhook_endpoints": func(w http.ResponseWriter, _ *http.Request) {
			// has_more with an empty page yields no cursor to advance from: the
			// provider must fail closed at once rather than re-request forever.
			listCalls++
			writeJSON(w, http.StatusOK, webhookListJSON(true))
		},
	}
	stub := stripeStub(t, routes)
	host.record(stub)
	_, err := server.Observe(t.Context(), &providerv0.ObserveRequest{
		Context: brokerContext(t, "op-observe", "action-observe", validInput(), providerv0.HostMode_HOST_MODE_DEVELOPMENT, ""),
	})
	if err == nil {
		t.Fatal("a has_more page with no cursor must fail closed")
	}
	if !strings.Contains(err.Error(), DiagValidation) {
		t.Fatalf("expected a validation diagnostic, got %v", err)
	}
	if listCalls != 1 {
		t.Fatalf("must not re-request an uncursorable page, list calls = %d", listCalls)
	}
}

func TestObserve_FiltersToSafeFieldsOnly(t *testing.T) {
	host := newFakeHost(t, true)
	server := fakeServer(t, host)
	events := []string{"customer.subscription.updated"}
	routes := map[string]http.HandlerFunc{
		"GET /v1/account": func(w http.ResponseWriter, _ *http.Request) {
			writeJSON(w, http.StatusOK, accountJSON("acct_test_123", true, true))
		},
		"GET /v1/webhook_endpoints": func(w http.ResponseWriter, _ *http.Request) {
			// The endpoint carries an undeclared, secret-shaped field the policy
			// must drop rather than forward.
			writeJSON(w, http.StatusOK, webhookListJSON(false,
				webhookJSON("we_owned", "https://app.example.com/v1/billing/webhook", "2024-06-20", statusEnabled, events, false, true, true)))
		},
	}
	response, err := observeRecordThenReplay(t, host, server, routes, validInput(), providerv0.HostMode_HOST_MODE_DEVELOPMENT)
	if err != nil {
		t.Fatalf("observe: %v", err)
	}
	encoded, err := json.Marshal(response)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if strings.Contains(string(encoded), poisonSigningSecret) {
		t.Fatal("undeclared secret-shaped field must never be forwarded")
	}
	if strings.Contains(string(encoded), "unrelated") {
		t.Fatal("undeclared metadata must never be forwarded")
	}
}

func TestObserve_ModeMismatchFailsClosed(t *testing.T) {
	host := newFakeHost(t, true)
	server := fakeServer(t, host)
	events := []string{"customer.subscription.updated"}
	routes := map[string]http.HandlerFunc{
		"GET /v1/account": func(w http.ResponseWriter, _ *http.Request) {
			writeJSON(w, http.StatusOK, accountJSON("acct_test_123", true, true))
		},
		"GET /v1/webhook_endpoints": func(w http.ResponseWriter, _ *http.Request) {
			// livemode=true contradicts the attested development mode.
			writeJSON(w, http.StatusOK, webhookListJSON(false,
				webhookJSON("we_owned", "https://app.example.com/v1/billing/webhook", "2024-06-20", statusEnabled, events, true, true, false)))
		},
	}
	stub := stripeStub(t, routes)
	host.record(stub)
	_, err := server.Observe(t.Context(), &providerv0.ObserveRequest{
		Context: brokerContext(t, "op-observe", "action-observe", validInput(), providerv0.HostMode_HOST_MODE_DEVELOPMENT, ""),
	})
	if err == nil {
		t.Fatal("expected a mode-mismatch failure")
	}
	if !strings.Contains(err.Error(), DiagModeMismatch) {
		t.Fatalf("expected mode-mismatch diagnostic, got %v", err)
	}
}

func TestObserve_AuthErrorFailsClosed(t *testing.T) {
	host := newFakeHost(t, true)
	server := fakeServer(t, host)
	routes := map[string]http.HandlerFunc{
		"GET /v1/account": func(w http.ResponseWriter, _ *http.Request) {
			writeJSON(w, http.StatusUnauthorized, `{"error":{"type":"authentication_error","message":"Invalid API Key provided: sk_live_xxx"}}`)
		},
	}
	stub := stripeStub(t, routes)
	host.record(stub)
	_, err := server.Observe(t.Context(), &providerv0.ObserveRequest{
		Context: brokerContext(t, "op-observe", "action-observe", validInput(), providerv0.HostMode_HOST_MODE_DEVELOPMENT, ""),
	})
	if err == nil || !strings.Contains(err.Error(), DiagAuthentication) {
		t.Fatalf("expected authentication failure, got %v", err)
	}
	if strings.Contains(err.Error(), "sk_live") {
		t.Fatal("the raw Stripe error body must never surface")
	}
}

func TestObserve_RateLimitFailsClosed(t *testing.T) {
	host := newFakeHost(t, true)
	server := fakeServer(t, host)
	routes := map[string]http.HandlerFunc{
		"GET /v1/account": func(w http.ResponseWriter, _ *http.Request) {
			writeJSON(w, http.StatusTooManyRequests, `{"error":{"type":"rate_limit_error"}}`)
		},
	}
	stub := stripeStub(t, routes)
	host.record(stub)
	_, err := server.Observe(t.Context(), &providerv0.ObserveRequest{
		Context: brokerContext(t, "op-observe", "action-observe", validInput(), providerv0.HostMode_HOST_MODE_DEVELOPMENT, ""),
	})
	if err == nil || !strings.Contains(err.Error(), DiagRateLimit) {
		t.Fatalf("expected rate-limit failure, got %v", err)
	}
}

func TestObserve_WithoutHostFailsClosed(t *testing.T) {
	server := testServer(t) // no host attached
	_, err := server.Observe(t.Context(), &providerv0.ObserveRequest{Context: brokerContext(t, "op", "action", validInput(), providerv0.HostMode_HOST_MODE_DEVELOPMENT, "")})
	if err == nil || !strings.Contains(err.Error(), "host callback channel") {
		t.Fatalf("expected a fail-closed error without a host, got %v", err)
	}
}
