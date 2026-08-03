package provider

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	providerv0 "github.com/codefly-dev/core/generated/go/codefly/services/provider/v0"
	"github.com/codefly-dev/core/provider/configuration"
	"github.com/codefly-dev/core/provider/sdk"
	providerstate "github.com/codefly-dev/core/provider/state"
)

func applyRequest(t *testing.T, action *providerv0.PlanAction, input map[string]*providerv0.PublicValue, prior *providerv0.ActionCheckpoint) *providerv0.ApplyActionRequest {
	t.Helper()
	return &providerv0.ApplyActionRequest{
		Context:         brokerContext(t, "op-apply", action.GetActionId(), input, providerv0.HostMode_HOST_MODE_DEVELOPMENT, "acct_test_123"),
		Action:          action,
		PriorCheckpoint: prior,
	}
}

// withSecret injects the declared, capturable webhook signing secret into a
// webhook endpoint object, as a create response returns exactly once.
func withSecret(objectJSON string) string {
	var object map[string]any
	_ = json.Unmarshal([]byte(objectJSON), &object)
	object["secret"] = poisonSigningSecret
	encoded, _ := json.Marshal(object)
	return string(encoded)
}

func createAction(t *testing.T) *providerv0.PlanAction {
	t.Helper()
	action, err := sdk.NewCreateAction("webhook-create", 0, resourceWebhook, "prospective-ws-env-bind-create")
	if err != nil {
		t.Fatalf("create action: %v", err)
	}
	action.Ownership = providerv0.Ownership_OWNERSHIP_OWNED
	return action
}

func TestApplyAction_CreateCapturesSecretWithoutLeaking(t *testing.T) {
	host := newFakeHost(t, false)
	server := fakeServer(t, host)
	events := []string{"customer.subscription.created", "customer.subscription.updated"}
	routes := map[string]http.HandlerFunc{
		"POST /v1/webhook_endpoints": func(w http.ResponseWriter, _ *http.Request) {
			writeJSON(w, http.StatusOK, withSecret(
				webhookJSON("we_new", "https://app.example.com/v1/billing/webhook", "2024-06-20", statusEnabled, events, false, true, false)))
		},
	}
	stub := stripeStub(t, routes)
	host.record(stub)

	response, err := server.ApplyAction(t.Context(), applyRequest(t, createAction(t), validInput(), nil))
	if err != nil {
		t.Fatalf("apply create: %v", err)
	}

	// The one-time signing secret was captured and reaches the provider only as an
	// opaque reference; the raw secret is stored in the sink alone.
	if got := host.sink.stored; len(got) != 1 || got[0] != poisonSigningSecret {
		t.Fatalf("sink stored = %v", got)
	}
	references := response.GetReceipt().GetCaptureReferences()
	if len(references) != 1 || references[0].GetPurpose() != providerv0.CredentialPurpose_CREDENTIAL_PURPOSE_WEBHOOK_VERIFICATION {
		t.Fatalf("capture references = %v", references)
	}
	state := response.GetNextState()
	if got := state.GetV1().GetRemoteIdentity().GetRemoteId(); got != "we_new" {
		t.Fatalf("next state remote id = %q", got)
	}
	if state.GetV1().GetOwnership() != providerv0.Ownership_OWNERSHIP_OWNED {
		t.Fatal("create must own the endpoint")
	}
	if err := providerstate.ValidateVersioned(state, manifestStateSchemaVersion); err != nil {
		t.Fatalf("next state is invalid: %v", err)
	}
	assertNoSecret(t, response)

	// Replay is enforcement-identical and reaches no network.
	host.replay()
	replayed, err := server.ApplyAction(t.Context(), applyRequest(t, createAction(t), validInput(), nil))
	if err != nil {
		t.Fatalf("apply create replay: %v", err)
	}
	if replayed.GetNextState().GetV1().GetRemoteIdentity().GetRemoteId() != "we_new" {
		t.Fatal("replay must reproduce the same endpoint identity")
	}
	// Replay served the capture from the cassette; the sink was not touched again.
	if len(host.sink.stored) != 1 {
		t.Fatalf("replay must not re-store the secret, stored = %v", host.sink.stored)
	}
}

func TestApplyAction_IdempotentReplayCreatesNoDuplicate(t *testing.T) {
	host := newFakeHost(t, false)
	server := fakeServer(t, host)
	created := 0
	events := []string{"customer.subscription.updated"}
	routes := map[string]http.HandlerFunc{
		"POST /v1/webhook_endpoints": func(w http.ResponseWriter, _ *http.Request) {
			created++
			writeJSON(w, http.StatusOK, withSecret(
				webhookJSON("we_new", "https://app.example.com/v1/billing/webhook", "2024-06-20", statusEnabled, events, false, true, false)))
		},
	}
	stub := stripeStub(t, routes)
	host.record(stub)
	first, err := server.ApplyAction(t.Context(), applyRequest(t, createAction(t), validInput(), nil))
	if err != nil {
		t.Fatalf("first apply: %v", err)
	}
	host.replay()
	second, err := server.ApplyAction(t.Context(), applyRequest(t, createAction(t), validInput(), nil))
	if err != nil {
		t.Fatalf("second apply: %v", err)
	}
	if created != 1 {
		t.Fatalf("expected exactly one create to reach Stripe, got %d", created)
	}
	if first.GetNextState().GetV1().GetRemoteIdentity().GetRemoteId() != second.GetNextState().GetV1().GetRemoteIdentity().GetRemoteId() {
		t.Fatal("a replay must resolve to the same endpoint identity")
	}
}

func TestApplyAction_RecoversLostCaptureViaResolveCapture(t *testing.T) {
	host := newFakeHost(t, false)
	server := fakeServer(t, host)
	events := []string{"customer.subscription.updated"}
	routes := map[string]http.HandlerFunc{
		"POST /v1/webhook_endpoints": func(w http.ResponseWriter, _ *http.Request) {
			writeJSON(w, http.StatusOK, withSecret(
				webhookJSON("we_new", "https://app.example.com/v1/billing/webhook", "2024-06-20", statusEnabled, events, false, true, false)))
		},
	}
	stub := stripeStub(t, routes)
	host.record(stub)

	// A first attempt durably captures the secret host-side.
	if _, err := server.ApplyAction(t.Context(), applyRequest(t, createAction(t), validInput(), nil)); err != nil {
		t.Fatalf("seed apply: %v", err)
	}
	recovered := host.captures[secretCaptureSelector]
	if recovered == nil {
		t.Fatal("first attempt should have captured the signing secret")
	}
	storedBefore := len(host.sink.stored)

	// A retry whose prior checkpoint recorded a received response recovers the
	// capture reference through ResolveCapture instead of re-materializing the
	// secret, while the idempotent replay mints no duplicate.
	host.replay()
	prior := &providerv0.ActionCheckpoint{
		CheckpointId: "checkpoint-op-apply-webhook-create",
		Operation:    &providerv0.OperationIdentity{OperationId: "op-apply", ActionId: "webhook-create", PlanId: "plan-1", AttemptId: "attempt-1"},
		Delivery:     providerv0.DeliveryState_DELIVERY_STATE_RESPONSE_RECEIVED,
		IdempotencyKey: idempotencyKey(
			&providerv0.OperationIdentity{OperationId: "op-apply", ActionId: "webhook-create"}, createAction(t)),
		ProspectiveRemoteId: "prospective-ws-env-bind-create",
	}
	response, err := server.ApplyAction(t.Context(), applyRequest(t, createAction(t), validInput(), prior))
	if err != nil {
		t.Fatalf("recovery apply: %v", err)
	}
	references := response.GetReceipt().GetCaptureReferences()
	if len(references) != 1 || references[0].GetReference() != recovered.GetReference() {
		t.Fatalf("recovery must reuse the durable capture reference, got %v", references)
	}
	if len(host.sink.stored) != storedBefore {
		t.Fatal("recovery must not re-store the secret")
	}
	assertNoSecret(t, response)
}

func TestApplyAction_UpdateConvergesOwnedEndpoint(t *testing.T) {
	host := newFakeHost(t, false)
	server := fakeServer(t, host)
	events := []string{"customer.subscription.updated"}
	routes := map[string]http.HandlerFunc{
		"POST /v1/webhook_endpoints/{id}": func(w http.ResponseWriter, r *http.Request) {
			if r.PathValue("id") != "we_owned" {
				writeJSON(w, http.StatusNotFound, `{}`)
				return
			}
			writeJSON(w, http.StatusOK,
				webhookJSON("we_owned", "https://app.example.com/v1/billing/webhook", "2024-06-20", statusEnabled, events, false, true, false))
		},
	}
	action, err := sdk.NewUpdateAction("webhook-update", 0, resourceWebhook)
	if err != nil {
		t.Fatalf("update action: %v", err)
	}
	action.Ownership = providerv0.Ownership_OWNERSHIP_OWNED
	action.RemoteIdentity = remoteIdentity("acct_test_123", resourceWebhook, "we_owned")

	stub := stripeStub(t, routes)
	host.record(stub)
	response, err := server.ApplyAction(t.Context(), applyRequest(t, action, validInput(), nil))
	if err != nil {
		t.Fatalf("apply update: %v", err)
	}
	if response.GetReceipt().GetDelivery() != providerv0.DeliveryState_DELIVERY_STATE_RESPONSE_RECEIVED {
		t.Fatalf("delivery = %v", response.GetReceipt().GetDelivery())
	}
	if response.GetNextState().GetV1().GetRemoteIdentity().GetRemoteId() != "we_owned" {
		t.Fatal("update must keep the owned identity")
	}
}

func TestApplyAction_UpdatePreservesSecretAndInfersAccount(t *testing.T) {
	host := newFakeHost(t, false)
	server := fakeServer(t, host)
	events := []string{"customer.subscription.updated"}
	routes := map[string]http.HandlerFunc{
		"POST /v1/webhook_endpoints/{id}": func(w http.ResponseWriter, r *http.Request) {
			if r.PathValue("id") != "we_owned" {
				writeJSON(w, http.StatusNotFound, `{}`)
				return
			}
			writeJSON(w, http.StatusOK,
				webhookJSON("we_owned", "https://app.example.com/v1/billing/webhook", "2024-06-20", statusEnabled, events, false, true, false))
		},
	}
	action, err := sdk.NewUpdateAction("webhook-update", 0, resourceWebhook)
	if err != nil {
		t.Fatalf("update action: %v", err)
	}
	action.Ownership = providerv0.Ownership_OWNERSHIP_OWNED
	// The action names the endpoint but omits the account id: the offline context
	// is the fallback source of truth for the account the endpoint belongs to.
	action.RemoteIdentity = remoteIdentity("", resourceWebhook, "we_owned")

	// The endpoint's signing secret was captured once at create time and lives in
	// the prior state as an opaque reference an update must carry forward untouched.
	secretRef := &providerv0.OpaqueReference{
		Reference:       "capture://cap-existing-secret",
		Purpose:         providerv0.CredentialPurpose_CREDENTIAL_PURPOSE_WEBHOOK_VERIFICATION,
		SafeFingerprint: "sha256:" + strings.Repeat("c", 64),
	}
	request := applyRequest(t, action, validInput(), nil)
	request.State = providerstate.WrapV1(&providerv0.ProviderStateV1{
		StateSchemaVersion: manifestStateSchemaVersion,
		SecretReferences:   []*providerv0.OpaqueReference{secretRef},
	})

	stub := stripeStub(t, routes)
	host.record(stub)
	response, err := server.ApplyAction(t.Context(), request)
	if err != nil {
		t.Fatalf("apply update: %v", err)
	}
	v1 := response.GetNextState().GetV1()
	refs := v1.GetSecretReferences()
	if len(refs) != 1 || refs[0].GetReference() != secretRef.GetReference() {
		t.Fatalf("update must carry the signing-secret reference forward, got %v", refs)
	}
	if got := v1.GetRemoteIdentity().GetAccountId(); got != "acct_test_123" {
		t.Fatalf("update must infer the account from the offline context, got %q", got)
	}
	if err := providerstate.ValidateVersioned(response.GetNextState(), manifestStateSchemaVersion); err != nil {
		t.Fatalf("next state is invalid: %v", err)
	}
}

func TestApplyAction_DeleteOwnedEndpoint(t *testing.T) {
	host := newFakeHost(t, false)
	server := fakeServer(t, host)
	routes := map[string]http.HandlerFunc{
		"DELETE /v1/webhook_endpoints/{id}": func(w http.ResponseWriter, r *http.Request) {
			writeJSON(w, http.StatusOK, `{"id":"`+r.PathValue("id")+`","deleted":true,"object":"webhook_endpoint"}`)
		},
	}
	action, err := sdk.NewDeleteAction("webhook-delete", 0, resourceWebhook)
	if err != nil {
		t.Fatalf("delete action: %v", err)
	}
	action.Ownership = providerv0.Ownership_OWNERSHIP_OWNED
	action.RemoteIdentity = remoteIdentity("acct_test_123", resourceWebhook, "we_owned")

	stub := stripeStub(t, routes)
	host.record(stub)
	response, err := server.ApplyAction(t.Context(), applyRequest(t, action, validInput(), nil))
	if err != nil {
		t.Fatalf("apply delete: %v", err)
	}
	if response.GetNextState().GetV1().GetOwnership() != providerv0.Ownership_OWNERSHIP_OBSERVED {
		t.Fatal("a deleted endpoint leaves no owned remote object")
	}
}

func TestApplyAction_DeleteRefusedWithoutOwnership(t *testing.T) {
	host := newFakeHost(t, false)
	server := fakeServer(t, host)
	action, err := sdk.NewDeleteAction("webhook-delete", 0, resourceWebhook)
	if err != nil {
		t.Fatalf("delete action: %v", err)
	}
	// Unmanaged, and with no exact identity: deletion must be refused outright.
	action.Ownership = providerv0.Ownership_OWNERSHIP_UNMANAGED
	_, err = server.ApplyAction(t.Context(), applyRequest(t, action, validInput(), nil))
	if err == nil || !strings.Contains(err.Error(), "deletion is refused") {
		t.Fatalf("expected deletion to be refused, got %v", err)
	}
}

func TestApplyAction_CreateQuotaErrorIsPermanentNoDuplicate(t *testing.T) {
	host := newFakeHost(t, false)
	server := fakeServer(t, host)
	routes := map[string]http.HandlerFunc{
		"POST /v1/webhook_endpoints": func(w http.ResponseWriter, _ *http.Request) {
			// Stripe rejects an over-quota create with a 400 whose body the host drops.
			writeJSON(w, http.StatusBadRequest, `{"error":{"type":"invalid_request_error","message":"You have reached the maximum of 16 test webhook endpoints"}}`)
		},
	}
	stub := stripeStub(t, routes)
	host.record(stub)
	response, err := server.ApplyAction(t.Context(), applyRequest(t, createAction(t), validInput(), nil))
	if err != nil {
		t.Fatalf("apply create: %v", err)
	}
	receipt := response.GetReceipt()
	if receipt.GetCertainty() != providerv0.OutcomeCertainty_OUTCOME_CERTAINTY_COMPLETE {
		t.Fatalf("a 4xx is a definitive outcome, got %v", receipt.GetCertainty())
	}
	if len(receipt.GetDiagnostics()) == 0 || !hasError(receipt.GetDiagnostics()) {
		t.Fatal("a rejected create must carry an error diagnostic")
	}
	if response.GetNextState().GetV1().GetOwnership() == providerv0.Ownership_OWNERSHIP_OWNED {
		t.Fatal("a rejected create must own nothing")
	}
	if len(host.sink.stored) != 0 {
		t.Fatal("a rejected create captures no secret")
	}
}

func TestApplyAction_CreateWithoutSecretFailsClosed(t *testing.T) {
	host := newFakeHost(t, false)
	server := fakeServer(t, host)
	events := []string{"customer.subscription.updated"}
	routes := map[string]http.HandlerFunc{
		"POST /v1/webhook_endpoints": func(w http.ResponseWriter, _ *http.Request) {
			// A malformed create response omits the required signing secret.
			writeJSON(w, http.StatusOK,
				webhookJSON("we_new", "https://app.example.com/v1/billing/webhook", "2024-06-20", statusEnabled, events, false, true, false))
		},
	}
	stub := stripeStub(t, routes)
	host.record(stub)
	_, err := server.ApplyAction(t.Context(), applyRequest(t, createAction(t), validInput(), nil))
	if err == nil {
		t.Fatal("a create whose response omits the required secret must fail closed")
	}
}

func TestApplyAction_ReplaceMintsNewEndpointAndSecret(t *testing.T) {
	host := newFakeHost(t, false)
	server := fakeServer(t, host)
	events := []string{"customer.subscription.updated"}
	routes := map[string]http.HandlerFunc{
		"POST /v1/webhook_endpoints": func(w http.ResponseWriter, _ *http.Request) {
			writeJSON(w, http.StatusOK, withSecret(
				webhookJSON("we_replacement", "https://app.example.com/v1/billing/webhook", "2024-06-20", statusEnabled, events, false, true, false)))
		},
	}
	action, err := sdk.NewReplaceAction("webhook-replace", 0, resourceWebhook, "prospective-ws-env-bind-replace")
	if err != nil {
		t.Fatalf("replace action: %v", err)
	}
	action.Ownership = providerv0.Ownership_OWNERSHIP_OWNED
	action.RemoteIdentity = remoteIdentity("acct_test_123", resourceWebhook, "we_old")

	stub := stripeStub(t, routes)
	host.record(stub)
	response, err := server.ApplyAction(t.Context(), applyRequest(t, action, validInput(), nil))
	if err != nil {
		t.Fatalf("apply replace: %v", err)
	}
	if response.GetNextState().GetV1().GetRemoteIdentity().GetRemoteId() != "we_replacement" {
		t.Fatal("replace must own the freshly minted endpoint")
	}
	if len(response.GetReceipt().GetCaptureReferences()) != 1 {
		t.Fatal("replace mints a new signing secret to capture")
	}
}

func TestApplyAction_ImportAdoptsExactEndpoint(t *testing.T) {
	host := newFakeHost(t, false)
	server := fakeServer(t, host)
	events := []string{"customer.subscription.updated"}
	routes := map[string]http.HandlerFunc{
		"GET /v1/webhook_endpoints/{id}": func(w http.ResponseWriter, r *http.Request) {
			if r.PathValue("id") != "we_existing" {
				writeJSON(w, http.StatusNotFound, `{}`)
				return
			}
			writeJSON(w, http.StatusOK,
				webhookJSON("we_existing", "https://legacy.example.com/hook", "2024-06-20", statusEnabled, events, false, false, false))
		},
	}
	action, err := sdk.NewImportAction("webhook-import", 0, resourceWebhook)
	if err != nil {
		t.Fatalf("import action: %v", err)
	}
	action.Ownership = providerv0.Ownership_OWNERSHIP_OBSERVED
	action.RemoteIdentity = remoteIdentity("acct_test_123", resourceWebhook, "we_existing")

	stub := stripeStub(t, routes)
	host.record(stub)
	response, err := server.ApplyAction(t.Context(), applyRequest(t, action, validInput(), nil))
	if err != nil {
		t.Fatalf("apply import: %v", err)
	}
	if response.GetNextState().GetV1().GetOwnership() != providerv0.Ownership_OWNERSHIP_ADOPTED {
		t.Fatal("import adopts the exact endpoint")
	}
	if response.GetNextState().GetV1().GetRemoteIdentity().GetRemoteId() != "we_existing" {
		t.Fatal("import binds the exact endpoint id")
	}
}

func TestApplyAction_ProjectOutput(t *testing.T) {
	host := newFakeHost(t, false)
	server := fakeServer(t, host)
	proposal := &providerv0.OutputProposal{
		Contract:         configuration.BillingContract,
		TargetGeneration: 1,
		Values: map[string]*providerv0.OutputValue{
			"STRIPE_PUBLISHABLE_KEY": {Kind: &providerv0.OutputValue_PublicValue{PublicValue: publicStringValue("pk_test_123")}},
			"STRIPE_WEBHOOK_SECRET": {Kind: &providerv0.OutputValue_OpaqueReference{OpaqueReference: &providerv0.OpaqueReference{
				Reference: "capture://cap-webhook", Purpose: providerv0.CredentialPurpose_CREDENTIAL_PURPOSE_WEBHOOK_VERIFICATION,
			}}},
		},
	}
	action, err := sdk.NewProjectOutputAction("billing-project", 0, proposal)
	if err != nil {
		t.Fatalf("project output action: %v", err)
	}
	response, err := server.ApplyAction(t.Context(), applyRequest(t, action, validInput(), nil))
	if err != nil {
		t.Fatalf("apply project output: %v", err)
	}
	if len(host.outputs) != 1 || host.outputs[0].GetContract() != configuration.BillingContract {
		t.Fatalf("expected one billing projection, got %v", host.outputs)
	}
	if response.GetNextState().GetV1().GetOutputContract() != configuration.BillingContract {
		t.Fatal("next state must record the committed output contract")
	}
}

func TestApplyAction_NoOpOnOwnedEndpointYieldsValidState(t *testing.T) {
	host := newFakeHost(t, false)
	server := fakeServer(t, host)
	// A no-op that changes nothing but reports an owned endpoint: with no prior
	// state to keep, the result must still be an identity-complete owned state,
	// not an owned state missing its remote identity and stamp.
	action := &providerv0.PlanAction{
		ActionId:       "webhook-noop",
		Type:           providerv0.ActionType_ACTION_TYPE_NO_OP,
		ResourceType:   resourceWebhook,
		Ownership:      providerv0.Ownership_OWNERSHIP_OWNED,
		RemoteIdentity: remoteIdentity("acct_test_123", resourceWebhook, "we_owned"),
	}
	response, err := server.ApplyAction(t.Context(), applyRequest(t, action, validInput(), nil))
	if err != nil {
		t.Fatalf("apply no-op: %v", err)
	}
	state := response.GetNextState()
	if state.GetV1().GetRemoteIdentity().GetRemoteId() != "we_owned" {
		t.Fatalf("no-op must preserve the owned identity, got %q", state.GetV1().GetRemoteIdentity().GetRemoteId())
	}
	if err := providerstate.ValidateVersioned(state, manifestStateSchemaVersion); err != nil {
		t.Fatalf("a no-op owned result must be a valid state: %v", err)
	}
}

func TestApplyAction_WithoutHostFailsClosed(t *testing.T) {
	server := testServer(t)
	_, err := server.ApplyAction(t.Context(), applyRequest(t, createAction(t), validInput(), nil))
	if err == nil || !strings.Contains(err.Error(), "host callback channel") {
		t.Fatalf("expected a fail-closed error without a host, got %v", err)
	}
}

func assertNoSecret(t *testing.T, message interface{ String() string }) {
	t.Helper()
	if strings.Contains(message.String(), poisonSigningSecret) || strings.Contains(message.String(), managementKey) {
		t.Fatal("a secret must never appear in a provider-facing message")
	}
}
