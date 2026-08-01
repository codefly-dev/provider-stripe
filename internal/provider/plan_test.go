package provider

import (
	"strings"
	"testing"

	providerv0 "github.com/codefly-dev/core/generated/go/codefly/services/provider/v0"
	"github.com/codefly-dev/core/provider/canonical"
)

func TestPlanCreatesWhenNoOwnedEndpoint(t *testing.T) {
	action := singleAction(t, planRequest(validInput(), &providerv0.MaterialObservation{Complete: true}))
	if action.GetType() != providerv0.ActionType_ACTION_TYPE_CREATE {
		t.Fatalf("expected CREATE, got %v", action.GetType())
	}
	if action.GetProspectiveRemoteId() == "" {
		t.Fatal("create must carry a prospective remote id for lost-response recovery")
	}
	if action.GetOwnership() != providerv0.Ownership_OWNERSHIP_OWNED {
		t.Fatal("a created endpoint is Codefly-owned")
	}
}

func TestPlanNoOpWhenConverged(t *testing.T) {
	observation := ownedObservation("we_1", "https://app.example.com/v1/billing/webhook", "2024-06-20",
		[]string{"customer.subscription.created", "customer.subscription.updated"}, statusEnabled)
	action := singleAction(t, planRequest(validInput(), observation))
	if action.GetType() != providerv0.ActionType_ACTION_TYPE_NO_OP {
		t.Fatalf("expected NO_OP, got %v", action.GetType())
	}
}

func TestPlanUpdatesOnMutableDrift(t *testing.T) {
	observation := ownedObservation("we_1", "https://app.example.com/v1/billing/webhook", "2024-06-20",
		[]string{"customer.subscription.created"}, statusEnabled) // desired has an extra event
	action := singleAction(t, planRequest(validInput(), observation))
	if action.GetType() != providerv0.ActionType_ACTION_TYPE_UPDATE {
		t.Fatalf("expected UPDATE, got %v", action.GetType())
	}
	if action.GetRemoteIdentity().GetRemoteId() != "we_1" {
		t.Fatal("update must target the owned remote id")
	}
}

func TestPlanReplacesOnAPIVersionChange(t *testing.T) {
	observation := ownedObservation("we_1", "https://app.example.com/v1/billing/webhook", "2020-08-27",
		[]string{"customer.subscription.created", "customer.subscription.updated"}, statusEnabled)
	response, err := testServer(t).Plan(t.Context(), planRequest(validInput(), observation))
	if err != nil {
		t.Fatal(err)
	}
	action := response.GetPlan().GetActions()[0]
	if action.GetType() != providerv0.ActionType_ACTION_TYPE_REPLACE {
		t.Fatalf("expected REPLACE on API-version change, got %v", action.GetType())
	}
	if action.GetProspectiveRemoteId() == "" {
		t.Fatal("replace must carry a prospective remote id")
	}
	// The prospective id must carry binding attribution (like create), so a
	// replayed replace after a lost response remains attributable to its binding.
	if want := "ws-env-bind"; !strings.Contains(action.GetProspectiveRemoteId(), want) {
		t.Fatalf("replace prospective id %q must carry binding attribution %q", action.GetProspectiveRemoteId(), want)
	}
	if !hasDiagnostic(response.GetDiagnostics(), DiagValidation) {
		t.Fatal("replace must warn about the rotated signing secret and retained endpoint")
	}
}

func TestPlanImportsExistingByExactID(t *testing.T) {
	input := validInput()
	input["callback_mode"] = str("existing")
	input["existing_webhook_id"] = str("we_operator")
	action := singleAction(t, planRequest(input, &providerv0.MaterialObservation{Complete: true}))
	if action.GetType() != providerv0.ActionType_ACTION_TYPE_IMPORT {
		t.Fatalf("expected IMPORT, got %v", action.GetType())
	}
	if action.GetRemoteIdentity().GetRemoteId() != "we_operator" {
		t.Fatal("import must reference the exact operator-supplied id")
	}
}

func TestPlanBlocksOnUnmanagedSameURL(t *testing.T) {
	url := "https://app.example.com/v1/billing/webhook"
	observation := &providerv0.MaterialObservation{
		Complete: true,
		Resources: []*providerv0.MaterialResourceObservation{{
			Identity:  &providerv0.RemoteIdentity{Provider: "stripe", ResourceType: resourceWebhook, RemoteId: "we_foreign"},
			Ownership: providerv0.Ownership_OWNERSHIP_UNMANAGED,
			ProviderOwnedFields: map[string]*providerv0.PublicValue{
				fieldURL: str(url), fieldAPIVersion: str("2024-06-20"),
			},
		}},
	}
	response, err := testServer(t).Plan(t.Context(), planRequest(validInput(), observation))
	if err != nil {
		t.Fatal(err)
	}
	action := response.GetPlan().GetActions()[0]
	if action.GetType() != providerv0.ActionType_ACTION_TYPE_BLOCKED {
		t.Fatalf("expected BLOCKED, got %v", action.GetType())
	}
	if action.GetOwnership() != providerv0.Ownership_OWNERSHIP_UNMANAGED {
		t.Fatal("a same-URL foreign endpoint must remain unmanaged, never adopted")
	}
	if !hasDiagnostic(response.GetDiagnostics(), DiagUnmanagedConflict) {
		t.Fatal("expected an unmanaged-conflict diagnostic")
	}
}

func TestPlanLocalForwardedCreatesNoRemoteEndpoint(t *testing.T) {
	input := validInput()
	input["callback_mode"] = str("local-forwarded")
	delete(input, "callback_url")
	action := singleAction(t, planRequest(input, &providerv0.MaterialObservation{Complete: true}))
	if action.GetType() != providerv0.ActionType_ACTION_TYPE_NO_OP {
		t.Fatalf("local-forwarded must not create a remote endpoint; got %v", action.GetType())
	}
}

func TestPlanProjectsBillingWithReferencesButNotManagementKey(t *testing.T) {
	observation := ownedObservation("we_1", "https://app.example.com/v1/billing/webhook", "2024-06-20",
		[]string{"customer.subscription.created", "customer.subscription.updated"}, statusEnabled)
	request := planRequest(validInput(), observation)
	request.OutputTarget = &providerv0.OutputTarget{Contract: "codefly.dev/configuration/billing@1", TargetGeneration: 2}
	request.Desired.CredentialReferences = []*providerv0.OpaqueReference{
		{Reference: "secret://stripe/runtime", Purpose: providerv0.CredentialPurpose_CREDENTIAL_PURPOSE_RUNTIME},
		{Reference: "secret://stripe/webhook", Purpose: providerv0.CredentialPurpose_CREDENTIAL_PURPOSE_WEBHOOK_VERIFICATION},
		{Reference: "secret://stripe/management", Purpose: providerv0.CredentialPurpose_CREDENTIAL_PURPOSE_MANAGEMENT},
	}
	response, err := testServer(t).Plan(t.Context(), request)
	if err != nil {
		t.Fatal(err)
	}
	var output *providerv0.PlanAction
	for _, action := range response.GetPlan().GetActions() {
		if action.GetType() == providerv0.ActionType_ACTION_TYPE_PROJECT_OUTPUT {
			output = action
		}
	}
	if output == nil {
		t.Fatal("expected a PROJECT_OUTPUT action")
	}
	values := output.GetOutput().GetValues()
	if _, ok := values["STRIPE_SECRET_KEY"]; !ok {
		t.Fatal("runtime key reference must be projected")
	}
	if _, ok := values["STRIPE_WEBHOOK_SECRET"]; !ok {
		t.Fatal("webhook verification reference must be projected")
	}
	for key, value := range values {
		if reference := value.GetOpaqueReference(); reference != nil &&
			reference.GetPurpose() == providerv0.CredentialPurpose_CREDENTIAL_PURPOSE_MANAGEMENT {
			t.Fatalf("management credential must never be projected (found in %q)", key)
		}
	}
}

func TestPlanDefersBillingWithoutReferences(t *testing.T) {
	observation := ownedObservation("we_1", "https://app.example.com/v1/billing/webhook", "2024-06-20",
		[]string{"customer.subscription.created", "customer.subscription.updated"}, statusEnabled)
	request := planRequest(validInput(), observation)
	request.OutputTarget = &providerv0.OutputTarget{Contract: "codefly.dev/configuration/billing@1", TargetGeneration: 2}
	response, err := testServer(t).Plan(t.Context(), request)
	if err != nil {
		t.Fatal(err)
	}
	for _, action := range response.GetPlan().GetActions() {
		if action.GetType() == providerv0.ActionType_ACTION_TYPE_PROJECT_OUTPUT {
			t.Fatal("billing projection must be deferred when references are unavailable")
		}
	}
}

func TestPlanDigestIsBoundAndPositionsAreSequential(t *testing.T) {
	response, err := testServer(t).Plan(t.Context(), planRequest(validInput(), &providerv0.MaterialObservation{Complete: true}))
	if err != nil {
		t.Fatal(err)
	}
	plan := response.GetPlan()
	if plan.GetPlanDigest() == "" {
		t.Fatal("plan digest must be bound")
	}
	rebound, err := canonical.BindOrderedPlanDigest(plan)
	if err != nil {
		t.Fatalf("plan does not re-validate: %v", err)
	}
	if rebound.GetPlanDigest() != plan.GetPlanDigest() {
		t.Fatal("plan digest is not stable")
	}
	for i, action := range plan.GetActions() {
		if action.GetPosition() != uint32(i) {
			t.Fatalf("action %d has position %d", i, action.GetPosition())
		}
	}
}

func TestPlanRejectsInvalidInput(t *testing.T) {
	input := validInput()
	delete(input, "stripe_api_version")
	response, err := testServer(t).Plan(t.Context(), planRequest(input, &providerv0.MaterialObservation{Complete: true}))
	if err != nil {
		t.Fatal(err)
	}
	if response.GetPlan() != nil {
		t.Fatal("an invalid plan request must not produce a plan")
	}
}
