package provider

import (
	"context"
	"fmt"
	"strings"

	basev0 "github.com/codefly-dev/core/generated/go/codefly/base/v0"
	providerv0 "github.com/codefly-dev/core/generated/go/codefly/services/provider/v0"
	"github.com/codefly-dev/core/provider/canonical"
	"github.com/codefly-dev/core/provider/configuration"
	"github.com/codefly-dev/core/provider/sdk"
)

// Plan produces the exact ordered plan offline, without broker access. It never
// contacts Stripe; the host supplies the observation. Planned broker requests
// carry no admitted origin (that is bound at ApplyAction), so offline actions
// declare intent and ownership only.
func (s *Server) Plan(_ context.Context, request *providerv0.PlanRequest) (*providerv0.PlanResponse, error) {
	ctx := request.GetContext()
	desired := request.GetDesired()
	binding := desired.GetBinding()
	if binding == nil {
		binding = ctx.GetBinding()
	}

	in, err := parseInputs(desired.GetInput())
	if err != nil {
		return &providerv0.PlanResponse{
			Diagnostics: []*basev0.FailureDiagnostic{diag(basev0.FailureDiagnostic_ERROR, DiagInvalidInput, err.Error())},
		}, nil
	}
	if diagnostics := validateInputs(in, ctx.GetMode()); hasError(diagnostics) {
		return &providerv0.PlanResponse{Diagnostics: diagnostics}, nil
	}

	target := desiredFrom(in, binding)
	observed := observedWebhooks(request.GetObservation())
	accountID := ctx.GetAccountIdentity()

	actions, diagnostics, secretCaptured := s.planWebhook(in, target, observed, binding, accountID)

	// Emit the billing projection only when every required reference is
	// resolvable offline. On first-time create/replace the signing secret is
	// captured at ApplyAction, so the projection follows that capture.
	if output := s.planBilling(in, request.GetOutputTarget(), desired.GetCredentialReferences(), uint32(len(actions))); output != nil {
		actions = append(actions, output)
	} else if !secretCaptured {
		diagnostics = append(diagnostics, diag(basev0.FailureDiagnostic_INFO, DiagValidation,
			"billing projection is deferred until the webhook signing secret is captured"))
	}

	plan, err := s.assemblePlan(request, binding, actions)
	if err != nil {
		return nil, err
	}
	return &providerv0.PlanResponse{Plan: plan, Diagnostics: diagnostics}, nil
}

// planWebhook decides the webhook-endpoint action set. secretCaptured reports
// whether the resulting owned endpoint already holds a captured signing secret
// (i.e. no create/replace is pending).
func (s *Server) planWebhook(in inputs, target desiredWebhook, observed []observedWebhook, binding *providerv0.BindingAddress, accountID string) ([]*providerv0.PlanAction, []*basev0.FailureDiagnostic, bool) {
	remoteIdentity := func(remoteID string) *providerv0.RemoteIdentity {
		return &providerv0.RemoteIdentity{
			Provider:     "stripe",
			AccountId:    accountID,
			ResourceType: resourceWebhook,
			RemoteId:     remoteID,
		}
	}

	switch in.CallbackMode {
	case modeLocalForwarded:
		action, _ := sdk.NewNoOpAction("webhook-local-forwarded", 0, resourceWebhook)
		action.Ownership = providerv0.Ownership_OWNERSHIP_OBSERVED
		action.Summary = "local-forwarded mode manages no remote endpoint; the Stripe CLI listener supplies the verification secret"
		return []*providerv0.PlanAction{action}, nil, false

	case modeExisting:
		if owned := ownedBy(observed, binding); owned != nil {
			return s.convergeOwned(target, *owned, binding, remoteIdentity)
		}
		action, _ := sdk.NewImportAction("webhook-import", 0, resourceWebhook)
		action.RemoteIdentity = remoteIdentity(in.ExistingID)
		action.Ownership = providerv0.Ownership_OWNERSHIP_OBSERVED
		action.Summary = fmt.Sprintf("import the operator-supplied endpoint %s by exact id before any mutation", in.ExistingID)
		return []*providerv0.PlanAction{action}, nil, false

	default: // modePublic
		if owned := ownedBy(observed, binding); owned != nil {
			return s.convergeOwned(target, *owned, binding, remoteIdentity)
		}
		if conflicts := unmanagedAtURL(observed, target.URL); len(conflicts) > 0 {
			return s.blockOnUnmanaged(conflicts)
		}
		action, _ := sdk.NewCreateAction("webhook-create", 0, resourceWebhook, prospectiveID(binding, "create"))
		action.Ownership = providerv0.Ownership_OWNERSHIP_OWNED
		action.Summary = "create the Codefly-owned billing webhook endpoint and capture its signing secret"
		return []*providerv0.PlanAction{action}, nil, false
	}
}

// convergeOwned classifies drift on an owned endpoint and returns the exact
// converging action.
func (s *Server) convergeOwned(target desiredWebhook, owned observedWebhook, binding *providerv0.BindingAddress, remoteIdentity func(string) *providerv0.RemoteIdentity) ([]*providerv0.PlanAction, []*basev0.FailureDiagnostic, bool) {
	switch classifyDrift(target, owned) {
	case driftNone:
		action, _ := sdk.NewNoOpAction("webhook-noop", 0, resourceWebhook)
		action.RemoteIdentity = remoteIdentity(owned.RemoteID)
		action.Ownership = providerv0.Ownership_OWNERSHIP_OWNED
		action.Summary = "owned webhook endpoint already matches desired state"
		return []*providerv0.PlanAction{action}, nil, true

	case driftMutable:
		action, _ := sdk.NewUpdateAction("webhook-update", 0, resourceWebhook)
		action.RemoteIdentity = remoteIdentity(owned.RemoteID)
		action.Ownership = providerv0.Ownership_OWNERSHIP_OWNED
		action.Summary = "converge Codefly-owned fields (url, events, description, metadata, enabled) of the owned endpoint"
		return []*providerv0.PlanAction{action}, nil, true

	default: // driftReplace
		action, _ := sdk.NewReplaceAction("webhook-replace", 0, resourceWebhook, prospectiveID(binding, "replace-"+owned.RemoteID))
		action.RemoteIdentity = remoteIdentity(owned.RemoteID)
		action.Ownership = providerv0.Ownership_OWNERSHIP_OWNED
		action.Summary = fmt.Sprintf("endpoint API version changes from %q to %q: replace mints a new endpoint and signing secret; the prior endpoint is retained", owned.APIVersion, target.APIVersion)
		diagnostic := diag(basev0.FailureDiagnostic_WARNING, DiagValidation,
			"changing the endpoint API version is a replacement: Stripe rotates the signing secret and the prior endpoint is retained by default")
		return []*providerv0.PlanAction{action}, []*basev0.FailureDiagnostic{diagnostic}, false
	}
}

// blockOnUnmanaged refuses to touch a same-URL endpoint that Codefly does not
// own. Adoption is never inferred from the URL; the operator must import by
// exact id.
func (s *Server) blockOnUnmanaged(conflicts []observedWebhook) ([]*providerv0.PlanAction, []*basev0.FailureDiagnostic, bool) {
	ids := make([]string, 0, len(conflicts))
	for _, c := range conflicts {
		ids = append(ids, c.RemoteID)
	}
	action, _ := sdk.NewBlockedAction("webhook-unmanaged", 0, resourceWebhook)
	action.Ownership = providerv0.Ownership_OWNERSHIP_UNMANAGED
	action.Summary = fmt.Sprintf("unmanaged endpoint(s) at the desired URL: %s; import one by exact id, do not adopt by URL", strings.Join(ids, ", "))
	severity := basev0.FailureDiagnostic_ERROR
	message := fmt.Sprintf("an unmanaged webhook endpoint already serves this URL (%s); import it by exact id via existing mode before Codefly manages it", strings.Join(ids, ", "))
	if len(conflicts) > 1 {
		message = fmt.Sprintf("multiple unmanaged webhook endpoints serve this URL (%s); this is an ambiguous conflict and must be resolved by exact-id import", strings.Join(ids, ", "))
	}
	return []*providerv0.PlanAction{action}, []*basev0.FailureDiagnostic{diag(severity, DiagUnmanagedConflict, message)}, false
}

// planBilling emits a PROJECT_OUTPUT action projecting billing@1 when every
// required reference is available. The management credential is never
// projected; only the runtime key reference, the webhook verification
// reference, and public identifiers are.
func (s *Server) planBilling(in inputs, target *providerv0.OutputTarget, references []*providerv0.OpaqueReference, position uint32) *providerv0.PlanAction {
	if target == nil || target.GetContract() != configuration.BillingContract || target.GetTargetGeneration() == 0 {
		return nil
	}
	runtime := referenceByPurpose(references, providerv0.CredentialPurpose_CREDENTIAL_PURPOSE_RUNTIME)
	webhook := referenceByPurpose(references, providerv0.CredentialPurpose_CREDENTIAL_PURPOSE_WEBHOOK_VERIFICATION)
	if in.PublishableKey == "" || runtime == nil || webhook == nil {
		return nil
	}
	values := map[string]*providerv0.OutputValue{
		"STRIPE_PUBLISHABLE_KEY": publicOutput(in.PublishableKey),
		"STRIPE_SECRET_KEY":      referenceOutput(runtime),
		"STRIPE_WEBHOOK_SECRET":  referenceOutput(webhook),
	}
	if in.PriceID != "" {
		values["STRIPE_PRICE_ID"] = publicOutput(in.PriceID)
	}
	proposal := &providerv0.OutputProposal{
		Contract:         target.GetContract(),
		TargetGeneration: target.GetTargetGeneration(),
		Values:           values,
	}
	action, err := sdk.NewProjectOutputAction("billing-project", position, proposal)
	if err != nil {
		return nil
	}
	action.Summary = "project billing@1 configuration (runtime key and webhook verification as opaque references)"
	return action
}

// assemblePlan binds the input digests and computes the plan digest.
func (s *Server) assemblePlan(request *providerv0.PlanRequest, binding *providerv0.BindingAddress, actions []*providerv0.PlanAction) (*providerv0.OrderedPlan, error) {
	plan := &providerv0.OrderedPlan{
		PlanId:         planID(binding, request.GetStateGeneration()),
		ArtifactDigest: s.artifactDigest,
		ManifestDigest: s.manifestDigest,
		CatalogDigest:  s.catalogDigest,
		Actions:        actions,
	}
	if desired := request.GetDesired(); desired != nil {
		digest, err := canonical.BindingDesiredStateDigest(desired)
		if err != nil {
			return nil, err
		}
		plan.DesiredDigest = digest
	}
	if observation := request.GetObservation(); observation != nil {
		digest, err := canonical.MaterialObservationDigest(observation)
		if err != nil {
			return nil, err
		}
		plan.ObservationDigest = digest
	}
	if target := request.GetOutputTarget(); target != nil {
		digest, err := canonical.OutputTargetDigest(target)
		if err != nil {
			return nil, err
		}
		plan.OutputTargetDigest = digest
	}
	if generation := request.GetStateGeneration(); generation != nil {
		digest, err := canonical.StateGenerationDigest(generation)
		if err != nil {
			return nil, err
		}
		plan.StateGenerationDigest = digest
	}
	if policy := request.GetPolicyInput(); policy != nil {
		digest, err := canonical.PolicyApprovalInputDigest(policy)
		if err != nil {
			return nil, err
		}
		plan.PolicyInputDigest = digest
	}
	return canonical.BindOrderedPlanDigest(plan)
}

func referenceByPurpose(references []*providerv0.OpaqueReference, purpose providerv0.CredentialPurpose) *providerv0.OpaqueReference {
	for _, reference := range references {
		if reference.GetPurpose() == purpose {
			return reference
		}
	}
	return nil
}

func publicOutput(value string) *providerv0.OutputValue {
	return &providerv0.OutputValue{Kind: &providerv0.OutputValue_PublicValue{PublicValue: publicStringValue(value)}}
}

func referenceOutput(reference *providerv0.OpaqueReference) *providerv0.OutputValue {
	return &providerv0.OutputValue{Kind: &providerv0.OutputValue_OpaqueReference{OpaqueReference: reference}}
}

func prospectiveID(binding *providerv0.BindingAddress, suffix string) string {
	return fmt.Sprintf("prospective-%s-%s-%s-%s",
		binding.GetWorkspaceId(), binding.GetEnvironmentId(), binding.GetBindingId(), suffix)
}

func planID(binding *providerv0.BindingAddress, generation *providerv0.StateGeneration) string {
	return fmt.Sprintf("plan-%s-%s-%s-%d",
		binding.GetWorkspaceId(), binding.GetEnvironmentId(), binding.GetBindingId(), generation.GetGeneration())
}
