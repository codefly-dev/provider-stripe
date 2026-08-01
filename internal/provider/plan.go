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

	webhook, err := s.planWebhook(in, target, observed, binding, accountID)
	if err != nil {
		return nil, err
	}
	actions := webhook.actions
	diagnostics := webhook.diagnostics

	// The billing projection is admissible only when the webhook plan actually
	// manages or observes an endpoint. A blocked conflict manages nothing, so
	// there is no verification secret to project and billing must not be emitted.
	// When billing is requested and admissible but the credential references are
	// not yet wired, the projection is deferred with an informational diagnostic
	// rather than emitted against unresolved references.
	if webhook.billingAdmissible {
		output, err := s.planBilling(in, request.GetOutputTarget(), desired.GetCredentialReferences())
		if err != nil {
			return nil, err
		}
		switch {
		case output != nil:
			actions = append(actions, output)
		case billingRequested(request.GetOutputTarget()):
			diagnostics = append(diagnostics, diag(basev0.FailureDiagnostic_INFO, DiagProjectionDeferred,
				"billing projection is deferred until the runtime and webhook credential references are available"))
		}
	}

	plan, err := s.assemblePlan(request, binding, actions)
	if err != nil {
		return nil, err
	}
	return &providerv0.PlanResponse{Plan: plan, Diagnostics: diagnostics}, nil
}

// webhookPlan is the outcome of planning the billing webhook endpoint: the
// ordered actions, their diagnostics, and whether the outcome admits a billing
// projection. A blocked (refused) webhook manages no endpoint, so it never
// admits a projection; every other outcome does, since the verification secret
// is either already captured, captured at ApplyAction before the projection, or
// supplied out of band (local-forwarded, imported).
type webhookPlan struct {
	actions           []*providerv0.PlanAction
	diagnostics       []*basev0.FailureDiagnostic
	billingAdmissible bool
}

// planWebhook decides the webhook-endpoint action set. It fails closed if the
// SDK refuses to build an action, so a malformed action can never reach the
// plan.
func (s *Server) planWebhook(in inputs, target desiredWebhook, observed []observedWebhook, binding *providerv0.BindingAddress, accountID string) (webhookPlan, error) {
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
		action, err := sdk.NewNoOpAction("webhook-local-forwarded", 0, resourceWebhook)
		if err != nil {
			return webhookPlan{}, err
		}
		action.Ownership = providerv0.Ownership_OWNERSHIP_OBSERVED
		action.Summary = "local-forwarded mode manages no remote endpoint; the Stripe CLI listener supplies the verification secret"
		return webhookPlan{actions: []*providerv0.PlanAction{action}, billingAdmissible: true}, nil

	case modeExisting:
		if owned := ownedBy(observed, binding); owned != nil {
			return s.convergeOwned(target, *owned, binding, remoteIdentity)
		}
		action, err := sdk.NewImportAction("webhook-import", 0, resourceWebhook)
		if err != nil {
			return webhookPlan{}, err
		}
		action.RemoteIdentity = remoteIdentity(in.ExistingID)
		action.Ownership = providerv0.Ownership_OWNERSHIP_OBSERVED
		action.Summary = fmt.Sprintf("import the operator-supplied endpoint %s by exact id before any mutation", in.ExistingID)
		return webhookPlan{actions: []*providerv0.PlanAction{action}, billingAdmissible: true}, nil

	default: // modePublic
		if owned := ownedBy(observed, binding); owned != nil {
			return s.convergeOwned(target, *owned, binding, remoteIdentity)
		}
		if conflicts := unmanagedAtURL(observed, target.URL); len(conflicts) > 0 {
			return s.blockOnUnmanaged(conflicts)
		}
		action, err := sdk.NewCreateAction("webhook-create", 0, resourceWebhook, prospectiveID(binding, "create"))
		if err != nil {
			return webhookPlan{}, err
		}
		action.Ownership = providerv0.Ownership_OWNERSHIP_OWNED
		action.Summary = "create the Codefly-owned billing webhook endpoint and capture its signing secret"
		return webhookPlan{actions: []*providerv0.PlanAction{action}, billingAdmissible: true}, nil
	}
}

// convergeOwned classifies drift on an owned endpoint and returns the exact
// converging action.
func (s *Server) convergeOwned(target desiredWebhook, owned observedWebhook, binding *providerv0.BindingAddress, remoteIdentity func(string) *providerv0.RemoteIdentity) (webhookPlan, error) {
	switch classifyDrift(target, owned) {
	case driftNone:
		action, err := sdk.NewNoOpAction("webhook-noop", 0, resourceWebhook)
		if err != nil {
			return webhookPlan{}, err
		}
		action.RemoteIdentity = remoteIdentity(owned.RemoteID)
		action.Ownership = providerv0.Ownership_OWNERSHIP_OWNED
		action.Summary = "owned webhook endpoint already matches desired state"
		return webhookPlan{actions: []*providerv0.PlanAction{action}, billingAdmissible: true}, nil

	case driftMutable:
		action, err := sdk.NewUpdateAction("webhook-update", 0, resourceWebhook)
		if err != nil {
			return webhookPlan{}, err
		}
		action.RemoteIdentity = remoteIdentity(owned.RemoteID)
		action.Ownership = providerv0.Ownership_OWNERSHIP_OWNED
		action.Summary = "converge Codefly-owned fields (url, events, description, metadata, enabled) of the owned endpoint"
		return webhookPlan{actions: []*providerv0.PlanAction{action}, billingAdmissible: true}, nil

	default: // driftReplace
		action, err := sdk.NewReplaceAction("webhook-replace", 0, resourceWebhook, prospectiveID(binding, "replace-"+owned.RemoteID))
		if err != nil {
			return webhookPlan{}, err
		}
		action.RemoteIdentity = remoteIdentity(owned.RemoteID)
		action.Ownership = providerv0.Ownership_OWNERSHIP_OWNED
		action.Summary = fmt.Sprintf("endpoint API version changes from %q to %q: replace mints a new endpoint and signing secret; the prior endpoint is retained", owned.APIVersion, target.APIVersion)
		diagnostic := diag(basev0.FailureDiagnostic_WARNING, DiagValidation,
			"changing the endpoint API version is a replacement: Stripe rotates the signing secret and the prior endpoint is retained by default")
		return webhookPlan{
			actions:           []*providerv0.PlanAction{action},
			diagnostics:       []*basev0.FailureDiagnostic{diagnostic},
			billingAdmissible: true,
		}, nil
	}
}

// blockOnUnmanaged refuses to touch a same-URL endpoint that Codefly does not
// own. Adoption is never inferred from the URL; the operator must import by
// exact id. A blocked webhook manages no endpoint, so billing is not admissible.
func (s *Server) blockOnUnmanaged(conflicts []observedWebhook) (webhookPlan, error) {
	ids := make([]string, 0, len(conflicts))
	for _, c := range conflicts {
		ids = append(ids, c.RemoteID)
	}
	action, err := sdk.NewBlockedAction("webhook-unmanaged", 0, resourceWebhook)
	if err != nil {
		return webhookPlan{}, err
	}
	action.Ownership = providerv0.Ownership_OWNERSHIP_UNMANAGED
	action.Summary = fmt.Sprintf("unmanaged endpoint(s) at the desired URL: %s; import one by exact id, do not adopt by URL", strings.Join(ids, ", "))
	severity := basev0.FailureDiagnostic_ERROR
	message := fmt.Sprintf("an unmanaged webhook endpoint already serves this URL (%s); import it by exact id via existing mode before Codefly manages it", strings.Join(ids, ", "))
	if len(conflicts) > 1 {
		message = fmt.Sprintf("multiple unmanaged webhook endpoints serve this URL (%s); this is an ambiguous conflict and must be resolved by exact-id import", strings.Join(ids, ", "))
	}
	return webhookPlan{
		actions:           []*providerv0.PlanAction{action},
		diagnostics:       []*basev0.FailureDiagnostic{diag(severity, DiagUnmanagedConflict, message)},
		billingAdmissible: false,
	}, nil
}

// billingRequested reports whether the host asked for a billing projection on
// this plan (a billing output target with a real target generation).
func billingRequested(target *providerv0.OutputTarget) bool {
	return target.GetContract() == configuration.BillingContract && target.GetTargetGeneration() != 0
}

// planBilling emits a PROJECT_OUTPUT action projecting billing@1 when a billing
// projection is requested and every required reference is available. The
// management credential is never projected; only the runtime key reference, the
// webhook verification reference, and public identifiers are.
func (s *Server) planBilling(in inputs, target *providerv0.OutputTarget, references []*providerv0.OpaqueReference) (*providerv0.PlanAction, error) {
	if !billingRequested(target) {
		return nil, nil
	}
	runtime := referenceByPurpose(references, providerv0.CredentialPurpose_CREDENTIAL_PURPOSE_RUNTIME)
	webhook := referenceByPurpose(references, providerv0.CredentialPurpose_CREDENTIAL_PURPOSE_WEBHOOK_VERIFICATION)
	if in.PublishableKey == "" || runtime == nil || webhook == nil {
		return nil, nil
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
	// Position is assigned authoritatively by assemblePlan from slice order.
	action, err := sdk.NewProjectOutputAction("billing-project", 0, proposal)
	if err != nil {
		return nil, err
	}
	action.Summary = "project billing@1 configuration (runtime key and webhook verification as opaque references)"
	return action, nil
}

// assemblePlan numbers the actions from slice order, binds the input digests,
// and computes the plan digest. Positions are authoritative from slice order,
// so the plan is sequentially numbered regardless of how many actions each path
// emits.
func (s *Server) assemblePlan(request *providerv0.PlanRequest, binding *providerv0.BindingAddress, actions []*providerv0.PlanAction) (*providerv0.OrderedPlan, error) {
	for i, action := range actions {
		action.Position = uint32(i)
	}
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
