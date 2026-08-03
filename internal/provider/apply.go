package provider

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"

	basev0 "github.com/codefly-dev/core/generated/go/codefly/base/v0"
	providerv0 "github.com/codefly-dev/core/generated/go/codefly/services/provider/v0"
	"github.com/codefly-dev/core/provider/sdk"
	providerstate "github.com/codefly-dev/core/provider/state"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// secretCaptureSelector is the exact response selector the manifest captures the
// one-time webhook signing secret from. It is the capture id the host echoes and
// the key ResolveCapture recovers a lost reference by.
const secretCaptureSelector = "$.secret"

// ApplyAction applies exactly one host-selected action from the bound plan. Every
// mutation is preceded by a durable checkpoint and carries a stable idempotency
// key, so a replay after a lost response creates no duplicate; a captured signing
// secret is recovered as an opaque reference and never re-materialized.
func (s *Server) ApplyAction(ctx context.Context, request *providerv0.ApplyActionRequest) (*providerv0.ApplyActionResponse, error) {
	if s.host == nil {
		return nil, status.Error(codes.FailedPrecondition, "provider host callback channel is not attached")
	}
	action := request.GetAction()
	if action == nil {
		return nil, status.Error(codes.InvalidArgument, "apply action requires an action")
	}
	switch action.GetType() {
	case providerv0.ActionType_ACTION_TYPE_CREATE, providerv0.ActionType_ACTION_TYPE_REPLACE:
		return s.applyCreate(ctx, request)
	case providerv0.ActionType_ACTION_TYPE_UPDATE:
		return s.applyUpdate(ctx, request)
	case providerv0.ActionType_ACTION_TYPE_DELETE:
		return s.applyDelete(ctx, request)
	case providerv0.ActionType_ACTION_TYPE_IMPORT:
		return s.applyImport(ctx, request)
	case providerv0.ActionType_ACTION_TYPE_PROJECT_OUTPUT:
		return s.applyProjectOutput(ctx, request)
	case providerv0.ActionType_ACTION_TYPE_NO_OP, providerv0.ActionType_ACTION_TYPE_BLOCKED,
		providerv0.ActionType_ACTION_TYPE_MANUAL:
		return s.applyInert(request)
	default:
		return nil, status.Errorf(codes.InvalidArgument, "unsupported action type %s", action.GetType())
	}
}

func (s *Server) applyCreate(ctx context.Context, request *providerv0.ApplyActionRequest) (*providerv0.ApplyActionResponse, error) {
	pctx := request.GetContext()
	action := request.GetAction()
	binding := pctx.GetOffline().GetBinding()
	origin, err := admittedOrigin(pctx, originRuleAPI)
	if err != nil {
		return nil, status.Error(codes.FailedPrecondition, err.Error())
	}
	in, err := parseInputs(pctx.GetOffline().GetInput())
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}
	target := desiredFrom(in, binding)
	key := idempotencyKey(pctx.GetOperation(), action)

	planned, err := s.plannedRequest("webhook.create", origin, nil, nil, createBody(target), key)
	if err != nil {
		return nil, err
	}
	if err := s.checkpointBeforeSend(ctx, pctx.GetOperation(), key, action.GetProspectiveRemoteId()); err != nil {
		return nil, err
	}
	response, err := s.execute(ctx, pctx, origin, planned, "apply-"+action.GetActionId())
	if err != nil {
		return nil, err
	}
	if diagnostic := diagnoseResponse(response); diagnostic != nil {
		return s.failedApply(request, response, diagnostic), nil
	}
	fields, err := decodeFiltered(response)
	if err != nil {
		return nil, err
	}
	remoteID := fields.string("$.id")
	if remoteID == "" {
		return nil, status.Error(codes.FailedPrecondition, DiagValidation+": the create response carried no endpoint id")
	}
	reference, err := s.resolveSigningSecret(ctx, pctx.GetOperation(), request.GetPriorCheckpoint(), response)
	if err != nil {
		return nil, err
	}

	identity := remoteIdentity(pctx.GetOffline().GetAccountIdentity(), resourceWebhook, remoteID)
	state := s.ownedState(request, identity, providerv0.Ownership_OWNERSHIP_OWNED, target, []*providerv0.OpaqueReference{reference})
	receipt := s.receipt(request, response, fields, []*providerv0.OpaqueReference{reference}, nil)
	return &providerv0.ApplyActionResponse{Receipt: receipt, NextState: state}, nil
}

func (s *Server) applyUpdate(ctx context.Context, request *providerv0.ApplyActionRequest) (*providerv0.ApplyActionResponse, error) {
	pctx := request.GetContext()
	action := request.GetAction()
	binding := pctx.GetOffline().GetBinding()
	origin, err := admittedOrigin(pctx, originRuleAPI)
	if err != nil {
		return nil, status.Error(codes.FailedPrecondition, err.Error())
	}
	remoteID := action.GetRemoteIdentity().GetRemoteId()
	if remoteID == "" {
		return nil, status.Error(codes.FailedPrecondition, DiagValidation+": update requires the owned endpoint identity")
	}
	in, err := parseInputs(pctx.GetOffline().GetInput())
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}
	target := desiredFrom(in, binding)
	key := idempotencyKey(pctx.GetOperation(), action)
	pathParams := map[string]*providerv0.PublicValue{"webhook_endpoint_id": publicStringValue(remoteID)}

	planned, err := s.plannedRequest("webhook.update", origin, pathParams, nil, updateBody(target), key)
	if err != nil {
		return nil, err
	}
	if err := s.checkpointBeforeSend(ctx, pctx.GetOperation(), key, ""); err != nil {
		return nil, err
	}
	response, err := s.execute(ctx, pctx, origin, planned, "apply-"+action.GetActionId())
	if err != nil {
		return nil, err
	}
	if diagnostic := diagnoseResponse(response); diagnostic != nil {
		return s.failedApply(request, response, diagnostic), nil
	}
	fields, err := decodeFiltered(response)
	if err != nil {
		return nil, err
	}
	identity := remoteIdentity(accountIdentity(action, pctx), resourceWebhook, remoteID)
	// An update mutates the endpoint in place: the signing secret was minted once
	// at create time, so its capture reference must survive the update untouched.
	state := s.ownedState(request, identity, providerv0.Ownership_OWNERSHIP_OWNED, target, request.GetState().GetV1().GetSecretReferences())
	receipt := s.receipt(request, response, fields, nil, nil)
	return &providerv0.ApplyActionResponse{Receipt: receipt, NextState: state}, nil
}

func (s *Server) applyDelete(ctx context.Context, request *providerv0.ApplyActionRequest) (*providerv0.ApplyActionResponse, error) {
	pctx := request.GetContext()
	action := request.GetAction()
	origin, err := admittedOrigin(pctx, originRuleAPI)
	if err != nil {
		return nil, status.Error(codes.FailedPrecondition, err.Error())
	}
	// Deletion defaults to retain: only an exact endpoint this binding owns or
	// adopted may be destroyed, and only through this explicit teardown action.
	if !ownsForTeardown(action) {
		return nil, status.Error(codes.FailedPrecondition,
			DiagValidation+": deletion is refused unless the exact owned or imported endpoint is named")
	}
	remoteID := action.GetRemoteIdentity().GetRemoteId()
	key := idempotencyKey(pctx.GetOperation(), action)
	pathParams := map[string]*providerv0.PublicValue{"webhook_endpoint_id": publicStringValue(remoteID)}

	planned, err := s.plannedRequest("webhook.delete", origin, pathParams, nil, nil, key)
	if err != nil {
		return nil, err
	}
	if err := s.checkpointBeforeSend(ctx, pctx.GetOperation(), key, ""); err != nil {
		return nil, err
	}
	response, err := s.execute(ctx, pctx, origin, planned, "apply-"+action.GetActionId())
	if err != nil {
		return nil, err
	}
	if diagnostic := diagnoseResponse(response); diagnostic != nil {
		return s.failedApply(request, response, diagnostic), nil
	}
	fields, err := decodeFiltered(response)
	if err != nil {
		return nil, err
	}
	// The endpoint is gone; the binding retains no owned remote object.
	state := s.baseState(request, providerv0.Ownership_OWNERSHIP_OBSERVED)
	receipt := s.receipt(request, response, fields, nil, nil)
	return &providerv0.ApplyActionResponse{Receipt: receipt, NextState: state}, nil
}

func (s *Server) applyImport(ctx context.Context, request *providerv0.ApplyActionRequest) (*providerv0.ApplyActionResponse, error) {
	pctx := request.GetContext()
	action := request.GetAction()
	binding := pctx.GetOffline().GetBinding()
	origin, err := admittedOrigin(pctx, originRuleAPI)
	if err != nil {
		return nil, status.Error(codes.FailedPrecondition, err.Error())
	}
	remoteID := action.GetRemoteIdentity().GetRemoteId()
	if remoteID == "" {
		return nil, status.Error(codes.FailedPrecondition, DiagValidation+": import requires the exact endpoint id")
	}
	pathParams := map[string]*providerv0.PublicValue{"webhook_endpoint_id": publicStringValue(remoteID)}
	planned, err := s.plannedRequest("webhook.retrieve", origin, pathParams, nil, nil, "")
	if err != nil {
		return nil, err
	}
	if err := s.checkpointBeforeSend(ctx, pctx.GetOperation(), "", ""); err != nil {
		return nil, err
	}
	response, err := s.execute(ctx, pctx, origin, planned, "apply-"+action.GetActionId())
	if err != nil {
		return nil, err
	}
	if diagnostic := diagnoseResponse(response); diagnostic != nil {
		return s.failedApply(request, response, diagnostic), nil
	}
	fields, err := decodeFiltered(response)
	if err != nil {
		return nil, err
	}
	webhook, ok := fields.webhookAt("$", binding)
	if !ok {
		return nil, status.Error(codes.FailedPrecondition, DiagNotFound+": the endpoint to import was not found")
	}
	identity := remoteIdentity(accountIdentity(action, pctx), resourceWebhook, remoteID)
	state := s.ownedState(request, identity, providerv0.Ownership_OWNERSHIP_ADOPTED, desiredWebhook{
		URL: webhook.URL, EnabledEvents: webhook.EnabledEvents, APIVersion: webhook.APIVersion,
		Description: webhook.Description, Metadata: webhook.Metadata,
	}, nil)
	receipt := s.receipt(request, response, fields, nil, nil)
	return &providerv0.ApplyActionResponse{Receipt: receipt, NextState: state}, nil
}

func (s *Server) applyProjectOutput(ctx context.Context, request *providerv0.ApplyActionRequest) (*providerv0.ApplyActionResponse, error) {
	pctx := request.GetContext()
	action := request.GetAction()
	proposal := action.GetOutput()
	response, err := s.host.ProposeOutput(ctx, &providerv0.ProposeOutputRequest{
		Operation: pctx.GetOperation(),
		Proposal:  proposal,
	})
	if err != nil {
		return nil, err
	}
	if !response.GetDurable() {
		return nil, status.Error(codes.FailedPrecondition, DiagValidation+": the host did not commit the output projection")
	}
	state := s.baseState(request, providerv0.Ownership_OWNERSHIP_OBSERVED)
	state.GetV1().OutputContract = proposal.GetContract()
	state.GetV1().OutputGeneration = response.GetGeneration()
	state.GetV1().OutputDigest = response.GetDigest()
	receipt := s.receipt(request, nil, nil, nil, nil)
	return &providerv0.ApplyActionResponse{Receipt: receipt, NextState: state}, nil
}

// applyInert records a no-op, blocked, or manual action without any broker call.
func (s *Server) applyInert(request *providerv0.ApplyActionRequest) (*providerv0.ApplyActionResponse, error) {
	receipt := s.receipt(request, nil, nil, nil, nil)
	return &providerv0.ApplyActionResponse{Receipt: receipt, NextState: s.inertState(request)}, nil
}

// inertState is the state after an action that changes nothing. The binding
// keeps exactly the state it entered with; when there is none, the action's own
// ownership and identity seed a valid state — an owned or adopted result carries
// the exact remote identity and stamp the state schema requires.
func (s *Server) inertState(request *providerv0.ApplyActionRequest) *providerv0.ProviderState {
	if prior := request.GetState(); prior.GetV1() != nil {
		return prior
	}
	action := request.GetAction()
	state := s.baseState(request, action.GetOwnership())
	switch action.GetOwnership() {
	case providerv0.Ownership_OWNERSHIP_OWNED, providerv0.Ownership_OWNERSHIP_ADOPTED:
		state.GetV1().RemoteIdentity = action.GetRemoteIdentity()
		state.GetV1().OwnershipStamp = ownershipStamp(action.GetRemoteIdentity())
	}
	return state
}

// resolveSigningSecret returns the opaque reference for the one-time signing
// secret. When a prior attempt already received a response, its capture is
// recovered through ResolveCapture rather than trusting a re-sent secret; the
// idempotent replay still reaches Stripe so the endpoint identity is confirmed
// without minting a duplicate.
func (s *Server) resolveSigningSecret(ctx context.Context, operation *providerv0.OperationIdentity, prior *providerv0.ActionCheckpoint, response *providerv0.ExecuteRequestResponse) (*providerv0.OpaqueReference, error) {
	if prior.GetDelivery() == providerv0.DeliveryState_DELIVERY_STATE_RESPONSE_RECEIVED {
		resolved, err := s.host.ResolveCapture(ctx, &providerv0.ResolveCaptureRequest{
			Operation: operation,
			CaptureId: secretCaptureSelector,
		})
		if err != nil {
			return nil, err
		}
		if resolved.GetReference() == nil {
			return nil, status.Error(codes.FailedPrecondition, DiagOutcomeUnknown+": the prior signing-secret capture could not be recovered")
		}
		return resolved.GetReference(), nil
	}
	for _, capture := range response.GetCaptures() {
		if capture.GetCaptureId() != secretCaptureSelector {
			continue
		}
		return sdk.HandleCaptureResult(capture)
	}
	return nil, status.Error(codes.FailedPrecondition, DiagValidation+": the create response captured no signing secret")
}

// checkpointBeforeSend records the durable pre-send checkpoint the broker
// requires. The idempotency key and prospective remote id survive a lost
// response so a retry is idempotent and its create outcome recoverable.
func (s *Server) checkpointBeforeSend(ctx context.Context, operation *providerv0.OperationIdentity, idempotencyKey, prospectiveRemoteID string) error {
	return s.recordCheckpoint(ctx, &providerv0.ActionCheckpoint{
		CheckpointId:        "checkpoint-" + operation.GetOperationId() + "-" + operation.GetActionId(),
		Operation:           operation,
		Delivery:            providerv0.DeliveryState_DELIVERY_STATE_NOT_SENT,
		IdempotencyKey:      idempotencyKey,
		ProspectiveRemoteId: prospectiveRemoteID,
	})
}

// failedApply records a failed action without claiming any new effect: the
// binding keeps exactly the state it entered with, or an owning-nothing base
// state when there was none.
func (s *Server) failedApply(request *providerv0.ApplyActionRequest, response *providerv0.ExecuteRequestResponse, diagnostic *basev0.FailureDiagnostic) *providerv0.ApplyActionResponse {
	state := request.GetState()
	if state.GetV1() == nil {
		state = s.baseState(request, providerv0.Ownership_OWNERSHIP_OBSERVED)
	}
	receipt := s.receipt(request, response, nil, nil, []*basev0.FailureDiagnostic{diagnostic})
	return &providerv0.ApplyActionResponse{Receipt: receipt, NextState: state}
}

func (s *Server) receipt(request *providerv0.ApplyActionRequest, response *providerv0.ExecuteRequestResponse, fields filteredResponse, references []*providerv0.OpaqueReference, diagnostics []*basev0.FailureDiagnostic) *providerv0.ActionReceipt {
	operation := request.GetContext().GetOperation()
	// A result with no broker send (project-output, no-op) is a completed effect
	// that never crossed the network, not an unknown one.
	delivery := providerv0.DeliveryState_DELIVERY_STATE_NOT_SENT
	certainty := providerv0.OutcomeCertainty_OUTCOME_CERTAINTY_COMPLETE
	if response != nil {
		delivery = response.GetDelivery()
		certainty = response.GetCertainty()
	}
	receipt := &providerv0.ActionReceipt{
		ReceiptId:         "receipt-" + operation.GetOperationId() + "-" + operation.GetActionId(),
		Operation:         operation,
		Action:            request.GetAction(),
		Delivery:          delivery,
		Certainty:         certainty,
		ArtifactDigest:    s.artifactDigest,
		CaptureReferences: references,
		Diagnostics:       diagnostics,
	}
	if len(fields) > 0 {
		receipt.SafeResult = map[string]*providerv0.PublicValue(fields)
	}
	return receipt
}

// idempotencyKey derives a key stable across coordinator retries. Both the
// operation and action ids are stable across retries, so the same action always
// yields the same key and Stripe collapses a replay onto the original effect.
func idempotencyKey(operation *providerv0.OperationIdentity, action *providerv0.PlanAction) string {
	return "stripe-" + operation.GetOperationId() + "-" + action.GetActionId()
}

// accountIdentity resolves the Stripe account a mutated endpoint belongs to. The
// action's own remote identity is authoritative when the host supplied one;
// otherwise the offline context's account identity is the single source of truth.
// The two never disagree, but preferring the action keeps a host-attested account
// binding intact even when the offline context omits it.
func accountIdentity(action *providerv0.PlanAction, pctx *providerv0.ProviderContext) string {
	if id := action.GetRemoteIdentity().GetAccountId(); id != "" {
		return id
	}
	return pctx.GetOffline().GetAccountIdentity()
}

func ownsForTeardown(action *providerv0.PlanAction) bool {
	if action.GetRemoteIdentity().GetRemoteId() == "" {
		return false
	}
	switch action.GetOwnership() {
	case providerv0.Ownership_OWNERSHIP_OWNED, providerv0.Ownership_OWNERSHIP_ADOPTED:
		return true
	default:
		return false
	}
}

func createBody(target desiredWebhook) map[string]*providerv0.PublicValue {
	return map[string]*providerv0.PublicValue{
		"url":            publicStringValue(target.URL),
		"enabled_events": publicStringList(target.EnabledEvents),
		"api_version":    publicStringValue(target.APIVersion),
		"description":    publicStringValue(target.Description),
		"metadata":       publicStringObject(target.Metadata),
	}
}

func updateBody(target desiredWebhook) map[string]*providerv0.PublicValue {
	return map[string]*providerv0.PublicValue{
		"url":            publicStringValue(target.URL),
		"enabled_events": publicStringList(target.EnabledEvents),
		"description":    publicStringValue(target.Description),
		"metadata":       publicStringObject(target.Metadata),
		"disabled":       {Kind: &providerv0.PublicValue_BoolValue{BoolValue: false}},
	}
}

// baseState builds the identity-complete provider state shared by every action
// result. Ownership-specific fields are layered on by ownedState.
func (s *Server) baseState(request *providerv0.ApplyActionRequest, ownership providerv0.Ownership) *providerv0.ProviderState {
	v1 := &providerv0.ProviderStateV1{
		StateSchemaVersion:    manifestStateSchemaVersion,
		Generation:            request.GetState().GetV1().GetGeneration() + 1,
		Binding:               request.GetContext().GetOffline().GetBinding(),
		ProviderId:            s.manifest.Agent.Publisher + "/" + s.manifest.Agent.Name,
		ProviderVersion:       s.manifest.Agent.Version,
		ManifestSchemaVersion: s.manifest.SchemaVersion,
		ManifestDigest:        s.manifestDigest,
		ArtifactDigest:        s.artifactDigest,
		Ownership:             ownership,
		PlanDigest:            request.GetPlan().GetPlanDigest(),
		Operation:             request.GetContext().GetOperation(),
	}
	return providerstate.WrapV1(v1)
}

func (s *Server) ownedState(request *providerv0.ApplyActionRequest, identity *providerv0.RemoteIdentity, ownership providerv0.Ownership, target desiredWebhook, references []*providerv0.OpaqueReference) *providerv0.ProviderState {
	state := s.baseState(request, ownership)
	v1 := state.GetV1()
	v1.RemoteIdentity = identity
	v1.OwnershipStamp = ownershipStamp(identity)
	v1.SecretReferences = references
	v1.ProviderOwnedFields = map[string]*providerv0.PublicValue{
		fieldURL:         publicStringValue(target.URL),
		fieldEvents:      publicStringList(target.EnabledEvents),
		fieldAPIVersion:  publicStringValue(target.APIVersion),
		fieldDescription: publicStringValue(target.Description),
		fieldMetadata:    publicStringObject(target.Metadata),
	}
	return state
}

// ownershipStamp binds a remote object to the identity that owns it. It is a
// non-reversible fingerprint the host can re-derive to verify ownership.
func ownershipStamp(identity *providerv0.RemoteIdentity) string {
	sum := sha256.Sum256(fmt.Appendf(nil, "%s|%s|%s|%s",
		identity.GetProvider(), identity.GetAccountId(), identity.GetResourceType(), identity.GetRemoteId()))
	return "sha256:" + hex.EncodeToString(sum[:])
}
