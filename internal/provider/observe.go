package provider

import (
	"context"
	"fmt"

	basev0 "github.com/codefly-dev/core/generated/go/codefly/base/v0"
	providerv0 "github.com/codefly-dev/core/generated/go/codefly/services/provider/v0"
	"github.com/codefly-dev/core/provider/sdk"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// maxObservePages bounds paginated webhook enumeration so a host that reports
// has_more forever cannot spin the provider; the request budget is the primary
// bound and this is a hard backstop.
const maxObservePages = 32

// Observe reads the Stripe account and Codefly-visible webhook endpoints through
// the host broker and projects only the Codefly-owned safe fields the offline
// Plan consumes. It never sees a raw credential; the account's operating mode is
// taken from the host attestation, never claimed from the Account object, and a
// webhook whose livemode contradicts the attested mode fails closed.
func (s *Server) Observe(ctx context.Context, request *providerv0.ObserveRequest) (*providerv0.ObserveResponse, error) {
	if s.host == nil {
		return nil, status.Error(codes.FailedPrecondition, "provider host callback channel is not attached")
	}
	pctx := request.GetContext()
	offline := pctx.GetOffline()
	binding := offline.GetBinding()
	mode := offline.GetMode()
	origin, err := admittedOrigin(pctx, originRuleAPI)
	if err != nil {
		return nil, status.Error(codes.FailedPrecondition, err.Error())
	}
	operation := pctx.GetOperation()
	checkpoint := &providerv0.ActionCheckpoint{
		CheckpointId: "checkpoint-" + operation.GetOperationId() + "-observe",
		Operation:    operation,
		Delivery:     providerv0.DeliveryState_DELIVERY_STATE_NOT_SENT,
	}
	if err := s.recordCheckpoint(ctx, checkpoint); err != nil {
		return nil, err
	}

	accountID, accountResource, err := s.observeAccount(ctx, pctx, origin)
	if err != nil {
		return nil, err
	}
	resources := []*providerv0.MaterialResourceObservation{accountResource}

	webhooks, err := s.observeWebhooks(ctx, pctx, origin, binding, accountID, mode)
	if err != nil {
		return nil, err
	}
	resources = append(resources, webhooks...)

	// existing mode names one endpoint by exact id; retrieve it directly so an
	// operator-supplied endpoint outside the owned set is still observed.
	if in, err := parseInputs(offline.GetInput()); err == nil && in.CallbackMode == modeExisting && in.ExistingID != "" && !observesRemote(resources, in.ExistingID) {
		resource, err := s.retrieveWebhook(ctx, pctx, origin, binding, accountID, mode, in.ExistingID)
		if err != nil {
			return nil, err
		}
		resources = append(resources, resource)
	}

	material := &providerv0.MaterialObservation{
		AccountIdentity: accountID,
		Mode:            mode,
		Complete:        true,
		Resources:       resources,
	}
	return sdk.Observation(material, nil)
}

func (s *Server) observeAccount(ctx context.Context, pctx *providerv0.ProviderContext, origin *providerv0.AdmittedOrigin) (string, *providerv0.MaterialResourceObservation, error) {
	planned, err := s.plannedRequest("account.observe", origin, nil, nil, nil, "")
	if err != nil {
		return "", nil, err
	}
	response, err := s.execute(ctx, pctx, origin, planned, "observe-account")
	if err != nil {
		return "", nil, err
	}
	if diagnostic := diagnoseResponse(response); diagnostic != nil {
		return "", nil, observeFailure(diagnostic)
	}
	fields, err := decodeFiltered(response)
	if err != nil {
		return "", nil, err
	}
	accountID := fields.string("$.id")
	if accountID == "" {
		return "", nil, status.Error(codes.FailedPrecondition, DiagNotFound+": the account response carried no identity")
	}
	resource := &providerv0.MaterialResourceObservation{
		Identity:  remoteIdentity(accountID, resourceAccount, accountID),
		Ownership: providerv0.Ownership_OWNERSHIP_OBSERVED,
		ProviderOwnedFields: map[string]*providerv0.PublicValue{
			"id":                publicStringValue(accountID),
			"charges_enabled":   publicBoolValue(fields.bool("$.charges_enabled")),
			"details_submitted": publicBoolValue(fields.bool("$.details_submitted")),
			"default_currency":  publicStringValue(fields.string("$.default_currency")),
		},
	}
	return accountID, resource, nil
}

// observeWebhooks enumerates every webhook endpoint page, following has_more with
// the last endpoint id as the cursor, and projects each into a resource
// observation.
func (s *Server) observeWebhooks(ctx context.Context, pctx *providerv0.ProviderContext, origin *providerv0.AdmittedOrigin, binding *providerv0.BindingAddress, accountID string, mode providerv0.HostMode) ([]*providerv0.MaterialResourceObservation, error) {
	var resources []*providerv0.MaterialResourceObservation
	startingAfter := ""
	for page := range maxObservePages {
		query := map[string]*providerv0.PublicValue{"limit": publicStringValue("100")}
		if startingAfter != "" {
			query["starting_after"] = publicStringValue(startingAfter)
		}
		planned, err := s.plannedRequest("webhook.list", origin, nil, query, nil, "")
		if err != nil {
			return nil, err
		}
		response, err := s.execute(ctx, pctx, origin, planned, fmt.Sprintf("observe-webhooks-%d", page))
		if err != nil {
			return nil, err
		}
		if diagnostic := diagnoseResponse(response); diagnostic != nil {
			return nil, observeFailure(diagnostic)
		}
		fields, err := decodeFiltered(response)
		if err != nil {
			return nil, err
		}
		indices := fields.dataIndices()
		for _, index := range indices {
			prefix := fmt.Sprintf("$.data[%d]", index)
			if err := crossCheckMode(fields, prefix, mode); err != nil {
				return nil, err
			}
			webhook, ok := fields.webhookAt(prefix, binding)
			if !ok {
				continue
			}
			resources = append(resources, webhookResource(webhook, accountID))
		}
		if !fields.bool("$.has_more") {
			return resources, nil
		}
		// The cursor must advance from the last element of the raw page, not the
		// last projected webhook: an endpoint filtered out of the projection is
		// still Stripe's pagination boundary, and skipping it would re-request the
		// same page forever. A has_more page with no usable id fails closed.
		if len(indices) == 0 {
			return nil, status.Error(codes.FailedPrecondition, DiagValidation+": webhook page reported more results but carried none")
		}
		last := fields.string(fmt.Sprintf("$.data[%d].id", indices[len(indices)-1]))
		if last == "" {
			return nil, status.Error(codes.FailedPrecondition, DiagValidation+": webhook page cursor could not be determined")
		}
		startingAfter = last
	}
	return nil, status.Error(codes.FailedPrecondition, DiagValidation+": webhook enumeration did not terminate")
}

func (s *Server) retrieveWebhook(ctx context.Context, pctx *providerv0.ProviderContext, origin *providerv0.AdmittedOrigin, binding *providerv0.BindingAddress, accountID string, mode providerv0.HostMode, endpointID string) (*providerv0.MaterialResourceObservation, error) {
	pathParams := map[string]*providerv0.PublicValue{"webhook_endpoint_id": publicStringValue(endpointID)}
	planned, err := s.plannedRequest("webhook.retrieve", origin, pathParams, nil, nil, "")
	if err != nil {
		return nil, err
	}
	response, err := s.execute(ctx, pctx, origin, planned, "observe-webhook-"+endpointID)
	if err != nil {
		return nil, err
	}
	if diagnostic := diagnoseResponse(response); diagnostic != nil {
		return nil, observeFailure(diagnostic)
	}
	fields, err := decodeFiltered(response)
	if err != nil {
		return nil, err
	}
	if err := crossCheckMode(fields, "$", mode); err != nil {
		return nil, err
	}
	webhook, ok := fields.webhookAt("$", binding)
	if !ok {
		return nil, status.Error(codes.FailedPrecondition, DiagNotFound+": the webhook endpoint response carried no identity")
	}
	return webhookResource(webhook, accountID), nil
}

// crossCheckMode fails closed when a webhook endpoint's livemode contradicts the
// host-attested mode. Only production is live; every other attested mode must
// observe a test-mode object.
func crossCheckMode(fields filteredResponse, prefix string, mode providerv0.HostMode) error {
	livemode, present := fields.livemodeAt(prefix)
	if !present {
		return nil
	}
	if livemode != (mode == providerv0.HostMode_HOST_MODE_PRODUCTION) {
		return status.Errorf(codes.FailedPrecondition,
			"%s: host attests %s but a webhook endpoint reports livemode=%t", DiagModeMismatch, mode, livemode)
	}
	return nil
}

func webhookResource(webhook observedWebhook, accountID string) *providerv0.MaterialResourceObservation {
	return &providerv0.MaterialResourceObservation{
		Identity:  remoteIdentity(accountID, resourceWebhook, webhook.RemoteID),
		Ownership: webhook.Ownership,
		ProviderOwnedFields: map[string]*providerv0.PublicValue{
			fieldURL:         publicStringValue(webhook.URL),
			fieldEvents:      publicStringList(webhook.EnabledEvents),
			fieldAPIVersion:  publicStringValue(webhook.APIVersion),
			fieldDescription: publicStringValue(webhook.Description),
			fieldStatus:      publicStringValue(webhook.Status),
			fieldMetadata:    publicStringObject(webhook.Metadata),
		},
	}
}

func remoteIdentity(accountID, resourceType, remoteID string) *providerv0.RemoteIdentity {
	return &providerv0.RemoteIdentity{
		Provider:     "stripe",
		AccountId:    accountID,
		ResourceType: resourceType,
		RemoteId:     remoteID,
	}
}

func observesRemote(resources []*providerv0.MaterialResourceObservation, remoteID string) bool {
	for _, resource := range resources {
		if resource.GetIdentity().GetResourceType() == resourceWebhook && resource.GetIdentity().GetRemoteId() == remoteID {
			return true
		}
	}
	return false
}

// observeFailure turns a blocking response diagnostic into a fail-closed gRPC
// error. A read that cannot be trusted must never surface a partial, plausible
// observation the planner would act on.
func observeFailure(diagnostic *basev0.FailureDiagnostic) error {
	return status.Error(codes.FailedPrecondition, diagnostic.GetCode()+": "+diagnostic.GetMessage())
}

func publicBoolValue(value bool) *providerv0.PublicValue {
	return &providerv0.PublicValue{Kind: &providerv0.PublicValue_BoolValue{BoolValue: value}}
}

func publicStringList(values []string) *providerv0.PublicValue {
	items := make([]*providerv0.PublicValue, 0, len(values))
	for _, value := range values {
		items = append(items, publicStringValue(value))
	}
	return &providerv0.PublicValue{Kind: &providerv0.PublicValue_ListValue{ListValue: &providerv0.PublicList{Values: items}}}
}

func publicStringObject(values map[string]string) *providerv0.PublicValue {
	fields := make(map[string]*providerv0.PublicValue, len(values))
	for key, value := range values {
		fields[key] = publicStringValue(value)
	}
	return &providerv0.PublicValue{Kind: &providerv0.PublicValue_ObjectValue{ObjectValue: &providerv0.PublicObject{Fields: fields}}}
}
