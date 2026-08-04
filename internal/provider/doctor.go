package provider

import (
	"context"
	"fmt"

	basev0 "github.com/codefly-dev/core/generated/go/codefly/base/v0"
	providerv0 "github.com/codefly-dev/core/generated/go/codefly/services/provider/v0"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// Doctor runs admitted read-only diagnostics: it confirms the management
// credential reaches Stripe, reports whether the account is ready to transact,
// and whether a Codefly-owned endpoint is present. It performs no mutation and
// surfaces only neutral, bounded diagnostics — never a raw credential, secret,
// or Stripe error body.
func (s *Server) Doctor(ctx context.Context, request *providerv0.DoctorRequest) (*providerv0.DoctorResponse, error) {
	if s.host == nil {
		return nil, status.Error(codes.FailedPrecondition, "provider host callback channel is not attached")
	}
	pctx := request.GetContext()
	origin, err := admittedOrigin(pctx, originRuleAPI)
	if err != nil {
		return nil, status.Error(codes.FailedPrecondition, err.Error())
	}
	operation := pctx.GetOperation()
	checkpoint := &providerv0.ActionCheckpoint{
		CheckpointId: "checkpoint-" + operation.GetOperationId() + "-doctor",
		Operation:    operation,
		Delivery:     providerv0.DeliveryState_DELIVERY_STATE_NOT_SENT,
	}
	if err := s.recordCheckpoint(ctx, checkpoint); err != nil {
		return nil, err
	}

	var diagnostics []*basev0.FailureDiagnostic

	planned, err := s.plannedRequest("account.observe", origin, nil, nil, nil, "")
	if err != nil {
		return nil, err
	}
	response, err := s.execute(ctx, pctx, origin, planned, "doctor-account")
	if err != nil {
		return nil, err
	}
	if diagnostic := diagnoseResponse(response); diagnostic != nil {
		// Credential unreachable or the account is not readable: the provider is
		// not healthy, but the diagnostic stays neutral and body-free.
		return &providerv0.DoctorResponse{Healthy: false, Diagnostics: []*basev0.FailureDiagnostic{diagnostic}}, nil
	}
	fields, err := decodeFiltered(response)
	if err != nil {
		return nil, err
	}
	if fields.string("$.id") == "" {
		return &providerv0.DoctorResponse{
			Healthy:     false,
			Diagnostics: []*basev0.FailureDiagnostic{diag(basev0.FailureDiagnostic_ERROR, DiagNotFound, "the Stripe account is unreadable")},
		}, nil
	}
	if !fields.bool("$.charges_enabled") || !fields.bool("$.details_submitted") {
		diagnostics = append(diagnostics, diag(basev0.FailureDiagnostic_WARNING, DiagAccountNotReady,
			"the Stripe account is reachable but not yet ready to transact (charges or onboarding incomplete)"))
	}

	present, err := s.ownedEndpointPresent(ctx, pctx, origin, pctx.GetOffline().GetBinding())
	if err != nil {
		return nil, err
	}
	if !present {
		diagnostics = append(diagnostics, diag(basev0.FailureDiagnostic_INFO, DiagEndpointAbsent,
			"no Codefly-owned webhook endpoint is present yet for this binding"))
	}
	return &providerv0.DoctorResponse{Healthy: !hasError(diagnostics), Diagnostics: diagnostics}, nil
}

// ownedEndpointPresent reports whether a Codefly-owned webhook endpoint for this
// binding exists, reading the first page of endpoints read-only.
func (s *Server) ownedEndpointPresent(ctx context.Context, pctx *providerv0.ProviderContext, origin *providerv0.AdmittedOrigin, binding *providerv0.BindingAddress) (bool, error) {
	query := map[string]*providerv0.PublicValue{"limit": publicStringValue("100")}
	planned, err := s.plannedRequest("webhook.list", origin, nil, query, nil, "")
	if err != nil {
		return false, err
	}
	response, err := s.execute(ctx, pctx, origin, planned, "doctor-webhooks")
	if err != nil {
		return false, err
	}
	if diagnostic := diagnoseResponse(response); diagnostic != nil {
		return false, observeFailure(diagnostic)
	}
	fields, err := decodeFiltered(response)
	if err != nil {
		return false, err
	}
	for _, index := range fields.dataIndices() {
		prefix := fmt.Sprintf("$.data[%d]", index)
		if webhook, ok := fields.webhookAt(prefix, binding); ok && webhook.Ownership == providerv0.Ownership_OWNERSHIP_OWNED {
			return true, nil
		}
	}
	return false, nil
}
