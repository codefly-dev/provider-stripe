package provider

import (
	"context"
	"fmt"

	basev0 "github.com/codefly-dev/core/generated/go/codefly/base/v0"
	providerv0 "github.com/codefly-dev/core/generated/go/codefly/services/provider/v0"
)

// recordCheckpoint drives the host's durable pre-send checkpoint and fails
// closed unless the host confirms it committed. Nothing may be sent to Stripe
// until a checkpoint binding this operation is durable.
func (s *Server) recordCheckpoint(ctx context.Context, checkpoint *providerv0.ActionCheckpoint) error {
	response, err := s.host.RecordCheckpoint(ctx, &providerv0.RecordCheckpointRequest{Checkpoint: checkpoint})
	if err != nil {
		return err
	}
	if !response.GetDurable() {
		return fmt.Errorf("host did not durably record the pre-send checkpoint")
	}
	return nil
}

// execute drives one host-admitted broker request. The provider supplies the
// planned request, the host-attested origin, and the purpose-matched handles;
// the host owns delivery, filtering, and capture.
func (s *Server) execute(ctx context.Context, pctx *providerv0.ProviderContext, origin *providerv0.AdmittedOrigin, planned *providerv0.PlannedRequest, requestID string) (*providerv0.ExecuteRequestResponse, error) {
	handles, err := credentialHandles(pctx, planned.GetCredentialPurposes())
	if err != nil {
		return nil, err
	}
	return s.host.ExecuteRequest(ctx, &providerv0.ExecuteRequestRequest{
		Context:           pctx,
		RequestId:         requestID,
		Request:           planned,
		Origin:            origin,
		CredentialHandles: handles,
	})
}

// diagnoseResponse classifies a broker response into a blocking or advisory
// diagnostic, or nil when a success body was received. Stripe error bodies are
// dropped by the host, so a failure is classified by delivery and HTTP status
// alone — never by an untrusted, secret-shaped error body.
func diagnoseResponse(response *providerv0.ExecuteRequestResponse) *basev0.FailureDiagnostic {
	switch response.GetDelivery() {
	case providerv0.DeliveryState_DELIVERY_STATE_RESPONSE_RECEIVED:
		httpStatus := int(response.GetStatusCode())
		if httpStatus >= 200 && httpStatus < 300 {
			return nil
		}
		code := ClassifyStripeError(StripeError{StatusCode: httpStatus})
		return diag(basev0.FailureDiagnostic_ERROR, code, fmt.Sprintf("Stripe responded with HTTP %d", httpStatus))
	case providerv0.DeliveryState_DELIVERY_STATE_NOT_SENT:
		return diag(basev0.FailureDiagnostic_ERROR, DiagTimeoutBeforeSend, "the request was not sent to Stripe")
	case providerv0.DeliveryState_DELIVERY_STATE_SENT_OUTCOME_UNKNOWN:
		return diag(basev0.FailureDiagnostic_WARNING, DiagOutcomeUnknown, "the request reached Stripe but its outcome is unknown")
	default:
		return diag(basev0.FailureDiagnostic_ERROR, DiagValidation, "the broker returned an unknown delivery state")
	}
}
