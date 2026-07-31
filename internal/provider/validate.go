package provider

import (
	"context"
	"fmt"
	"net/url"
	"regexp"
	"strings"

	basev0 "github.com/codefly-dev/core/generated/go/codefly/base/v0"
	providerv0 "github.com/codefly-dev/core/generated/go/codefly/services/provider/v0"
)

// stripeVersionPattern matches a pinned Stripe API version (a date, optionally
// with a named release channel, e.g. 2024-06-20 or 2024-06-20.preview).
var stripeVersionPattern = regexp.MustCompile(`^\d{4}-\d{2}-\d{2}(\.[a-z0-9._-]+)?$`)

// Validate checks the normalized desired input offline, without broker access.
// It never contacts Stripe and never sees raw credentials.
func (s *Server) Validate(_ context.Context, request *providerv0.ValidateRequest) (*providerv0.ValidateResponse, error) {
	ctx := request.GetContext()
	in, err := parseInputs(ctx.GetInput())
	if err != nil {
		return &providerv0.ValidateResponse{
			Valid:       false,
			Diagnostics: []*basev0.FailureDiagnostic{diag(basev0.FailureDiagnostic_ERROR, DiagInvalidInput, err.Error())},
		}, nil
	}
	diagnostics := validateInputs(in, ctx.GetMode())
	return &providerv0.ValidateResponse{Valid: !hasError(diagnostics), Diagnostics: diagnostics}, nil
}

func validateInputs(in inputs, mode providerv0.HostMode) []*basev0.FailureDiagnostic {
	var out []*basev0.FailureDiagnostic
	invalid := func(format string, args ...any) {
		out = append(out, diag(basev0.FailureDiagnostic_ERROR, DiagInvalidInput, fmt.Sprintf(format, args...)))
	}

	if in.APIVersion == "" {
		invalid("stripe_api_version is required and must be pinned explicitly")
	} else if !stripeVersionPattern.MatchString(in.APIVersion) {
		invalid("stripe_api_version %q is not a valid pinned Stripe version", in.APIVersion)
	}

	switch in.AccountPolicy {
	case policySandbox, policyTest:
	case "":
		invalid("account_policy must be declared explicitly as sandbox or test; it is never inferred")
	default:
		// A live/production account policy is refused: v0.1 never mutates a live account.
		out = append(out, diag(basev0.FailureDiagnostic_ERROR, DiagWrongMode,
			fmt.Sprintf("account_policy %q is not permitted; only sandbox or test accounts are supported", in.AccountPolicy)))
	}

	if len(in.EnabledEvents) == 0 {
		invalid("enabled_events must declare at least one Stripe event")
	}

	switch in.CallbackMode {
	case modePublic:
		if err := validatePublicCallback(in.CallbackURL); err != nil {
			invalid("%s", err.Error())
		}
	case modeLocalForwarded:
		// The Stripe CLI listener supplies the verification secret through host
		// input; no remote endpoint is created and no public URL is required.
	case modeExisting:
		if in.ExistingID == "" {
			invalid("existing_webhook_id is required to observe and import an existing endpoint")
		} else if !strings.HasPrefix(in.ExistingID, "we_") {
			invalid("existing_webhook_id %q is not a Stripe webhook endpoint id", in.ExistingID)
		}
	case "":
		invalid("callback_mode is required (public, local-forwarded, or existing)")
	default:
		invalid("callback_mode %q is not supported", in.CallbackMode)
	}

	if mode == providerv0.HostMode_HOST_MODE_PRODUCTION {
		out = append(out, diag(basev0.FailureDiagnostic_WARNING, DiagWrongMode,
			"host attests production mode; v0.1 supports production observe only, not production mutation"))
	}
	return out
}

func validatePublicCallback(raw string) error {
	if raw == "" {
		return fmt.Errorf("callback_url is required for public callback mode")
	}
	parsed, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("callback_url is not a valid URL")
	}
	if parsed.Scheme != "https" {
		return fmt.Errorf("callback_url must be a public HTTPS origin")
	}
	host := parsed.Hostname()
	if host == "" || host == "localhost" || host == "127.0.0.1" || host == "::1" {
		return fmt.Errorf("callback_url must be a public host; Stripe cannot deliver to loopback in public mode")
	}
	return nil
}
