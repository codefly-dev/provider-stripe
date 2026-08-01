package provider

import "strings"

// StripeError is the bounded, safe classification of a Stripe API failure. It
// carries only the HTTP status and Stripe's own error type/code strings — never
// the raw error body, message, request id, or any customer data.
type StripeError struct {
	StatusCode int
	Type       string // Stripe error object "type" (e.g. authentication_error, rate_limit_error).
	Code       string // Stripe error object "code" (e.g. resource_missing).
	RetryAfter bool   // A Retry-After header was present.
}

// ClassifyStripeError maps a Stripe failure onto a stable provider diagnostic
// code. The mapping is intentionally coarse and provider-neutral: it never
// surfaces the raw Stripe message, so no customer or account data can leak
// through a diagnostic.
func ClassifyStripeError(e StripeError) string {
	code := strings.ToLower(strings.TrimSpace(e.Code))
	typ := strings.ToLower(strings.TrimSpace(e.Type))

	switch {
	case e.StatusCode == 401 || typ == "authentication_error":
		return DiagAuthentication
	case e.StatusCode == 403 || strings.Contains(code, "permission") || strings.Contains(code, "scope"):
		return DiagPermission
	case e.StatusCode == 429 || typ == "rate_limit_error" || e.RetryAfter:
		return DiagRateLimit
	case typ == "idempotency_error" || strings.Contains(code, "idempotency"):
		return DiagIdempotency
	case strings.Contains(code, "livemode") || strings.Contains(code, "testmode") || strings.Contains(code, "test_mode"):
		return DiagModeMismatch
	case e.StatusCode == 404 || code == "resource_missing":
		return DiagNotFound
	case strings.Contains(code, "limit") || strings.Contains(code, "quota"):
		return DiagEndpointQuota
	case e.StatusCode == 400 || typ == "invalid_request_error":
		return DiagValidation
	default:
		return DiagValidation
	}
}
