package provider

import "testing"

func TestClassifyStripeError(t *testing.T) {
	cases := []struct {
		name string
		in   StripeError
		want string
	}{
		{"authentication", StripeError{StatusCode: 401, Type: "authentication_error"}, DiagAuthentication},
		{"permission", StripeError{StatusCode: 403, Code: "insufficient_scope"}, DiagPermission},
		{"rate limit", StripeError{StatusCode: 429, Type: "rate_limit_error", RetryAfter: true}, DiagRateLimit},
		{"idempotency", StripeError{StatusCode: 400, Type: "idempotency_error"}, DiagIdempotency},
		{"mode mismatch", StripeError{StatusCode: 400, Code: "testmode_charges_only"}, DiagModeMismatch},
		{"not found", StripeError{StatusCode: 404, Code: "resource_missing"}, DiagNotFound},
		{"quota", StripeError{StatusCode: 400, Code: "webhook_endpoint_limit_exceeded"}, DiagEndpointQuota},
		{"validation", StripeError{StatusCode: 400, Type: "invalid_request_error", Code: "url_invalid"}, DiagValidation},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := ClassifyStripeError(tc.in); got != tc.want {
				t.Fatalf("ClassifyStripeError(%+v) = %s, want %s", tc.in, got, tc.want)
			}
		})
	}
}

func TestClassifyStripeErrorNeverReturnsEmpty(t *testing.T) {
	if ClassifyStripeError(StripeError{StatusCode: 500}) == "" {
		t.Fatal("classification must always map to a diagnostic code")
	}
}
