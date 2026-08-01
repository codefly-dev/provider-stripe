package provider

import (
	"testing"

	basev0 "github.com/codefly-dev/core/generated/go/codefly/base/v0"
	providerv0 "github.com/codefly-dev/core/generated/go/codefly/services/provider/v0"
)

func validate(t *testing.T, input map[string]*providerv0.PublicValue, mode providerv0.HostMode) *providerv0.ValidateResponse {
	t.Helper()
	response, err := testServer(t).Validate(t.Context(), &providerv0.ValidateRequest{
		Context: &providerv0.OfflineProviderContext{Binding: binding(), Mode: mode, Input: input},
	})
	if err != nil {
		t.Fatalf("validate: %v", err)
	}
	return response
}

func TestValidateAcceptsWellFormedInput(t *testing.T) {
	if !validate(t, validInput(), providerv0.HostMode_HOST_MODE_DEVELOPMENT).GetValid() {
		t.Fatal("expected valid input to pass")
	}
}

func TestValidateRejectsMissingOrBadFields(t *testing.T) {
	cases := map[string]func(map[string]*providerv0.PublicValue){
		"missing api version":    func(m map[string]*providerv0.PublicValue) { delete(m, "stripe_api_version") },
		"bad api version":        func(m map[string]*providerv0.PublicValue) { m["stripe_api_version"] = str("v1") },
		"missing account policy": func(m map[string]*providerv0.PublicValue) { delete(m, "account_policy") },
		"no events":              func(m map[string]*providerv0.PublicValue) { delete(m, "enabled_events") },
		"public without url":     func(m map[string]*providerv0.PublicValue) { delete(m, "callback_url") },
		"loopback public url":    func(m map[string]*providerv0.PublicValue) { m["callback_url"] = str("https://localhost/x") },
		"private ip url":         func(m map[string]*providerv0.PublicValue) { m["callback_url"] = str("https://10.0.0.1/x") },
		"loopback range ip url":  func(m map[string]*providerv0.PublicValue) { m["callback_url"] = str("https://127.0.0.2/x") },
		"unspecified ip url":     func(m map[string]*providerv0.PublicValue) { m["callback_url"] = str("https://0.0.0.0/x") },
		"link-local ip url":      func(m map[string]*providerv0.PublicValue) { m["callback_url"] = str("https://169.254.1.1/x") },
		"bad callback mode":      func(m map[string]*providerv0.PublicValue) { m["callback_mode"] = str("carrier-pigeon") },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			input := validInput()
			mutate(input)
			if validate(t, input, providerv0.HostMode_HOST_MODE_DEVELOPMENT).GetValid() {
				t.Fatalf("expected %q to be rejected", name)
			}
		})
	}
}

func TestValidateRefusesLiveAccountPolicy(t *testing.T) {
	input := validInput()
	input["account_policy"] = str("live")
	response := validate(t, input, providerv0.HostMode_HOST_MODE_DEVELOPMENT)
	if response.GetValid() {
		t.Fatal("a live account policy must be refused")
	}
	if !hasDiagnostic(response.GetDiagnostics(), DiagWrongMode) {
		t.Fatal("expected a wrong-mode diagnostic")
	}
}

func TestValidateRejectsSecretShapedInput(t *testing.T) {
	input := validInput()
	input["publishable_key"] = str("sk_live_0123456789abcdef")
	if validate(t, input, providerv0.HostMode_HOST_MODE_DEVELOPMENT).GetValid() {
		t.Fatal("a secret-shaped literal must never be accepted as input")
	}
}

func TestValidateRequiresExistingID(t *testing.T) {
	input := validInput()
	input["callback_mode"] = str("existing")
	delete(input, "callback_url")
	if validate(t, input, providerv0.HostMode_HOST_MODE_DEVELOPMENT).GetValid() {
		t.Fatal("existing mode without an endpoint id must be rejected")
	}
}

func hasDiagnostic(diagnostics []*basev0.FailureDiagnostic, code string) bool {
	for _, d := range diagnostics {
		if d.GetCode() == code {
			return true
		}
	}
	return false
}
