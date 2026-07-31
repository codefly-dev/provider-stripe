package provider

import (
	"fmt"
	"sort"
	"strings"

	providerv0 "github.com/codefly-dev/core/generated/go/codefly/services/provider/v0"
	"github.com/codefly-dev/core/provider/configuration"
)

// callbackMode is how Stripe reaches the Codefly billing webhook.
type callbackMode string

const (
	modePublic         callbackMode = "public"          // Codefly resolves a stable public HTTPS origin and manages a remote endpoint.
	modeLocalForwarded callbackMode = "local-forwarded" // Stripe CLI forwards to the loopback callback; no remote endpoint is created.
	modeExisting       callbackMode = "existing"        // An operator-supplied endpoint is observed until imported by exact ID.
)

// accountPolicy is the operator-declared Stripe account class. It is never
// inferred by the provider; the host attests mode from the credential and the
// operator declares the policy.
type accountPolicy string

const (
	policySandbox accountPolicy = "sandbox"
	policyTest    accountPolicy = "test"
)

// inputs is the typed, normalized, non-secret desired input for a billing
// binding. Secrets are never present here; they arrive as opaque credential
// references on the desired state.
type inputs struct {
	APIVersion     string
	CallbackMode   callbackMode
	CallbackURL    string
	EnabledEvents  []string
	ExistingID     string
	AccountPolicy  accountPolicy
	PublishableKey string
	PriceID        string
	Description    string
}

const defaultDescription = "Codefly billing lifecycle"

// parseInputs reads the typed inputs from a normalized public-value map. It only
// reads declared keys and rejects secret-shaped literals, which must never
// reach the provider as raw input.
func parseInputs(raw map[string]*providerv0.PublicValue) (inputs, error) {
	var in inputs
	for key, value := range raw {
		if s, ok := publicString(value); ok && configuration.LooksSecret(s) {
			return inputs{}, fmt.Errorf("input %q carries a secret-shaped literal; secrets must be opaque references", key)
		}
	}
	in.APIVersion = strings.TrimSpace(stringInput(raw, "stripe_api_version"))
	in.CallbackMode = callbackMode(strings.TrimSpace(stringInput(raw, "callback_mode")))
	in.CallbackURL = strings.TrimRight(strings.TrimSpace(stringInput(raw, "callback_url")), "/")
	in.ExistingID = strings.TrimSpace(stringInput(raw, "existing_webhook_id"))
	in.AccountPolicy = accountPolicy(strings.TrimSpace(stringInput(raw, "account_policy")))
	in.PublishableKey = strings.TrimSpace(stringInput(raw, "publishable_key"))
	in.PriceID = strings.TrimSpace(stringInput(raw, "price_id"))
	in.Description = strings.TrimSpace(stringInput(raw, "description"))
	if in.Description == "" {
		in.Description = defaultDescription
	}
	in.EnabledEvents = normalizeEvents(stringListInput(raw, "enabled_events"))
	return in, nil
}

// normalizeEvents returns the sorted, de-duplicated event set. Stripe's wildcard
// "*" is preserved as a literal member so a wildcard subscription compares equal
// only to another wildcard subscription.
func normalizeEvents(events []string) []string {
	seen := make(map[string]struct{}, len(events))
	out := make([]string, 0, len(events))
	for _, e := range events {
		e = strings.TrimSpace(e)
		if e == "" {
			continue
		}
		if _, dup := seen[e]; dup {
			continue
		}
		seen[e] = struct{}{}
		out = append(out, e)
	}
	sort.Strings(out)
	return out
}

// eventsEqual compares two event sets as sorted sets.
func eventsEqual(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func stringInput(raw map[string]*providerv0.PublicValue, key string) string {
	s, _ := publicString(raw[key])
	return s
}

func stringListInput(raw map[string]*providerv0.PublicValue, key string) []string {
	list := raw[key].GetListValue()
	if list == nil {
		return nil
	}
	out := make([]string, 0, len(list.GetValues()))
	for _, v := range list.GetValues() {
		if s, ok := publicString(v); ok {
			out = append(out, s)
		}
	}
	return out
}

// publicString returns the string payload of a public value when it is a string.
func publicString(v *providerv0.PublicValue) (string, bool) {
	if v == nil {
		return "", false
	}
	if _, ok := v.GetKind().(*providerv0.PublicValue_StringValue); ok {
		return v.GetStringValue(), true
	}
	return "", false
}

func publicStringValue(s string) *providerv0.PublicValue {
	return &providerv0.PublicValue{Kind: &providerv0.PublicValue_StringValue{StringValue: s}}
}
