package provider

import (
	"os"
	"strings"
	"testing"

	providerv0 "github.com/codefly-dev/core/generated/go/codefly/services/provider/v0"
	"github.com/codefly-dev/core/provider/manifest"
)

const manifestPath = "../../provider.codefly.yaml"

func loadManifestBytes(t *testing.T) []byte {
	t.Helper()
	data, err := os.ReadFile(manifestPath)
	if err != nil {
		t.Fatalf("read manifest: %v", err)
	}
	return data
}

// testServer builds a server with an identity that matches the packaged
// manifest, using a syntactically valid placeholder artifact digest.
func testServer(t *testing.T) *Server {
	t.Helper()
	data := loadManifestBytes(t)
	m, err := manifest.Load(data)
	if err != nil {
		t.Fatalf("load manifest: %v", err)
	}
	manifestDigest, err := m.Digest()
	if err != nil {
		t.Fatalf("manifest digest: %v", err)
	}
	server, err := NewServer(data, Identity{
		Publisher:      m.Agent.Publisher,
		Name:           m.Agent.Name,
		Version:        m.Agent.Version,
		ArtifactDigest: "sha256:" + strings.Repeat("a", 64),
		ManifestDigest: manifestDigest,
	})
	if err != nil {
		t.Fatalf("new server: %v", err)
	}
	return server
}

func binding() *providerv0.BindingAddress {
	return &providerv0.BindingAddress{WorkspaceId: "ws", EnvironmentId: "env", BindingId: "bind"}
}

func str(s string) *providerv0.PublicValue {
	return &providerv0.PublicValue{Kind: &providerv0.PublicValue_StringValue{StringValue: s}}
}

func list(values ...string) *providerv0.PublicValue {
	items := make([]*providerv0.PublicValue, 0, len(values))
	for _, v := range values {
		items = append(items, str(v))
	}
	return &providerv0.PublicValue{Kind: &providerv0.PublicValue_ListValue{ListValue: &providerv0.PublicList{Values: items}}}
}

func object(fields map[string]string) *providerv0.PublicValue {
	out := make(map[string]*providerv0.PublicValue, len(fields))
	for k, v := range fields {
		out[k] = str(v)
	}
	return &providerv0.PublicValue{Kind: &providerv0.PublicValue_ObjectValue{ObjectValue: &providerv0.PublicObject{Fields: out}}}
}

// validInput is a well-formed public-mode desired input.
func validInput() map[string]*providerv0.PublicValue {
	return map[string]*providerv0.PublicValue{
		"stripe_api_version": str("2024-06-20"),
		"callback_mode":      str("public"),
		"callback_url":       str("https://app.example.com/v1/billing/webhook"),
		"enabled_events":     list("customer.subscription.updated", "customer.subscription.created"),
		"account_policy":     str("test"),
		"publishable_key":    str("pk_test_123"),
	}
}

// ownedObservation returns a material observation with one Codefly-owned webhook
// endpoint carrying the given fields.
func ownedObservation(remoteID, url, apiVersion string, events []string, status string) *providerv0.MaterialObservation {
	return &providerv0.MaterialObservation{
		Complete: true,
		Resources: []*providerv0.MaterialResourceObservation{{
			Identity: &providerv0.RemoteIdentity{
				Provider: "stripe", AccountId: "acct_123", ResourceType: resourceWebhook, RemoteId: remoteID,
			},
			Ownership: providerv0.Ownership_OWNERSHIP_OWNED,
			ProviderOwnedFields: map[string]*providerv0.PublicValue{
				fieldURL:         str(url),
				fieldEvents:      list(events...),
				fieldAPIVersion:  str(apiVersion),
				fieldDescription: str(defaultDescription),
				fieldStatus:      str(status),
				fieldMetadata: object(map[string]string{
					metaWorkspace: "ws", metaEnvironment: "env", metaBinding: "bind", metaResource: resourceWebhook,
				}),
			},
		}},
	}
}

func planRequest(input map[string]*providerv0.PublicValue, observation *providerv0.MaterialObservation) *providerv0.PlanRequest {
	return &providerv0.PlanRequest{
		Context: &providerv0.OfflineProviderContext{
			Binding: binding(), Mode: providerv0.HostMode_HOST_MODE_DEVELOPMENT, AccountIdentity: "acct_123",
		},
		Desired:     &providerv0.BindingDesiredState{Binding: binding(), Input: input},
		Observation: observation,
	}
}

// singleAction runs Plan and requires exactly one action, returning it.
func singleAction(t *testing.T, request *providerv0.PlanRequest) *providerv0.PlanAction {
	t.Helper()
	response, err := testServer(t).Plan(t.Context(), request)
	if err != nil {
		t.Fatalf("plan: %v", err)
	}
	actions := response.GetPlan().GetActions()
	if len(actions) != 1 {
		t.Fatalf("expected 1 action, got %d", len(actions))
	}
	return actions[0]
}
