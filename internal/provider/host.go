package provider

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"

	providerv0 "github.com/codefly-dev/core/generated/go/codefly/services/provider/v0"
	"github.com/codefly-dev/core/provider/canonical"
	"github.com/codefly-dev/core/provider/manifest"
)

// Host is the provider-to-host callback surface this provider drives. It is the
// exact subset of the generated ProviderHostClient the broker-driven methods
// use: every Stripe request, checkpoint, capture recovery, and output
// projection travels through it, so the provider never opens a socket and never
// holds a raw credential or the webhook signing secret.
type Host = providerv0.ProviderHostClient

// Option customizes a Server at construction.
type Option func(*Server)

// WithHost attaches the host callback channel that Observe, ApplyAction, and
// Doctor drive. The offline methods (information, validate, plan, upgrade) never
// touch it, so a server built without a host still serves them; the
// broker-driven methods fail closed until a host is attached.
func WithHost(host Host) Option {
	return func(s *Server) { s.host = host }
}

// originRuleAPI is the single manifest origin rule; every Stripe request is
// admitted against it.
const originRuleAPI = "api"

var httpMethods = map[string]providerv0.HTTPMethod{
	"GET":    providerv0.HTTPMethod_HTTP_METHOD_GET,
	"HEAD":   providerv0.HTTPMethod_HTTP_METHOD_HEAD,
	"POST":   providerv0.HTTPMethod_HTTP_METHOD_POST,
	"PUT":    providerv0.HTTPMethod_HTTP_METHOD_PUT,
	"PATCH":  providerv0.HTTPMethod_HTTP_METHOD_PATCH,
	"DELETE": providerv0.HTTPMethod_HTTP_METHOD_DELETE,
}

// descriptor returns the packaged request descriptor by id.
func (s *Server) descriptor(id string) (manifest.RequestDescriptor, error) {
	for _, d := range s.manifest.Requests {
		if d.ID == id {
			return d, nil
		}
	}
	return manifest.RequestDescriptor{}, fmt.Errorf("request descriptor %q is not packaged", id)
}

// admittedOrigin selects the host-attested origin for the manifest origin rule.
// The concrete origin and its admission digest are host-owned; the provider only
// references them.
func admittedOrigin(ctx *providerv0.ProviderContext, ruleID string) (*providerv0.AdmittedOrigin, error) {
	for _, origin := range ctx.GetAdmittedOrigins() {
		if origin.GetOriginRuleId() == ruleID {
			return origin, nil
		}
	}
	return nil, fmt.Errorf("host attested no origin for rule %q", ruleID)
}

// credentialHandles selects the host-minted handles carrying the given
// purposes, in the descriptor's declared order.
func credentialHandles(ctx *providerv0.ProviderContext, purposes []providerv0.CredentialPurpose) ([]*providerv0.CredentialHandle, error) {
	handles := make([]*providerv0.CredentialHandle, 0, len(purposes))
	for _, purpose := range purposes {
		var found *providerv0.CredentialHandle
		for _, handle := range ctx.GetCredentials() {
			if handle.GetPurpose() == purpose {
				found = handle
				break
			}
		}
		if found == nil {
			return nil, fmt.Errorf("host provided no credential handle for purpose %s", purpose)
		}
		handles = append(handles, found)
	}
	return handles, nil
}

// plannedRequest builds and digest-binds one broker request from a packaged
// descriptor and host-owned origin. The provider owns only the descriptor
// selection and structured fields; the host re-derives and owns the URL,
// headers, and credential injection at execution.
func (s *Server) plannedRequest(descriptorID string, origin *providerv0.AdmittedOrigin, pathParams, query, body map[string]*providerv0.PublicValue, idempotencyKey string) (*providerv0.PlannedRequest, error) {
	descriptor, err := s.descriptor(descriptorID)
	if err != nil {
		return nil, err
	}
	method, ok := httpMethods[descriptor.Method]
	if !ok {
		return nil, fmt.Errorf("descriptor %q has an unsupported method %q", descriptorID, descriptor.Method)
	}
	descriptorDigest, err := manifest.RequestDescriptorDigest(descriptor)
	if err != nil {
		return nil, err
	}
	policyDigest, err := s.responsePolicyDigest(descriptor.ResponseSchema)
	if err != nil {
		return nil, err
	}
	purposes := make([]providerv0.CredentialPurpose, 0, len(descriptor.CredentialPurposes))
	for _, consumer := range descriptor.CredentialPurposes {
		purpose, err := credentialPurpose(consumer)
		if err != nil {
			return nil, err
		}
		purposes = append(purposes, purpose)
	}
	request := &providerv0.PlannedRequest{
		RequestDescriptorId:     descriptor.ID,
		RequestDescriptorDigest: descriptorDigest,
		Method:                  method,
		AdmittedOriginDigest:    origin.GetAdmissionDigest(),
		PathParameters:          pathParams,
		Query:                   query,
		Body:                    body,
		CredentialPurposes:      purposes,
		ResponsePolicyDigest:    policyDigest,
		IdempotencyKey:          idempotencyKey,
	}
	return canonical.BindPlannedRequestDigest(request)
}

// responsePolicyDigest derives a stable digest of the host response policy the
// named schema induces. The provider and host both derive it from the same
// packaged manifest, so it binds a recorded response to the exact filtering and
// capture policy in force when it was produced.
func (s *Server) responsePolicyDigest(schemaID string) (string, error) {
	for _, schema := range s.manifest.ResponseSchemas {
		if schema.ID == schemaID {
			encoded, err := json.Marshal(schema)
			if err != nil {
				return "", err
			}
			sum := sha256.Sum256(encoded)
			return "sha256:" + hex.EncodeToString(sum[:]), nil
		}
	}
	return "", fmt.Errorf("response schema %q is not packaged", schemaID)
}

func credentialPurpose(consumer string) (providerv0.CredentialPurpose, error) {
	switch consumer {
	case "management":
		return providerv0.CredentialPurpose_CREDENTIAL_PURPOSE_MANAGEMENT, nil
	case "runtime":
		return providerv0.CredentialPurpose_CREDENTIAL_PURPOSE_RUNTIME, nil
	case "build":
		return providerv0.CredentialPurpose_CREDENTIAL_PURPOSE_BUILD, nil
	case "webhook_verification", "webhook-verification":
		return providerv0.CredentialPurpose_CREDENTIAL_PURPOSE_WEBHOOK_VERIFICATION, nil
	default:
		return providerv0.CredentialPurpose_CREDENTIAL_PURPOSE_UNSPECIFIED, fmt.Errorf("unknown credential purpose %q", consumer)
	}
}
