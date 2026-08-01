package provider

import (
	providerv0 "github.com/codefly-dev/core/generated/go/codefly/services/provider/v0"
)

// Resource types and canonical observed-field keys. The provider owns these
// keys: Observe writes them and Plan reads them, so drift comparison is over a
// stable, provider-defined projection rather than raw Stripe fields.
const (
	resourceAccount = "stripe.account"
	resourceWebhook = "stripe.webhook-endpoint"

	fieldURL         = "url"
	fieldEvents      = "enabled_events"
	fieldAPIVersion  = "api_version"
	fieldDescription = "description"
	fieldStatus      = "status"
	fieldMetadata    = "metadata"

	metaWorkspace   = "codefly_workspace"
	metaEnvironment = "codefly_environment"
	metaBinding     = "codefly_binding"
	metaResource    = "codefly_resource"

	statusEnabled = "enabled"
)

// desiredWebhook is the Codefly-owned target shape of the billing webhook
// endpoint. Only Codefly-owned fields appear here; Stripe owns the endpoint id,
// created time, application, and the signing secret bytes.
type desiredWebhook struct {
	URL           string
	EnabledEvents []string
	APIVersion    string
	Description   string
	Metadata      map[string]string
}

// observedWebhook is the provider's projection of a remote Stripe webhook
// endpoint, as produced by Observe and carried into offline Plan.
type observedWebhook struct {
	RemoteID      string
	Ownership     providerv0.Ownership
	URL           string
	EnabledEvents []string
	APIVersion    string
	Description   string
	Status        string
	Metadata      map[string]string
}

// desiredFrom builds the Codefly-owned desired webhook for a binding. The
// ownership metadata is stamped from the binding identity, never from operator
// input, so a Codefly-owned endpoint is always attributable.
func desiredFrom(in inputs, binding *providerv0.BindingAddress) desiredWebhook {
	return desiredWebhook{
		URL:           in.CallbackURL,
		EnabledEvents: in.EnabledEvents,
		APIVersion:    in.APIVersion,
		Description:   in.Description,
		Metadata: map[string]string{
			metaWorkspace:   binding.GetWorkspaceId(),
			metaEnvironment: binding.GetEnvironmentId(),
			metaBinding:     binding.GetBindingId(),
			metaResource:    resourceWebhook,
		},
	}
}

// observedWebhooks extracts the webhook-endpoint projections from a material
// observation.
func observedWebhooks(observation *providerv0.MaterialObservation) []observedWebhook {
	var out []observedWebhook
	for _, resource := range observation.GetResources() {
		if resource.GetIdentity().GetResourceType() != resourceWebhook {
			continue
		}
		fields := resource.GetProviderOwnedFields()
		out = append(out, observedWebhook{
			RemoteID:      resource.GetIdentity().GetRemoteId(),
			Ownership:     resource.GetOwnership(),
			URL:           normalizeURL(fields[fieldURL].GetStringValue()),
			EnabledEvents: normalizeEvents(publicStringSlice(fields[fieldEvents])),
			APIVersion:    fields[fieldAPIVersion].GetStringValue(),
			Description:   fields[fieldDescription].GetStringValue(),
			Status:        fields[fieldStatus].GetStringValue(),
			Metadata:      publicStringMap(fields[fieldMetadata]),
		})
	}
	return out
}

// ownedBy returns the single Codefly-owned webhook for this binding, if any.
// Ownership is established by owned state plus matching ownership metadata,
// never by URL.
func ownedBy(observed []observedWebhook, binding *providerv0.BindingAddress) *observedWebhook {
	for i := range observed {
		w := observed[i]
		owned := w.Ownership == providerv0.Ownership_OWNERSHIP_OWNED || w.Ownership == providerv0.Ownership_OWNERSHIP_ADOPTED
		if owned && metadataMatchesBinding(w.Metadata, binding) {
			return &observed[i]
		}
	}
	return nil
}

// unmanagedAtURL returns webhook endpoints that live at the desired URL but are
// not Codefly-owned. They must never be auto-adopted; the operator must import
// by exact ID.
func unmanagedAtURL(observed []observedWebhook, url string) []observedWebhook {
	var out []observedWebhook
	for _, w := range observed {
		if w.URL == url && w.Ownership != providerv0.Ownership_OWNERSHIP_OWNED && w.Ownership != providerv0.Ownership_OWNERSHIP_ADOPTED {
			out = append(out, w)
		}
	}
	return out
}

func metadataMatchesBinding(metadata map[string]string, binding *providerv0.BindingAddress) bool {
	return metadata[metaWorkspace] == binding.GetWorkspaceId() &&
		metadata[metaEnvironment] == binding.GetEnvironmentId() &&
		metadata[metaBinding] == binding.GetBindingId()
}

// driftKind classifies the change required to converge an owned endpoint.
type driftKind int

const (
	driftNone    driftKind = iota // owned fields already converge
	driftMutable                  // mutable owned fields differ; UPDATE
	driftReplace                  // the endpoint API version differs; REPLACE (write-once secret rotates)
)

// classifyDrift compares the Codefly-owned fields. Changing the endpoint API
// version is a REPLACE, not an UPDATE: Stripe does not expose api_version in
// update parameters, and the replacement mints a new signing secret.
func classifyDrift(desired desiredWebhook, observed observedWebhook) driftKind {
	if desired.APIVersion != observed.APIVersion {
		return driftReplace
	}
	if desired.URL != observed.URL ||
		!eventsEqual(desired.EnabledEvents, observed.EnabledEvents) ||
		desired.Description != observed.Description ||
		!metadataEqual(desired.Metadata, observed.Metadata) ||
		observed.Status != statusEnabled {
		return driftMutable
	}
	return driftNone
}

func metadataEqual(a, b map[string]string) bool {
	for _, key := range []string{metaWorkspace, metaEnvironment, metaBinding, metaResource} {
		if a[key] != b[key] {
			return false
		}
	}
	return true
}

func publicStringSlice(v *providerv0.PublicValue) []string {
	list := v.GetListValue()
	if list == nil {
		return nil
	}
	out := make([]string, 0, len(list.GetValues()))
	for _, item := range list.GetValues() {
		if s, ok := publicString(item); ok {
			out = append(out, s)
		}
	}
	return out
}

func publicStringMap(v *providerv0.PublicValue) map[string]string {
	object := v.GetObjectValue()
	if object == nil {
		return map[string]string{}
	}
	out := make(map[string]string, len(object.GetFields()))
	for key, value := range object.GetFields() {
		if s, ok := publicString(value); ok {
			out[key] = s
		}
	}
	return out
}
