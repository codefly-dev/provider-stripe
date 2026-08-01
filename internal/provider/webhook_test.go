package provider

import "testing"

func TestEventsCompareAsSortedSets(t *testing.T) {
	a := normalizeEvents([]string{"b", "a", "a"})
	b := normalizeEvents([]string{"a", "b"})
	if !eventsEqual(a, b) {
		t.Fatal("event sets differing only by order/duplicates must compare equal")
	}
	if eventsEqual(normalizeEvents([]string{"a"}), normalizeEvents([]string{"a", "b"})) {
		t.Fatal("different event sets must not compare equal")
	}
	if eventsEqual(normalizeEvents([]string{"*"}), normalizeEvents([]string{"a"})) {
		t.Fatal("a wildcard subscription must not equal an explicit set")
	}
}

func TestClassifyDrift(t *testing.T) {
	desired := desiredWebhook{
		URL: "https://x/y", EnabledEvents: normalizeEvents([]string{"a", "b"}), APIVersion: "2024-06-20",
		Description: defaultDescription,
		Metadata:    map[string]string{metaWorkspace: "ws", metaEnvironment: "env", metaBinding: "bind", metaResource: resourceWebhook},
	}
	converged := observedWebhook{
		URL: "https://x/y", EnabledEvents: normalizeEvents([]string{"b", "a"}), APIVersion: "2024-06-20",
		Description: defaultDescription, Status: statusEnabled,
		Metadata: map[string]string{metaWorkspace: "ws", metaEnvironment: "env", metaBinding: "bind", metaResource: resourceWebhook},
	}
	if classifyDrift(desired, converged) != driftNone {
		t.Fatal("identical owned fields must be driftNone")
	}

	apiChanged := converged
	apiChanged.APIVersion = "2020-08-27"
	if classifyDrift(desired, apiChanged) != driftReplace {
		t.Fatal("an API-version change must be driftReplace")
	}

	eventsChanged := converged
	eventsChanged.EnabledEvents = normalizeEvents([]string{"a"})
	if classifyDrift(desired, eventsChanged) != driftMutable {
		t.Fatal("an event-set change must be driftMutable")
	}

	disabled := converged
	disabled.Status = "disabled"
	if classifyDrift(desired, disabled) != driftMutable {
		t.Fatal("a disabled owned endpoint must be converged via update")
	}
}

func TestOwnershipRequiresMetadataMatchNotURL(t *testing.T) {
	// Same URL, but metadata belongs to a different binding: not owned.
	observed := []observedWebhook{{
		RemoteID: "we_other", URL: "https://x/y", Ownership: 2, // OWNED
		Metadata: map[string]string{metaWorkspace: "other", metaEnvironment: "env", metaBinding: "bind"},
	}}
	if ownedBy(observed, binding()) != nil {
		t.Fatal("ownership must require matching binding metadata, never URL alone")
	}
}
