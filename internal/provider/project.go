package provider

import (
	"sort"
	"strings"

	providerv0 "github.com/codefly-dev/core/generated/go/codefly/services/provider/v0"
	"github.com/codefly-dev/core/provider/sdk"
)

// filteredResponse is the flat map of concrete selector paths to safe values the
// host forwarded. Wildcard selectors resolve to one entry per matched element
// (e.g. "$.data[0].url"), so a list projects to many keys sharing a prefix.
type filteredResponse map[string]*providerv0.PublicValue

func decodeFiltered(response *providerv0.ExecuteRequestResponse) (filteredResponse, error) {
	fields, err := sdk.DecodeFilteredResponse(response)
	if err != nil {
		return nil, err
	}
	return filteredResponse(fields), nil
}

func (f filteredResponse) string(path string) string {
	if value, ok := f[path]; ok {
		if s, ok := publicString(value); ok {
			return s
		}
	}
	return ""
}

func (f filteredResponse) bool(path string) bool {
	if value, ok := f[path]; ok {
		if _, isBool := value.GetKind().(*providerv0.PublicValue_BoolValue); isBool {
			return value.GetBoolValue()
		}
	}
	return false
}

// present reports whether any forwarded field addresses the given exact path.
func (f filteredResponse) present(path string) bool {
	_, ok := f[path]
	return ok
}

// dataIndices returns the sorted element indices present under a "$.data[N]"
// list projection, keyed off each element's forwarded id.
func (f filteredResponse) dataIndices() []int {
	seen := map[int]struct{}{}
	for key := range f {
		if index, ok := listIndex(key, "$.data", ".id"); ok {
			seen[index] = struct{}{}
		}
	}
	indices := make([]int, 0, len(seen))
	for index := range seen {
		indices = append(indices, index)
	}
	sort.Ints(indices)
	return indices
}

// webhookAt reconstructs the projected webhook fields rooted at prefix (either
// "$" for a single retrieve or "$.data[N]" for one list element) together with
// the response's livemode flag for the host mode cross-check.
func (f filteredResponse) webhookAt(prefix string, binding *providerv0.BindingAddress) (observedWebhook, bool) {
	id := f.string(prefix + ".id")
	if id == "" {
		return observedWebhook{}, false
	}
	metadata := f.collectMetadata(prefix + ".metadata.")
	ownership := providerv0.Ownership_OWNERSHIP_UNMANAGED
	if metadataMatchesBinding(metadata, binding) {
		ownership = providerv0.Ownership_OWNERSHIP_OWNED
	}
	return observedWebhook{
		RemoteID:      id,
		Ownership:     ownership,
		URL:           f.string(prefix + ".url"),
		EnabledEvents: normalizeEvents(f.collectList(prefix + ".enabled_events")),
		APIVersion:    f.string(prefix + ".api_version"),
		Description:   f.string(prefix + ".description"),
		Status:        f.string(prefix + ".status"),
		Metadata:      metadata,
	}, true
}

func (f filteredResponse) livemodeAt(prefix string) (bool, bool) {
	return f.bool(prefix + ".livemode"), f.present(prefix + ".livemode")
}

func (f filteredResponse) collectList(prefix string) []string {
	type indexed struct {
		index int
		value string
	}
	var items []indexed
	for key, value := range f {
		if index, ok := listIndex(key, prefix, ""); ok {
			if s, ok := publicString(value); ok {
				items = append(items, indexed{index: index, value: s})
			}
		}
	}
	sort.Slice(items, func(i, j int) bool { return items[i].index < items[j].index })
	out := make([]string, 0, len(items))
	for _, item := range items {
		out = append(out, item.value)
	}
	return out
}

func (f filteredResponse) collectMetadata(prefix string) map[string]string {
	out := map[string]string{}
	for key, value := range f {
		if suffix, ok := strings.CutPrefix(key, prefix); ok && !strings.ContainsAny(suffix, ".[") {
			if s, ok := publicString(value); ok {
				out[suffix] = s
			}
		}
	}
	return out
}

// listIndex parses a concrete wildcard path of the form "<prefix>[N]<suffix>"
// and returns N. suffix "" matches a scalar element ("<prefix>[N]").
func listIndex(key, prefix, suffix string) (int, bool) {
	rest, ok := strings.CutPrefix(key, prefix+"[")
	if !ok {
		return 0, false
	}
	digits, tail, ok := strings.Cut(rest, "]")
	if !ok || tail != suffix {
		return 0, false
	}
	index := 0
	for _, r := range digits {
		if r < '0' || r > '9' {
			return 0, false
		}
		index = index*10 + int(r-'0')
	}
	if digits == "" {
		return 0, false
	}
	return index, true
}
