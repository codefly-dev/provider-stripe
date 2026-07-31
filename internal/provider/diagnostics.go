package provider

import (
	"strings"

	basev0 "github.com/codefly-dev/core/generated/go/codefly/base/v0"
	"github.com/codefly-dev/core/provider/sdk"
)

// diag builds a namespaced failure diagnostic. fullCode must be one of the
// package diagnostic-code constants (namespace + local code).
func diag(severity basev0.FailureDiagnostic_Severity, fullCode, message string) *basev0.FailureDiagnostic {
	local := strings.TrimPrefix(fullCode, diagNamespace)
	if message == "" {
		message = fullCode
	}
	if len(message) > 2048 {
		message = message[:2048]
	}
	d, err := sdk.Diagnostic(severity, diagNamespace, local, message)
	if err != nil {
		return &basev0.FailureDiagnostic{Severity: severity, Code: fullCode, Message: message}
	}
	return d
}

func hasError(diagnostics []*basev0.FailureDiagnostic) bool {
	for _, d := range diagnostics {
		if d.GetSeverity() == basev0.FailureDiagnostic_ERROR {
			return true
		}
	}
	return false
}
