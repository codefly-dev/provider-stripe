package provider

import (
	"context"

	providerv0 "github.com/codefly-dev/core/generated/go/codefly/services/provider/v0"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// UpgradeState performs one offline state-schema upgrade step. v0.1 defines
// only state schema version 1, so there is no prior schema to advance from: the
// method fails closed rather than fabricating an upgrade. When later versions
// are introduced this method gains the exact stepwise transitions.
func (s *Server) UpgradeState(_ context.Context, request *providerv0.UpgradeStateRequest) (*providerv0.UpgradeStateResponse, error) {
	return nil, status.Errorf(codes.FailedPrecondition,
		"no state schema upgrade is defined: only version %d exists (requested %d to %d)",
		manifestStateSchemaVersion, request.GetFromVersion(), request.GetToVersion())
}

// manifestStateSchemaVersion is the single supported state schema version.
const manifestStateSchemaVersion = 1
