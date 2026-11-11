//go:build !darwin && !windows && !linux

package checks

import (
	"context"

	"github.com/ptrinh/bordercheck/internal/policy"
)

// trustFactsOS reads nothing here: only the proxy environment variables are
// checked.
func trustFactsOS(context.Context, policy.TrustStore) trustFacts {
	return trustFacts{CAErr: errUnsupported.Error()}
}
