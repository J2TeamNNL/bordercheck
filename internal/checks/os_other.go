//go:build !darwin && !windows

package checks

import (
	"context"

	"github.com/ptrinh/bordercheck/internal/check"
)

func firewall(context.Context, bool) check.Result { return unsupported() }

func diskEncryption(context.Context) check.Result { return unsupported() }

func listListeners(context.Context) ([]listener, string, error) { return nil, "", errUnsupported }
