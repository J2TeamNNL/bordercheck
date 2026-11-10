//go:build !darwin && !windows && !linux

package checks

import (
	"context"

	"github.com/ptrinh/bordercheck/internal/check"
	"github.com/ptrinh/bordercheck/internal/msg"
)

func firewall(context.Context, bool) check.Result { return unsupported() }

func diskEncryption(context.Context) check.Result { return unsupported() }

func listListeners(context.Context) ([]listener, msg.Text, error) { return nil, nil, errUnsupported }
