//go:build !darwin && !windows && !linux

package notify

import (
	"context"
	"errors"
	"runtime"
)

func show(context.Context, Message) error {
	return errors.New("desktop notifications are not supported on " + runtime.GOOS)
}
