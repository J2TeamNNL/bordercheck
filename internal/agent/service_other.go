//go:build !darwin && !windows && !linux

package agent

import (
	"errors"
	"runtime"
)

var errNoService = errors.New("installing as a service is not supported on " + runtime.GOOS + " yet")

func registerService(string, string) error { return errNoService }

func canRegisterService() error { return errNoService }

func unregisterService() error { return errNoService }

func serviceStatus() string { return errNoService.Error() }
