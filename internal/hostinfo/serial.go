package hostinfo

import (
	"context"
	"os"
	"regexp"
	"runtime"
	"strings"
	"time"

	"github.com/ptrinh/bordercheck/internal/sysx"
)

// Serial is this machine's hardware serial number, as the OS reports it (the
// same one device-management and Zero Trust clients such as Cloudflare WARP
// read), or "" when there is none or it can't be read without more rights.
// The portal uses it to tell which machine another system means: an asset
// identifier, not a secret.
func Serial(ctx context.Context) string {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	var raw string
	switch runtime.GOOS {
	case "darwin":
		out, err := sysx.Run(ctx, "/usr/sbin/ioreg", "-rd1", "-c", "IOPlatformExpertDevice")
		if err == nil {
			raw = ioregSerial(out)
		}
	case "linux":
		// Readable by root only on most distributions; the service may not be.
		if b, err := os.ReadFile("/sys/class/dmi/id/product_serial"); err == nil {
			raw = string(b)
		}
	case "windows":
		if out, err := sysx.PowerShell(ctx, "(Get-CimInstance -ClassName Win32_BIOS).SerialNumber"); err == nil {
			raw = out
		}
	}
	return cleanSerial(raw)
}

var ioregSerialRe = regexp.MustCompile(`"IOPlatformSerialNumber"\s*=\s*"([^"]*)"`)

func ioregSerial(out string) string {
	if m := ioregSerialRe.FindStringSubmatch(out); m != nil {
		return m[1]
	}
	return ""
}

// Placeholders firmware ships instead of a real serial: they would match
// every machine of a model, so they count as none.
var placeholderSerials = []string{
	"to be filled by o.e.m.", "default string", "system serial number", "not specified", "none",
	"not applicable", "chassis serial number", "0", "00000000", "0123456789", "123456789",
}

func cleanSerial(s string) string {
	s = strings.TrimSpace(s)
	if len(s) > 64 || strings.ContainsAny(s, "\n\r\t\x00") {
		return ""
	}
	for _, p := range placeholderSerials {
		if strings.EqualFold(s, p) {
			return ""
		}
	}
	return s
}
