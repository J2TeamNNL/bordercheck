package checks

import (
	"context"
	"os/exec"

	"github.com/ptrinh/bordercheck/internal/policy"
	"github.com/ptrinh/bordercheck/internal/sysx"
)

// linuxAnchorDirs are where locally added roots go: Debian and Ubuntu
// (update-ca-certificates), Fedora and RHEL (update-ca-trust), Arch
// (trust anchor). The distribution's own roots live elsewhere.
var linuxAnchorDirs = []string{
	"/usr/local/share/ca-certificates",
	"/etc/pki/ca-trust/source/anchors",
	"/etc/ca-certificates/trust-source/anchors",
}

// trustFactsOS reads the local anchor folders and GNOME's proxy settings.
// Browsers' own NSS databases are not read: that needs certutil, which is
// often missing.
func trustFactsOS(ctx context.Context, opts policy.TrustStore) trustFacts {
	var f trustFacts
	if opts.CAs {
		f.Certs = linuxAnchors(linuxAnchorDirs)
	}
	if opts.Proxies {
		if _, err := exec.LookPath("gsettings"); err == nil {
			get := func(schema, key string) string {
				out, err := sysx.Run(ctx, "gsettings", "get", schema, key)
				if err != nil {
					return ""
				}
				return out
			}
			f.Proxies = gnomeProxies(get)
		}
	}
	return f
}
