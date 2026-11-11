package checks

import (
	"context"
	"strings"

	"github.com/ptrinh/bordercheck/internal/policy"
	"github.com/ptrinh/bordercheck/internal/sysx"
)

// trustFactsOS reads the user and admin trust settings (never the system
// domain, Apple's own roots) and the system proxy. None of these commands
// shows a dialog: trust settings and certificates are not access-controlled.
func trustFactsOS(ctx context.Context, opts policy.TrustStore) trustFacts {
	var f trustFacts
	if opts.CAs {
		read := 0
		var lastErr string
		seen := map[string]bool{}
		for _, d := range []struct {
			args  []string
			where string
		}{
			{nil, "user trust settings"}, {[]string{"-d"}, "admin trust settings"},
		} {
			out, err := sysx.RunCombined(ctx, "/usr/bin/security", append([]string{"dump-trust-settings"}, d.args...)...)
			if err != nil && !strings.Contains(out, "No Trust Settings") {
				lastErr = firstLine(out)
				if lastErr == "" {
					lastErr = err.Error()
				}
				continue
			}
			read++
			for _, e := range parseMacTrustSettings(out) {
				switch {
				case !e.Trusted:
				case e.HostOnly:
					f.HostOnly++
				default:
					for _, c := range macFindCerts(ctx, e.Name, d.where) {
						if c.SHA256 == "" || !seen[c.SHA256] {
							seen[c.SHA256] = true
							f.Certs = append(f.Certs, c)
						}
					}
				}
			}
		}
		if read == 0 {
			f.CAErr = lastErr
		}
	}
	if opts.Proxies {
		out, err := sysx.Run(ctx, "/usr/sbin/scutil", "--proxy")
		if err != nil {
			f.ProxyErr = err.Error()
		} else {
			f.Proxies = parseScutilProxy(out)
		}
	}
	return f
}

// macFindCerts finds the certificates a trust-settings label names, in the
// keychain search list and the System keychain. The label is usually the
// subject's common name; when no certificate matches, the label alone is
// reported.
func macFindCerts(ctx context.Context, name, where string) []trustCert {
	var out []trustCert
	for _, kc := range [][]string{nil, {"/Library/Keychains/System.keychain"}} {
		pemOut, err := sysx.Run(ctx, "/usr/bin/security", append([]string{"find-certificate", "-a", "-c", name, "-p"}, kc...)...)
		if err != nil {
			continue
		}
		for _, c := range certsFromFile([]byte(pemOut), "", where) {
			if c.CN == name && !containsCert(out, c) {
				out = append(out, c)
			}
		}
	}
	if len(out) == 0 {
		out = append(out, trustCert{Name: name, Where: where})
	}
	return out
}

func containsCert(cs []trustCert, c trustCert) bool {
	for _, x := range cs {
		if x.SHA256 == c.SHA256 {
			return true
		}
	}
	return false
}
