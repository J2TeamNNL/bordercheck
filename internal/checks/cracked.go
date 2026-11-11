package checks

import (
	"context"
	"fmt"
	"net"
	"os"
	"slices"
	"sort"
	"strings"

	"github.com/ptrinh/bordercheck/internal/check"
	"github.com/ptrinh/bordercheck/internal/msg"
	"github.com/ptrinh/bordercheck/internal/policy"
)

// The cracked-software check looks for the traces that cracks of paid software
// leave behind. Cracked installers are a common way to spread malware
// (information stealers above all), so any trace fails high. It only reads:
// the hosts file, on Windows the activation settings in the registry, and
// whether well-known crack tools are installed. It never lists installed
// software or goes online.

// crackFacts is what the per-OS code gathers.
type crackFacts struct {
	HostsPath string            // the hosts file, as shown
	Hosts     string            // its contents; "" if unreadable
	KMS       map[string]string // "Windows" / "Microsoft Office" → KeyManagementServiceName
	Tools     []string          // crack tools found: "KMSpico (C:\Program Files\KMSpico)"
}

// crackHost marks a vendor's licensing or activation servers. A crack blocks
// them in the hosts file so the product can't find out it is not licensed.
type crackHost struct {
	vendor string
	domain string   // the vendor's domain; subdomains match
	words  []string // a blocked name counts only if it holds one of these; nil = any name under domain
	exact  []string // licensing hosts whose names hold none of the words
}

var crackHosts = []crackHost{
	{vendor: "Adobe", domain: "adobegenuine.com"},
	{vendor: "Adobe", domain: "adobe.com", words: []string{"activat", "licens", "genuine", "3dns"},
		exact: []string{"na1r.services.adobe.com", "hlrcv.stage.adobe.com"}},
	{vendor: "Adobe", domain: "adobe.io", words: []string{"activat", "licens", "genuine"}, exact: []string{"ic.adobe.io"}},
	{vendor: "Autodesk", domain: "autodesk.com", words: []string{"activat", "licens", "genuine"}},
}

// blockingAddr reports whether a hosts-file address sends traffic nowhere.
func blockingAddr(a string) bool {
	if a == "0.0.0.0" || a == "::" {
		return true
	}
	ip := net.ParseIP(a)
	return ip != nil && ip.IsLoopback()
}

// crackHostVendor returns the vendor whose licensing server name is, or "".
func crackHostVendor(name string) string {
	name = strings.TrimSuffix(strings.ToLower(name), ".")
	for _, h := range crackHosts {
		if name != h.domain && !strings.HasSuffix(name, "."+h.domain) {
			continue
		}
		if h.words == nil || slices.Contains(h.exact, name) {
			return h.vendor
		}
		sub := strings.TrimSuffix(name, h.domain)
		for _, w := range h.words {
			if strings.Contains(sub, w) {
				return h.vendor
			}
		}
	}
	return ""
}

// parseCrackHosts returns the vendor licensing servers a hosts file blocks,
// keyed by vendor.
func parseCrackHosts(hosts string) map[string][]string {
	out := map[string][]string{}
	for _, line := range strings.Split(hosts, "\n") {
		line, _, _ = strings.Cut(line, "#")
		f := strings.Fields(line)
		if len(f) < 2 || !blockingAddr(f[0]) {
			continue
		}
		for _, name := range f[1:] {
			if v := crackHostVendor(name); v != "" && !slices.Contains(out[v], strings.ToLower(name)) {
				out[v] = append(out[v], strings.ToLower(name))
			}
		}
	}
	return out
}

// kmsEmulated reports whether a KMS server setting points at this machine,
// where only a KMS emulator (KMSpico, KMS_VL_ALL, KMSAuto…) would answer. A
// company's own KMS server is a real host on its network and passes.
func kmsEmulated(server string) bool {
	host := strings.TrimSpace(server)
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	} else if i := strings.LastIndex(host, ":"); i > 0 && !strings.Contains(host[:i], ":") {
		host = host[:i] // "127.0.0.2:1688"
	}
	host = strings.Trim(strings.ToLower(host), "[]")
	return host == "localhost" || blockingAddr(host)
}

// crackAlternatives are free, open-source replacements from ArtCraft
// (getartcraft.com), by the vendor whose product was cracked.
var crackAlternatives = map[string]string{
	"Adobe":            "cracked.alt.adobe",
	"Microsoft Office": "cracked.alt.office",
	"Autodesk":         "cracked.alt.autodesk",
}

func evalCracked(f crackFacts, opts policy.CrackedSoftware) check.Result {
	var ev []string
	vendors := map[string]bool{}
	blocked := parseCrackHosts(f.Hosts)
	names := make([]string, 0, len(blocked))
	for v := range blocked {
		names = append(names, v)
	}
	sort.Strings(names)
	for _, v := range names {
		vendors[v] = true
		hs := blocked[v]
		shown := strings.Join(hs, ", ")
		if len(hs) > 3 {
			shown = strings.Join(hs[:3], ", ") + fmt.Sprintf(" and %d more", len(hs)-3)
		}
		ev = append(ev, fmt.Sprintf("%s blocks %s licensing servers: %s", f.HostsPath, v, shown))
	}
	// Signs of compromise are only the strongest traces: a KMS emulator this
	// machine activates against, and an installed crack tool. Both are
	// programs from the crack scene running with the system's rights, and the
	// usual carriers of bundled malware. A hosts-file line is not one: it
	// blocks a licence check, but runs nothing.
	var compromise []check.Indicator
	for _, product := range []string{"Windows", "Microsoft Office"} {
		if s := f.KMS[product]; s != "" && kmsEmulated(s) {
			vendors[product] = true
			ev = append(ev, fmt.Sprintf("%s activates against a KMS server on this machine (%s): a KMS emulator", product, s))
			compromise = append(compromise, check.Indicator{What: msg.P("compromise.kmsEmulator", "product", product), Detail: s})
		}
	}
	for _, t := range f.Tools {
		vendors["Windows"], vendors["Microsoft Office"] = true, true // these tools activate both
		ev = append(ev, "crack tool installed: "+t)
		compromise = append(compromise, check.Indicator{What: msg.P("compromise.crackTool"), Detail: t})
	}
	if len(ev) == 0 {
		return check.Result{Status: check.Pass}.WithSummary(msg.Of("cracked.pass"))
	}
	var what []string
	for _, v := range []string{"Adobe", "Autodesk", "Microsoft Office", "Windows"} {
		if vendors[v] {
			what = append(what, v)
		}
	}
	return check.Result{Status: check.Fail, Severity: check.High, Evidence: ev, Compromise: compromise}.
		WithSummary(msg.Of("cracked.found", "products", strings.Join(what, ", "))).
		WithFix(crackFix(vendors, opts.SuggestAlternatives))
}

func crackFix(vendors map[string]bool, alternatives bool) msg.Text {
	var alts msg.Text
	for _, v := range []string{"Adobe", "Microsoft Office", "Autodesk"} {
		if a := crackAlternatives[v]; vendors[v] && a != "" {
			alts = append(alts, msg.P(a))
		}
	}
	if !alternatives || len(alts) == 0 {
		return msg.Of("cracked.fix")
	}
	return append(msg.Of("cracked.fixAlternatives"), alts...)
}

func crackedSoftware(opts policy.CrackedSoftware) func(context.Context) check.Result {
	return func(ctx context.Context) check.Result {
		f := crackFactsOS(ctx)
		if f.HostsPath != "" {
			if b, err := os.ReadFile(f.HostsPath); err == nil {
				f.Hosts = string(b)
			}
		}
		return evalCracked(f, opts)
	}
}
