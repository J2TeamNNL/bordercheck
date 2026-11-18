package checks

import (
	"fmt"
	"os"
	"strings"

	"github.com/ptrinh/bordercheck/internal/check"
	"github.com/ptrinh/bordercheck/internal/msg"
)

// Besides what starts at login, the startup-items check looks at three things
// malware does to keep working unseen, all quick to read:
//   - Microsoft Defender exclusions so broad that whatever lands there is never
//     scanned (a drive, the temporary or download folders, PowerShell, every .exe);
//   - programs running right now from a temporary or download folder that are
//     not signed (signed installers run from there all the time);
//   - the hosts file sending a bank's, a sign-in page's or a crypto exchange's
//     name to another address (phishing), or blocking security vendors' sites.

// hiddenFacts is what the per-OS code gathers for these.
type hiddenFacts struct {
	ExclusionsRead bool     // Defender's exclusions could be read (Windows needs admin rights on most versions)
	Exclusions     []string // "path C:\Users\me\AppData", "process powershell.exe", "extension .exe"
	Running        []string // unsigned programs running from a temporary or download folder
	HostsPath      string
	Hosts          string
	Getenv         func(string) string // Windows environment, to expand %APPDATA% and the like; nil elsewhere
}

// broadExclusion says why a Defender exclusion opens the machine wide, or "".
// e is "path <p>", "process <name>" or "extension <ext>"; env expands and
// normalises Windows paths as startupEnv does.
func broadExclusion(e string, env startupEnv, getenv func(string) string) string {
	if getenv == nil {
		getenv = func(string) string { return "" }
	}
	dir := func(s string) string {
		x := expandWinEnv(s, getenv)
		if strings.Contains(x, "%") {
			return "" // a variable this machine does not set
		}
		return env.norm(x)
	}
	kind, val, _ := strings.Cut(e, " ")
	v := strings.ToLower(strings.TrimSpace(val))
	switch kind {
	case "extension":
		v = strings.TrimPrefix(v, "*")
		if !strings.HasPrefix(v, ".") {
			v = "." + v
		}
		switch v {
		case ".exe", ".dll", ".scr", ".ps1", ".bat", ".cmd", ".vbs", ".js", ".hta", ".msi", ".com", ".lnk":
			return "every " + v + " file"
		}
	case "process":
		base := v
		if i := strings.LastIndexAny(base, `\/`); i >= 0 {
			base = base[i+1:]
		}
		switch base {
		case "powershell.exe", "pwsh.exe", "cmd.exe", "wscript.exe", "cscript.exe", "mshta.exe", "rundll32.exe",
			"regsvr32.exe", "msiexec.exe", "explorer.exe", "svchost.exe":
			return "everything " + base + " runs"
		}
		if why := env.suspiciousPlace(expandWinEnv(val, getenv)); why != "" {
			return "a program in " + why
		}
	case "path":
		p := strings.TrimSuffix(env.norm(expandWinEnv(val, getenv)), "/")
		home := env.norm(env.home)
		if len(p) <= 3 && strings.HasSuffix(p, ":") || p == "" || p == "/" {
			return "a whole drive"
		}
		for _, d := range []struct{ dir, what string }{
			{dir(`%SystemRoot%`), "the Windows folder"},
			{dir(`%ProgramData%`), "ProgramData"},
			{dir(`%SystemDrive%\Users`), "every user's folder"},
			{home, "your whole user folder"},
			{dir(`%APPDATA%`), "AppData"},
			{dir(`%LOCALAPPDATA%`), "AppData"},
			{dir(`%TEMP%`), "the temporary folder"},
			{dir(`%LOCALAPPDATA%\Temp`), "the temporary folder"},
			{dir(`%SystemRoot%\Temp`), "the temporary folder"},
			{env.norm(env.home + `\Downloads`), "the Downloads folder"},
			{env.norm(env.home + `\Desktop`), "the Desktop"},
			{dir(`%PUBLIC%`), "the Public folder"},
		} {
			if d.dir != "" && d.dir != "/" && p == strings.TrimSuffix(d.dir, "/") {
				return d.what
			}
		}
		if why := env.suspiciousPlace(expandWinEnv(val, getenv)); why != "" && strings.Contains(why, "temporary") {
			return why
		}
	}
	return ""
}

// sensitiveDomains are sites whose sign-in a hosts-file redirect would phish:
// sign-in pages, mail, payments, crypto exchanges, and banks and wallets used
// in Vietnam.
var sensitiveDomains = []string{
	"google.com", "gmail.com", "googleapis.com", "microsoftonline.com", "live.com", "outlook.com", "office.com",
	"microsoft.com", "apple.com", "icloud.com", "facebook.com", "instagram.com", "github.com", "gitlab.com",
	"cloudflare.com", "amazon.com", "aws.amazon.com", "paypal.com", "stripe.com", "shopify.com", "zalo.me",
	"binance.com", "coinbase.com", "okx.com", "bybit.com", "kraken.com", "metamask.io",
	"vietcombank.com.vn", "techcombank.com", "techcombank.com.vn", "vpbank.com.vn", "mbbank.com.vn", "bidv.com.vn",
	"vietinbank.vn", "acb.com.vn", "tpb.vn", "sacombank.com", "sacombank.com.vn", "agribank.com.vn", "vib.com.vn",
	"shb.com.vn", "hdbank.com.vn", "ocb.com.vn", "msb.com.vn", "momo.vn", "zalopay.vn", "vnpay.vn",
}

// securityDomains are security vendors' and scanners' sites; malware blocks
// them so updates and second opinions fail.
var securityDomains = []string{
	"virustotal.com", "malwarebytes.com", "kaspersky.com", "eset.com", "avast.com", "avg.com", "bitdefender.com",
	"norton.com", "mcafee.com", "sophos.com", "trendmicro.com", "f-secure.com", "hitmanpro.com", "objective-see.org",
	"wdcp.microsoft.com", "wdcpalt.microsoft.com", "definitionupdates.microsoft.com", "smartscreen.microsoft.com",
	"smartscreen-prod.microsoft.com", "checkappexec.microsoft.com", "windowsdefender.com",
}

func underDomain(name string, ds []string) string {
	n := strings.TrimSuffix(strings.ToLower(name), ".")
	for _, d := range ds {
		if n == d || strings.HasSuffix(n, "."+d) {
			return d
		}
	}
	return ""
}

// hostsHijacks reads a hosts file: names of sensitive sites sent to another
// address (redirects), and security sites sent nowhere (blocks).
func hostsHijacks(hosts string) (redirects, blocks []string) {
	for _, line := range strings.Split(hosts, "\n") {
		if i := strings.IndexByte(line, '#'); i >= 0 {
			line = line[:i]
		}
		f := strings.Fields(line)
		if len(f) < 2 {
			continue
		}
		addr := f[0]
		for _, name := range f[1:] {
			switch {
			case blockingAddr(addr):
				if underDomain(name, securityDomains) != "" {
					blocks = append(blocks, name)
				}
			default:
				if underDomain(name, sensitiveDomains) != "" {
					redirects = append(redirects, name+" → "+addr)
				}
			}
		}
	}
	return uniqSorted(redirects), uniqSorted(blocks)
}

// hiddenFindings is what evalStartup adds for hiddenFacts.
type hiddenFindings struct {
	high, medium []string
	compromise   []check.Indicator
	parts, fix   msg.Text
}

func evalHidden(x hiddenFacts, env startupEnv) hiddenFindings {
	var h hiddenFindings
	n := 0
	for _, e := range x.Exclusions {
		if why := broadExclusion(e, env, x.Getenv); why != "" {
			n++
			line := fmt.Sprintf("Microsoft Defender exclusion %s: %s is never scanned", e, why)
			h.high = append(h.high, line)
			h.compromise = append(h.compromise, check.Indicator{What: msg.P("compromise.defenderExclusion"), Detail: e})
		}
	}
	if n > 0 {
		h.parts = append(h.parts, msg.P("startup.defenderExclusion", "n", n))
		h.fix = append(h.fix, msg.P("startup.fix.defenderExclusion"))
	}
	redirects, blocks := hostsHijacks(x.Hosts)
	for _, r := range redirects {
		h.high = append(h.high, fmt.Sprintf("%s sends %s", x.HostsPath, r))
		h.compromise = append(h.compromise, check.Indicator{What: msg.P("compromise.hostsRedirect"), Detail: r})
	}
	for _, b := range blocks {
		h.high = append(h.high, fmt.Sprintf("%s blocks %s", x.HostsPath, b))
		h.compromise = append(h.compromise, check.Indicator{What: msg.P("compromise.securityBlocked"), Detail: b})
	}
	if len(redirects) > 0 {
		h.parts = append(h.parts, msg.P("startup.hostsRedirect", "n", len(redirects)))
	}
	if len(blocks) > 0 {
		h.parts = append(h.parts, msg.P("startup.securityBlocked", "n", len(blocks)))
	}
	if len(redirects)+len(blocks) > 0 {
		h.fix = append(h.fix, msg.P("startup.fix.hosts", "path", x.HostsPath))
	}
	self, _ := os.Executable()
	var running []string
	for _, p := range uniqSorted(x.Running) {
		if !strings.EqualFold(p, self) { // a copy of BorderCheck run from Downloads or a build folder
			running = append(running, p)
		}
	}
	for _, p := range running {
		what := "not signed by a known developer, from "
		if env.goos == "linux" {
			what = "from "
		}
		h.medium = append(h.medium, fmt.Sprintf("running now: %s  %s%s", tildePath(env.home, p), what, orUnknown(env.suspiciousPlace(p))))
	}
	if len(running) > 0 {
		key := "startup.unsignedRunning"
		if env.goos == "linux" {
			key = "startup.tempRunning"
		}
		h.parts = append(h.parts, msg.P(key, "n", len(running)))
		h.fix = append(h.fix, msg.P("startup.fix.unsignedRunning"))
	}
	return h
}

// parseHiddenScan reads winHiddenScript's lines (portable, so it is tested everywhere).
func parseHiddenScan(out string) (exclusions []string, read bool, running []string) {
	read = true
	for _, line := range strings.Split(out, "\n") {
		f := strings.Split(strings.TrimRight(line, "\r"), "\t")
		switch {
		case len(f) == 2 && f[0] == "excl" && f[1] == "na":
			read = false
		case len(f) == 3 && f[0] == "excl" && f[2] != "":
			exclusions = append(exclusions, f[1]+" "+f[2])
		case len(f) == 2 && f[0] == "proc" && f[1] != "":
			running = append(running, f[1])
		}
	}
	return exclusions, read, running
}
