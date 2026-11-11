package checks

import (
	"context"
	"errors"
	"slices"
	"strconv"
	"strings"

	"github.com/ptrinh/bordercheck/internal/check"
	"github.com/ptrinh/bordercheck/internal/msg"
	"github.com/ptrinh/bordercheck/internal/policy"
)

// The os-protections check looks at the defences the OS ships with: System
// Integrity Protection and Gatekeeper on macOS; Defender (or another
// antivirus), SmartScreen and Secure Boot on Windows; Secure Boot and AppArmor
// or SELinux on Linux. XProtect's updates are judged by os-updates ("Install
// Security Responses and system files").

type protFacts struct {
	Family string // "macos", "windows" or "linux"

	SIP        string // "enabled", "disabled", "custom"; "" unknown
	Gatekeeper *bool

	DefenderKnown bool   // Get-MpComputerStatus answered
	DefenderRTP   bool   // real-time protection on
	DefenderMode  string // AMRunningMode: "Normal", "Passive Mode", "EDR Block Mode"…
	Tamper        *bool
	OtherAV       []string // other antivirus products Security Center reports as on
	AVKnown       bool     // Security Center answered
	DefenderSCOn  bool     // Security Center reports Defender as on
	SmartScreen   *bool

	SecureBoot *bool
	NoUEFI     bool // legacy BIOS: no Secure Boot at all

	SELinux  string // "enforcing", "permissive"; "" not active
	AppArmor bool
	WSL      bool // Windows Subsystem for Linux: nothing here applies

	Notes msg.Text
}

func osProtections(opts policy.OSProtections) func(context.Context) check.Result {
	return func(ctx context.Context) check.Result {
		f, err := protFactsOS(ctx)
		if errors.Is(err, errUnsupported) {
			return unsupported()
		}
		if err != nil {
			return check.Errored(err)
		}
		return evalOSProtections(f, opts)
	}
}

func evalOSProtections(f protFacts, opts policy.OSProtections) check.Result {
	if f.WSL {
		return check.SkippedMsg(msg.Of("prot.wsl"))
	}
	var p issueList
	notes := f.Notes
	var on, evidence []string
	unknown := func(what string) { notes = append(notes, msg.P("prot.note.unknown", "what", what)) }
	judged := 0
	switch f.Family {
	case "macos":
		if opts.SIP {
			switch f.SIP {
			case "":
				unknown("System Integrity Protection")
			case "enabled":
				on = append(on, "System Integrity Protection")
			case "disabled":
				p.add(true, msg.Of("prot.sipOff"), msg.P("prot.fix.sip"))
			default:
				p.add(false, msg.Of("prot.sipPartial"), msg.P("prot.fix.sip"))
			}
			if f.SIP != "" {
				judged++
				evidence = append(evidence, "System Integrity Protection: "+f.SIP)
			}
		}
		if opts.Gatekeeper {
			switch {
			case f.Gatekeeper == nil:
				unknown("Gatekeeper")
			case *f.Gatekeeper:
				on = append(on, "Gatekeeper")
			default:
				p.add(true, msg.Of("prot.gatekeeperOff"), msg.P("prot.fix.gatekeeper"))
			}
			if f.Gatekeeper != nil {
				judged++
				evidence = append(evidence, "Gatekeeper: "+onOff(*f.Gatekeeper))
			}
		}
	case "windows":
		if opts.Antivirus {
			judged += evalWinAV(f, &p, &on, &evidence, &notes)
		}
		if opts.SmartScreen {
			switch {
			case f.SmartScreen == nil:
				unknown("SmartScreen")
			case *f.SmartScreen:
				on = append(on, "SmartScreen")
			default:
				p.add(false, msg.Of("prot.smartscreenOff"), msg.P("prot.fix.smartscreen"))
			}
			if f.SmartScreen != nil {
				judged++
				evidence = append(evidence, "SmartScreen for apps and files: "+onOff(*f.SmartScreen))
			}
		}
	case "linux":
		if opts.LSM {
			judged++
			switch {
			case f.SELinux == "enforcing":
				on = append(on, "SELinux")
				evidence = append(evidence, "SELinux: enforcing")
			case f.AppArmor:
				on = append(on, "AppArmor")
				evidence = append(evidence, "AppArmor: enabled")
			case f.SELinux == "permissive":
				evidence = append(evidence, "SELinux: permissive")
				p.add(false, msg.Of("prot.selinuxPermissive"), msg.P("prot.fix.selinux"))
			default:
				evidence = append(evidence, "AppArmor and SELinux: not active")
				p.add(false, msg.Of("prot.noLSM"), msg.P("prot.fix.lsm"))
			}
		}
	}
	if opts.SecureBoot && (f.Family == "windows" || f.Family == "linux") {
		switch {
		case f.NoUEFI:
			notes = append(notes, msg.P("prot.note.noUEFI"))
		case f.SecureBoot == nil:
			unknown("Secure Boot")
		case *f.SecureBoot:
			on = append(on, "Secure Boot")
		default:
			fix := msg.P("prot.fix.secureBoot.linux")
			if f.Family == "windows" {
				fix = msg.P("prot.fix.secureBoot.windows")
			}
			p.add(false, msg.Of("prot.secureBootOff"), fix)
		}
		if f.SecureBoot != nil {
			judged++
			evidence = append(evidence, "Secure Boot: "+onOff(*f.SecureBoot))
		}
	}
	if judged == 0 && len(p.high)+len(p.medium) == 0 {
		if len(notes) == 0 {
			return check.SkippedMsg(msg.Of("prot.nothing"))
		}
		return check.Result{Status: check.Error, Evidence: evidence}.WithSummary(notes)
	}
	var pass msg.Text
	if len(on) > 0 {
		pass = msg.Of("prot.pass", "list", strings.Join(on, ", "))
	}
	return p.result(pass, notes, evidence)
}

// evalWinAV judges Defender and other antivirus; it returns 1 if it could tell.
func evalWinAV(f protFacts, p *issueList, on, evidence *[]string, notes *msg.Text) int {
	defenderActive := f.DefenderKnown && f.DefenderRTP && !strings.Contains(strings.ToLower(f.DefenderMode), "passive") ||
		!f.DefenderKnown && f.DefenderSCOn
	if f.DefenderKnown {
		*evidence = append(*evidence, "Microsoft Defender real-time protection: "+onOff(f.DefenderRTP))
		if f.DefenderMode != "" {
			*evidence = append(*evidence, "Microsoft Defender mode: "+f.DefenderMode)
		}
	}
	if len(f.OtherAV) > 0 {
		*evidence = append(*evidence, "other antivirus on: "+strings.Join(f.OtherAV, ", "))
	}
	switch {
	case defenderActive:
		*on = append(*on, "Microsoft Defender")
		if f.Tamper != nil {
			*evidence = append(*evidence, "tamper protection: "+onOff(*f.Tamper))
			if !*f.Tamper {
				p.add(false, msg.Of("prot.tamperOff"), msg.P("prot.fix.tamper"))
			}
		}
	case len(f.OtherAV) > 0:
		*on = append(*on, strings.Join(f.OtherAV, ", "))
	case f.DefenderKnown || f.AVKnown:
		p.add(true, msg.Of("prot.avOff"), msg.P("prot.fix.av"))
	default:
		*notes = append(*notes, msg.P("prot.note.unknown", "what", "antivirus"))
		return 0
	}
	return 1
}

// ---- macOS ----

// parseCsrutil reads `csrutil status`.
func parseCsrutil(out string) string {
	line := firstLine(out)
	switch {
	case strings.Contains(line, "status: enabled"):
		return "enabled"
	case strings.Contains(line, "status: disabled"):
		return "disabled"
	case strings.Contains(line, "Custom Configuration"), strings.Contains(line, "unknown"):
		return "custom"
	}
	return ""
}

// parseSpctlStatus reads `spctl --status`: "assessments enabled" or
// "assessments disabled".
func parseSpctlStatus(out string) *bool {
	switch {
	case strings.Contains(out, "assessments enabled"):
		return protBool(true)
	case strings.Contains(out, "assessments disabled"):
		return protBool(false)
	}
	return nil
}

// ---- Windows ----

// winProtScript prints Defender's state, the antivirus products Security
// Center knows (not on Windows Server), SmartScreen's setting and policy, and
// Secure Boot's state from the registry (Confirm-SecureBootUEFI needs admin).
const winProtScript = `$ErrorActionPreference = 'SilentlyContinue'
$m = Get-MpComputerStatus
if ($m) { "defender=1"; "rtp=$($m.RealTimeProtectionEnabled)"; "mode=$($m.AMRunningMode)"; "tamper=$($m.IsTamperProtected)" }
$av = Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntiVirusProduct
if ($?) { "sc=1" }
foreach ($a in $av) { "av=$($a.productState)|$($a.displayName)" }
"smartscreen=$((Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer').SmartScreenEnabled)"
"smartscreen_policy=$((Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System').EnableSmartScreen)"
"secureboot=$((Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot\State').UEFISecureBootEnabled)"
"firmware=$env:firmware_type"`

// winProtFacts reads winProtScript's output. Its av= lines are repeated, so
// they are read here rather than through kvLines.
func winProtFacts(out string) protFacts {
	f := protFacts{Family: "windows"}
	kv := kvLines(out)
	if kv["defender"] == "1" {
		f.DefenderKnown = true
		f.DefenderRTP = strings.EqualFold(kv["rtp"], "True")
		f.DefenderMode = kv["mode"]
		if t := kv["tamper"]; t != "" {
			f.Tamper = protBool(strings.EqualFold(t, "True"))
		}
	}
	f.AVKnown = kv["sc"] == "1"
	for _, line := range strings.Split(out, "\n") {
		v, ok := strings.CutPrefix(strings.TrimSpace(line), "av=")
		if !ok {
			continue
		}
		state, name, _ := strings.Cut(v, "|")
		if strings.Contains(strings.ToLower(name), "windows defender") || strings.Contains(strings.ToLower(name), "microsoft defender") {
			f.DefenderSCOn = f.DefenderSCOn || avProductOn(state)
			continue
		}
		if avProductOn(state) && !slices.Contains(f.OtherAV, name) {
			f.OtherAV = append(f.OtherAV, name)
		}
	}
	switch pol, set := kv["smartscreen_policy"], kv["smartscreen"]; {
	case pol == "0":
		f.SmartScreen = protBool(false)
	case pol == "1":
		f.SmartScreen = protBool(true)
	case strings.EqualFold(set, "Off"):
		f.SmartScreen = protBool(false)
	default: // Warn, RequireAdmin, Prompt, or unset: on
		f.SmartScreen = protBool(true)
	}
	switch kv["secureboot"] {
	case "1":
		f.SecureBoot = protBool(true)
	case "0":
		f.SecureBoot = protBool(false)
	default:
		f.NoUEFI = strings.EqualFold(kv["firmware"], "Legacy")
	}
	return f
}

// avProductOn decodes Security Center's productState: bits 12-15 are 1 when
// the product's real-time scanning is on (0x061100 on, 0x060100 off).
func avProductOn(state string) bool {
	n, err := strconv.Atoi(strings.TrimSpace(state))
	return err == nil && (n>>12)&0xF == 1
}

// ---- Linux ----

// efiSecureBoot reads the SecureBoot EFI variable from efivarfs: four bytes of
// attributes, then 1 (on) or 0 (off).
func efiSecureBoot(b []byte) *bool {
	if len(b) < 5 {
		return nil
	}
	return protBool(b[4] == 1)
}

// parseMokutilSB reads `mokutil --sb-state`.
func parseMokutilSB(out string) *bool {
	switch {
	case strings.Contains(out, "SecureBoot enabled"):
		return protBool(true)
	case strings.Contains(out, "SecureBoot disabled"):
		return protBool(false)
	}
	return nil
}

// selinuxMode reads /sys/fs/selinux/enforce ("" when SELinux is not active).
func selinuxMode(enforce string, present bool) string {
	if !present {
		return ""
	}
	if strings.TrimSpace(enforce) == "1" {
		return "enforcing"
	}
	return "permissive"
}

// protBool returns a pointer to b.
func protBool(b bool) *bool { return &b }
