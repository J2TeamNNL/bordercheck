package msg

// Entry is the English for one key. One, when set, makes it plural on {n}.
type Entry struct {
	One   string `json:"one,omitempty"`
	Other string `json:"other"`
}

func s(text string) Entry        { return Entry{Other: text} }
func pl(one, other string) Entry { return Entry{One: one, Other: other} }

// Catalog is every message a check can put in a summary or fix, in English.
// Menu paths and setting names are written as the English OS shows them;
// commands go in [code]. See the package comment for the syntax, and
// receiver/README.md for how a new key reaches the portal's translations.
var Catalog = map[string]Entry{
	// ---- Any check ----
	"check.unsupported": s("Not supported on {os} yet."),
	"check.timeout":     s("Did not finish within {after:dur} and was stopped; the other checks are unaffected."),
	"check.interrupted": s("Interrupted before it finished."),
	"check.moreAllowed": s("{n} more allowed by policy."),

	// ---- Signs of compromise (check.Indicator): what was found, without the item ----
	"compromise.startupDownloadRun": s("A program set to start automatically downloads code from the internet and runs it."),
	"compromise.blockedExtension":   s("An extension your organisation has blocked as harmful is installed."),
	"compromise.crackTool":          s("A software crack or activation tool is installed."),
	"compromise.kmsEmulator":        s("{product} is activated by a fake activation server running on this computer."),

	// ---- What the person at the machine ignored (bordercheck ignore): secrets, ai-agents, ssh-keys ----
	"ignore.more": pl("1 more ignored by you.", "{n} more ignored by you."),
	"ignore.all": pl("The only finding is one you marked as not sensitive.",
		"The only findings are {n} you marked as not sensitive."),
	"ignore.off": s("This computer's policy does not allow ignoring findings of this check, so your list is not applied to it."),
	"ignore.unreadable": s("Your list of ignored findings could not be read, so nothing is ignored; " +
		"run [code]bordercheck ignore -list[/code]."),

	// ---- firewall: macOS ----
	"firewall.mac.off": s("The macOS firewall is off."),
	"firewall.mac.off.fix": s("System Settings → Network → Firewall → turn it on. " +
		"Or: [code]sudo /usr/libexec/ApplicationFirewall/socketfilterfw --setglobalstate on[/code]"),
	"firewall.mac.stealthOff": s("The firewall is on, but stealth mode is off: this Mac answers probes from the network."),
	"firewall.mac.stealthOff.fix": s("System Settings → Network → Firewall → Options → turn on stealth mode. " +
		"Or: [code]sudo /usr/libexec/ApplicationFirewall/socketfilterfw --setstealthmode on[/code]"),
	"firewall.mac.on":        s("Firewall is on."),
	"firewall.mac.onStealth": s("Firewall and stealth mode are on."),

	// ---- firewall: Windows ----
	"firewall.win.noProfiles": s("Windows reported no firewall profiles"),
	"firewall.win.on":         s("Windows Firewall is on for every profile."),
	"firewall.win.off":        s("Windows Firewall is off for: {profiles}."),
	"firewall.win.off.fix": s("Windows Security → Firewall & network protection → turn it on for every network. " +
		"Or, as administrator: [code]Set-NetFirewallProfile -All -Enabled True[/code]"),

	// ---- firewall: Linux ----
	"firewall.linux.zoneOpenPorts": s("firewalld is on, but its default zone {zone} lets in every port from 1025 to 65535."),
	"firewall.linux.zoneTrusted":   s("firewalld is on, but its default zone {zone} lets everything in."),
	"firewall.linux.zone.fix": s("[code]sudo firewall-cmd --set-default-zone=public[/code] (allows SSH and DHCPv6 only); " +
		"open what you need with [code]--add-service[/code]."),
	"firewall.linux.firewalldOn":     s("firewalld is on."),
	"firewall.linux.firewalldOnZone": s("firewalld is on (default zone {zone})."),
	"firewall.linux.ufwOn":           s("ufw is on."),
	"firewall.linux.ufwOnConf":       s("ufw is on (enabled in /etc/ufw/ufw.conf)."),
	"firewall.linux.inputDrops":      s("The firewall drops incoming connections by default (input policy)."),
	"firewall.linux.noDrop":          s("No firewall drops incoming connections: no nftables or iptables input chain defaults to drop."),
	"firewall.linux.fix": s("Ubuntu/Debian: [code]sudo ufw enable[/code] (it blocks incoming connections and allows outgoing). " +
		"Fedora/RHEL/openSUSE: [code]sudo systemctl enable --now firewalld[/code]."),
	"firewall.linux.rootOnly": s("The {services} service loads firewall rules, but they can only be read as root, so bordercheck " +
		"cannot tell whether they block incoming connections. Run [code]sudo bordercheck -only firewall[/code] to check them."),
	"firewall.linux.unknown": s("Could not tell without root: there is no ufw configuration and systemd did not say which " +
		"firewall services run. Run [code]sudo bordercheck -only firewall[/code] to check the rules."),
	"firewall.linux.noneUfwOff": s("No firewall is on: ufw is installed but off, and no firewalld, nftables or iptables " +
		"service is running. (If you load rules some other way, [code]sudo bordercheck -only firewall[/code] checks them.)"),
	"firewall.linux.noneNoUfw": s("No firewall is on: ufw is not installed, and no firewalld, nftables or iptables " +
		"service is running. (If you load rules some other way, [code]sudo bordercheck -only firewall[/code] checks them.)"),

	// ---- firewall: outbound filtering (macOS, Windows) ----
	"outbound.found":       s("Outgoing connections are filtered by {apps}."),
	"outbound.found.winFw": s("Windows Firewall blocks outgoing connections by default."),
	"outbound.none.mac":    s("No outbound firewall (such as LuLu or Little Snitch) controls which apps connect out."),
	"outbound.none.win": s("No outbound firewall (such as simplewall, or Windows Firewall blocking outgoing connections " +
		"by default) controls which apps connect out."),
	"outbound.fix.mac": s("Install a free outbound firewall such as LuLu from Objective-See " +
		"(https://objective-see.org/products/lulu.html, open source): it asks before an app connects out, " +
		"so malware phoning home or a program sending your data somewhere shows up."),
	"outbound.fix.win": s("Install simplewall (https://github.com/henrypp/simplewall, free and open source). Once its filters " +
		"are enabled it blocks every app you have not allowed, so it will ask you to allow each app the first " +
		"time it connects; then malware phoning home or a program sending your data somewhere shows up. " +
		"Or ask IT to set Windows Firewall to block outgoing connections by default."),

	// ---- disk-encryption ----
	"disk.mac.on":      s("FileVault is on."),
	"disk.mac.off":     s("FileVault is off: anyone who takes this Mac can read its disk."),
	"disk.mac.off.fix": s("System Settings → Privacy & Security → FileVault → Turn On."),
	"disk.mac.partial": s("FileVault is not fully on: {status}"),
	"disk.win.on":      s("BitLocker is on for the system drive."),
	"disk.win.off":     s("BitLocker is off: anyone who takes this PC can read its disk."),
	"disk.win.unknown": s("Windows did not report BitLocker status for the system drive."),
	"disk.win.partial": s("BitLocker is not fully on for the system drive (status {code})."),
	"disk.win.fix": s("Settings → Privacy & security → Device encryption, or Control Panel → BitLocker Drive Encryption → " +
		"turn on."),
	"disk.linux.noRoot":    s("Could not find the root filesystem in /proc/self/mounts."),
	"disk.linux.plain":     s("{mount} is not on an encrypted disk: anyone who takes this machine can read it."),
	"disk.linux.plainBoth": s("{mount} and {other} are not on an encrypted disk: anyone who takes this machine can read them."),
	"disk.linux.plain.fix": s("Linux cannot easily encrypt a disk in use: back up, reinstall and choose \"Encrypt the new " +
		"installation\" (LUKS), then restore. Experts: [code]cryptsetup reencrypt --encrypt[/code] from a live USB."),
	"disk.linux.unknown":        s("Could not tell whether the disk is encrypted."),
	"disk.linux.unknownZFS":     s("{mount}: ZFS, encryption unknown."),
	"disk.linux.unknownVirtual": s("{mount}: {fstype}, a live system or container."),
	"disk.linux.unknownDevice":  s("{mount}: could not find the device under {source}."),
	"disk.linux.onLUKS":         s("The disk is encrypted (LUKS / dm-crypt)."),
	"disk.linux.onZFS":          s("The disk is encrypted (ZFS native encryption)."),

	// ---- listeners ----
	"listeners.pass": pl("1 listening socket, on localhost.", "{n} listening sockets, all on localhost."),
	"listeners.exposed": pl("1 port can be reached from other machines (LAN, Wi-Fi, Tailscale).",
		"{n} ports can be reached from other machines (LAN, Wi-Fi, Tailscale)."),
	"listeners.fix": s("Bind dev servers to 127.0.0.1 (Vite: drop [code]--host[/code]; Docker: " +
		"[code]-p 127.0.0.1:PORT:PORT[/code]) and quit what you don't need. To share something, use a Cloudflare " +
		"Tunnel instead of an open port."),
	"listeners.note.mac":       s("Only your own processes are visible; run with sudo to include system services."),
	"listeners.note.linux":     s("Process names are shown only for your own processes; run with sudo to name system services."),
	"listeners.note.linuxNoSS": s("ss was not found, so process names are unknown."),

	// ---- tailscale ----
	"tailscale.notInstalled": s("Tailscale is not installed."),
	"tailscale.denied": s("Only root or the Tailscale operator may read Tailscale's settings here. Run " +
		"[code]sudo tailscale set --operator=$USER[/code] once, or [code]sudo bordercheck -only tailscale[/code]. ({err})"),
	"tailscale.unreadable": s("Could not read Tailscale settings; is Tailscale running? ({err})"),
	"tailscale.badPrefs":   s("unexpected output from `tailscale debug prefs`"),
	"tailscale.shieldsUp":  s("Shields up: other devices on the tailnet cannot open connections to this machine."),
	"tailscale.open": s("Tailscale accepts incoming connections. Tailscale traffic may bypass the OS firewall, so any " +
		"device on the tailnet, including a hacked one, can reach every port this machine listens on."),
	"tailscale.open.fix": s("Tailscale → Settings → untick \"Allow incoming connections\". " +
		"Or: [code]tailscale set --shields-up[/code]. Admins: also limit who can reach whom with tailnet ACLs."),

	// ---- docker ----
	"docker.notInstalled": s("Docker is not installed."),
	"docker.noPermission": s("Docker is installed, but this user may not use it (not in the docker group), so its " +
		"containers were not checked."),
	"docker.notRunning":   s("Docker is not running."),
	"docker.noContainers": s("No running containers."),
	"docker.pass":         pl("1 running container, isolated.", "{n} running containers, all isolated."),
	"docker.problems": pl("1 problem in {containers} running container(s).",
		"{n} problems in {containers} running container(s)."),
	"docker.fix": s("Publish ports on localhost only ([code]-p 127.0.0.1:5432:5432[/code]). Don't use " +
		"[code]--network host[/code] or [code]--privileged[/code]. Mount only the project folder, never the Docker " +
		"socket, your home folder or credential folders."),

	// ---- secrets ----
	"secrets.pass":  s("No plain-text secrets in shell files, shell history, credential files or .env files."),
	"secrets.found": pl("1 secret in plain text across {files} file(s).", "{n} secrets in plain text across {files} file(s)."),
	"secrets.foundProd": pl("1 secret in plain text across {files} file(s), {prod} marked production.",
		"{n} secrets in plain text across {files} file(s), {prod} marked production."),
	"secrets.incomplete": s("The scan hit its time limit, so some folders were not checked."),
	"secrets.fix.mac": s("Move each key into the Keychain behind Touch ID with touchenv " +
		"(https://github.com/ptrinh/touch-env): [code]touchenv set NAME[/code], then delete the line or file."),
	"secrets.fix.win": s("Move each key into Windows Credential Manager or a password manager CLI (e.g. 1Password " +
		"[code]op run[/code]), then delete the line or file."),
	"secrets.fix.linux": s("Move each key into the desktop keyring ([code]secret-tool store[/code] / " +
		"[code]secret-tool lookup[/code], from libsecret) or a password manager CLI such as pass or 1Password " +
		"[code]op run[/code], then delete the line or file."),
	"secrets.fix.other": s("Move each key into a password manager or the OS keyring, then delete the line or file."),
	"secrets.fix.rotate": s("For a key in shell history, deleting those lines is enough. Rotate a key only if there is " +
		"evidence that this computer was compromised."),

	// ---- os-updates: problems ----
	"updates.belowMin":           s("{os} is older than the minimum version {min} set by policy."),
	"updates.belowMinWin":        s("{os} is older than the minimum version build {min} set by policy."),
	"updates.autoUnknown":        s("Could not tell whether automatic updates are on."),
	"updates.autoOff.mac":        s("Automatic updates are off ({settings})."),
	"updates.autoOff.win":        s("Automatic updates are off."),
	"updates.autoOff.winService": s("The Windows Update service is disabled."),
	"updates.autoOff.winPolicy":  s("A policy turns automatic updates off."),
	"updates.autoOff.winNotify":  s("A policy only notifies about updates."),
	"updates.autoOff.apt":        s("Automatic updates are off (unattended-upgrades is not installed or not enabled)."),
	"updates.autoOff.dnf": s("Automatic updates are off (no dnf-automatic timer is enabled and GNOME Software does not " +
		"download updates)."),
	"updates.paused":       s("Updates are paused until {until:date}."),
	"updates.checkStale":   s("The OS last checked for updates {ago:ago} (policy: every {max} days)."),
	"updates.waitingLong":  s("{name} has been waiting to be installed for {days} days (policy: {max})."),
	"updates.ready":        s("{name} is ready to install (found {ago:ago})."),
	"updates.readyUndated": s("{name} is ready to install."),
	"updates.countWaitingLong": pl("1 update is waiting and nothing has been installed for {days} days (policy: {max}).",
		"{n} updates are waiting and nothing has been installed for {days} days (policy: {max})."),
	"updates.countReady":    pl("1 update is ready to install.", "{n} updates are ready to install."),
	"updates.reboot":        s("Updates are installed but need a restart to take effect."),
	"updates.noneInstalled": s("No OS update has been installed for {days} days (policy: {max})."),
	"updates.browserStale": s("{browser} has not updated for {days} days (policy: {max}); browsers ship security fixes " +
		"every few weeks."),
	"updates.browserBelowMin": s("{browser} {version} is older than the minimum {min} set by policy."),
	// Notes the OS side adds.
	"updates.note.macSettings":    s("Could not read Software Update's settings."),
	"updates.note.winLastInstall": s("Could not read when Windows last installed an update."),
	"updates.note.gnomeSoftware":  s("GNOME Software downloads updates; they install on restart."),
	// ---- os-updates: the state when all is well ----
	"updates.state":            s("{os}."),
	"updates.stateAuto":        s("{os}, automatic updates on."),
	"updates.stateChecked":     s("{os}, last checked for updates {ago:ago}."),
	"updates.stateAutoChecked": s("{os}, automatic updates on, last checked for updates {ago:ago}."),
	"updates.noneWaiting":      s("No updates waiting."),
	"updates.browsersFresh":    pl("1 browser recently updated.", "{n} browsers recently updated."),
	// ---- os-updates: fixes ----
	"updates.fix.browser": s("Open each browser's About page (Chrome/Edge/Brave: Settings → About; Firefox: Help → " +
		"About Firefox) to update it, then relaunch it; uninstall browsers you don't use."),
	"updates.fix.macos.upgrade": s("System Settings → General → Software Update → upgrade to a supported macOS."),
	"updates.fix.macos.auto": s("System Settings → General → Software Update → Automatic updates (i) → turn on Check " +
		"for updates, Download new updates when available and Install Security Responses and system files."),
	"updates.fix.macos.pending": s("System Settings → General → Software Update → Update Now."),
	"updates.fix.macos.check": s("Connect to the internet and open System Settings → General → Software Update so " +
		"macOS checks again."),
	"updates.fix.windows.upgrade": s("Settings → Windows Update → install the latest Windows 11 feature update."),
	"updates.fix.windows.auto": s("Windows Update must run automatically: the Windows Update service (wuauserv) must " +
		"not be Disabled and no policy may turn automatic updates off. If Settings → Windows Update says some " +
		"settings are managed by your organisation, ask IT."),
	"updates.fix.windows.paused":  s("Settings → Windows Update → Resume updates."),
	"updates.fix.windows.pending": s("Settings → Windows Update → Check for updates, install everything, then restart."),
	"updates.fix.windows.check":   s("Settings → Windows Update → Check for updates."),
	"updates.fix.windows.reboot":  s("Restart the PC to finish installing updates."),
	"updates.fix.debian.upgrade":  s("Upgrade to a supported release (Ubuntu: [code]sudo do-release-upgrade[/code])."),
	"updates.fix.debian.auto": s("[code]sudo apt install unattended-upgrades && sudo dpkg-reconfigure -plow " +
		"unattended-upgrades[/code]"),
	"updates.fix.debian.pending": s("[code]sudo apt update && sudo apt full-upgrade[/code]"),
	"updates.fix.debian.check":   s("[code]sudo apt update[/code]"),
	"updates.fix.debian.reboot":  s("Restart to finish installing updates (/var/run/reboot-required is set)."),
	"updates.fix.fedora.upgrade": s("Upgrade to a supported release: [code]sudo dnf system-upgrade[/code] (see the " +
		"Fedora upgrade guide)."),
	"updates.fix.fedora.auto": s("[code]sudo dnf install dnf-automatic[/code], set [code]apply_updates = yes[/code] in " +
		"/etc/dnf/automatic.conf, then [code]sudo systemctl enable --now dnf-automatic.timer[/code] " +
		"(dnf5-automatic.timer on dnf5)."),
	"updates.fix.fedora.pending": s("[code]sudo dnf upgrade --refresh[/code]"),
	"updates.fix.fedora.check":   s("[code]sudo dnf check-update --refresh[/code]"),
	"updates.fix.arch.pending":   s("[code]sudo pacman -Syu[/code]"),
	"updates.fix.generic":        s("Install the latest updates with your distribution's package manager, and restart."),

	// ---- screen-lock ----
	"screenlock.noDesktop":       s("No desktop whose screen lock bordercheck can read (GNOME and KDE Plasma are supported)."),
	"screenlock.unknown":         s("Could not tell whether a password is needed after sleep or when the screen locks."),
	"screenlock.passwordUnknown": s("Could not tell whether a password is needed after sleep."),
	"screenlock.noPassword":      s("No password is needed to get back in after sleep or the screen saver."),
	"screenlock.idleUnknown":     s("Could not tell when the screen locks by itself."),
	"screenlock.never":           s("The screen never locks by itself when the machine is left alone."),
	"screenlock.tooLate":         s("The screen locks only after {after:dur} idle (policy: {max:dur})."),
	"screenlock.passBoth":        s("A password is needed after sleep and the screen locks after {after:dur} idle."),
	"screenlock.passPassword":    s("A password is needed after sleep."),
	"screenlock.passIdle":        s("The screen locks after {after:dur} idle."),
	"screenlock.fix.macos.password": s("System Settings → Lock Screen → \"Require password after screen saver begins " +
		"or display is turned off\" → Immediately."),
	"screenlock.fix.macos.idle": s("System Settings → Lock Screen → set \"Turn display off on battery when inactive\" " +
		"and \"…on power adapter when inactive\" (and \"Start Screen Saver when inactive\", if used) to the policy's " +
		"limit or less."),
	"screenlock.fix.windows.password": s("Settings → Accounts → Sign-in options → \"If you've been away, when should " +
		"Windows require you to sign in again?\" → When PC wakes up from sleep."),
	"screenlock.fix.windows.idle": s("Settings → System → Power & battery → Screen, sleep & hibernate timeouts → put " +
		"the device to sleep within the policy's limit (on battery and plugged in), or Settings → Personalization → " +
		"Lock screen → Screen saver → a short wait with \"On resume, display logon screen\"."),
	"screenlock.fix.gnome.password": s("Settings → Privacy & Security → Screen Lock → turn on Automatic Screen Lock " +
		"and Lock Screen on Suspend, Automatic Screen Lock Delay → Screen Turns Off."),
	"screenlock.fix.gnome.idle": s("Settings → Power → Screen Blank → the policy's limit or less, and Settings → " +
		"Privacy & Security → Screen Lock → Automatic Screen Lock on."),
	"screenlock.fix.kde.password": s("System Settings → Screen Locking → turn on \"After waking from sleep\"."),
	"screenlock.fix.kde.idle": s("System Settings → Screen Locking → \"Lock screen automatically\" after the policy's " +
		"limit or less."),

	// ---- remote-access ----
	"remote.on":             s("{service} is on."),
	"remote.off":            s("Off: {services}."),
	"remote.allowed":        s("On but allowed by policy: {services}."),
	"remote.note.noSystemd": s("Could not read systemd unit states; judged from open ports only."),
	"remote.fix.macSharing": s("System Settings → General → Sharing → turn off {service}."),
	"remote.fix.macGuest": s("System Settings → Users & Groups → Guest User → turn off \"Allow guests to log in to " +
		"this computer\"."),
	"remote.fix.winRDP": s("Settings → System → Remote Desktop → Off (if a policy turned it on, ask IT)."),
	"remote.fix.winRM": s("As administrator: [code]winrm delete winrm/config/Listener?Address=*+Transport=HTTP[/code], " +
		"then [code]Stop-Service WinRM; Set-Service WinRM -StartupType Disabled[/code]."),
	"remote.fix.winSSH": s("As administrator: [code]Stop-Service sshd; Set-Service sshd -StartupType Disabled[/code]. " +
		"Or Settings → System → Optional features → remove OpenSSH Server."),
	"remote.fix.winGuest": s("As administrator: Computer Management → Local Users and Groups → Users → Guest → tick " +
		"\"Account is disabled\"."),
	"remote.fix.linuxSSH": s("[code]sudo systemctl disable --now ssh.service ssh.socket[/code] (Debian/Ubuntu) or " +
		"sshd.service (Fedora/Arch), or uninstall openssh-server."),
	"remote.fix.linuxRDP": s("GNOME: Settings → System → Remote Desktop → turn off Desktop Sharing and Remote Login. " +
		"xrdp: [code]sudo systemctl disable --now xrdp[/code]."),
	"remote.fix.linuxVNC": s("Turn off screen sharing (GNOME: Settings → Sharing; KDE: Krfb) and stop VNC servers " +
		"such as x11vnc or TigerVNC."),
	"remote.fix.linuxGuest": s("Set [code]allow-guest=false[/code] under [Seat:*] in /etc/lightdm/lightdm.conf."),

	// ---- ssh-keys ----
	"sshkeys.pass": pl("1 private key checked: it has a passphrase and private permissions; no authorized_keys.",
		"{n} private keys checked: all have a passphrase and private permissions; no authorized_keys."),
	"sshkeys.hardware": pl("1 hardware-backed key needs its token and is fine.",
		"{n} hardware-backed keys need their token and are fine."),
	"sshkeys.noPassphrase": pl("1 private key has no passphrase.", "{n} private keys have no passphrase."),
	"sshkeys.readable":     pl("1 key is readable by other users.", "{n} keys are readable by other users."),
	"sshkeys.authorized": pl("1 key in authorized_keys can log in to this machine.",
		"{n} keys in authorized_keys can log in to this machine."),
	"sshkeys.fix.passphrase": s("Add a passphrase: [code]ssh-keygen -p -f <key>[/code] (the key stays the same, nothing " +
		"to re-upload), or move to a hardware key ([code]ssh-keygen -t ed25519-sk[/code]) or a password manager's SSH agent."),
	"sshkeys.fix.mac": s("Let the Keychain remember the passphrase: [code]ssh-add --apple-use-keychain <key>[/code]."),
	"sshkeys.fix.win": s("Let the Windows ssh-agent service hold the unlocked key: [code]ssh-add <key>[/code]."),
	"sshkeys.fix.rest": s("Make keys private: [code]chmod 600 <key>[/code]. Remove authorized_keys lines you don't " +
		"recognise, and turn off the SSH server (Remote Login) if you don't use it."),
	"sshkeys.config.all": pl("1 setting in the SSH client config weakens every connection.",
		"{n} settings in the SSH client config weaken every connection."),
	"sshkeys.config.some": pl("1 setting in the SSH client config weakens connections to particular hosts.",
		"{n} settings in the SSH client config weaken connections to particular hosts."),
	"sshkeys.fix.config": s("In ~/.ssh/config, remove [code]ForwardAgent yes[/code] (use [code]ssh -A[/code] or " +
		"[code]ProxyJump[/code] only where you need it: a server you forward your agent to can use your keys while you " +
		"are logged in), and remove [code]StrictHostKeyChecking no[/code] and [code]UserKnownHostsFile /dev/null[/code] " +
		"(use [code]StrictHostKeyChecking accept-new[/code] instead), so a server that suddenly has another key is noticed."),

	// ---- tunnels ----
	"tunnels.pass":    s("No tunnels publish this machine to the internet or the tailnet."),
	"tunnels.found":   pl("1 tunnel publishes this machine beyond the local network.", "{n} tunnels publish this machine beyond the local network."),
	"tunnels.noProcs": s("Could not list processes ({err})."),
	"tunnels.noServe": s("Could not read `tailscale serve status`."),
	"tunnels.fix": s("Stop tunnels you aren't using ([code]tailscale funnel reset[/code], [code]tailscale serve " +
		"reset[/code]; quit ngrok, [code]ssh -R[/code]…). If you must share something, use a named Cloudflare Tunnel " +
		"behind Cloudflare Access, not a public URL."),

	// ---- ai-agents ----
	"ai.pass": pl("1 AI agent config file checked: no plain-text tokens, guardrails on.",
		"{n} AI agent config files checked: no plain-text tokens, guardrails on."),
	"ai.tokens": pl("1 plain-text token in AI agent / MCP configs.", "{n} plain-text tokens in AI agent / MCP configs."),
	"ai.guards": pl("1 agent setting skips approvals or the sandbox.", "{n} agent settings skip approvals or the sandbox."),
	"ai.fix": s("Keep tokens out of MCP configs: reference an environment variable instead " +
		"([code]\"env\": {\"API_KEY\": \"${env:API_KEY}\"}[/code] or the agent's own input/secret mechanism) and load it " +
		"from the OS keychain ([code]touchenv run[/code] on macOS). Turn " +
		"approvals and the sandbox back on: a prompt injection in any file, web page or issue the agent reads can " +
		"then run commands as you."),

	// ---- cracked-software ----
	"cracked.pass": s("No traces of cracked Adobe, Autodesk, Windows or Microsoft Office."),
	"cracked.found": s("Signs of cracked software ({products}). Cracks are a common way to install malware that " +
		"steals passwords and tokens."),
	"cracked.fix": s("Uninstall the cracked software and any crack or activation tool, remove the lines the crack " +
		"added to the hosts file, and run a full malware scan: cracks often carry information stealers. If the scan " +
		"finds one, change the passwords and tokens used on this machine. Ask IT for a licensed copy."),
	"cracked.fixAlternatives": s("Uninstall the cracked software and any crack or activation tool, remove the lines " +
		"the crack added to the hosts file, and run a full malware scan: cracks often carry information stealers. If " +
		"the scan finds one, change the passwords and tokens used on this machine. Ask IT for a licensed copy, or use a free, " +
		"open-source alternative from ArtCraft (https://getartcraft.com)."),
	"cracked.alt.adobe": s("Adobe: PhotoCraft for Photoshop, VectorCraft for Illustrator, FilmCraft for Premiere Pro, " +
		"LightCraft for Lightroom, EffectCraft for After Effects, DesignCraft for InDesign, PdfCraft for Acrobat."),
	"cracked.alt.office":   s("Microsoft Office: WordCraft for Word, GridCraft for Excel, DeckCraft for PowerPoint."),
	"cracked.alt.autodesk": s("Autodesk: CADCraft for AutoCAD."),

	// ---- admin-rights ----
	"admin.pass.standard": s("This account is a standard user."),
	"admin.pass.allowed":  s("This account is an administrator, which the policy allows."),
	"admin.pass.sudo":     s("No passwordless sudo rule."),
	"admin.isAdmin": s("This account is an administrator ({groups}): malware you run by mistake needs only one " +
		"approval to take over the whole machine."),
	"admin.nopasswd": s("sudo runs every command as root without a password ({where}): any program you run can take " +
		"over the machine silently."),
	"admin.nopasswdSome": s("sudo runs some commands as root without a password ({where}); many commands can be " +
		"abused to get a root shell."),
	"admin.uacOff": s("User Account Control is turned off (EnableLUA = 0): programs run with full administrator " +
		"rights without asking."),
	"admin.uacNoPrompt": s("UAC elevates administrators without asking (ConsentPromptBehaviorAdmin = 0): any program " +
		"can take administrator rights silently."),
	"admin.builtinAdmin": s("The built-in Administrator account is enabled."),
	"admin.note.unknown": s("Could not tell whether this account is an administrator."),
	"admin.note.sudo":    s("Could not ask sudo which rules apply ({err})."),
	"admin.note.uac":     s("Could not read the User Account Control settings."),
	"admin.fix.mac": s("Create a separate administrator account (System Settings → Users & Groups → Add User…, " +
		"type Administrator), log in to it once, then turn off \"Allow this user to administer this computer\" for " +
		"your daily account. Admin prompts then take the other account's name and password."),
	"admin.fix.win": s("Create a separate administrator account (Settings → Accounts → Other users → Add account, " +
		"then Change account type → Administrator), sign in to it once, then change your daily account's type to " +
		"Standard User. UAC then asks for the administrator's password."),
	"admin.fix.linux": s("Do administration from a separate account: from it, remove your daily account from the " +
		"group with [code]sudo gpasswd -d NAME sudo[/code], NAME being your daily account (wheel instead of sudo on Fedora/Arch)."),
	"admin.fix.nopasswd": s("Remove NOPASSWD (and !authenticate) from the rule with [code]sudo visudo[/code], or " +
		"[code]sudo visudo -f /etc/sudoers.d/FILE[/code]."),
	"admin.fix.uac": s("Control Panel → User Accounts → Change User Account Control settings → at least \"Notify me " +
		"only when apps try to make changes to my computer (default)\", then restart. If a policy sets it, ask IT."),
	"admin.fix.builtinAdmin": s("As administrator: [code]Get-LocalUser | Where-Object SID -like '*-500' | " +
		"Disable-LocalUser[/code]."),

	// ---- os-protections ----
	"prot.pass":    s("On: {list}."),
	"prot.nothing": s("Nothing to check: every part of this check is turned off for this OS."),
	"prot.wsl":     s("Windows Subsystem for Linux: Windows' own protections apply."),
	"prot.sipOff": s("System Integrity Protection is off: malware with administrator rights can change macOS itself " +
		"and hide there."),
	"prot.sipPartial": s("System Integrity Protection is only partly on (custom configuration)."),
	"prot.gatekeeperOff": s("Gatekeeper is off: downloaded apps open without being checked for malware or a " +
		"developer signature."),
	"prot.avOff":     s("Microsoft Defender real-time protection is off and no other antivirus is on."),
	"prot.tamperOff": s("Microsoft Defender tamper protection is off: malware can switch Defender off."),
	"prot.smartscreenOff": s("SmartScreen for apps and files is off: downloaded programs run without a reputation " +
		"check."),
	"prot.secureBootOff":     s("Secure Boot is off: malware can load before the OS starts."),
	"prot.selinuxPermissive": s("SELinux is in permissive mode: it logs violations but blocks nothing."),
	"prot.noLSM":             s("Neither AppArmor nor SELinux is active."),
	"prot.note.unknown":      s("Could not tell whether {what} is on."),
	"prot.note.noUEFI":       s("This machine boots in legacy BIOS mode, which has no Secure Boot."),
	"prot.fix.sip": s("Start up in macOS Recovery (Apple silicon: hold the power button; Intel: Command-R), open " +
		"Utilities → Terminal, run [code]csrutil enable[/code] and restart."),
	"prot.fix.gatekeeper": s("[code]sudo spctl --global-enable[/code], then System Settings → Privacy & Security → " +
		"Allow applications from → App Store & Known Developers."),
	"prot.fix.av": s("Windows Security → Virus & threat protection → Manage settings → turn on Real-time protection. " +
		"If it turns itself off again, ask IT: a policy or malware may be switching it off."),
	"prot.fix.tamper": s("Windows Security → Virus & threat protection → Manage settings → turn on Tamper Protection."),
	"prot.fix.smartscreen": s("Windows Security → App & browser control → Reputation-based protection settings → " +
		"turn on Check apps and files. If a policy sets it, ask IT."),
	"prot.fix.secureBoot.windows": s("Settings → System → Recovery → Advanced startup → Restart now → Troubleshoot → " +
		"Advanced options → UEFI Firmware Settings, and enable Secure Boot there. With BitLocker on, have the " +
		"recovery key at hand first."),
	"prot.fix.secureBoot.linux": s("Enable Secure Boot in the firmware settings ([code]systemctl reboot " +
		"--firmware-setup[/code]). Distributions with a signed shim (Ubuntu, Fedora, Debian…) boot as before; " +
		"self-built kernels and extra modules (such as NVIDIA's) must be signed with a MOK first."),
	"prot.fix.selinux": s("[code]sudo setenforce 1[/code], and set [code]SELINUX=enforcing[/code] in " +
		"/etc/selinux/config so it stays on after a restart."),
	"prot.fix.lsm": s("Ubuntu/Debian/openSUSE: [code]sudo systemctl enable --now apparmor[/code] (and remove " +
		"apparmor=0 from the kernel command line). Fedora/RHEL: set [code]SELINUX=enforcing[/code] in " +
		"/etc/selinux/config and restart."),

	// ---- sharing ----
	"sharing.on":             s("{service} is on."),
	"sharing.onOpen":         s("{service} is on and lets anyone on the network in without a password."),
	"sharing.off":            s("Off: {services}."),
	"sharing.allowed":        s("On but allowed by policy: {services}."),
	"sharing.note.unknown":   s("Could not tell whether {what} is on."),
	"sharing.note.noSystemd": s("Could not read systemd unit states; judged from open ports only."),
	"sharing.fix.macSharing": s("System Settings → General → Sharing → turn off {service}."),
	"sharing.fix.macAirDrop": s("Control Center → AirDrop → Contacts Only (or turn AirDrop off), or in Finder: Go → " +
		"AirDrop → \"Allow me to be discovered by\" → Contacts Only."),
	"sharing.fix.winShares": s("Stop sharing folders you don't need: as administrator, Computer Management → Shared " +
		"Folders → Shares → right-click → Stop Sharing, or [code]Remove-SmbShare -Name SHARE[/code]."),
	"sharing.fix.winPublic": s("Settings → Network & internet → Advanced network settings → Advanced sharing " +
		"settings → Public networks → turn off Network discovery and File and printer sharing; and set networks you " +
		"don't own to Public."),
	"sharing.fix.winPrinters": s("Settings → Bluetooth & devices → Printers & scanners → the printer → Printer " +
		"properties → Sharing → untick \"Share this printer\"."),
	"sharing.fix.winNearby": s("Settings → System → Nearby sharing → My devices only, or Off."),
	"sharing.fix.linuxSamba": s("Stop Samba if you don't need it: [code]sudo systemctl disable --now smbd[/code] " +
		"(smb on Fedora). Otherwise remove [code]guest ok = yes[/code] and [code]public = yes[/code] from " +
		"/etc/samba/smb.conf."),
	"sharing.fix.linuxNFS": s("[code]sudo systemctl disable --now nfs-server[/code] (nfs-kernel-server on " +
		"Debian/Ubuntu), or limit each line of /etc/exports to named hosts, then [code]sudo exportfs -ra[/code]."),
	"sharing.fix.cups":       s("[code]sudo cupsctl --no-share-printers[/code]"),
	"sharing.fix.linuxGnome": s("Settings → Sharing → File Sharing → off."),
	// ---- extensions ----
	"extensions.notFound": s("No supported browser or code editor profile found."),
	"extensions.found":    s("Extensions found: {counts}."),
	"extensions.pass":     s("None is blocked or installed from outside a store."),
	"extensions.blocked": pl("1 extension is on the organisation's block list: {names}.",
		"{n} extensions are on the organisation's block list: {names}."),
	"extensions.outside": pl("1 extension was installed from outside a store (loaded unpacked, from a file or by another program): {names}.",
		"{n} extensions were installed from outside a store (loaded unpacked, from a file or by another program): {names}."),
	"extensions.notAllowed": pl("1 extension is not on the organisation's allowed list: {names}.",
		"{n} extensions are not on the organisation's allowed list: {names}."),
	"extensions.allSites": pl("1 of them can read and change every website you visit.",
		"{n} of them can read and change every website you visit."),
	"extensions.allSitesWarn": pl("1 extension can read and change every website you visit: {names}.",
		"{n} extensions can read and change every website you visit: {names}."),
	"extensions.fix.blocked": s("Remove it now: in the browser open the extensions page ([code]chrome://extensions[/code], " +
		"[code]edge://extensions[/code], [code]brave://extensions[/code], or [code]about:addons[/code] in Firefox) → Remove; " +
		"in the editor open the Extensions view → the extension → Uninstall. Then tell IT. Change the passwords you used in " +
		"that browser or editor only if IT confirms the extension stole data."),
	"extensions.fix.outside": s("Remove extensions you did not install on purpose (the browser's extensions page → Remove, " +
		"or the editor's Extensions view → Uninstall) and install the ones you need from the Chrome Web Store, Microsoft " +
		"Edge Add-ons, addons.mozilla.org or the editor's marketplace. If IT approves one, it can be listed in the " +
		"policy's allow_unpacked."),
	"extensions.fix.notAllowed": s("Remove extensions your organisation has not approved, or ask IT to add them to the " +
		"allowed list."),
	"extensions.fix.allSites": s("Remove extensions you no longer use. In Chrome, Edge or Brave limit the rest: extensions " +
		"page → Details → Site access → On click or On specific sites."),

	// ---- browser-passwords ----
	"passwords.notFound": s("No supported browser profile found."),
	"passwords.pass":     s("No passwords are saved in the browsers, and they do not offer to save them."),
	"passwords.passSavingOn": s("No passwords are saved in the browsers, but {browsers} still offers to save them: " +
		"consider turning that off."),
	"passwords.stored": s("Passwords are saved in {browsers}. Information-stealing malware takes a browser's saved " +
		"passwords first."),
	"passwords.allowed": s("Allowed by policy: {browsers}."),
	"passwords.fix": s("Move these passwords to a password manager (the browser's password settings can export them), " +
		"delete them from the browser, and turn off saving."),
	"passwords.fix.mac": s("On a Mac, Apple's Passwords app is a good choice: it is built in, unlocks with Touch ID, " +
		"imports the file the browser exports, and fills in Chrome and Edge through Apple's iCloud Passwords extension."),
	"passwords.fix.chrome": s("Chrome: Settings → Autofill and passwords → Google Password Manager → Settings → turn off " +
		"Offer to save passwords."),
	"passwords.fix.edge": s("Edge: Settings → Passwords and autofill (Profiles → Passwords in older versions) → turn off " +
		"Offer to save passwords."),
	"passwords.fix.brave": s("Brave: Settings → Autofill and passwords → Password Manager → Settings → turn off Offer " +
		"to save passwords."),
	"passwords.fix.firefox": s("Firefox: Settings → Privacy & Security → Passwords → uncheck Ask to save passwords."),
	"passwords.fix.other":   s("Other browsers: the password settings → turn off Offer to save passwords."),

	// ---- trust-store ----
	"trust.pass":       s("No root certificates were added to the trust store, and no proxy is set."),
	"trust.pass.ca":    s("No root certificates were added to the trust store."),
	"trust.pass.proxy": s("No proxy is set."),
	"trust.unknown":    s("Could not read the trust store or the proxy settings: {err}"),
	"trust.ca.found": pl("1 root certificate was added to the trust store: {names}. Whoever holds its key can read "+
		"this machine's HTTPS traffic that passes through them. Company TLS inspection and developer tools such as "+
		"mkcert add one too.",
		"{n} root certificates were added to the trust store: {names}. Whoever holds their keys can read this "+
			"machine's HTTPS traffic that passes through them. Company TLS inspection and developer tools such as "+
			"mkcert add them too."),
	"trust.ca.devTool": s("They include a development or debugging tool's certificate ({tools}): keep it only while you " +
		"use the tool."),
	"trust.ca.hostOnly": pl("1 certificate is trusted for one host name only (such as a remote desktop's); not counted.",
		"{n} certificates are trusted for one host name only (such as a remote desktop's); not counted."),
	"trust.ca.unknown": s("The trust store could not be read: {err}"),
	"trust.proxy.found": s("Web traffic is sent through a proxy: {proxies}. A proxy you did not set up can see " +
		"every site you visit and read unencrypted traffic."),
	"trust.proxy.local":   s("A proxy on this machine is set ({proxies}), usually a local tool such as a VPN client or a debugging proxy."),
	"trust.proxy.unknown": s("The proxy settings could not be read: {err}"),
	"trust.fix.ca.mac": s("Keychain Access → login or System keychain → Certificates → double-click the certificate → " +
		"Trust → When using this certificate: Use System Defaults, or delete it. For mkcert: [code]mkcert -uninstall[/code]."),
	"trust.fix.ca.win": s("Run [code]certmgr.msc[/code] → Trusted Root Certification Authorities → Certificates → " +
		"right-click the certificate → Delete. For mkcert: [code]mkcert -uninstall[/code]."),
	"trust.fix.ca.linux": s("Delete the file and rebuild the store: [code]sudo update-ca-certificates --fresh[/code] " +
		"(Debian, Ubuntu) or [code]sudo update-ca-trust[/code] (Fedora, RHEL). For mkcert: [code]mkcert -uninstall[/code]."),
	"trust.fix.proxy.mac": s("System Settings → Network → your network → Details → Proxies → turn off the proxies " +
		"you did not set up."),
	"trust.fix.proxy.win": s("Settings → Network & internet → Proxy → turn off Use a proxy server and Use setup " +
		"script unless you set them up."),
	"trust.fix.proxy.linux": s("Settings → Network → Network Proxy → turn it off, unless you set it up."),
	"trust.fix.proxy.env": s("Remove http_proxy, https_proxy and all_proxy from your shell startup files or " +
		"environment unless you set them up."),
	"trust.fix.allow": s("If IT set this up, ask them to list it in the policy (allow_cas, allow_proxies)."),
	// ---- package-managers ----
	"pm.none": s("No npm, pnpm, Yarn, Bun, pip, uv, Go or Cargo found."),
	"pm.pass": pl("1 package manager checked ({tools}): nothing weakens how packages are fetched.",
		"{n} package managers checked ({tools}): nothing weakens how packages are fetched."),
	"pm.insecure": pl("1 setting fetches packages over plain http or ignores certificate errors.",
		"{n} settings fetch packages over plain http or ignore certificate errors."),
	"pm.checksum": pl("1 setting turns off Go's checksum database.", "{n} settings turn off Go's checksum database."),
	"pm.scripts": pl("1 package manager runs every package's install scripts.",
		"{n} package managers run every package's install scripts."),
	"pm.releaseAge": pl("1 package manager installs versions published minutes ago.",
		"{n} package managers install versions published minutes ago."),
	"pm.fix.insecure": s("Use https:// registries and indexes, and remove settings that ignore certificate errors: " +
		"[code]strict-ssl=false[/code] in ~/.npmrc, [code]trusted-host[/code] in pip.conf, " +
		"[code]allow-insecure-host[/code] in uv.toml, [code]enableStrictSsl: false[/code] in ~/.yarnrc.yml; for Go run " +
		"[code]go env -u GOINSECURE[/code]. If your company's own registry only speaks http, ask IT to add it to the " +
		"policy's allow_hosts."),
	"pm.fix.checksum": s("Turn Go's checksum database back on: [code]go env -u GOSUMDB GONOSUMDB[/code], and list only " +
		"your company's module paths in GOPRIVATE ([code]go env -w GOPRIVATE=git.example.com/*[/code]), not [code]*[/code]."),
	"pm.fix.scripts": s("Stop packages from running install scripts by default: [code]npm config set ignore-scripts " +
		"true[/code] (run [code]npm rebuild PACKAGE[/code] for one that needs its script); pnpm: remove " +
		"[code]dangerouslyAllowAllBuilds[/code]; Yarn: remove [code]enableScripts: true[/code] from ~/.yarnrc.yml."),
	"pm.fix.releaseAge": s("Wait a few days before installing a new version, so a hijacked release is caught first: " +
		"npm 11.10+: [code]npm config set min-release-age 3[/code] (days); Bun: [code]minimumReleaseAge = 259200[/code] " +
		"(seconds) under [install] in ~/.bunfig.toml; pnpm and Yarn: remove the line that sets " +
		"[code]minimumReleaseAge[/code] or [code]npmMinimalAgeGate[/code] to 0."),

	// ---- startup-items ----
	"startup.pass": pl("1 item starts at login or on a schedule; nothing unusual.",
		"{n} items start at login or on a schedule; nothing unusual."),
	"startup.total": pl("1 item starts at login or on a schedule in all.",
		"{n} items start at login or on a schedule in all."),
	"startup.downloadRun": pl("1 item downloads code and runs it each time it starts.",
		"{n} items download code and run it each time they start."),
	"startup.suspicious": pl("1 item starts a program from a temporary, download or hidden folder.",
		"{n} items start programs from temporary, download or hidden folders."),
	"startup.writable": pl("1 item starts a program that any user can change.",
		"{n} items start programs that any user can change."),
	"startup.missing": pl("1 item points to a program that no longer exists.",
		"{n} items point to programs that no longer exist."),
	"startup.fix.mac": s("Look up each item listed. If you don't recognise it, remove it: " +
		"[code]launchctl bootout gui/$(id -u)/LABEL[/code] and delete its .plist from ~/Library/LaunchAgents (items in " +
		"/Library need an administrator); System Settings → General → Login Items & Extensions shows them too. If one " +
		"downloads and runs code, run a malware scan; if it finds malware, change the passwords used on this Mac. Items whose program is " +
		"gone are leftovers of uninstalled apps and can simply be removed."),
	"startup.fix.win": s("Look up each item listed. If you don't recognise it, turn it off: Task Manager → Startup apps " +
		"→ Disable, Task Scheduler → the task → Disable, or delete its shortcut from the Startup folder " +
		"([code]shell:startup[/code]). If one downloads and runs code, run a full scan in Windows Security; if it " +
		"finds malware, change the passwords used on this PC. Items whose program is gone are leftovers of uninstalled apps."),
	"startup.fix.linux": s("Look up each item listed. If you don't recognise it, remove it: delete its .desktop file " +
		"from ~/.config/autostart, [code]systemctl --user disable --now UNIT[/code], or [code]crontab -e[/code]. If " +
		"one downloads and runs code, check the machine for malware; if you find any, change the passwords used on it."),

	// ---- backup ----
	"backup.unsupported": s("Not checked on {os}: there is no standard backup or device-finding service to read."),
	"backup.unencrypted": pl("1 Time Machine backup is not encrypted: whoever takes the disk can read your files.",
		"{n} Time Machine backups are not encrypted: whoever takes a disk can read your files."),
	"backup.stale":         pl("1 backup is older than {max} days.", "{n} backups are older than {max} days."),
	"backup.none":          s("No backup is set up: a lost or broken laptop takes its files with it."),
	"backup.findMyOff.mac": s("Find My Mac is off: a lost Mac cannot be located, locked or erased remotely."),
	"backup.findMyOff.win": s("Find my device is off: a lost PC cannot be located or locked remotely."),
	"backup.on":            pl("Backups go to 1 destination.", "Backups go to {n} destinations."),
	"backup.noneAllowed":   s("No Time Machine backup is set up (the policy does not require one)."),
	"backup.findMyOn.mac":  s("Find My Mac is on."),
	"backup.findMyOn.win":  s("Find my device is on."),
	"backup.unknown.mac": s("Could not tell whether Time Machine is set up (reading its settings may need Full Disk " +
		"Access)."),
	"backup.findMyUnknown": s("Could not tell whether the device can be located remotely."),
	"backup.win.notRead":   s("Windows backups (File History, Windows Backup, OneDrive) are not checked."),
	"backup.fix.mac.encrypt": s("System Settings → General → Time Machine → select the disk → Remove Disk, then Add " +
		"Backup Disk again with \"Encrypt backup\" turned on (on recent macOS an existing backup cannot be encrypted " +
		"in place, so the disk is erased)."),
	"backup.fix.mac.stale": s("Connect the backup disk, then Time Machine in the menu bar → Back Up Now."),
	"backup.fix.mac.setup": s("System Settings → General → Time Machine → Add Backup Disk, with \"Encrypt backup\" " +
		"turned on, or ask IT how this Mac should be backed up."),
	"backup.fix.mac.findMy": s("System Settings → your name (Apple Account) → iCloud → Find My Mac → turn it on."),
	"backup.fix.win.findMy": s("Settings → Privacy & security → Find my device → turn it on (it needs a Microsoft " +
		"account and location services)."),
}
