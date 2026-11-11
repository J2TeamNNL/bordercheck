// Simplified Chinese for the checks' summaries and fixes (keys:
// checks.en.json, generated from internal/msg/catalog.go). Same syntax as
// en.ts, plus typed parameters ({after:dur}, {ago:ago}, {until:date}); see
// checktext.ts. Parts are joined without spaces, so each ends in "。".
//
// Menu paths: mainland users often run macOS and Windows in Chinese, others in
// English. Every path is given as the Chinese OS shows it, followed once by
// the same path in English in full-width parentheses:
// "系统设置 → 网络 → 防火墙（System Settings → Network → Firewall）"; a quoted
// setting gets its English label the same way. Apps without a Chinese UI
// (Tailscale) stay in English only. Commands, flags, paths, product names and
// URLs are never translated. Terms follow zh.ts: policy 策略, token 令牌,
// secret 密钥, tunnel 隧道, AI agent AI 代理; a Windows "policy" is 组策略.

import type { CheckCatalog } from "../checktext";

export const checksZh: CheckCatalog = {
  "check.unsupported": "尚不支持 {os}。",
  "check.timeout": "未能在 {after:dur}内完成，已被停止；其他检查项不受影响。",
  "check.interrupted": "在完成前被中断。",
  "check.moreAllowed": "另有 {n} 项为策略所允许。",

  "firewall.mac.off": "macOS 防火墙已关闭。",
  "firewall.mac.off.fix":
    "前往 系统设置 → 网络 → 防火墙（System Settings → Network → Firewall），打开防火墙。或运行：[code]sudo /usr/libexec/ApplicationFirewall/socketfilterfw --setglobalstate on[/code]",
  "firewall.mac.stealthOff": "防火墙已开启，但隐身模式已关闭：这台 Mac 会响应来自网络的探测。",
  "firewall.mac.stealthOff.fix":
    "前往 系统设置 → 网络 → 防火墙 → 选项（System Settings → Network → Firewall → Options），打开隐身模式（stealth mode）。或运行：[code]sudo /usr/libexec/ApplicationFirewall/socketfilterfw --setstealthmode on[/code]",
  "firewall.mac.on": "防火墙已开启。",
  "firewall.mac.onStealth": "防火墙和隐身模式均已开启。",

  "firewall.win.noProfiles": "Windows 未报告任何防火墙配置文件",
  "firewall.win.on": "Windows 防火墙已在所有网络配置文件中开启。",
  "firewall.win.off": "Windows 防火墙在以下网络配置文件中已关闭：{profiles}。",
  "firewall.win.off.fix":
    "前往 Windows 安全中心 → 防火墙和网络保护（Windows Security → Firewall & network protection），为所有网络开启防火墙。或以管理员身份运行：[code]Set-NetFirewallProfile -All -Enabled True[/code]",

  "firewall.linux.zoneOpenPorts": "firewalld 已开启，但其默认区域 {zone} 放行 1025 到 65535 的所有端口。",
  "firewall.linux.zoneTrusted": "firewalld 已开启，但其默认区域 {zone} 放行所有传入连接。",
  "firewall.linux.zone.fix":
    "[code]sudo firewall-cmd --set-default-zone=public[/code]（仅允许 SSH 和 DHCPv6）；需要的服务再用 [code]--add-service[/code] 开放。",
  "firewall.linux.firewalldOn": "firewalld 已开启。",
  "firewall.linux.firewalldOnZone": "firewalld 已开启（默认区域 {zone}）。",
  "firewall.linux.ufwOn": "ufw 已开启。",
  "firewall.linux.ufwOnConf": "ufw 已开启（在 /etc/ufw/ufw.conf 中启用）。",
  "firewall.linux.inputDrops": "防火墙默认丢弃传入连接（input 链的默认策略）。",
  "firewall.linux.noDrop": "没有防火墙丢弃传入连接：nftables 和 iptables 都没有默认丢弃的 input 链。",
  "firewall.linux.fix":
    "Ubuntu/Debian：[code]sudo ufw enable[/code]（阻止传入连接，允许传出连接）。Fedora/RHEL/openSUSE：[code]sudo systemctl enable --now firewalld[/code]。",
  "firewall.linux.rootOnly":
    "{services} 服务会加载防火墙规则，但这些规则只有 root 才能读取，因此 bordercheck 无法判断它们是否阻止传入连接。运行 [code]sudo bordercheck -only firewall[/code] 进行检查。",
  "firewall.linux.unknown":
    "没有 root 权限无法判断：没有 ufw 配置，systemd 也未说明正在运行哪些防火墙服务。运行 [code]sudo bordercheck -only firewall[/code] 检查规则。",
  "firewall.linux.noneUfwOff":
    "没有开启任何防火墙：ufw 已安装但处于关闭状态，也没有运行 firewalld、nftables 或 iptables 服务。（如果你用其他方式加载规则，[code]sudo bordercheck -only firewall[/code] 会检查它们。）",
  "firewall.linux.noneNoUfw":
    "没有开启任何防火墙：未安装 ufw，也没有运行 firewalld、nftables 或 iptables 服务。（如果你用其他方式加载规则，[code]sudo bordercheck -only firewall[/code] 会检查它们。）",

  "outbound.found": "传出连接由 {apps} 过滤。",
  "outbound.found.winFw": "Windows 防火墙默认阻止传出连接。",
  "outbound.none.mac": "没有出站防火墙（如 LuLu 或 Little Snitch）控制哪些应用可以向外连接。",
  "outbound.none.win": "没有出站防火墙（如 simplewall，或默认阻止传出连接的 Windows 防火墙）控制哪些应用可以向外连接。",
  "outbound.fix.mac":
    "安装免费的出站防火墙，例如 Objective-See 的 LuLu（https://objective-see.org/products/lulu.html，开源）：应用向外连接前它会先询问你，这样恶意软件回连或程序把你的数据发往别处时就会暴露。",
  "outbound.fix.win":
    "安装 simplewall（https://github.com/henrypp/simplewall，免费开源）。启用过滤后，它会阻止所有未经你允许的应用，因此每个应用第一次连接时都会请你确认；之后恶意软件回连或程序把你的数据发往别处时就会暴露。也可以请 IT 将 Windows 防火墙设置为默认阻止传出连接。",

  "disk.mac.on": "文件保险箱（FileVault）已开启。",
  "disk.mac.off": "文件保险箱（FileVault）已关闭：任何拿到这台 Mac 的人都能读取其磁盘。",
  "disk.mac.off.fix": "前往 系统设置 → 隐私与安全性 → 文件保险箱（System Settings → Privacy & Security → FileVault），点按“打开”（Turn On）。",
  "disk.mac.partial": "文件保险箱（FileVault）未完全开启：{status}",
  "disk.win.on": "系统盘已开启 BitLocker。",
  "disk.win.off": "BitLocker 已关闭：任何拿到这台电脑的人都能读取其磁盘。",
  "disk.win.unknown": "Windows 未报告系统盘的 BitLocker 状态。",
  "disk.win.partial": "系统盘的 BitLocker 未完全开启（状态 {code}）。",
  "disk.win.fix":
    "前往 设置 → 隐私和安全性 → 设备加密（Settings → Privacy & security → Device encryption），或 控制面板 → BitLocker 驱动器加密（Control Panel → BitLocker Drive Encryption），将其打开。",
  "disk.linux.noRoot": "在 /proc/self/mounts 中找不到根文件系统。",
  "disk.linux.plain": "{mount} 不在加密磁盘上：任何拿到这台电脑的人都能读取它。",
  "disk.linux.plainBoth": "{mount} 和 {other} 不在加密磁盘上：任何拿到这台电脑的人都能读取它们。",
  "disk.linux.plain.fix":
    "Linux 很难加密正在使用的磁盘：先备份，重装系统时选择“加密新安装”（Encrypt the new installation，LUKS），再恢复数据。高级用户：从 live USB 启动后运行 [code]cryptsetup reencrypt --encrypt[/code]。",
  "disk.linux.unknown": "无法判断磁盘是否已加密。",
  "disk.linux.unknownZFS": "{mount}：ZFS，加密状态未知。",
  "disk.linux.unknownVirtual": "{mount}：{fstype}，属于 live 系统或容器。",
  "disk.linux.unknownDevice": "{mount}：找不到 {source} 对应的设备。",
  "disk.linux.onLUKS": "磁盘已加密（LUKS / dm-crypt）。",
  "disk.linux.onZFS": "磁盘已加密（ZFS 原生加密）。",

  "listeners.pass": "{n} 个监听套接字，全部只在 localhost 上。",
  "listeners.exposed": "{n} 个端口可被其他设备访问（局域网、Wi-Fi、Tailscale）。",
  "listeners.fix":
    "让开发服务器只绑定 127.0.0.1（Vite：去掉 [code]--host[/code]；Docker：[code]-p 127.0.0.1:PORT:PORT[/code]），并关闭不需要的服务。需要共享时，使用 Cloudflare Tunnel，而不是开放端口。",
  "listeners.note.mac": "只能看到你自己的进程；用 sudo 运行可包含系统服务。",
  "listeners.note.linux": "只显示你自己进程的名称；用 sudo 运行可显示系统服务的名称。",
  "listeners.note.linuxNoSS": "未找到 ss，因此无法得知进程名称。",

  "tailscale.notInstalled": "未安装 Tailscale。",
  "tailscale.denied":
    "在这台电脑上只有 root 或 Tailscale operator 才能读取 Tailscale 的设置。运行一次 [code]sudo tailscale set --operator=$USER[/code]，或运行 [code]sudo bordercheck -only tailscale[/code]。（{err}）",
  "tailscale.unreadable": "无法读取 Tailscale 设置；Tailscale 是否正在运行？（{err}）",
  "tailscale.badPrefs": "`tailscale debug prefs` 的输出不符合预期",
  "tailscale.shieldsUp": "Shields up：tailnet 中的其他设备无法主动连接到这台电脑。",
  "tailscale.open":
    "Tailscale 接受传入连接。Tailscale 流量可能绕过系统防火墙，因此 tailnet 中的任何设备（包括已被入侵的设备）都能访问这台电脑监听的所有端口。",
  "tailscale.open.fix":
    "在 Tailscale → Settings 中取消勾选“Allow incoming connections”。或运行：[code]tailscale set --shields-up[/code]。管理员：还应使用 tailnet ACL 限制设备之间的访问。",

  "docker.notInstalled": "未安装 Docker。",
  "docker.noPermission": "已安装 Docker，但当前用户无权使用（不在 docker 组中），因此未检查其容器。",
  "docker.notRunning": "Docker 未运行。",
  "docker.noContainers": "没有正在运行的容器。",
  "docker.pass": "{n} 个运行中的容器，全部保持隔离。",
  "docker.problems": "{containers} 个运行中的容器存在 {n} 个问题。",
  "docker.fix":
    "只在 localhost 上发布端口（[code]-p 127.0.0.1:5432:5432[/code]）。不要使用 [code]--network host[/code] 或 [code]--privileged[/code]。只挂载项目文件夹，切勿挂载 Docker socket、主目录或凭据文件夹。",

  "secrets.pass": "Shell 配置文件、Shell 历史、凭据文件和 .env 文件中都没有明文密钥。",
  "secrets.found": "{files} 个文件中共有 {n} 个明文密钥。",
  "secrets.foundProd": "{files} 个文件中共有 {n} 个明文密钥，其中 {prod} 个标记为生产环境。",
  "secrets.incomplete": "扫描达到时间上限，部分文件夹未检查。",
  "secrets.fix.mac":
    "用 touchenv（https://github.com/ptrinh/touch-env）把每个密钥移入受 Touch ID 保护的钥匙串：[code]touchenv set NAME[/code]，然后删除那一行或那个文件。",
  "secrets.fix.win":
    "把每个密钥移入 Windows 凭据管理器或密码管理器的命令行工具（例如 1Password [code]op run[/code]），然后删除那一行或那个文件。",
  "secrets.fix.linux":
    "把每个密钥移入桌面密钥环（libsecret 的 [code]secret-tool store[/code] / [code]secret-tool lookup[/code]）或密码管理器的命令行工具（如 pass 或 1Password [code]op run[/code]），然后删除那一行或那个文件。",
  "secrets.fix.other": "把每个密钥移入密码管理器或系统密钥环，然后删除那一行或那个文件。",
  "secrets.fix.rotate": 
    "对于出现在 Shell 历史中的密钥，删除相应的行即可。只有当这台电脑可能已被入侵，或文件曾被共享或同步到别处时，才需要轮换密钥。",

  "updates.belowMin": "{os} 低于策略规定的最低版本 {min}。",
  "updates.belowMinWin": "{os} 低于策略规定的最低版本 build {min}。",
  "updates.autoUnknown": "无法判断自动更新是否开启。",
  "updates.autoOff.mac": "自动更新已关闭（{settings}）。",
  "updates.autoOff.win": "自动更新已关闭。",
  "updates.autoOff.winService": "Windows Update 服务已被禁用（Disabled）。",
  "updates.autoOff.winPolicy": "组策略关闭了自动更新。",
  "updates.autoOff.winNotify": "组策略设置为只通知有可用更新。",
  "updates.autoOff.apt": "自动更新已关闭（未安装或未启用 unattended-upgrades）。",
  "updates.autoOff.dnf": "自动更新已关闭（没有启用任何 dnf-automatic 定时器，GNOME Software 也不会下载更新）。",
  "updates.paused": "更新已暂停至 {until:date}。",
  "updates.checkStale": "系统上次检查更新：{ago:ago}（策略：每 {max} 天一次）。",
  "updates.waitingLong": "{name} 已等待安装 {days} 天（策略：{max} 天）。",
  "updates.ready": "{name} 已可安装（{ago:ago}发现）。",
  "updates.readyUndated": "{name} 已可安装。",
  "updates.countWaitingLong": "{n} 个更新正在等待，且已有 {days} 天未安装任何更新（策略：{max} 天）。",
  "updates.countReady": "{n} 个更新已可安装。",
  "updates.reboot": "更新已安装，但需要重启才能生效。",
  "updates.noneInstalled": "已有 {days} 天未安装任何系统更新（策略：{max} 天）。",
  "updates.browserStale": "{browser} 已 {days} 天未更新（策略：{max} 天）；浏览器每隔几周就会发布安全修复。",
  "updates.browserBelowMin": "{browser} {version} 低于策略规定的最低版本 {min}。",
  "updates.note.macSettings": "无法读取“软件更新”（Software Update）的设置。",
  "updates.note.winLastInstall": "无法读取 Windows 上次安装更新的时间。",
  "updates.note.gnomeSoftware": "GNOME Software 会下载更新，并在重启时安装。",
  "updates.state": "{os}。",
  "updates.stateAuto": "{os}，自动更新已开启。",
  "updates.stateChecked": "{os}，上次检查更新：{ago:ago}。",
  "updates.stateAutoChecked": "{os}，自动更新已开启，上次检查更新：{ago:ago}。",
  "updates.noneWaiting": "没有待安装的更新。",
  "updates.browsersFresh": "{n} 个浏览器近期已更新。",
  "updates.fix.browser":
    "打开每个浏览器的“关于”页面进行更新：Chrome/Edge/Brave 在 设置 → 关于（Settings → About），Firefox 在 帮助 → 关于 Firefox（Help → About Firefox）；然后重新启动浏览器，并卸载不用的浏览器。",
  "updates.fix.macos.upgrade": "前往 系统设置 → 通用 → 软件更新（System Settings → General → Software Update），升级到仍受支持的 macOS 版本。",
  "updates.fix.macos.auto":
    "前往 系统设置 → 通用 → 软件更新 → 自动更新 (i)（System Settings → General → Software Update → Automatic updates (i)），打开“检查更新”“有可用更新时下载”和“安装安全性响应和系统文件”（Check for updates、Download new updates when available、Install Security Responses and system files）。",
  "updates.fix.macos.pending": "前往 系统设置 → 通用 → 软件更新（System Settings → General → Software Update），点按“现在更新”（Update Now）。",
  "updates.fix.macos.check":
    "连接互联网，然后打开 系统设置 → 通用 → 软件更新（System Settings → General → Software Update），让 macOS 重新检查。",
  "updates.fix.windows.upgrade": "前往 设置 → Windows 更新（Settings → Windows Update），安装最新的 Windows 11 功能更新。",
  "updates.fix.windows.auto":
    "Windows 更新必须自动运行：Windows Update 服务（wuauserv）不能设为“禁用”（Disabled），也不能有关闭自动更新的组策略。如果 设置 → Windows 更新（Settings → Windows Update）提示某些设置由你的组织管理，请联系 IT。",
  "updates.fix.windows.paused": "前往 设置 → Windows 更新（Settings → Windows Update），点击“继续更新”（Resume updates）。",
  "updates.fix.windows.pending":
    "前往 设置 → Windows 更新（Settings → Windows Update），点击“检查更新”（Check for updates），安装全部更新后重启。",
  "updates.fix.windows.check": "前往 设置 → Windows 更新（Settings → Windows Update），点击“检查更新”（Check for updates）。",
  "updates.fix.windows.reboot": "重启电脑以完成更新安装。",
  "updates.fix.debian.upgrade": "升级到仍受支持的版本（Ubuntu：[code]sudo do-release-upgrade[/code]）。",
  "updates.fix.debian.auto": "[code]sudo apt install unattended-upgrades && sudo dpkg-reconfigure -plow unattended-upgrades[/code]",
  "updates.fix.debian.pending": "[code]sudo apt update && sudo apt full-upgrade[/code]",
  "updates.fix.debian.check": "[code]sudo apt update[/code]",
  "updates.fix.debian.reboot": "重启以完成更新安装（/var/run/reboot-required 已存在）。",
  "updates.fix.fedora.upgrade": "升级到仍受支持的版本：[code]sudo dnf system-upgrade[/code]（参见 Fedora 升级指南）。",
  "updates.fix.fedora.auto":
    "[code]sudo dnf install dnf-automatic[/code]，在 /etc/dnf/automatic.conf 中设置 [code]apply_updates = yes[/code]，然后运行 [code]sudo systemctl enable --now dnf-automatic.timer[/code]（dnf5 上为 dnf5-automatic.timer）。",
  "updates.fix.fedora.pending": "[code]sudo dnf upgrade --refresh[/code]",
  "updates.fix.fedora.check": "[code]sudo dnf check-update --refresh[/code]",
  "updates.fix.arch.pending": "[code]sudo pacman -Syu[/code]",
  "updates.fix.generic": "使用发行版的包管理器安装最新更新，然后重启。",

  "screenlock.noDesktop": "没有 bordercheck 能读取锁屏设置的桌面环境（支持 GNOME 和 KDE Plasma）。",
  "screenlock.unknown": "无法判断睡眠后或锁屏时是否需要密码。",
  "screenlock.passwordUnknown": "无法判断睡眠后是否需要密码。",
  "screenlock.noPassword": "睡眠或屏幕保护程序启动后，无需密码即可重新进入。",
  "screenlock.idleUnknown": "无法判断屏幕何时自动锁定。",
  "screenlock.never": "离开电脑时，屏幕从不自动锁定。",
  "screenlock.tooLate": "闲置 {after:dur}后屏幕才会锁定（策略：{max:dur}）。",
  "screenlock.passBoth": "睡眠后需要密码，闲置 {after:dur}后屏幕会自动锁定。",
  "screenlock.passPassword": "睡眠后需要密码。",
  "screenlock.passIdle": "闲置 {after:dur}后屏幕会自动锁定。",
  "screenlock.fix.macos.password":
    "前往 系统设置 → 锁定屏幕（System Settings → Lock Screen），将“屏幕保护程序启动或显示器关闭后需要密码”（Require password after screen saver begins or display is turned off）设为“立即”（Immediately）。",
  "screenlock.fix.macos.idle":
    "前往 系统设置 → 锁定屏幕（System Settings → Lock Screen），将“使用电池供电且不活跃时关闭显示器”和“使用电源适配器且不活跃时关闭显示器”（Turn display off on battery / on power adapter when inactive）设为不超过策略上限；如使用屏幕保护程序，“不活跃时启动屏幕保护程序”（Start Screen Saver when inactive）也一样。",
  "screenlock.fix.windows.password":
    "前往 设置 → 账户 → 登录选项（Settings → Accounts → Sign-in options），在“如果你已离开，Windows 应在何时要求你重新登录？”（If you've been away, when should Windows require you to sign in again?）中选择“电脑从睡眠状态唤醒时”（When PC wakes up from sleep）。",
  "screenlock.fix.windows.idle":
    "前往 设置 → 系统 → 电源和电池 → 屏幕、睡眠和休眠超时（Settings → System → Power & battery → Screen, sleep & hibernate timeouts），让设备在策略上限内进入睡眠（使用电池和接通电源时都要设置）；或在 设置 → 个性化 → 锁屏界面 → 屏幕保护程序（Settings → Personalization → Lock screen → Screen saver）中设置较短的等待时间，并勾选“在恢复时显示登录屏幕”（On resume, display logon screen）。",
  "screenlock.fix.gnome.password":
    "前往 设置 → 隐私与安全 → 锁屏（Settings → Privacy & Security → Screen Lock），打开“自动锁屏”和“挂起时锁屏”（Automatic Screen Lock、Lock Screen on Suspend），并将“自动锁屏延迟”（Automatic Screen Lock Delay）设为“屏幕关闭时”（Screen Turns Off）。",
  "screenlock.fix.gnome.idle":
    "前往 设置 → 电源 → 息屏（Settings → Power → Screen Blank），设为不超过策略上限，并在 设置 → 隐私与安全 → 锁屏（Settings → Privacy & Security → Screen Lock）中打开“自动锁屏”（Automatic Screen Lock）。",
  "screenlock.fix.kde.password": "前往 系统设置 → 锁屏（System Settings → Screen Locking），打开“从睡眠中唤醒后”（After waking from sleep）。",
  "screenlock.fix.kde.idle": "前往 系统设置 → 锁屏（System Settings → Screen Locking），将“自动锁定屏幕”（Lock screen automatically）设为不超过策略上限的时间。",

  "remote.on": "{service} 已开启。",
  "remote.off": "已关闭：{services}。",
  "remote.allowed": "已开启但为策略所允许：{services}。",
  "remote.note.noSystemd": "无法读取 systemd 单元状态；仅根据开放的端口判断。",
  "remote.fix.macSharing": "前往 系统设置 → 通用 → 共享（System Settings → General → Sharing），关闭 {service}。",
  "remote.fix.macGuest":
    "前往 系统设置 → 用户与群组 → 客人用户（System Settings → Users & Groups → Guest User），关闭“允许客人登录这台电脑”（Allow guests to log in to this computer）。",
  "remote.fix.winRDP": "前往 设置 → 系统 → 远程桌面（Settings → System → Remote Desktop），将其关闭（如果是组织的策略开启的，请联系 IT）。",
  "remote.fix.winRM":
    "以管理员身份运行：[code]winrm delete winrm/config/Listener?Address=*+Transport=HTTP[/code]，然后运行 [code]Stop-Service WinRM; Set-Service WinRM -StartupType Disabled[/code]。",
  "remote.fix.winSSH":
    "以管理员身份运行：[code]Stop-Service sshd; Set-Service sshd -StartupType Disabled[/code]。或前往 设置 → 系统 → 可选功能（Settings → System → Optional features），删除 OpenSSH 服务器（OpenSSH Server）。",
  "remote.fix.winGuest":
    "以管理员身份打开 计算机管理 → 本地用户和组 → 用户 → Guest（Computer Management → Local Users and Groups → Users → Guest），勾选“账户已禁用”（Account is disabled）。",
  "remote.fix.linuxSSH":
    "[code]sudo systemctl disable --now ssh.service ssh.socket[/code]（Debian/Ubuntu）或 sshd.service（Fedora/Arch），或卸载 openssh-server。",
  "remote.fix.linuxRDP":
    "GNOME：前往 设置 → 系统 → 远程桌面（Settings → System → Remote Desktop），关闭“桌面共享”和“远程登录”（Desktop Sharing、Remote Login）。xrdp：[code]sudo systemctl disable --now xrdp[/code]。",
  "remote.fix.linuxVNC": "关闭屏幕共享（GNOME：设置 → 共享（Settings → Sharing）；KDE：Krfb），并停止 x11vnc、TigerVNC 等 VNC 服务器。",
  "remote.fix.linuxGuest": "在 /etc/lightdm/lightdm.conf 的 [Seat:*] 下设置 [code]allow-guest=false[/code]。",

  "sshkeys.pass": "已检查 {n} 个私钥：全部设有密码短语且仅本人可读；没有 authorized_keys。",
  "sshkeys.hardware": "{n} 个硬件密钥需要配合对应的硬件令牌才能使用，无需处理。",
  "sshkeys.noPassphrase": "{n} 个私钥没有设置密码短语。",
  "sshkeys.readable": "{n} 个密钥可被其他用户读取。",
  "sshkeys.authorized": "authorized_keys 中有 {n} 个密钥可以登录这台电脑。",
  "sshkeys.fix.passphrase":
    "设置密码短语：[code]ssh-keygen -p -f <key>[/code]（密钥本身不变，无需重新上传），或改用硬件密钥（[code]ssh-keygen -t ed25519-sk[/code]）或密码管理器的 SSH agent。",
  "sshkeys.fix.mac": "让钥匙串记住密码短语：[code]ssh-add --apple-use-keychain <key>[/code]。",
  "sshkeys.fix.win": "让 Windows 的 ssh-agent 服务保存已解锁的密钥：[code]ssh-add <key>[/code]。",
  "sshkeys.fix.rest":
    "将密钥设为仅本人可读：[code]chmod 600 <key>[/code]。删除 authorized_keys 中你不认识的条目；如果不使用 SSH 服务器（远程登录），请将其关闭。",
  "sshkeys.config.all": "SSH 客户端配置中有 {n} 项设置削弱了所有连接的安全性。",
  "sshkeys.config.some": "SSH 客户端配置中有 {n} 项设置削弱了与部分主机连接的安全性。",
  "sshkeys.fix.config":
    "在 ~/.ssh/config 中删除 [code]ForwardAgent yes[/code]（只在确实需要时使用 [code]ssh -A[/code] 或 [code]ProxyJump[/code]：接收你 agent 转发的服务器在你登录期间可以使用你的密钥），并删除 [code]StrictHostKeyChecking no[/code] 和 [code]UserKnownHostsFile /dev/null[/code]（改用 [code]StrictHostKeyChecking accept-new[/code]），这样服务器的密钥突然变化时才能被发现。",

  "tunnels.pass": "没有隧道把这台电脑暴露到互联网或 tailnet。",
  "tunnels.found": "{n} 条隧道把这台电脑暴露到本地网络之外。",
  "tunnels.noProcs": "无法列出进程（{err}）。",
  "tunnels.noServe": "无法读取 `tailscale serve status`。",
  "tunnels.fix":
    "停止不用的隧道（[code]tailscale funnel reset[/code]、[code]tailscale serve reset[/code]；退出 ngrok、[code]ssh -R[/code]…）。如果确需共享，请使用置于 Cloudflare Access 之后的命名 Cloudflare Tunnel，而不是公开 URL。",

  "ai.pass": "已检查 {n} 个 AI 代理配置文件：没有明文令牌，安全防护均已开启。",
  "ai.tokens": "AI 代理 / MCP 配置中有 {n} 个明文令牌。",
  "ai.guards": "{n} 项代理设置跳过了审批或沙箱。",
  "ai.fix":
    "不要把令牌写在 MCP 配置中：改为引用环境变量（[code]\"env\": {\"API_KEY\": \"${env:API_KEY}\"}[/code] 或代理自带的输入/密钥机制），并从系统钥匙串加载（macOS 上用 [code]touchenv run[/code]）。轮换曾写在这些文件中的令牌。重新开启审批和沙箱：否则，代理读取的任何文件、网页或 issue 中的提示词注入都能以你的身份执行命令。",

  "cracked.pass": "没有发现破解版 Adobe、Autodesk、Windows 或 Microsoft Office 的痕迹。",
  "cracked.found": "发现破解软件的迹象（{products}）。破解软件是植入窃取密码和令牌的恶意软件的常见途径。",
  "cracked.fix":
    "卸载破解软件及所有破解或激活工具，删除破解程序添加到 hosts 文件中的条目，并进行全盘恶意软件扫描。然后更改在这台电脑上使用过的密码和令牌：破解软件常常携带信息窃取木马。请向 IT 申请正版授权。",
  "cracked.fixAlternatives":
    "卸载破解软件及所有破解或激活工具，删除破解程序添加到 hosts 文件中的条目，并进行全盘恶意软件扫描。然后更改在这台电脑上使用过的密码和令牌：破解软件常常携带信息窃取木马。请向 IT 申请正版授权，或使用 ArtCraft 提供的免费开源替代软件（https://getartcraft.com）。",
  "cracked.alt.adobe":
    "Adobe：PhotoCraft 替代 Photoshop，VectorCraft 替代 Illustrator，FilmCraft 替代 Premiere Pro，LightCraft 替代 Lightroom，EffectCraft 替代 After Effects，DesignCraft 替代 InDesign，PdfCraft 替代 Acrobat。",
  "cracked.alt.office": "Microsoft Office：WordCraft 替代 Word，GridCraft 替代 Excel，DeckCraft 替代 PowerPoint。",
  "cracked.alt.autodesk": "Autodesk：CADCraft 替代 AutoCAD。",

  "admin.pass.standard": "此帐户是标准用户。",
  "admin.pass.allowed": "此帐户是管理员，策略允许这样做。",
  "admin.pass.sudo": "没有免密码的 sudo 规则。",
  "admin.isAdmin": "此帐户是管理员（{groups}）：你误运行的恶意软件只需你批准一次，就能控制整台电脑。",
  "admin.nopasswd": "sudo 无需密码即可以 root 身份运行任何命令（{where}）：你运行的任何程序都能悄悄控制整台电脑。",
  "admin.nopasswdSome": "sudo 无需密码即可以 root 身份运行部分命令（{where}）；许多命令可被利用来获得 root shell。",
  "admin.uacOff": "用户帐户控制（UAC）已关闭（EnableLUA = 0）：程序无需询问即以完整管理员权限运行。",
  "admin.uacNoPrompt":
    "UAC 不经询问就为管理员提升权限（ConsentPromptBehaviorAdmin = 0）：任何程序都能悄悄获得管理员权限。",
  "admin.builtinAdmin": "内置的 Administrator 帐户已启用。",
  "admin.note.unknown": "无法判断此帐户是否为管理员。",
  "admin.note.sudo": "无法向 sudo 查询适用的规则（{err}）。",
  "admin.note.uac": "无法读取用户帐户控制（UAC）设置。",
  "admin.fix.mac":
    "另建一个管理员帐户（System Settings → Users & Groups → Add User…，类型选 Administrator），登录一次，然后为日常使用的帐户关闭 \"Allow this user to administer this computer\"。之后需要管理员权限时，输入另一个帐户的名称和密码。",
  "admin.fix.win":
    "另建一个管理员帐户（Settings → Accounts → Other users → Add account，然后 Change account type → Administrator），登录一次，然后把日常使用的帐户类型改为 Standard User。之后 UAC 会要求输入管理员密码。",
  "admin.fix.linux":
    "用单独的帐户做管理工作：在该帐户中用 [code]sudo gpasswd -d NAME sudo[/code] 把日常帐户移出该组，NAME 为日常帐户名（Fedora/Arch 上用 wheel 代替 sudo）。",
  "admin.fix.nopasswd":
    "用 [code]sudo visudo[/code] 或 [code]sudo visudo -f /etc/sudoers.d/FILE[/code] 从规则中删除 NOPASSWD（以及 !authenticate）。",
  "admin.fix.uac":
    "前往 Control Panel → User Accounts → Change User Account Control settings，至少选择 \"Notify me only when apps try to make changes to my computer (default)\"，然后重启。如果是策略设置的，请联系 IT。",
  "admin.fix.builtinAdmin":
    "以管理员身份运行：[code]Get-LocalUser | Where-Object SID -like '*-500' | Disable-LocalUser[/code]。",

  "prot.pass": "已开启：{list}。",
  "prot.nothing": "没有可检查的内容：此检查在该操作系统上的所有部分都已关闭。",
  "prot.wsl": "适用于 Linux 的 Windows 子系统（WSL）：由 Windows 自身的防护负责。",
  "prot.sipOff": "系统完整性保护（SIP）已关闭：拥有管理员权限的恶意软件可以修改 macOS 本身并藏身其中。",
  "prot.sipPartial": "系统完整性保护（SIP）只部分开启（自定义配置）。",
  "prot.gatekeeperOff": "Gatekeeper 已关闭：下载的应用打开前不会检查恶意软件或开发者签名。",
  "prot.avOff": "Microsoft Defender 实时保护已关闭，且没有开启其他杀毒软件。",
  "prot.tamperOff": "Microsoft Defender 防篡改保护已关闭：恶意软件可以关闭 Defender。",
  "prot.smartscreenOff": "针对应用和文件的 SmartScreen 已关闭：下载的程序运行前不做信誉检查。",
  "prot.secureBootOff": "安全启动（Secure Boot）已关闭：恶意软件可以在操作系统启动前加载。",
  "prot.selinuxPermissive": "SELinux 处于 permissive 模式：只记录违规，不做任何拦截。",
  "prot.noLSM": "AppArmor 和 SELinux 都未启用。",
  "prot.note.unknown": "无法判断 {what} 是否开启。",
  "prot.note.noUEFI": "此电脑以传统 BIOS 模式启动，没有安全启动。",
  "prot.fix.sip":
    "进入 macOS 恢复模式（Apple 芯片：按住电源键；Intel：Command-R），打开 Utilities → Terminal，运行 [code]csrutil enable[/code] 后重启。",
  "prot.fix.gatekeeper":
    "运行 [code]sudo spctl --global-enable[/code]，然后前往 System Settings → Privacy & Security → Allow applications from → App Store & Known Developers。",
  "prot.fix.av":
    "前往 Windows Security → Virus & threat protection → Manage settings，开启 Real-time protection。如果它又自行关闭，请联系 IT：可能是策略或恶意软件在关闭它。",
  "prot.fix.tamper": "前往 Windows Security → Virus & threat protection → Manage settings，开启 Tamper Protection。",
  "prot.fix.smartscreen":
    "前往 Windows Security → App & browser control → Reputation-based protection settings，开启 Check apps and files。如果是策略设置的，请联系 IT。",
  "prot.fix.secureBoot.windows":
    "前往 Settings → System → Recovery → Advanced startup → Restart now → Troubleshoot → Advanced options → UEFI Firmware Settings，在其中启用 Secure Boot。如已开启 BitLocker，请先准备好恢复密钥。",
  "prot.fix.secureBoot.linux":
    "在固件设置中启用安全启动（[code]systemctl reboot --firmware-setup[/code]）。带有已签名 shim 的发行版（Ubuntu、Fedora、Debian…）照常启动；自行编译的内核和额外模块（如 NVIDIA 的）需先用 MOK 签名。",
  "prot.fix.selinux":
    "运行 [code]sudo setenforce 1[/code]，并在 /etc/selinux/config 中设置 [code]SELINUX=enforcing[/code]，使其重启后保持开启。",
  "prot.fix.lsm":
    "Ubuntu/Debian/openSUSE：[code]sudo systemctl enable --now apparmor[/code]（并从内核命令行中删除 apparmor=0）。Fedora/RHEL：在 /etc/selinux/config 中设置 [code]SELINUX=enforcing[/code] 后重启。",

  "sharing.on": "{service} 已开启。",
  "sharing.onOpen": "{service} 已开启，网络上的任何人无需密码即可进入。",
  "sharing.off": "已关闭：{services}。",
  "sharing.allowed": "已开启，但策略允许：{services}。",
  "sharing.note.unknown": "无法判断 {what} 是否开启。",
  "sharing.note.noSystemd": "无法读取 systemd 单元状态；仅根据开放端口判断。",
  "sharing.fix.macSharing": "前往 系统设置 → 通用 → 共享（System Settings → General → Sharing），关闭 {service}。",
  "sharing.fix.macAirDrop":
    "前往 Control Center → AirDrop → Contacts Only（或关闭 AirDrop），或在访达中：Go → AirDrop → \"Allow me to be discovered by\" → Contacts Only。",
  "sharing.fix.winShares":
    "停止共享不需要的文件夹：以管理员身份打开 Computer Management → Shared Folders → Shares → 右键 → Stop Sharing，或运行 [code]Remove-SmbShare -Name SHARE[/code]。",
  "sharing.fix.winPublic":
    "前往 Settings → Network & internet → Advanced network settings → Advanced sharing settings → Public networks，关闭 Network discovery 和 File and printer sharing；并把不属于你的网络设为 Public。",
  "sharing.fix.winPrinters":
    "前往 Settings → Bluetooth & devices → Printers & scanners → 选择打印机 → Printer properties → Sharing，取消勾选 \"Share this printer\"。",
  "sharing.fix.winNearby": "前往 Settings → System → Nearby sharing，选择 My devices only 或 Off。",
  "sharing.fix.linuxSamba":
    "如不需要 Samba 就停止它：[code]sudo systemctl disable --now smbd[/code]（Fedora 上为 smb）。否则请从 /etc/samba/smb.conf 中删除 [code]guest ok = yes[/code] 和 [code]public = yes[/code]。",
  "sharing.fix.linuxNFS":
    "[code]sudo systemctl disable --now nfs-server[/code]（Debian/Ubuntu 上为 nfs-kernel-server），或把 /etc/exports 的每一行限制为指定主机，然后运行 [code]sudo exportfs -ra[/code]。",
  "sharing.fix.cups": "[code]sudo cupsctl --no-share-printers[/code]",
  "sharing.fix.linuxGnome": "前往 Settings → Sharing → File Sharing，将其关闭。",
  "extensions.notFound": "未找到受支持的浏览器或代码编辑器配置文件。",
  "extensions.found": "发现的扩展：{counts}。",
  "extensions.pass": "没有扩展被列入阻止列表或来自应用商店以外。",
  "extensions.blocked": "{n} 个扩展在组织的阻止列表中：{names}。",
  "extensions.outside": "{n} 个扩展来自应用商店以外（以未打包方式加载、从文件安装或由其他程序安装）：{names}。",
  "extensions.notAllowed": "{n} 个扩展不在组织的允许列表中：{names}。",
  "extensions.allSites": "其中 {n} 个可以读取和更改你访问的所有网站。",
  "extensions.allSitesWarn": "{n} 个扩展可以读取和更改你访问的所有网站：{names}。",
  "extensions.fix.blocked":
    "立即移除：在浏览器中打开扩展页面（[code]chrome://extensions[/code]、[code]edge://extensions[/code]、[code]brave://extensions[/code]，Firefox 中为 [code]about:addons[/code]）→ 移除（Remove）；在编辑器中打开扩展视图（Extensions view）→ 该扩展 → 卸载（Uninstall）。然后更改在该浏览器或编辑器中使用过的密码，并通知 IT。",
  "extensions.fix.outside":
    "移除不是你有意安装的扩展（浏览器扩展页面 → 移除（Remove），或编辑器扩展视图 → 卸载（Uninstall）），需要的扩展请从 Chrome Web Store、Microsoft Edge Add-ons、addons.mozilla.org 或编辑器的扩展市场安装。如果 IT 批准了某个扩展，可以将其加入策略的 allow_unpacked。",
  "extensions.fix.notAllowed": "移除组织未批准的扩展，或请 IT 将其加入允许列表。",
  "extensions.fix.allSites":
    "移除不再使用的扩展。在 Chrome、Edge 或 Brave 中限制其余扩展：扩展页面 → 详情 → 网站访问权限（Details → Site access）→ 点击时（On click）或在特定网站上（On specific sites）。",
  "passwords.notFound": "未找到受支持的浏览器配置文件。",
  "passwords.pass": "浏览器中没有保存密码，也不会提示保存密码。",
  "passwords.passSavingOn": "浏览器中没有保存密码，但 {browsers} 仍会提示保存密码：建议关闭此功能。",
  "passwords.stored": "{browsers} 中保存了密码。信息窃取类恶意软件会首先窃取浏览器中保存的密码。",
  "passwords.allowed": "策略允许：{browsers}。",
  "passwords.fix": "将这些密码迁移到密码管理器（浏览器的密码设置可以导出密码），从浏览器中删除它们，并关闭密码保存功能。",
  "passwords.fix.mac":
    "在 Mac 上，推荐使用 Apple 的“密码”App（Passwords）：系统自带，可用触控 ID 解锁，能导入浏览器导出的文件，并通过 Apple 的 iCloud Passwords 扩展在 Chrome 和 Edge 中自动填充。",
  "passwords.fix.chrome":
    "Chrome：设置 → 自动填充和密码 → Google 密码管理工具 → 设置（Settings → Autofill and passwords → Google Password Manager → Settings），关闭“提示保存密码”（Offer to save passwords）。",
  "passwords.fix.edge":
    "Edge：设置 → 密码和自动填充（旧版本为 个人资料 → 密码）（Settings → Passwords and autofill / Profiles → Passwords），关闭“提示保存密码”（Offer to save passwords）。",
  "passwords.fix.brave":
    "Brave：设置 → 自动填充和密码 → 密码管理器 → 设置（Settings → Autofill and passwords → Password Manager → Settings），关闭“提示保存密码”（Offer to save passwords）。",
  "passwords.fix.firefox":
    "Firefox：设置 → 隐私与安全 → 密码（Settings → Privacy & Security → Passwords），取消勾选“询问是否保存密码”（Ask to save passwords）。",
  "passwords.fix.other": "其他浏览器：在密码设置中关闭“提示保存密码”（Offer to save passwords）。",
  "trust.pass": "信任存储中没有添加根证书，也没有设置代理。",
  "trust.pass.ca": "信任存储中没有添加根证书。",
  "trust.pass.proxy": "没有设置代理。",
  "trust.unknown": "无法读取信任存储或代理设置（{err}）。",
  "trust.ca.found": "信任存储中添加了 {n} 个根证书：{names}。持有其私钥的人可以读取经过他们的本机 HTTPS 流量。公司的 TLS 检查和 mkcert 等开发工具也会添加此类证书。",
  "trust.ca.devTool": "其中包括开发或调试工具的证书（{tools}）：仅在使用该工具期间保留。",
  "trust.ca.hostOnly": "{n} 个证书仅对单个主机名受信任（例如远程桌面的证书）；不计入。",
  "trust.ca.unknown": "无法读取信任存储（{err}）。",
  "trust.proxy.found": "网络流量经过代理：{proxies}。不是你自己设置的代理可以看到你访问的每个网站，并读取未加密的流量。",
  "trust.proxy.local": "本机设置了一个本地代理（{proxies}），通常是 VPN 客户端或调试代理等本地工具。",
  "trust.proxy.unknown": "无法读取代理设置（{err}）。",
  "trust.fix.ca.mac":
    "打开 钥匙串访问 → 登录或系统钥匙串 → 证书（Keychain Access → login / System → Certificates），双击该证书 → 信任 → 使用此证书时：使用系统默认（Trust → When using this certificate: Use System Defaults），或将其删除。mkcert：[code]mkcert -uninstall[/code]。",
  "trust.fix.ca.win":
    "运行 [code]certmgr.msc[/code] → 受信任的根证书颁发机构 → 证书（Trusted Root Certification Authorities → Certificates），右键单击该证书 → 删除（Delete）。mkcert：[code]mkcert -uninstall[/code]。",
  "trust.fix.ca.linux":
    "删除该文件并重建证书存储：[code]sudo update-ca-certificates --fresh[/code]（Debian、Ubuntu）或 [code]sudo update-ca-trust[/code]（Fedora、RHEL）。mkcert：[code]mkcert -uninstall[/code]。",
  "trust.fix.proxy.mac":
    "前往 系统设置 → 网络 → 当前网络 → 详细信息 → 代理（System Settings → Network → your network → Details → Proxies），关闭不是你自己设置的代理。",
  "trust.fix.proxy.win":
    "前往 设置 → 网络和 Internet → 代理（Settings → Network & internet → Proxy），除非是你自己设置的，否则关闭“使用代理服务器”（Use a proxy server）和“使用设置脚本”（Use setup script）。",
  "trust.fix.proxy.linux": "前往 设置 → 网络 → 网络代理（Settings → Network → Network Proxy），除非是你自己设置的，否则将其关闭。",
  "trust.fix.proxy.env": "除非是你自己设置的，否则从 shell 启动文件或环境变量中删除 http_proxy、https_proxy 和 all_proxy。",
  "trust.fix.allow": "如果这是 IT 设置的，请让他们将其加入策略（allow_cas、allow_proxies）。",
  "pm.none": "未找到 npm、pnpm、Yarn、Bun、pip、uv、Go 或 Cargo。",
  "pm.pass": "已检查 {n} 个包管理器（{tools}）：没有削弱软件包获取方式的设置。",
  "pm.insecure": "{n} 项设置通过明文 http 获取软件包或忽略证书错误。",
  "pm.checksum": "{n} 项设置关闭了 Go 的校验和数据库。",
  "pm.scripts": "{n} 个包管理器会运行每个软件包的安装脚本。",
  "pm.releaseAge": "{n} 个包管理器会安装刚发布几分钟的版本。",
  "pm.fix.insecure":
    "使用 https:// 的仓库和索引，并删除忽略证书错误的设置：~/.npmrc 中的 [code]strict-ssl=false[/code]、pip.conf 中的 [code]trusted-host[/code]、uv.toml 中的 [code]allow-insecure-host[/code]、~/.yarnrc.yml 中的 [code]enableStrictSsl: false[/code]；Go 请运行 [code]go env -u GOINSECURE[/code]。如果公司内部仓库只支持 http，请让 IT 将其加入 policy 的 allow_hosts。",
  "pm.fix.checksum":
    "重新启用 Go 的校验和数据库：[code]go env -u GOSUMDB GONOSUMDB[/code]，并且 GOPRIVATE 中只列出公司自己的模块路径（[code]go env -w GOPRIVATE=git.example.com/*[/code]），不要用 [code]*[/code]。",
  "pm.fix.scripts":
    "默认禁止软件包运行安装脚本：[code]npm config set ignore-scripts true[/code]（确实需要脚本的包可运行 [code]npm rebuild PACKAGE[/code]）；pnpm：删除 [code]dangerouslyAllowAllBuilds[/code]；Yarn：从 ~/.yarnrc.yml 删除 [code]enableScripts: true[/code]。",
  "pm.fix.releaseAge":
    "新版本发布几天后再安装，让被劫持的版本先被发现：npm 11.10+：[code]npm config set min-release-age 3[/code]（天）；Bun：在 ~/.bunfig.toml 的 [install] 下设置 [code]minimumReleaseAge = 259200[/code]（秒）；pnpm 和 Yarn：删除把 [code]minimumReleaseAge[/code] 或 [code]npmMinimalAgeGate[/code] 设为 0 的那一行。",

  "startup.pass": "{n} 个项目在登录时或按计划自动运行；没有异常。",
  "startup.total": "共有 {n} 个项目在登录时或按计划自动运行。",
  "startup.downloadRun": "{n} 个项目每次启动都会下载代码并运行。",
  "startup.suspicious": "{n} 个项目从临时、下载或隐藏文件夹启动程序。",
  "startup.writable": "{n} 个项目启动的程序任何用户都能修改。",
  "startup.missing": "{n} 个项目指向已不存在的程序。",
  "startup.fix.mac":
    "逐一查明列出的项目。如果不认识，就将其移除：[code]launchctl bootout gui/$(id -u)/LABEL[/code]，然后从 ~/Library/LaunchAgents 删除其 .plist（/Library 中的项目需要管理员权限）；System Settings → General → Login Items & Extensions 中也能看到它们。如果有项目会下载并运行代码，请进行恶意软件扫描，并更改在这台 Mac 上使用过的密码。程序已不存在的项目是已卸载应用的残留，直接删除即可。",
  "startup.fix.win":
    "逐一查明列出的项目。如果不认识，就将其关闭：Task Manager → Startup apps → Disable，Task Scheduler → 该任务 → Disable，或从 Startup 文件夹（[code]shell:startup[/code]）删除其快捷方式。如果有项目会下载并运行代码，请用 Windows Security 进行完整扫描，并更改在这台电脑上使用过的密码。程序已不存在的项目是已卸载应用的残留。",
  "startup.fix.linux":
    "逐一查明列出的项目。如果不认识，就将其移除：删除 ~/.config/autostart 中对应的 .desktop 文件、[code]systemctl --user disable --now UNIT[/code]，或 [code]crontab -e[/code]。如果有项目会下载并运行代码，请检查机器上的恶意软件，并更改在这台机器上使用过的密码。",

  "backup.unsupported": "未在 {os} 上检查：没有可读取的标准备份或设备查找服务。",
  "backup.unencrypted": "{n} 个 Time Machine 备份未加密：拿到磁盘的人都能读取你的文件。",
  "backup.stale": "{n} 个备份已超过 {max} 天。",
  "backup.none": "尚未设置备份：笔记本电脑丢失或损坏时，文件也会随之丢失。",
  "backup.findMyOff.mac": "Find My Mac 已关闭：丢失的 Mac 无法远程定位、锁定或抹掉。",
  "backup.findMyOff.win": "Find my device 已关闭：丢失的电脑无法远程定位或锁定。",
  "backup.on": "备份保存到 {n} 个位置。",
  "backup.noneAllowed": "尚未设置 Time Machine 备份（policy 不要求）。",
  "backup.findMyOn.mac": "Find My Mac 已开启。",
  "backup.findMyOn.win": "Find my device 已开启。",
  "backup.unknown.mac": "无法确定是否已设置 Time Machine（读取其设置可能需要 Full Disk Access）。",
  "backup.findMyUnknown": "无法确定设备能否被远程定位。",
  "backup.win.notRead": "未检查 Windows 备份（File History、Windows Backup、OneDrive）。",
  "backup.fix.mac.encrypt":
    "System Settings → General → Time Machine → 选择该磁盘 → Remove Disk，然后重新 Add Backup Disk 并开启 \"Encrypt backup\"（在较新的 macOS 上无法直接加密已有备份，因此磁盘会被抹掉）。",
  "backup.fix.mac.stale": "连接备份磁盘，然后在菜单栏中选择 Time Machine → Back Up Now。",
  "backup.fix.mac.setup": "System Settings → General → Time Machine → Add Backup Disk，并开启 \"Encrypt backup\"；或询问 IT 这台 Mac 应如何备份。",
  "backup.fix.mac.findMy": "System Settings → 你的名字（Apple Account）→ iCloud → Find My Mac → 开启。",
  "backup.fix.win.findMy": "Settings → Privacy & security → Find my device → 开启（需要 Microsoft 账户和定位服务）。",
};
