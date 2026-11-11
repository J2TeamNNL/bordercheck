// Vietnamese for the checks' summaries and fixes (keys: checks.en.json,
// generated from internal/msg/catalog.go). Same syntax as en.ts, plus typed
// parameters ({after:dur}, {ago:ago}, {until:date}); see checktext.ts.
//
// Menu paths and setting names stay exactly as the English OS shows them
// (most people in Vietnam run macOS and Windows in English), inside a
// Vietnamese sentence: "Mở System Settings → Network → Firewall rồi bật lên."
// Commands, flags, paths, product names and URLs are never translated.
// Terms follow vi.ts: secret, token, policy (bordercheck's), tunnel, AI agent,
// container, passphrase, sandbox stay as is; firewall tường lửa; a Windows
// "policy" is a Group Policy: chính sách (Group Policy).

import type { CheckCatalog } from "../checktext";

export const checksVi: CheckCatalog = {
  "check.unsupported": "Chưa hỗ trợ trên {os}.",
  "check.timeout": "Không chạy xong trong {after:dur} nên đã bị dừng; các mục kiểm tra khác không bị ảnh hưởng.",
  "check.interrupted": "Bị ngắt trước khi chạy xong.",
  "check.moreAllowed": "Còn {n} mục khác được policy cho phép.",

  "compromise.startupDownloadRun": "Một chương trình được đặt để tự chạy khi khởi động tải code từ Internet về rồi chạy nó.",
  "compromise.blockedExtension": "Một extension mà tổ chức của bạn đã chặn vì có hại đang được cài.",
  "compromise.crackTool": "Một công cụ crack hoặc kích hoạt bản quyền lậu đang được cài.",
  "compromise.kmsEmulator": "{product} được kích hoạt bằng một máy chủ kích hoạt giả chạy ngay trên máy này.",

  "firewall.mac.off": "Tường lửa macOS đang tắt.",
  "firewall.mac.off.fix":
    "Mở System Settings → Network → Firewall rồi bật lên. Hoặc chạy: [code]sudo /usr/libexec/ApplicationFirewall/socketfilterfw --setglobalstate on[/code]",
  "firewall.mac.stealthOff": "Tường lửa đang bật nhưng stealth mode đang tắt: máy Mac này vẫn trả lời các gói dò quét từ mạng.",
  "firewall.mac.stealthOff.fix":
    "Mở System Settings → Network → Firewall → Options rồi bật stealth mode. Hoặc chạy: [code]sudo /usr/libexec/ApplicationFirewall/socketfilterfw --setstealthmode on[/code]",
  "firewall.mac.on": "Tường lửa đang bật.",
  "firewall.mac.onStealth": "Tường lửa và stealth mode đều đang bật.",

  "firewall.win.noProfiles": "Windows không trả về profile tường lửa nào",
  "firewall.win.on": "Windows Firewall đang bật cho mọi profile.",
  "firewall.win.off": "Windows Firewall đang tắt cho: {profiles}.",
  "firewall.win.off.fix":
    "Mở Windows Security → Firewall & network protection rồi bật cho mọi mạng. Hoặc chạy với quyền administrator: [code]Set-NetFirewallProfile -All -Enabled True[/code]",

  "firewall.linux.zoneOpenPorts": "firewalld đang bật, nhưng zone mặc định {zone} mở mọi cổng từ 1025 đến 65535.",
  "firewall.linux.zoneTrusted": "firewalld đang bật, nhưng zone mặc định {zone} cho mọi kết nối đi vào.",
  "firewall.linux.zone.fix":
    "[code]sudo firewall-cmd --set-default-zone=public[/code] (chỉ cho phép SSH và DHCPv6); mở thêm những gì cần bằng [code]--add-service[/code].",
  "firewall.linux.firewalldOn": "firewalld đang bật.",
  "firewall.linux.firewalldOnZone": "firewalld đang bật (zone mặc định {zone}).",
  "firewall.linux.ufwOn": "ufw đang bật.",
  "firewall.linux.ufwOnConf": "ufw đang bật (bật trong /etc/ufw/ufw.conf).",
  "firewall.linux.inputDrops": "Tường lửa mặc định chặn kết nối đến (policy của chain input).",
  "firewall.linux.noDrop": "Không có tường lửa nào chặn kết nối đến: không chain input nào của nftables hay iptables mặc định là drop.",
  "firewall.linux.fix":
    "Ubuntu/Debian: [code]sudo ufw enable[/code] (chặn kết nối đến, cho phép kết nối đi). Fedora/RHEL/openSUSE: [code]sudo systemctl enable --now firewalld[/code].",
  "firewall.linux.rootOnly":
    "Service {services} có nạp luật tường lửa, nhưng chỉ root mới đọc được các luật này, nên bordercheck không biết chúng có chặn kết nối đến hay không. Chạy [code]sudo bordercheck -only firewall[/code] để kiểm tra.",
  "firewall.linux.unknown":
    "Không xác định được khi không có quyền root: không có cấu hình ufw và systemd không cho biết service tường lửa nào đang chạy. Chạy [code]sudo bordercheck -only firewall[/code] để kiểm tra các luật.",
  "firewall.linux.noneUfwOff":
    "Không có tường lửa nào đang bật: ufw đã cài nhưng đang tắt, và không có service firewalld, nftables hay iptables nào chạy. (Nếu bạn nạp luật theo cách khác, [code]sudo bordercheck -only firewall[/code] sẽ kiểm tra chúng.)",
  "firewall.linux.noneNoUfw":
    "Không có tường lửa nào đang bật: chưa cài ufw, và không có service firewalld, nftables hay iptables nào chạy. (Nếu bạn nạp luật theo cách khác, [code]sudo bordercheck -only firewall[/code] sẽ kiểm tra chúng.)",

  "outbound.found": "Kết nối đi ra được {apps} kiểm soát.",
  "outbound.found.winFw": "Windows Firewall mặc định chặn kết nối đi ra.",
  "outbound.none.mac": "Chưa có tường lửa chiều đi (như LuLu hoặc Little Snitch) để kiểm soát ứng dụng nào được kết nối ra ngoài.",
  "outbound.none.win":
    "Chưa có tường lửa chiều đi (như simplewall, hoặc Windows Firewall đặt mặc định chặn kết nối đi ra) để kiểm soát ứng dụng nào được kết nối ra ngoài.",
  "outbound.fix.mac":
    "Cài một tường lửa chiều đi miễn phí như LuLu của Objective-See (https://objective-see.org/products/lulu.html, mã nguồn mở): LuLu hỏi bạn trước khi một ứng dụng kết nối ra ngoài, nhờ vậy mã độc gửi tín hiệu về máy chủ của nó hay chương trình lén gửi dữ liệu của bạn đi đều lộ diện.",
  "outbound.fix.win":
    "Cài simplewall (https://github.com/henrypp/simplewall, miễn phí, mã nguồn mở). Khi đã bật bộ lọc, simplewall chặn mọi ứng dụng bạn chưa cho phép, nên lần đầu mỗi ứng dụng kết nối nó sẽ hỏi bạn; nhờ vậy mã độc gửi tín hiệu về máy chủ của nó hay chương trình lén gửi dữ liệu của bạn đi đều lộ diện. Hoặc nhờ IT đặt Windows Firewall mặc định chặn kết nối đi ra.",

  "disk.mac.on": "FileVault đang bật.",
  "disk.mac.off": "FileVault đang tắt: ai lấy được máy Mac này cũng đọc được ổ đĩa.",
  "disk.mac.off.fix": "Mở System Settings → Privacy & Security → FileVault rồi chọn Turn On.",
  "disk.mac.partial": "FileVault chưa bật hoàn toàn: {status}",
  "disk.win.on": "BitLocker đang bật cho ổ hệ thống.",
  "disk.win.off": "BitLocker đang tắt: ai lấy được máy này cũng đọc được ổ đĩa.",
  "disk.win.unknown": "Windows không báo trạng thái BitLocker của ổ hệ thống.",
  "disk.win.partial": "BitLocker chưa bật hoàn toàn cho ổ hệ thống (trạng thái {code}).",
  "disk.win.fix":
    "Mở Settings → Privacy & security → Device encryption, hoặc Control Panel → BitLocker Drive Encryption, rồi bật lên.",
  "disk.linux.noRoot": "Không tìm thấy filesystem gốc trong /proc/self/mounts.",
  "disk.linux.plain": "{mount} không nằm trên ổ đĩa được mã hoá: ai lấy được máy này cũng đọc được.",
  "disk.linux.plainBoth": "{mount} và {other} không nằm trên ổ đĩa được mã hoá: ai lấy được máy này cũng đọc được.",
  "disk.linux.plain.fix":
    "Linux khó mã hoá một ổ đĩa đang dùng: hãy sao lưu, cài lại và chọn \"Encrypt the new installation\" (LUKS), rồi khôi phục dữ liệu. Người có kinh nghiệm: chạy [code]cryptsetup reencrypt --encrypt[/code] từ USB live.",
  "disk.linux.unknown": "Không xác định được ổ đĩa có được mã hoá hay không.",
  "disk.linux.unknownZFS": "{mount}: ZFS, không rõ trạng thái mã hoá.",
  "disk.linux.unknownVirtual": "{mount}: {fstype}, là hệ thống live hoặc container.",
  "disk.linux.unknownDevice": "{mount}: không tìm thấy thiết bị bên dưới {source}.",
  "disk.linux.onLUKS": "Ổ đĩa đã được mã hoá (LUKS / dm-crypt).",
  "disk.linux.onZFS": "Ổ đĩa đã được mã hoá (mã hoá gốc của ZFS).",

  "listeners.pass": "{n} socket đang lắng nghe, tất cả chỉ trên localhost.",
  "listeners.exposed": "{n} cổng có thể được truy cập từ máy khác (LAN, Wi-Fi, Tailscale).",
  "listeners.infoOnly":
    "Có {n} cổng truy cập được từ máy khác, đều do các dịch vụ quen thuộc như AirPlay Receiver hoặc Dropbox LAN sync nắm giữ: chỉ liệt kê để biết, không cần sửa.",
  "listeners.fix":
    "Cho dev server chỉ lắng nghe trên 127.0.0.1 (Vite: bỏ [code]--host[/code]; Docker: [code]-p 127.0.0.1:PORT:PORT[/code]) và tắt những gì không cần. Muốn chia sẻ thì dùng Cloudflare Tunnel thay vì mở cổng.",
  "listeners.note.mac": "Chỉ thấy được tiến trình của bạn; chạy với sudo để thấy cả service hệ thống.",
  "listeners.note.linux": "Chỉ hiện tên tiến trình của bạn; chạy với sudo để thấy tên service hệ thống.",
  "listeners.note.linuxNoSS": "Không tìm thấy ss nên không biết tên tiến trình.",

  "tailscale.notInstalled": "Chưa cài Tailscale.",
  "tailscale.denied":
    "Trên máy này chỉ root hoặc operator của Tailscale mới đọc được thiết lập của Tailscale. Chạy [code]sudo tailscale set --operator=$USER[/code] một lần, hoặc [code]sudo bordercheck -only tailscale[/code]. ({err})",
  "tailscale.unreadable": "Không đọc được thiết lập của Tailscale; Tailscale có đang chạy không? ({err})",
  "tailscale.badPrefs": "kết quả không như mong đợi từ `tailscale debug prefs`",
  "tailscale.shieldsUp": "Shields up: các thiết bị khác trong tailnet không mở được kết nối tới máy này.",
  "tailscale.open":
    "Tailscale đang nhận kết nối đến. Lưu lượng Tailscale có thể đi vòng qua tường lửa của hệ điều hành, nên mọi thiết bị trong tailnet, kể cả thiết bị đã bị chiếm quyền, đều truy cập được mọi cổng máy này đang lắng nghe.",
  "tailscale.open.fix":
    "Mở Tailscale → Settings rồi bỏ chọn \"Allow incoming connections\". Hoặc chạy: [code]tailscale set --shields-up[/code]. Quản trị viên: nên giới hạn thêm thiết bị nào được kết nối tới thiết bị nào bằng ACL của tailnet.",

  "docker.notInstalled": "Chưa cài Docker.",
  "docker.noPermission": "Docker đã được cài nhưng người dùng này không có quyền dùng (không thuộc nhóm docker), nên chưa kiểm tra được container.",
  "docker.notRunning": "Docker không chạy.",
  "docker.noContainers": "Không có container nào đang chạy.",
  "docker.pass": "{n} container đang chạy, tất cả đều được cô lập.",
  "docker.problems": "{n} vấn đề trong {containers} container đang chạy.",
  "docker.fix":
    "Chỉ publish cổng trên localhost ([code]-p 127.0.0.1:5432:5432[/code]). Không dùng [code]--network host[/code] hay [code]--privileged[/code]. Chỉ mount thư mục dự án; không bao giờ mount Docker socket, thư mục home hay thư mục chứa thông tin đăng nhập.",

  "secrets.pass": "Không có secret dạng văn bản thuần trong file shell, lịch sử shell, file thông tin đăng nhập hay file .env.",
  "secrets.found": "{n} secret dạng văn bản thuần trong {files} file.",
  "secrets.foundProd": "{n} secret dạng văn bản thuần trong {files} file, {prod} secret được đánh dấu production.",
  "secrets.incomplete": "Lần quét đã hết thời gian cho phép nên một số thư mục chưa được kiểm tra.",
  "ignore.more": "Ngoài ra còn {n} mục bạn đã bỏ qua.",
  "ignore.all": "Các mục tìm thấy đều là {n} mục bạn đã đánh dấu là không nhạy cảm.",
  "ignore.off": "Policy của máy này không cho phép bỏ qua các mục của mục kiểm tra này, nên danh sách của bạn không được áp dụng cho nó.",
  "ignore.unreadable": "Không đọc được danh sách các mục bạn đã bỏ qua, nên không mục nào được bỏ qua; hãy chạy [code]bordercheck ignore -list[/code].",
  "secrets.fix.mac":
    "Chuyển từng key vào Keychain, có Touch ID bảo vệ, bằng touchenv (https://github.com/ptrinh/touch-env): [code]touchenv set NAME[/code], rồi xoá dòng hoặc file đó.",
  "secrets.fix.win":
    "Chuyển từng key vào Windows Credential Manager hoặc CLI của trình quản lý mật khẩu (ví dụ 1Password [code]op run[/code]), rồi xoá dòng hoặc file đó.",
  "secrets.fix.linux":
    "Chuyển từng key vào keyring của desktop ([code]secret-tool store[/code] / [code]secret-tool lookup[/code], thuộc libsecret) hoặc CLI của trình quản lý mật khẩu như pass hay 1Password [code]op run[/code], rồi xoá dòng hoặc file đó.",
  "secrets.fix.other": "Chuyển từng key vào trình quản lý mật khẩu hoặc keyring của hệ điều hành, rồi xoá dòng hoặc file đó.",
  "secrets.fix.rotate": 
    "Với key nằm trong lịch sử shell, xoá các dòng đó là đủ. Chỉ cần đổi (rotate) key khi có bằng chứng máy này đã bị xâm nhập.",

  "updates.belowMin": "{os} cũ hơn phiên bản tối thiểu {min} mà policy yêu cầu.",
  "updates.belowMinWin": "{os} cũ hơn phiên bản tối thiểu build {min} mà policy yêu cầu.",
  "updates.autoUnknown": "Không xác định được cập nhật tự động có đang bật hay không.",
  "updates.autoOff.mac": "Cập nhật tự động đang tắt ({settings}).",
  "updates.autoOff.win": "Cập nhật tự động đang tắt.",
  "updates.autoOff.winService": "Service Windows Update đang bị tắt (Disabled).",
  "updates.autoOff.winPolicy": "Một chính sách (Group Policy) đang tắt cập nhật tự động.",
  "updates.autoOff.winNotify": "Một chính sách (Group Policy) chỉ cho phép thông báo khi có bản cập nhật.",
  "updates.autoOff.apt": "Cập nhật tự động đang tắt (unattended-upgrades chưa được cài hoặc chưa bật).",
  "updates.autoOff.dnf":
    "Cập nhật tự động đang tắt (không có timer dnf-automatic nào được bật và GNOME Software không tự tải bản cập nhật).",
  "updates.paused": "Cập nhật đang tạm dừng đến {until:date}.",
  "updates.checkStale": "Hệ điều hành kiểm tra cập nhật lần cuối {ago:ago} (policy: mỗi {max} ngày).",
  "updates.waitingLong": "{name} đã chờ cài đặt {days} ngày (policy: {max} ngày).",
  "updates.ready": "{name} đã sẵn sàng để cài (phát hiện {ago:ago}).",
  "updates.readyUndated": "{name} đã sẵn sàng để cài.",
  "updates.countWaitingLong": "{n} bản cập nhật đang chờ và đã {days} ngày không cài gì (policy: {max} ngày).",
  "updates.countReady": "{n} bản cập nhật đã sẵn sàng để cài.",
  "updates.reboot": "Bản cập nhật đã cài nhưng cần khởi động lại để có hiệu lực.",
  "updates.noneInstalled": "Đã {days} ngày không cài bản cập nhật hệ điều hành nào (policy: {max} ngày).",
  "updates.browserStale":
    "{browser} đã {days} ngày không cập nhật (policy: {max} ngày); trình duyệt ra bản vá bảo mật vài tuần một lần.",
  "updates.browserBelowMin": "{browser} {version} cũ hơn phiên bản tối thiểu {min} mà policy yêu cầu.",
  "updates.note.macSettings": "Không đọc được thiết lập của Software Update.",
  "updates.note.winLastInstall": "Không đọc được thời điểm Windows cài bản cập nhật gần nhất.",
  "updates.note.gnomeSoftware": "GNOME Software tự tải bản cập nhật; chúng sẽ được cài khi khởi động lại.",
  "updates.state": "{os}.",
  "updates.stateAuto": "{os}, cập nhật tự động đang bật.",
  "updates.stateChecked": "{os}, kiểm tra cập nhật lần cuối {ago:ago}.",
  "updates.stateAutoChecked": "{os}, cập nhật tự động đang bật, kiểm tra cập nhật lần cuối {ago:ago}.",
  "updates.noneWaiting": "Không có bản cập nhật nào đang chờ.",
  "updates.browsersFresh": "{n} trình duyệt được cập nhật gần đây.",
  "updates.fix.browser":
    "Mở trang About của từng trình duyệt (Chrome/Edge/Brave: Settings → About; Firefox: Help → About Firefox) để cập nhật, rồi mở lại trình duyệt; gỡ những trình duyệt bạn không dùng.",
  "updates.fix.macos.upgrade": "Mở System Settings → General → Software Update rồi nâng cấp lên bản macOS còn được hỗ trợ.",
  "updates.fix.macos.auto":
    "Mở System Settings → General → Software Update → Automatic updates (i), bật Check for updates, Download new updates when available và Install Security Responses and system files.",
  "updates.fix.macos.pending": "Mở System Settings → General → Software Update rồi chọn Update Now.",
  "updates.fix.macos.check": "Kết nối internet rồi mở System Settings → General → Software Update để macOS kiểm tra lại.",
  "updates.fix.windows.upgrade": "Mở Settings → Windows Update rồi cài bản feature update mới nhất của Windows 11.",
  "updates.fix.windows.auto":
    "Windows Update phải chạy tự động: service Windows Update (wuauserv) không được ở trạng thái Disabled và không chính sách nào được tắt cập nhật tự động. Nếu Settings → Windows Update báo một số thiết lập do tổ chức của bạn quản lý, hãy liên hệ IT.",
  "updates.fix.windows.paused": "Mở Settings → Windows Update rồi chọn Resume updates.",
  "updates.fix.windows.pending": "Mở Settings → Windows Update → Check for updates, cài hết các bản cập nhật rồi khởi động lại.",
  "updates.fix.windows.check": "Mở Settings → Windows Update rồi chọn Check for updates.",
  "updates.fix.windows.reboot": "Khởi động lại máy để hoàn tất việc cài bản cập nhật.",
  "updates.fix.debian.upgrade": "Nâng cấp lên bản phát hành còn được hỗ trợ (Ubuntu: [code]sudo do-release-upgrade[/code]).",
  "updates.fix.debian.auto": "[code]sudo apt install unattended-upgrades && sudo dpkg-reconfigure -plow unattended-upgrades[/code]",
  "updates.fix.debian.pending": "[code]sudo apt update && sudo apt full-upgrade[/code]",
  "updates.fix.debian.check": "[code]sudo apt update[/code]",
  "updates.fix.debian.reboot": "Khởi động lại để hoàn tất việc cài bản cập nhật (/var/run/reboot-required đang tồn tại).",
  "updates.fix.fedora.upgrade":
    "Nâng cấp lên bản phát hành còn được hỗ trợ: [code]sudo dnf system-upgrade[/code] (xem hướng dẫn nâng cấp của Fedora).",
  "updates.fix.fedora.auto":
    "[code]sudo dnf install dnf-automatic[/code], đặt [code]apply_updates = yes[/code] trong /etc/dnf/automatic.conf, rồi chạy [code]sudo systemctl enable --now dnf-automatic.timer[/code] (dùng dnf5-automatic.timer nếu là dnf5).",
  "updates.fix.fedora.pending": "[code]sudo dnf upgrade --refresh[/code]",
  "updates.fix.fedora.check": "[code]sudo dnf check-update --refresh[/code]",
  "updates.fix.arch.pending": "[code]sudo pacman -Syu[/code]",
  "updates.fix.generic": "Cài các bản cập nhật mới nhất bằng trình quản lý gói của bản phân phối, rồi khởi động lại.",

  "screenlock.noDesktop": "Không có môi trường desktop nào mà bordercheck đọc được thiết lập khoá màn hình (hỗ trợ GNOME và KDE Plasma).",
  "screenlock.unknown": "Không xác định được có cần mật khẩu sau khi máy ngủ hay khi màn hình khoá hay không.",
  "screenlock.passwordUnknown": "Không xác định được có cần mật khẩu sau khi máy ngủ hay không.",
  "screenlock.noPassword": "Không cần mật khẩu để vào lại máy sau khi máy ngủ hoặc sau trình bảo vệ màn hình.",
  "screenlock.idleUnknown": "Không xác định được khi nào màn hình tự khoá.",
  "screenlock.never": "Màn hình không bao giờ tự khoá khi bạn rời khỏi máy.",
  "screenlock.tooLate": "Màn hình chỉ khoá sau {after:dur} không hoạt động (policy: {max:dur}).",
  "screenlock.passBoth": "Cần mật khẩu sau khi máy ngủ, và màn hình tự khoá sau {after:dur} không hoạt động.",
  "screenlock.passPassword": "Cần mật khẩu sau khi máy ngủ.",
  "screenlock.passIdle": "Màn hình tự khoá sau {after:dur} không hoạt động.",
  "screenlock.fix.macos.password":
    "Mở System Settings → Lock Screen, đặt \"Require password after screen saver begins or display is turned off\" thành Immediately.",
  "screenlock.fix.macos.idle":
    "Mở System Settings → Lock Screen, đặt \"Turn display off on battery when inactive\" và \"…on power adapter when inactive\" (cả \"Start Screen Saver when inactive\" nếu có dùng) không dài hơn giới hạn của policy.",
  "screenlock.fix.windows.password":
    "Mở Settings → Accounts → Sign-in options, ở mục \"If you've been away, when should Windows require you to sign in again?\" chọn When PC wakes up from sleep.",
  "screenlock.fix.windows.idle":
    "Mở Settings → System → Power & battery → Screen, sleep & hibernate timeouts, cho máy ngủ trong giới hạn của policy (cả khi dùng pin lẫn khi cắm sạc); hoặc vào Settings → Personalization → Lock screen → Screen saver, đặt thời gian chờ ngắn và bật \"On resume, display logon screen\".",
  "screenlock.fix.gnome.password":
    "Mở Settings → Privacy & Security → Screen Lock, bật Automatic Screen Lock và Lock Screen on Suspend, đặt Automatic Screen Lock Delay thành Screen Turns Off.",
  "screenlock.fix.gnome.idle":
    "Mở Settings → Power → Screen Blank, đặt không dài hơn giới hạn của policy, và bật Automatic Screen Lock trong Settings → Privacy & Security → Screen Lock.",
  "screenlock.fix.kde.password": "Mở System Settings → Screen Locking rồi bật \"After waking from sleep\".",
  "screenlock.fix.kde.idle": "Mở System Settings → Screen Locking, đặt \"Lock screen automatically\" không dài hơn giới hạn của policy.",

  "remote.on": "{service} đang bật.",
  "remote.off": "Đang tắt: {services}.",
  "remote.allowed": "Đang bật nhưng được policy cho phép: {services}.",
  "remote.note.noSystemd": "Không đọc được trạng thái unit của systemd; chỉ đánh giá dựa trên các cổng đang mở.",
  "remote.fix.macSharing": "Mở System Settings → General → Sharing rồi tắt {service}.",
  "remote.fix.macGuest": "Mở System Settings → Users & Groups → Guest User rồi tắt \"Allow guests to log in to this computer\".",
  "remote.fix.winRDP": "Mở Settings → System → Remote Desktop rồi chuyển sang Off (nếu do chính sách của tổ chức bật, hãy liên hệ IT).",
  "remote.fix.winRM":
    "Với quyền administrator: [code]winrm delete winrm/config/Listener?Address=*+Transport=HTTP[/code], rồi [code]Stop-Service WinRM; Set-Service WinRM -StartupType Disabled[/code].",
  "remote.fix.winSSH":
    "Với quyền administrator: [code]Stop-Service sshd; Set-Service sshd -StartupType Disabled[/code]. Hoặc mở Settings → System → Optional features rồi gỡ OpenSSH Server.",
  "remote.fix.winGuest":
    "Với quyền administrator: mở Computer Management → Local Users and Groups → Users → Guest rồi tích \"Account is disabled\".",
  "remote.fix.linuxSSH":
    "[code]sudo systemctl disable --now ssh.service ssh.socket[/code] (Debian/Ubuntu) hoặc sshd.service (Fedora/Arch), hoặc gỡ openssh-server.",
  "remote.fix.linuxRDP":
    "GNOME: mở Settings → System → Remote Desktop rồi tắt Desktop Sharing và Remote Login. xrdp: [code]sudo systemctl disable --now xrdp[/code].",
  "remote.fix.linuxVNC": "Tắt chia sẻ màn hình (GNOME: Settings → Sharing; KDE: Krfb) và dừng các VNC server như x11vnc hay TigerVNC.",
  "remote.fix.linuxGuest": "Đặt [code]allow-guest=false[/code] trong mục [Seat:*] của /etc/lightdm/lightdm.conf.",

  "sshkeys.pass":
    "Đã kiểm tra {n} private key: tất cả đều có passphrase và chỉ chủ sở hữu đọc được; không có authorized_keys.",
  "sshkeys.hardware": "{n} key phần cứng cần thiết bị token đi kèm mới dùng được, nên không sao.",
  "sshkeys.noPassphrase": "{n} private key không có passphrase.",
  "sshkeys.readable": "Người dùng khác đọc được {n} key.",
  "sshkeys.authorized": "{n} key trong authorized_keys có thể đăng nhập vào máy này.",
  "sshkeys.fix.passphrase":
    "Đặt passphrase: [code]ssh-keygen -p -f <key>[/code] (key vẫn giữ nguyên, không phải tải lên lại), hoặc chuyển sang key phần cứng ([code]ssh-keygen -t ed25519-sk[/code]) hay SSH agent của trình quản lý mật khẩu.",
  "sshkeys.fix.mac": "Để Keychain nhớ passphrase: [code]ssh-add --apple-use-keychain <key>[/code].",
  "sshkeys.fix.win": "Để service ssh-agent của Windows giữ key đã mở khoá: [code]ssh-add <key>[/code].",
  "sshkeys.fix.rest":
    "Chỉ cho chủ sở hữu đọc key: [code]chmod 600 <key>[/code]. Xoá những dòng trong authorized_keys mà bạn không nhận ra, và tắt SSH server (Remote Login) nếu không dùng.",
  "sshkeys.config.all": "{n} thiết lập trong cấu hình SSH client làm yếu mọi kết nối.",
  "sshkeys.config.some": "{n} thiết lập trong cấu hình SSH client làm yếu kết nối tới một số host.",
  "sshkeys.fix.config":
    "Trong ~/.ssh/config, bỏ [code]ForwardAgent yes[/code] (chỉ dùng [code]ssh -A[/code] hoặc [code]ProxyJump[/code] khi thật cần: server nhận agent của bạn có thể dùng key của bạn trong lúc bạn đăng nhập), và bỏ [code]StrictHostKeyChecking no[/code] cùng [code]UserKnownHostsFile /dev/null[/code] (dùng [code]StrictHostKeyChecking accept-new[/code] thay thế), để nhận ra khi một server bỗng đổi sang key khác.",

  "tunnels.pass": "Không có tunnel nào đưa máy này ra internet hay tailnet.",
  "tunnels.found": "{n} tunnel đang đưa máy này ra ngoài mạng nội bộ.",
  "tunnels.noProcs": "Không liệt kê được các tiến trình ({err}).",
  "tunnels.noServe": "Không đọc được `tailscale serve status`.",
  "tunnels.fix":
    "Dừng các tunnel không dùng ([code]tailscale funnel reset[/code], [code]tailscale serve reset[/code]; thoát ngrok, [code]ssh -R[/code]…). Nếu buộc phải chia sẻ, hãy dùng một Cloudflare Tunnel có tên, đặt sau Cloudflare Access, thay vì URL công khai.",

  "ai.pass": "Đã kiểm tra {n} file cấu hình AI agent: không có token dạng văn bản thuần, các rào chắn an toàn vẫn bật.",
  "ai.tokens": "{n} token dạng văn bản thuần trong cấu hình AI agent / MCP.",
  "ai.guards": "{n} thiết lập của agent bỏ qua bước xác nhận hoặc sandbox.",
  "ai.fix":
    "Không để token trong cấu hình MCP: hãy tham chiếu biến môi trường ([code]\"env\": {\"API_KEY\": \"${env:API_KEY}\"}[/code] hoặc cơ chế input/secret riêng của agent) và nạp giá trị từ keychain của hệ điều hành ([code]touchenv run[/code] trên macOS). Bật lại bước xác nhận và sandbox: nếu không, một đoạn prompt injection trong bất kỳ file, trang web hay issue nào agent đọc đều có thể chạy lệnh dưới danh nghĩa của bạn.",

  "cracked.pass": "Không có dấu vết của Adobe, Autodesk, Windows hay Microsoft Office bẻ khoá.",
  "cracked.found":
    "Có dấu hiệu phần mềm bẻ khoá ({products}). Bản crack là con đường phổ biến để cài mã độc đánh cắp mật khẩu và token.",
  "cracked.fix":
    "Gỡ phần mềm bẻ khoá cùng mọi công cụ crack hoặc kích hoạt, xoá các dòng mà bản crack đã thêm vào file hosts, rồi quét mã độc toàn bộ máy: bản crack thường kèm mã độc đánh cắp thông tin. Nếu quét ra mã độc, hãy đổi các mật khẩu và token đã dùng trên máy này. Hãy đề nghị IT cấp bản có bản quyền.",
  "cracked.fixAlternatives":
    "Gỡ phần mềm bẻ khoá cùng mọi công cụ crack hoặc kích hoạt, xoá các dòng mà bản crack đã thêm vào file hosts, rồi quét mã độc toàn bộ máy: bản crack thường kèm mã độc đánh cắp thông tin. Nếu quét ra mã độc, hãy đổi các mật khẩu và token đã dùng trên máy này. Hãy đề nghị IT cấp bản có bản quyền, hoặc dùng phần mềm thay thế miễn phí, mã nguồn mở của ArtCraft (https://getartcraft.com).",
  "cracked.alt.adobe":
    "Adobe: PhotoCraft thay cho Photoshop, VectorCraft thay cho Illustrator, FilmCraft thay cho Premiere Pro, LightCraft thay cho Lightroom, EffectCraft thay cho After Effects, DesignCraft thay cho InDesign, PdfCraft thay cho Acrobat.",
  "cracked.alt.office": "Microsoft Office: WordCraft thay cho Word, GridCraft thay cho Excel, DeckCraft thay cho PowerPoint.",
  "cracked.alt.autodesk": "Autodesk: CADCraft thay cho AutoCAD.",

  "admin.pass.standard": "Tài khoản này là người dùng thường (standard user).",
  "admin.pass.allowed": "Tài khoản này là quản trị viên, và chính sách cho phép điều đó.",
  "admin.pass.sudo": "Không có quy tắc sudo nào chạy được mà không cần mật khẩu.",
  "admin.isAdmin":
    "Tài khoản này là quản trị viên ({groups}): mã độc bạn lỡ chạy chỉ cần bạn đồng ý một lần là chiếm được toàn bộ máy.",
  "admin.nopasswd":
    "sudo chạy mọi lệnh với quyền root mà không cần mật khẩu ({where}): bất kỳ chương trình nào bạn chạy cũng có thể âm thầm chiếm toàn bộ máy.",
  "admin.nopasswdSome":
    "sudo chạy một số lệnh với quyền root mà không cần mật khẩu ({where}); nhiều lệnh có thể bị lợi dụng để mở shell root.",
  "admin.uacOff":
    "User Account Control đang tắt (EnableLUA = 0): các chương trình chạy với toàn quyền quản trị mà không hỏi.",
  "admin.uacNoPrompt":
    "UAC nâng quyền cho quản trị viên mà không hỏi (ConsentPromptBehaviorAdmin = 0): bất kỳ chương trình nào cũng có thể âm thầm lấy quyền quản trị.",
  "admin.builtinAdmin": "Tài khoản Administrator có sẵn của Windows đang bật.",
  "admin.note.unknown": "Không xác định được tài khoản này có phải quản trị viên hay không.",
  "admin.note.sudo": "Không hỏi được sudo những quy tắc nào áp dụng ({err}).",
  "admin.note.uac": "Không đọc được thiết lập User Account Control.",
  "admin.fix.mac":
    "Tạo một tài khoản quản trị riêng (System Settings → Users & Groups → Add User…, loại Administrator), đăng nhập vào đó một lần, rồi tắt \"Allow this user to administer this computer\" cho tài khoản dùng hằng ngày. Từ đó, khi được hỏi quyền quản trị, hãy nhập tên và mật khẩu của tài khoản kia.",
  "admin.fix.win":
    "Tạo một tài khoản quản trị riêng (Settings → Accounts → Other users → Add account, rồi Change account type → Administrator), đăng nhập vào đó một lần, rồi đổi loại tài khoản dùng hằng ngày thành Standard User. Khi đó UAC sẽ hỏi mật khẩu của tài khoản quản trị.",
  "admin.fix.linux":
    "Làm việc quản trị từ một tài khoản riêng: từ tài khoản đó, gỡ tài khoản dùng hằng ngày khỏi nhóm bằng [code]sudo gpasswd -d NAME sudo[/code], với NAME là tài khoản dùng hằng ngày (trên Fedora/Arch dùng wheel thay cho sudo).",
  "admin.fix.nopasswd":
    "Bỏ NOPASSWD (và !authenticate) khỏi quy tắc bằng [code]sudo visudo[/code], hoặc [code]sudo visudo -f /etc/sudoers.d/FILE[/code].",
  "admin.fix.uac":
    "Mở Control Panel → User Accounts → Change User Account Control settings → chọn ít nhất \"Notify me only when apps try to make changes to my computer (default)\", rồi khởi động lại. Nếu do chính sách đặt, hãy liên hệ IT.",
  "admin.fix.builtinAdmin":
    "Với quyền quản trị: [code]Get-LocalUser | Where-Object SID -like '*-500' | Disable-LocalUser[/code].",

  "prot.pass": "Đang bật: {list}.",
  "prot.nothing": "Không có gì để kiểm tra: mọi phần của kiểm tra này đều bị tắt cho hệ điều hành này.",
  "prot.wsl": "Windows Subsystem for Linux: các lớp bảo vệ của chính Windows được áp dụng.",
  "prot.sipOff":
    "System Integrity Protection đang tắt: mã độc có quyền quản trị có thể sửa chính macOS và ẩn náu trong đó.",
  "prot.sipPartial": "System Integrity Protection chỉ bật một phần (cấu hình tuỳ chỉnh).",
  "prot.gatekeeperOff":
    "Gatekeeper đang tắt: ứng dụng tải về được mở mà không kiểm tra mã độc hay chữ ký nhà phát triển.",
  "prot.avOff": "Tính năng bảo vệ thời gian thực của Microsoft Defender đang tắt và không có phần mềm diệt virus nào khác đang bật.",
  "prot.tamperOff": "Tamper protection của Microsoft Defender đang tắt: mã độc có thể tắt Defender.",
  "prot.smartscreenOff":
    "SmartScreen cho ứng dụng và file đang tắt: chương trình tải về được chạy mà không kiểm tra độ tin cậy.",
  "prot.secureBootOff": "Secure Boot đang tắt: mã độc có thể nạp trước khi hệ điều hành khởi động.",
  "prot.selinuxPermissive": "SELinux đang ở chế độ permissive: chỉ ghi log vi phạm mà không chặn gì.",
  "prot.noLSM": "Cả AppArmor lẫn SELinux đều không hoạt động.",
  "prot.note.unknown": "Không xác định được {what} có đang bật hay không.",
  "prot.note.noUEFI": "Máy này khởi động ở chế độ legacy BIOS, vốn không có Secure Boot.",
  "prot.fix.sip":
    "Khởi động vào macOS Recovery (Apple silicon: giữ nút nguồn; Intel: Command-R), mở Utilities → Terminal, chạy [code]csrutil enable[/code] rồi khởi động lại.",
  "prot.fix.gatekeeper":
    "[code]sudo spctl --global-enable[/code], rồi mở System Settings → Privacy & Security → Allow applications from → App Store & Known Developers.",
  "prot.fix.av":
    "Mở Windows Security → Virus & threat protection → Manage settings → bật Real-time protection. Nếu nó tự tắt lại, hãy liên hệ IT: có thể một chính sách hoặc mã độc đang tắt nó.",
  "prot.fix.tamper": "Mở Windows Security → Virus & threat protection → Manage settings → bật Tamper Protection.",
  "prot.fix.smartscreen":
    "Mở Windows Security → App & browser control → Reputation-based protection settings → bật Check apps and files. Nếu do chính sách đặt, hãy liên hệ IT.",
  "prot.fix.secureBoot.windows":
    "Mở Settings → System → Recovery → Advanced startup → Restart now → Troubleshoot → Advanced options → UEFI Firmware Settings, rồi bật Secure Boot ở đó. Nếu BitLocker đang bật, hãy chuẩn bị sẵn recovery key trước.",
  "prot.fix.secureBoot.linux":
    "Bật Secure Boot trong phần cài đặt firmware ([code]systemctl reboot --firmware-setup[/code]). Các bản phân phối có shim đã ký (Ubuntu, Fedora, Debian…) vẫn khởi động như cũ; kernel tự build và module bổ sung (như của NVIDIA) phải được ký bằng MOK trước.",
  "prot.fix.selinux":
    "[code]sudo setenforce 1[/code], và đặt [code]SELINUX=enforcing[/code] trong /etc/selinux/config để giữ nguyên sau khi khởi động lại.",
  "prot.fix.lsm":
    "Ubuntu/Debian/openSUSE: [code]sudo systemctl enable --now apparmor[/code] (và bỏ apparmor=0 khỏi dòng lệnh kernel). Fedora/RHEL: đặt [code]SELINUX=enforcing[/code] trong /etc/selinux/config rồi khởi động lại.",

  "sharing.on": "{service} đang bật.",
  "sharing.onOpen": "{service} đang bật và cho bất kỳ ai trong mạng vào mà không cần mật khẩu.",
  "sharing.off": "Đang tắt: {services}.",
  "sharing.allowed": "Đang bật nhưng được chính sách cho phép: {services}.",
  "sharing.note.unknown": "Không xác định được {what} có đang bật hay không.",
  "sharing.note.noSystemd": "Không đọc được trạng thái các unit systemd; chỉ đánh giá dựa trên các cổng đang mở.",
  "sharing.fix.macSharing": "Mở System Settings → General → Sharing rồi tắt {service}.",
  "sharing.fix.macAirDrop":
    "Control Center → AirDrop → Contacts Only (hoặc tắt AirDrop), hoặc trong Finder: Go → AirDrop → \"Allow me to be discovered by\" → Contacts Only.",
  "sharing.fix.winShares":
    "Ngừng chia sẻ những thư mục không cần: với quyền quản trị, mở Computer Management → Shared Folders → Shares → nhấp chuột phải → Stop Sharing, hoặc chạy [code]Remove-SmbShare -Name SHARE[/code].",
  "sharing.fix.winPublic":
    "Mở Settings → Network & internet → Advanced network settings → Advanced sharing settings → Public networks → tắt Network discovery và File and printer sharing; đồng thời đặt các mạng không phải của bạn thành Public.",
  "sharing.fix.winPrinters":
    "Mở Settings → Bluetooth & devices → Printers & scanners → chọn máy in → Printer properties → Sharing → bỏ chọn \"Share this printer\".",
  "sharing.fix.winNearby": "Mở Settings → System → Nearby sharing → chọn My devices only, hoặc Off.",
  "sharing.fix.linuxSamba":
    "Dừng Samba nếu không cần: [code]sudo systemctl disable --now smbd[/code] (smb trên Fedora). Nếu cần, hãy bỏ [code]guest ok = yes[/code] và [code]public = yes[/code] khỏi /etc/samba/smb.conf.",
  "sharing.fix.linuxNFS":
    "[code]sudo systemctl disable --now nfs-server[/code] (nfs-kernel-server trên Debian/Ubuntu), hoặc giới hạn từng dòng trong /etc/exports cho các máy được nêu tên, rồi chạy [code]sudo exportfs -ra[/code].",
  "sharing.fix.cups": "[code]sudo cupsctl --no-share-printers[/code]",
  "sharing.fix.linuxGnome": "Mở Settings → Sharing → File Sharing → tắt.",
  "extensions.notFound": "Không tìm thấy hồ sơ của trình duyệt hay trình soạn thảo code nào được hỗ trợ.",
  "extensions.found": "Tiện ích tìm thấy: {counts}.",
  "extensions.pass": "Không có tiện ích nào bị chặn hay được cài từ ngoài cửa hàng.",
  "extensions.blocked": "{n} tiện ích nằm trong danh sách chặn của tổ chức: {names}.",
  "extensions.outside":
    "{n} tiện ích được cài từ ngoài cửa hàng (nạp dạng unpacked, từ file hoặc do chương trình khác cài): {names}.",
  "extensions.notAllowed": "{n} tiện ích không nằm trong danh sách được phép của tổ chức: {names}.",
  "extensions.allSites": "{n} tiện ích trong số đó có thể đọc và thay đổi mọi trang web bạn truy cập.",
  "extensions.allSitesWarn": "{n} tiện ích có thể đọc và thay đổi mọi trang web bạn truy cập: {names}.",
  "extensions.fix.blocked":
    "Gỡ ngay: trong trình duyệt, mở trang tiện ích ([code]chrome://extensions[/code], [code]edge://extensions[/code], [code]brave://extensions[/code], hoặc [code]about:addons[/code] trong Firefox) → Remove; trong trình soạn thảo, mở Extensions view → chọn tiện ích → Uninstall. Sau đó báo cho IT. Chỉ đổi các mật khẩu đã dùng trong trình duyệt hoặc trình soạn thảo đó nếu IT xác nhận tiện ích đã lấy cắp dữ liệu.",
  "extensions.fix.outside":
    "Gỡ những tiện ích bạn không chủ động cài (trang tiện ích của trình duyệt → Remove, hoặc Extensions view của trình soạn thảo → Uninstall), rồi cài những tiện ích cần dùng từ Chrome Web Store, Microsoft Edge Add-ons, addons.mozilla.org hoặc marketplace của trình soạn thảo. Nếu IT duyệt một tiện ích, có thể thêm nó vào allow_unpacked trong chính sách.",
  "extensions.fix.notAllowed":
    "Gỡ những tiện ích tổ chức chưa duyệt, hoặc đề nghị IT thêm chúng vào danh sách được phép.",
  "extensions.fix.allSites":
    "Gỡ những tiện ích không còn dùng. Trong Chrome, Edge hoặc Brave, giới hạn các tiện ích còn lại: trang tiện ích → Details → Site access → On click hoặc On specific sites.",
  "passwords.notFound": "Không tìm thấy hồ sơ trình duyệt nào được hỗ trợ.",
  "passwords.pass": "Trình duyệt không lưu mật khẩu nào, và cũng không đề nghị lưu mật khẩu.",
  "passwords.passSavingOn":
    "Trình duyệt không lưu mật khẩu nào, nhưng {browsers} vẫn đề nghị lưu mật khẩu: nên tắt tính năng này.",
  "passwords.stored":
    "Có mật khẩu được lưu trong {browsers}. Mã độc đánh cắp thông tin lấy mật khẩu đã lưu trong trình duyệt trước tiên.",
  "passwords.savingOn": "{browsers} vẫn đề nghị lưu mật khẩu: nên tắt tính năng này.",
  "passwords.few": "Không profile nào lưu quá {n} mật khẩu, nên nhiều khả năng đây không phải các mật khẩu chính của bạn.",
  "passwords.fewPass": "{browsers} lưu ít hơn {n} mật khẩu ở mỗi profile: nhiều khả năng không phải mật khẩu chính của bạn, nên không tính.",
  "passwords.allowed": "Được chính sách cho phép: {browsers}.",
  "passwords.fix":
    "Chuyển các mật khẩu này sang một trình quản lý mật khẩu (phần cài đặt mật khẩu của trình duyệt có thể xuất chúng ra), xoá chúng khỏi trình duyệt, rồi tắt tính năng lưu mật khẩu.",
  "passwords.fix.mac":
    "Trên máy Mac, nên dùng app Passwords của Apple: có sẵn trong máy, mở khoá bằng Touch ID, nhập được file mà trình duyệt xuất ra, và tự điền trong Chrome và Edge qua tiện ích iCloud Passwords của Apple.",
  "passwords.fix.chrome":
    "Chrome: Settings → Autofill and passwords → Google Password Manager → Settings → tắt Offer to save passwords.",
  "passwords.fix.edge":
    "Edge: Settings → Passwords and autofill (bản cũ: Profiles → Passwords) → tắt Offer to save passwords.",
  "passwords.fix.brave":
    "Brave: Settings → Autofill and passwords → Password Manager → Settings → tắt Offer to save passwords.",
  "passwords.fix.firefox": "Firefox: Settings → Privacy & Security → Passwords → bỏ chọn Ask to save passwords.",
  "passwords.fix.other": "Trình duyệt khác: phần cài đặt mật khẩu → tắt Offer to save passwords.",
  "trust.pass": "Không có chứng chỉ gốc nào được thêm vào kho tin cậy, và không đặt proxy nào.",
  "trust.pass.ca": "Không có chứng chỉ gốc nào được thêm vào kho tin cậy.",
  "trust.pass.proxy": "Không đặt proxy nào.",
  "trust.unknown": "Không đọc được kho tin cậy hay cài đặt proxy: {err}",
  "trust.ca.found":
    "{n} chứng chỉ gốc đã được thêm vào kho tin cậy: {names}. Ai giữ khoá của chứng chỉ đó có thể đọc lưu lượng HTTPS của máy này khi nó đi qua họ. Hệ thống kiểm tra TLS của công ty và công cụ lập trình như mkcert cũng thêm loại chứng chỉ này.",
  "trust.ca.devTool":
    "Trong đó có chứng chỉ của công cụ lập trình hoặc gỡ lỗi ({tools}): chỉ giữ lại khi bạn còn dùng công cụ đó.",
  "trust.ca.hostOnly": "{n} chứng chỉ chỉ được tin cậy cho một tên máy (ví dụ của remote desktop); không tính.",
  "trust.ca.unknown": "Không đọc được kho tin cậy: {err}",
  "trust.proxy.found":
    "Lưu lượng web đang đi qua proxy: {proxies}. Một proxy bạn không tự cài có thể thấy mọi trang bạn truy cập và đọc lưu lượng không mã hoá.",
  "trust.proxy.local":
    "Có đặt proxy trên chính máy này ({proxies}), thường là công cụ cục bộ như VPN client hoặc proxy gỡ lỗi.",
  "trust.proxy.unknown": "Không đọc được cài đặt proxy: {err}",
  "trust.fix.ca.mac":
    "Keychain Access → keychain login hoặc System → Certificates → nhấp đúp vào chứng chỉ → Trust → When using this certificate: Use System Defaults, hoặc xoá nó. Với mkcert: [code]mkcert -uninstall[/code].",
  "trust.fix.ca.win":
    "Chạy [code]certmgr.msc[/code] → Trusted Root Certification Authorities → Certificates → nhấp chuột phải vào chứng chỉ → Delete. Với mkcert: [code]mkcert -uninstall[/code].",
  "trust.fix.ca.linux":
    "Xoá file rồi dựng lại kho: [code]sudo update-ca-certificates --fresh[/code] (Debian, Ubuntu) hoặc [code]sudo update-ca-trust[/code] (Fedora, RHEL). Với mkcert: [code]mkcert -uninstall[/code].",
  "trust.fix.proxy.mac":
    "System Settings → Network → mạng đang dùng → Details → Proxies → tắt những proxy bạn không tự cài.",
  "trust.fix.proxy.win":
    "Settings → Network & internet → Proxy → tắt Use a proxy server và Use setup script nếu không phải bạn tự cài.",
  "trust.fix.proxy.linux": "Settings → Network → Network Proxy → tắt đi, nếu không phải bạn tự cài.",
  "trust.fix.proxy.env":
    "Xoá http_proxy, https_proxy và all_proxy khỏi các file khởi động shell hoặc biến môi trường nếu không phải bạn tự đặt.",
  "trust.fix.allow": "Nếu IT cài đặt điều này, hãy đề nghị họ thêm nó vào chính sách (allow_cas, allow_proxies).",
  "pm.none": "Không tìm thấy npm, pnpm, Yarn, Bun, pip, uv, Go hay Cargo.",
  "pm.pass": "Đã kiểm tra {n} trình quản lý gói ({tools}): không có thiết lập nào làm yếu cách tải gói.",
  "pm.insecure": "{n} thiết lập tải gói qua http thường hoặc bỏ qua lỗi chứng chỉ.",
  "pm.checksum": "{n} thiết lập tắt checksum database của Go.",
  "pm.scripts": "{n} trình quản lý gói chạy script cài đặt của mọi gói.",
  "pm.releaseAge": "{n} trình quản lý gói cài cả phiên bản vừa phát hành được vài phút.",
  "pm.fix.insecure":
    "Dùng registry và index https://, và bỏ các thiết lập bỏ qua lỗi chứng chỉ: [code]strict-ssl=false[/code] trong ~/.npmrc, [code]trusted-host[/code] trong pip.conf, [code]allow-insecure-host[/code] trong uv.toml, [code]enableStrictSsl: false[/code] trong ~/.yarnrc.yml; với Go chạy [code]go env -u GOINSECURE[/code]. Nếu registry nội bộ của công ty chỉ chạy http, hãy đề nghị IT thêm nó vào allow_hosts của policy.",
  "pm.fix.checksum":
    "Bật lại checksum database của Go: [code]go env -u GOSUMDB GONOSUMDB[/code], và trong GOPRIVATE chỉ liệt kê đường dẫn module của công ty ([code]go env -w GOPRIVATE=git.example.com/*[/code]), không dùng [code]*[/code].",
  "pm.fix.scripts":
    "Mặc định không cho gói chạy script cài đặt: [code]npm config set ignore-scripts true[/code] (chạy [code]npm rebuild PACKAGE[/code] cho gói nào thật sự cần script); pnpm: bỏ [code]dangerouslyAllowAllBuilds[/code]; Yarn: bỏ [code]enableScripts: true[/code] khỏi ~/.yarnrc.yml.",
  "pm.fix.releaseAge":
    "Đợi vài ngày rồi mới cài phiên bản mới, để bản phát hành bị chiếm quyền được phát hiện trước: npm 11.10+: [code]npm config set min-release-age 3[/code] (ngày); Bun: [code]minimumReleaseAge = 259200[/code] (giây) trong mục [install] của ~/.bunfig.toml; pnpm và Yarn: xoá dòng đặt [code]minimumReleaseAge[/code] hoặc [code]npmMinimalAgeGate[/code] bằng 0.",

  "startup.pass": "{n} mục tự chạy khi đăng nhập hoặc theo lịch; không có gì bất thường.",
  "startup.total": "Tổng cộng {n} mục tự chạy khi đăng nhập hoặc theo lịch.",
  "startup.downloadRun": "{n} mục tải code về và chạy mỗi lần khởi động.",
  "startup.suspicious": "{n} mục chạy chương trình từ thư mục tạm, thư mục tải về hoặc thư mục ẩn.",
  "startup.writable": "{n} mục chạy chương trình mà người dùng nào cũng sửa được.",
  "startup.missing": "{n} mục trỏ tới chương trình không còn tồn tại.",
  "startup.fix.mac":
    "Tra cứu từng mục được liệt kê. Nếu không nhận ra, hãy gỡ nó: [code]launchctl bootout gui/$(id -u)/LABEL[/code] rồi xoá file .plist của nó trong ~/Library/LaunchAgents (mục trong /Library cần quyền administrator); System Settings → General → Login Items & Extensions cũng liệt kê chúng. Nếu có mục tải code về và chạy, hãy quét mã độc; nếu quét ra mã độc thì đổi các mật khẩu đã dùng trên máy Mac này. Mục có chương trình đã mất là phần sót lại của app đã gỡ, cứ xoá đi.",
  "startup.fix.win":
    "Tra cứu từng mục được liệt kê. Nếu không nhận ra, hãy tắt nó: Task Manager → Startup apps → Disable, Task Scheduler → chọn task → Disable, hoặc xoá shortcut của nó khỏi thư mục Startup ([code]shell:startup[/code]). Nếu có mục tải code về và chạy, hãy quét toàn bộ máy bằng Windows Security; nếu quét ra mã độc thì đổi các mật khẩu đã dùng trên máy này. Mục có chương trình đã mất là phần sót lại của app đã gỡ.",
  "startup.fix.linux":
    "Tra cứu từng mục được liệt kê. Nếu không nhận ra, hãy gỡ nó: xoá file .desktop của nó trong ~/.config/autostart, [code]systemctl --user disable --now UNIT[/code], hoặc [code]crontab -e[/code]. Nếu có mục tải code về và chạy, hãy kiểm tra mã độc trên máy; nếu tìm thấy thì đổi các mật khẩu đã dùng trên đó.",

  "backup.unsupported": "Không kiểm tra trên {os}: không có dịch vụ sao lưu hay định vị thiết bị chuẩn nào để đọc.",
  "backup.unencrypted": "{n} bản sao lưu Time Machine không được mã hoá: ai lấy được ổ đĩa đều đọc được file của bạn.",
  "backup.stale": "{n} bản sao lưu cũ hơn {max} ngày.",
  "backup.none": "Chưa thiết lập sao lưu: laptop mất hoặc hỏng là mất luôn file.",
  "backup.findMyOff.mac": "Find My Mac đang tắt: máy Mac bị mất không thể định vị, khoá hay xoá từ xa.",
  "backup.findMyOff.win": "Find my device đang tắt: PC bị mất không thể định vị hay khoá từ xa.",
  "backup.on": "Dữ liệu được sao lưu tới {n} nơi.",
  "backup.noneAllowed": "Chưa thiết lập sao lưu Time Machine (policy không bắt buộc).",
  "backup.findMyOn.mac": "Find My Mac đang bật.",
  "backup.findMyOn.win": "Find my device đang bật.",
  "backup.unknown.mac": "Không xác định được Time Machine đã được thiết lập chưa (đọc thiết lập của nó có thể cần Full Disk Access).",
  "backup.findMyUnknown": "Không xác định được thiết bị có định vị từ xa được hay không.",
  "backup.win.notRead": "Không kiểm tra sao lưu của Windows (File History, Windows Backup, OneDrive).",
  "backup.fix.mac.encrypt":
    "Mở System Settings → General → Time Machine → chọn ổ đĩa → Remove Disk, rồi Add Backup Disk lại với \"Encrypt backup\" được bật (trên macOS gần đây không thể mã hoá một bản sao lưu đang có, nên ổ đĩa sẽ bị xoá).",
  "backup.fix.mac.stale": "Cắm ổ sao lưu, rồi chọn Time Machine trên thanh menu → Back Up Now.",
  "backup.fix.mac.setup":
    "Mở System Settings → General → Time Machine → Add Backup Disk, với \"Encrypt backup\" được bật, hoặc hỏi IT máy Mac này nên được sao lưu thế nào.",
  "backup.fix.mac.findMy": "Mở System Settings → tên của bạn (Apple Account) → iCloud → Find My Mac rồi bật lên.",
  "backup.fix.win.findMy": "Mở Settings → Privacy & security → Find my device rồi bật lên (cần tài khoản Microsoft và location services).",
  "samples.more": "Ngoài ra còn {n} mục có vẻ là khoá mẫu.",
  "samples.all": "Các mục tìm thấy đều là {n} mục có vẻ là khoá mẫu, không phải khoá thật.",
};
