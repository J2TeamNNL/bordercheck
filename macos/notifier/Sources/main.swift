// Bordercheck.app: posts bordercheck's desktop notifications under its own
// name and icon, and opens the machine's report page when one is clicked.
//
// bordercheck launches it with /usr/bin/open, so macOS treats this app, not
// bordercheck or Terminal, as the sender: "bordercheck" in the banner and in
// System Settings → Notifications, where the person can turn it off. It asks
// macOS for permission only in "authorize" mode (see Request.swift); the
// hourly run uses "post", which posts only if the person already allowed it.
//
// It runs nothing and opens nothing but an https link on the one host
// bordercheck allowed, checked here again when the notification is clicked.
import AppKit
import UserNotifications

/// How long to wait for the person to answer macOS's question.
let answerSeconds = 120.0
/// How long anything else may take.
let quickSeconds = 15.0
/// How long a relaunch for a click waits for macOS to hand over the click.
let clickSeconds = 10.0

func finish(_ a: Answer) -> Never {
    FileHandle.standardOutput.write(Data((a.json() + "\n").utf8))
    exit(0)
}

func readRequest() -> Request {
    let data: Data
    do {
        data = try FileHandle.standardInput.read(upToCount: maxRequestBytes + 1) ?? Data()
    } catch {
        finish(Answer(status: "invalid", error: "cannot read the request"))
    }
    do {
        return try parseRequest(data)
    } catch {
        finish(Answer(status: "invalid", error: "\(error)"))
    }
}

final class Notifier: NSObject, UNUserNotificationCenterDelegate {
    let mode: Mode?
    var asked = false

    init(mode: Mode?) {
        self.mode = mode
        super.init()
    }

    var center: UNUserNotificationCenter { UNUserNotificationCenter.current() }

    func start() {
        let limit = mode == .authorize ? answerSeconds : (mode == nil ? clickSeconds : quickSeconds)
        DispatchQueue.main.asyncAfter(deadline: .now() + limit) { self.timedOut() }
        switch mode {
        case .status?:
            center.getNotificationSettings { s in
                DispatchQueue.main.async { finish(Answer(status: statusName(s.authorizationStatus))) }
            }
        case .authorize?:
            authorize()
        case .post?:
            post(readRequest())
        case .validate?, nil:
            break // nil: a click arrives through the delegate, or nothing does and the timer quits
        }
    }

    /// Asks macOS once, and only when it has never been answered.
    func authorize() {
        guard let m = mode, mayRequestAuthorization(m) else { return }
        // macOS shows its question for the app in front.
        NSApp.activate(ignoringOtherApps: true)
        center.getNotificationSettings { s in
            guard s.authorizationStatus == .notDetermined else {
                DispatchQueue.main.async { finish(Answer(status: statusName(s.authorizationStatus))) }
                return
            }
            DispatchQueue.main.async {
                self.asked = true
                self.center.requestAuthorization(options: [.alert]) { _, _ in
                    self.reportStatus()
                }
            }
        }
    }

    /// Posts the request only if notifications are already allowed; never asks.
    func post(_ req: Request) {
        center.getNotificationSettings { s in
            let status = statusName(s.authorizationStatus)
            guard status == "authorized" else {
                DispatchQueue.main.async { finish(Answer(status: status)) }
                return
            }
            let c = UNMutableNotificationContent()
            c.title = req.title
            c.body = req.body
            c.threadIdentifier = "bordercheck"
            if let link = req.link {
                // Only for the click; never shown.
                c.userInfo = ["link": link.absoluteString, "allowed_host": req.allowedHost]
            }
            let r = UNNotificationRequest(identifier: UUID().uuidString, content: c, trigger: nil)
            self.center.add(r) { err in
                DispatchQueue.main.async {
                    if let err = err {
                        finish(Answer(status: "error", error: (err as NSError).domain + " " + String((err as NSError).code)))
                    }
                    finish(Answer(status: "posted"))
                }
            }
        }
    }

    func reportStatus() {
        center.getNotificationSettings { s in
            DispatchQueue.main.async { finish(Answer(status: statusName(s.authorizationStatus))) }
        }
    }

    func timedOut() {
        if mode == nil { exit(0) }
        if mode == .authorize { reportStatus(); return } // unanswered: not_determined
        finish(Answer(status: "error", error: "timed out"))
    }

    // Shown even if this app happens to be in front.
    func userNotificationCenter(_ c: UNUserNotificationCenter, willPresent n: UNNotification,
                                withCompletionHandler done: @escaping (UNNotificationPresentationOptions) -> Void) {
        done([.banner, .list])
    }

    // A click: open the report link, after checking it again, and nothing else.
    func userNotificationCenter(_ c: UNUserNotificationCenter, didReceive r: UNNotificationResponse,
                                withCompletionHandler done: @escaping () -> Void) {
        let info = r.notification.request.content.userInfo
        if r.actionIdentifier == UNNotificationDefaultActionIdentifier,
           let link = info["link"] as? String, let host = info["allowed_host"] as? String,
           let url = allowedURL(link, host: host) {
            NSWorkspace.shared.open(url)
        }
        done()
        if mode == nil {
            DispatchQueue.main.asyncAfter(deadline: .now() + 1) { exit(0) }
        }
    }
}

let args = CommandLine.arguments
let mode = parseMode(args)
if mode == nil && !launchedWithoutMode(args) {
    exit(2) // not something bordercheck runs
}
if mode == .validate {
    // Tests only: check the request and say what would be posted. No
    // notification API is touched, so nothing is asked or shown.
    let req = readRequest()
    let o: [String: Any] = ["v": 1, "status": "ok", "title": req.title, "body": req.body,
                            "link": req.link?.absoluteString ?? "", "allowed_host": req.allowedHost]
    let data = (try? JSONSerialization.data(withJSONObject: o, options: [.sortedKeys])) ?? Data()
    FileHandle.standardOutput.write(data + Data("\n".utf8))
    exit(0)
}

let app = NSApplication.shared
app.setActivationPolicy(.accessory)
let notifier = Notifier(mode: mode)
// Before the app finishes launching, so a click that launched it is delivered.
UNUserNotificationCenter.current().delegate = notifier
DispatchQueue.main.async { notifier.start() }
app.run()
