// Bordercheck.app: posts bordercheck's desktop notifications under its own
// name and icon, and opens the machine's report page when one is clicked.
//
// bordercheck launches it with /usr/bin/open, so macOS treats this app, not
// bordercheck or Terminal, as the sender: "bordercheck" in the banner and in
// System Settings → Notifications, where the person can turn it off. It asks
// macOS for permission only in "authorize" mode (see Request.swift); the
// hourly run uses "post", which posts only if the person already allowed it.
//
// It opens nothing but an https link on the one host bordercheck allowed,
// checked here again when the notification is clicked. The one program it
// runs is the installed bordercheck, with the fixed argument "open", when a
// person opens the app themselves (it is copied to ~/Applications so that
// Spotlight and Launchpad find it): that opens this machine's report page.
import AppKit
import UserNotifications

/// How long to wait for the person to answer macOS's question.
let answerSeconds = 120.0
/// How long anything else may take.
let quickSeconds = 15.0
/// How long a relaunch for a click waits for macOS to hand over the click.
let clickSeconds = 10.0
/// How long a launch without a mode waits for a click before it is taken as a
/// person opening the app.
let launchSeconds = 1.5
/// How long `bordercheck open` may take.
let openSeconds = 30.0

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
    /// A click was delivered, or the app took the launch as a person's: only one of the two acts.
    var clicked = false
    var opening = false

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
        case .validate?:
            break
        case nil:
            // A click arrives through the delegate at once; if none does, a person opened the app.
            DispatchQueue.main.asyncAfter(deadline: .now() + launchSeconds) {
                if !self.clicked { self.openReport() }
            }
        }
    }

    /// Runs `bordercheck open`; quits when it worked, says why when it did not.
    func openReport() {
        opening = true
        let p = Process()
        p.executableURL = installedBinary(home: FileManager.default.homeDirectoryForCurrentUser)
        p.arguments = ["open"]
        let err = Pipe()
        p.standardInput = FileHandle.nullDevice
        p.standardOutput = FileHandle.nullDevice
        p.standardError = err
        do {
            try p.run()
        } catch {
            explain("BorderCheck is not installed for this user on this computer.")
        }
        DispatchQueue.main.asyncAfter(deadline: .now() + openSeconds) { if p.isRunning { p.terminate() } }
        DispatchQueue.global().async {
            let said = err.fileHandleForReading.readDataToEndOfFile()
            p.waitUntilExit()
            DispatchQueue.main.async {
                if p.terminationReason == .exit && p.terminationStatus == 0 { exit(0) }
                self.explain(openFailure(said))
            }
        }
    }

    func explain(_ text: String) -> Never {
        NSApp.activate(ignoringOtherApps: true)
        let a = NSAlert()
        a.messageText = "BorderCheck"
        a.informativeText = text
        a.addButton(withTitle: "OK")
        a.runModal()
        exit(0)
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
        if mode == nil {
            if !opening { exit(0) }
            return // a person opened the app: it quits when bordercheck is done or the message is closed
        }
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
        clicked = true
        if !opening, r.actionIdentifier == UNNotificationDefaultActionIdentifier,
           let link = info["link"] as? String, let host = info["allowed_host"] as? String,
           let url = allowedURL(link, host: host) {
            NSWorkspace.shared.open(url)
        }
        done()
        if mode == nil && !opening {
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
