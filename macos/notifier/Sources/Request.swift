// The contract between bordercheck and Bordercheck.app, kept free of AppKit so
// it can be tested on its own (Tests/main.swift, scripts/build-notifier.sh
// --test). Nothing here asks macOS for anything.
//
// bordercheck runs the app with one argument, a mode:
//
//	status     write the authorization status; never asks
//	authorize  ask macOS once whether "bordercheck" may send notifications (only
//	           run by `bordercheck install` and `bordercheck notifications`,
//	           with a person at the terminal), then write the status
//	post       read a Request on stdin and post it if, and only if, the person
//	           already allowed notifications; never asks
//	validate   read a Request on stdin, check it and write what would be
//	           posted; touches no notification API (for tests)
//
// and reads its answer, one JSON line, from stdout:
//
//	{"v":1,"status":"posted"}
//	{"v":1,"status":"denied"}
//	{"v":1,"status":"invalid","error":"..."}
//
// Launched with no argument, it is macOS delivering a click on one of its
// notifications (or someone opening it from Finder): it opens the
// notification's report link if it passes allowedURL, and quits.
import Foundation
import UserNotifications

enum Mode: String {
    case status, authorize, post, validate
}

/// The mode bordercheck asked for. nil: no argument (a click on a notification,
/// or opened by hand). Anything else is refused by the caller.
func parseMode(_ args: [String]) -> Mode? {
    guard args.count == 2 else { return nil }
    return Mode(rawValue: args[1])
}

/// Launched without arguments: macOS relaunching the app for a click, or a
/// person opening it. Old systems add a process serial number argument.
func launchedWithoutMode(_ args: [String]) -> Bool {
    args.count == 1 || (args.count == 2 && args[1].hasPrefix("-psn_"))
}

/// Only authorize may ask macOS; every other mode just reads the answer.
func mayRequestAuthorization(_ m: Mode) -> Bool { m == .authorize }

let maxRequestBytes = 16 * 1024
let maxTitle = 120
let maxBodyLine = 240
let maxBodyLines = 8
let maxLink = 2048

struct Request {
    let title: String
    let body: String
    let link: URL?
    let allowedHost: String
}

struct RequestError: Error, CustomStringConvertible {
    let description: String
    init(_ d: String) { description = d }
}

private let requestKeys: Set<String> = ["v", "title", "body", "link", "allowed_host"]

/// Reads bordercheck's request: {"v":1,"title":"...","body":"...","link":"https://...","allowed_host":"host"}.
/// The text is plain text from check results: control and bidi characters are
/// dropped and it is capped. A link must pass allowedURL, or the request is refused.
func parseRequest(_ data: Data) throws -> Request {
    if data.count > maxRequestBytes { throw RequestError("the request is larger than \(maxRequestBytes) bytes") }
    guard let obj = (try? JSONSerialization.jsonObject(with: data)) as? [String: Any] else {
        throw RequestError("the request is not a JSON object")
    }
    if let k = obj.keys.sorted().first(where: { !requestKeys.contains($0) }) {
        throw RequestError("unknown field \(plainText(k, max: 32))")
    }
    guard let v = obj["v"] as? NSNumber, CFGetTypeID(v) != CFBooleanGetTypeID(), v.intValue == 1, v.doubleValue == 1 else {
        throw RequestError("the request is not format 1")
    }
    guard let rawTitle = obj["title"] as? String else { throw RequestError("the request has no title") }
    let title = plainText(rawTitle, max: maxTitle)
    if title.isEmpty { throw RequestError("the request has no title") }
    var body = ""
    if let b = obj["body"] {
        guard let s = b as? String else { throw RequestError("body is not text") }
        body = plainLines(s)
    }
    var host = ""
    if let h = obj["allowed_host"] {
        guard let s = h as? String, validHost(s) else { throw RequestError("allowed_host is not a host name") }
        host = s.lowercased()
    }
    var link: URL?
    if let l = obj["link"] {
        guard let s = l as? String else { throw RequestError("link is not text") }
        if !s.isEmpty {
            guard !host.isEmpty, let u = allowedURL(s, host: host) else {
                throw RequestError("the link is not https on the allowed host")
            }
            link = u
        }
    }
    return Request(title: title, body: body, link: link, allowedHost: host)
}

/// One line of plain text: newlines and tabs become spaces, other control
/// characters and Unicode format characters (bidi overrides, zero-width
/// joiners) are dropped, runs of spaces collapse, and it is clipped to max
/// characters.
func plainText(_ s: String, max: Int) -> String {
    var scalars = String.UnicodeScalarView()
    for u in s.unicodeScalars {
        switch u.properties.generalCategory {
        case .control:
            if u == "\n" || u == "\r" || u == "\t" { scalars.append(" ") }
        case .format, .lineSeparator, .paragraphSeparator, .surrogate, .privateUse, .unassigned:
            continue
        default:
            scalars.append(u)
        }
    }
    let words = String(scalars).split(whereSeparator: { $0.isWhitespace })
    let line = words.joined(separator: " ")
    if line.count <= max { return line }
    return String(line.prefix(max - 1)).trimmingCharacters(in: .whitespaces) + "…"
}

/// The body: at most maxBodyLines lines, each plainText.
func plainLines(_ s: String) -> String {
    let lines = s.split(separator: "\n", omittingEmptySubsequences: true)
        .map { plainText(String($0), max: maxBodyLine) }
        .filter { !$0.isEmpty }
    return lines.prefix(maxBodyLines).joined(separator: "\n")
}

private let hostPattern = try! NSRegularExpression(
    pattern: "^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*(:[0-9]{1,5})?$",
    options: [.caseInsensitive])

/// A host name (or IPv4 address), with an optional port: what bordercheck
/// passes as the one host a link may point to.
func validHost(_ h: String) -> Bool {
    if h.isEmpty || h.utf8.count > 260 { return false }
    return hostPattern.firstMatch(in: h, range: NSRange(h.startIndex..., in: h)) != nil
}

/// The link as a URL if it may be opened: printable ASCII, at most maxLink
/// characters, https, no user name or password, and exactly on host (and
/// port). Anything else is nil and is never opened.
func allowedURL(_ link: String, host: String) -> URL? {
    guard link.utf8.count <= maxLink, validHost(host),
          link.unicodeScalars.allSatisfy({ $0.value > 0x20 && $0.value < 0x7f }),
          let c = URLComponents(string: link),
          c.scheme == "https", c.user == nil, c.password == nil,
          let h = c.host, !h.isEmpty
    else { return nil }
    let hostPort = h.lowercased() + (c.port.map { ":\($0)" } ?? "")
    guard hostPort == host.lowercased(), let url = c.url, url.scheme == "https" else { return nil }
    return url
}

/// What the app writes to stdout: one JSON line.
struct Answer {
    let status: String
    var error: String?

    func json() -> String {
        var o: [String: Any] = ["v": 1, "status": status]
        if let e = error { o["error"] = plainText(e, max: 200) }
        let data = (try? JSONSerialization.data(withJSONObject: o, options: [.sortedKeys])) ?? Data()
        return String(decoding: data, as: UTF8.self)
    }
}

/// The authorization status as bordercheck names it. Provisional and
/// ephemeral authorization deliver notifications, so they count as authorized.
func statusName(_ s: UNAuthorizationStatus) -> String {
    switch s {
    case .authorized, .provisional, .ephemeral: return "authorized"
    case .denied: return "denied"
    case .notDetermined: return "not_determined"
    @unknown default: return "not_determined"
    }
}
