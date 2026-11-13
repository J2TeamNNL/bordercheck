// Tests for Request.swift, built and run by scripts/build-notifier.sh --test.
// They never touch the notification center: nothing is asked or posted.
import Foundation

var failures = 0
func check(_ ok: Bool, _ what: String, line: Int = #line) {
    if !ok {
        failures += 1
        print("FAIL line \(line): \(what)")
    }
}

func object(_ s: String) -> [String: Any] {
    (try? JSONSerialization.jsonObject(with: Data(s.utf8))) as? [String: Any] ?? [:]
}

func req(_ o: [String: Any]) throws -> Request {
    try parseRequest(try JSONSerialization.data(withJSONObject: o))
}

func refused(_ o: [String: Any]) -> Bool { (try? req(o)) == nil }

// Arguments: exactly one known mode; no argument is a click.
check(parseMode(["x", "status"]) == .status, "status")
check(parseMode(["x", "authorize"]) == .authorize, "authorize")
check(parseMode(["x", "post"]) == .post, "post")
check(parseMode(["x", "validate"]) == .validate, "validate")
check(parseMode(["x"]) == nil && launchedWithoutMode(["x"]), "no argument")
check(parseMode(["x", "-psn_0_1234"]) == nil && launchedWithoutMode(["x", "-psn_0_1234"]), "process serial number")
check(parseMode(["x", "post", "https://evil.example"]) == nil && !launchedWithoutMode(["x", "post", "y"]), "extra argument")
check(parseMode(["x", "POST"]) == nil && !launchedWithoutMode(["x", "POST"]), "case")
check(parseMode(["x", "open"]) == nil, "unknown mode")

// Opened by a person: the one program it runs, and what it says on failure.
check(installedBinary(home: URL(fileURLWithPath: "/Users/an")).path == "/Users/an/Library/Application Support/bordercheck/bordercheck", "installed binary")
check(openFailure(Data("bordercheck: no report has been sent yet\n".utf8)) == "No report has been sent yet", "prefix and newline dropped")
check(openFailure(Data()) == "BorderCheck could not open this computer's report page.", "nothing written")
check(openFailure(Data("a\u{1b}[31mb\u{202e}c".utf8)) == "A[31mbc", "control and format characters dropped")
check(openFailure(Data(String(repeating: "x", count: 5000).utf8)).count == maxExplanation + 1, "bounded")

// Only authorize may ask macOS.
check(mayRequestAuthorization(.authorize), "authorize asks")
for m in [Mode.status, .post, .validate] {
    check(!mayRequestAuthorization(m), "\(m) must never ask")
}

// Links: https on exactly the allowed host, nothing else.
let host = "portal.example.com"
check(allowedURL("https://portal.example.com/r/abc", host: host)?.absoluteString == "https://portal.example.com/r/abc", "good link")
check(allowedURL("https://PORTAL.example.com/r/abc", host: host) != nil, "host case")
check(allowedURL("https://portal.example.com:8443/r/abc", host: "portal.example.com:8443") != nil, "port")
for bad in [
    "http://portal.example.com/r/abc",
    "https://portal.example.com:8443/r/abc",
    "https://evil.example.com/r/abc",
    "https://portal.example.com.evil.example/r/abc",
    "https://user@portal.example.com/r/abc",
    "https://user:pw@portal.example.com/r/abc",
    "file:///etc/passwd",
    "javascript:alert(1)",
    "x-apple.systempreferences:com.apple.preference.security",
    "/Applications/Calculator.app",
    "portal.example.com/r/abc",
    "https://portal.example.com/r/a b",
    "https://portal.example.com/r/\u{202E}abc",
    "https://portal.example.com/r/\n",
    "https://portal.example.com/" + String(repeating: "a", count: maxLink),
    "",
] {
    check(allowedURL(bad, host: host) == nil, "refused: \(bad)")
}
check(allowedURL("https://portal.example.com/r/abc", host: "") == nil, "no host")
check(allowedURL("https://portal.example.com/r/abc", host: "portal.example.com/x") == nil, "host with a path")
check(!validHost("a b") && !validHost("-a.com") && !validHost("a..com") && validHost("127.0.0.1:8787"), "validHost")

// Requests.
do {
    let r = try req(["v": 1, "title": "2 problems", "body": "firewall: off\nsecrets: found",
                     "link": "https://portal.example.com/r/abc", "allowed_host": host])
    check(r.title == "2 problems" && r.body == "firewall: off\nsecrets: found", "text: \(r)")
    check(r.link?.absoluteString == "https://portal.example.com/r/abc" && r.allowedHost == host, "link: \(r)")
    let plain = try req(["v": 1, "title": "t"])
    check(plain.link == nil && plain.body == "", "no link, no body")
    let empty = try req(["v": 1, "title": "t", "link": "", "allowed_host": host])
    check(empty.link == nil, "empty link")
} catch {
    check(false, "valid request refused: \(error)")
}
check(refused(["v": 1, "title": "t", "link": "https://evil.example.com/r", "allowed_host": host]), "foreign link")
check(refused(["v": 1, "title": "t", "link": "http://portal.example.com/r", "allowed_host": host]), "http link")
check(refused(["v": 1, "title": "t", "link": "https://portal.example.com/r"]), "link without a host")
check(refused(["v": 1, "title": "t", "allowed_host": "evil host"]), "bad host")
check(refused(["v": 2, "title": "t"]), "version 2")
check(refused(["v": true, "title": "t"]), "version true")
check(refused(["v": 1.5, "title": "t"]), "version 1.5")
check(refused(["title": "t"]), "no version")
check(refused(["v": 1]), "no title")
check(refused(["v": 1, "title": "\u{1b}\u{7}"]), "title of control characters only")
check(refused(["v": 1, "title": "t", "action": "open"]), "unknown field")
check(refused(["v": 1, "title": 5]), "title not text")
check((try? parseRequest(Data("[1]".utf8))) == nil, "not an object")
check((try? parseRequest(Data("{\"v\":1,\"title\":\"t\"".utf8))) == nil, "truncated")
check((try? parseRequest(Data(count: maxRequestBytes + 1))) == nil, "oversize")

// Text is plain and capped.
check(plainText("a\u{1b}[31mb\u{0}c\td\u{202E}e\u{200B}f", max: 100) == "a[31mbc def", "controls: \(plainText("a\u{1b}[31mb\u{0}c\td\u{202E}e\u{200B}f", max: 100))")
check(plainText(String(repeating: "x", count: 500), max: maxTitle).count == maxTitle, "title cap")
check(plainText("%@ %n %s", max: 100) == "%@ %n %s", "format characters are just text")
let many = (1...20).map { "line \($0) " + String(repeating: "y", count: 400) }.joined(separator: "\n")
let lines = plainLines(many).split(separator: "\n")
check(lines.count == maxBodyLines && lines.allSatisfy { $0.count <= maxBodyLine }, "body cap")
check(plainLines("a\n\n\u{7}\nb") == "a\nb", "empty lines dropped")

// Answers: one line, the contract's fields.
let posted = Answer(status: "posted").json()
check(!posted.contains("\n") && object(posted)["status"] as? String == "posted" && object(posted)["v"] as? Int == 1, posted)
check(Set(object(posted).keys) == ["v", "status"], "no other keys: \(posted)")
let long = object(Answer(status: "error", error: String(repeating: "e", count: 1000) + "\n").json())
check((long["error"] as? String)?.count == 200, "error capped")

if failures > 0 {
    print("\(failures) failure(s)")
    exit(1)
}
print("ok: notifier contract")
