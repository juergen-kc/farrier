import Foundation

/// Replaces what identifies this Mac or its people in output meant to be shared (`--redact`, `FARRIER_REDACT=1`, and
/// the MCP server by default): user and account names, the computer and host names, the hardware UUID, the MDM server,
/// home folders and email addresses. The
/// result keeps its shape (JSON stays valid JSON), so it can still be read and compared.
public struct Redactor: Sendable {
    public struct Secret: Sendable, Equatable {
        public let value: String
        public let placeholder: String
        public init(_ value: String, _ placeholder: String) { self.value = value; self.placeholder = placeholder }
    }

    public let secrets: [Secret]

    /// Values shorter than this are left alone: replacing a two-letter account name everywhere would mangle text.
    static let minimumLength = 3
    /// Accounts that aren't personal.
    static let systemAccounts: Set<String> = ["root", "daemon", "nobody", "_mbsetupuser"]

    public init(secrets: [Secret]) {
        // Longest first, so a full name is replaced before the short name inside it.
        self.secrets = secrets
            .filter { $0.value.count >= Self.minimumLength && !Self.systemAccounts.contains($0.value) }
            .sorted { $0.value.count > $1.value.count }
    }

    /// From this Mac: the user's short and full names, the admins (other than system accounts), the computer and host
    /// names, and whatever the caller adds (the hardware UUID, the MDM server).
    public static func live(extra: [Secret] = [], runner: CommandRunning = ProcessRunner()) -> Redactor {
        var s: [Secret] = [Secret(NSUserName(), "<user>"), Secret(NSFullUserName(), "<user name>")]
        if let out = runner.run("/usr/bin/dscl", [".", "-read", "/Groups/admin", "GroupMembership"], timeout: 5),
           let admins = Parsers.groupMembers(out.combined)?.array?.compactMap(\.string) {
            for (n, name) in admins.enumerated() where name != NSUserName() { s.append(Secret(name, "<account-\(n + 1)>")) }
        }
        if let computer = runner.run("/usr/sbin/scutil", ["--get", "ComputerName"], timeout: 5)?.stdout
            .trimmingCharacters(in: .whitespacesAndNewlines), !computer.isEmpty {
            s.append(Secret(computer, "<computer>"))
        }
        let host = ProcessInfo.processInfo.hostName
        s.append(Secret(host, "<host>"))
        if host.hasSuffix(".local") { s.append(Secret(String(host.dropLast(".local".count)), "<host>")) }
        return Redactor(secrets: s + extra)
    }

    /// The text with every secret, and every home folder (`/Users/<name>`), replaced.
    public func redact(_ text: String) -> String {
        var out = text
        out = Self.emails.stringByReplacingMatches(in: out, range: NSRange(out.startIndex..., in: out), withTemplate: "<email>")
        // Home folders first, whoever's they are: the name in them is personal even when it isn't on the list.
        out = Self.homeFolders.stringByReplacingMatches(in: out, range: NSRange(out.startIndex..., in: out),
                                                        withTemplate: "/Users/<user>")
        for secret in secrets {
            out = Self.wholeWord(secret.value).stringByReplacingMatches(
                in: out, range: NSRange(out.startIndex..., in: out),
                withTemplate: NSRegularExpression.escapedTemplate(for: secret.placeholder))
        }
        return out
    }

    /// JSON in, the same JSON with every string value redacted out (it stays valid: placeholders need no escaping).
    public func redactJSON(_ data: Data) -> Data {
        Data(redact(String(decoding: data, as: UTF8.self)).utf8)
    }

    static let emails = try! NSRegularExpression(pattern: #"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}"#)
    static let homeFolders = try! NSRegularExpression(pattern: #"/Users/(?!Shared(?:/|\b)|<user>)[^/\s"'),;]+"#)

    /// The value where it stands as a word of its own (not inside a longer name, path component or identifier).
    static func wholeWord(_ value: String) -> NSRegularExpression {
        let escaped = NSRegularExpression.escapedPattern(for: value)
        return try! NSRegularExpression(pattern: "(?<![A-Za-z0-9_\\-])\(escaped)(?![A-Za-z0-9_\\-])", options: [.caseInsensitive])
    }
}
