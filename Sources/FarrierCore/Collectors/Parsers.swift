import Foundation

/// Pure parsers: Apple CLI output in, facts out. They run under `LANG=C`. Each one returns nil when it doesn't
/// recognise the output, which turns the fact into "unknown" rather than a wrong pass or fail.
/// Golden tests: Tests/FarrierCoreTests/ParserTests.swift. Add a case for every macOS version whose output differs.
public enum Parsers {
    /// `fdesetup status` → "On" | "Off" | "Encrypting" | "Decrypting"
    public static func fdesetupStatus(_ text: String) -> FactValue? {
        if text.contains("Encryption in progress") { return .string("Encrypting") }
        if text.contains("Decryption in progress") { return .string("Decrypting") }
        if text.contains("FileVault is On") { return .string("On") }
        if text.contains("FileVault is Off") { return .string("Off") }
        return nil
    }

    /// `csrutil status` → "enabled" | "disabled" | "custom"
    public static func csrutilStatus(_ text: String) -> FactValue? {
        // Only the explicit marker means custom. Any other unrecognised status stays unknown, never a guess.
        if text.contains("(Custom Configuration)") { return .string("custom") }
        guard let value = firstMatch(#"System Integrity Protection status:\s*(\w+)\."#, in: text) else { return nil }
        switch value {
        case "enabled": return .string("enabled")
        case "disabled": return .string("disabled")
        default: return nil
        }
    }

    /// `spctl --status` → "enabled" | "disabled"
    public static func spctlStatus(_ text: String) -> FactValue? {
        if text.contains("assessments enabled") { return .string("enabled") }
        if text.contains("assessments disabled") { return .string("disabled") }
        return nil
    }

    /// `socketfilterfw --getglobalstate` → "off" | "on" | "blockAll"
    public static func firewallGlobalState(_ text: String) -> FactValue? {
        if let state = firstMatch(#"State\s*=\s*(\d+)\)"#, in: text) {  // the whole number: State = 10 is not 1
            switch state {
            case "0": return .string("off")
            case "1": return .string("on")
            case "2": return .string("blockAll")
            default: return nil
            }
        }
        if text.contains("blocking all") { return .string("blockAll") }
        if text.contains("Firewall is enabled") { return .string("on") }
        if text.contains("Firewall is disabled") { return .string("off") }
        return nil
    }

    /// `socketfilterfw --getstealthmode` → "on" | "off". Newer macOS: "Firewall stealth mode is on"; older:
    /// "Stealth mode enabled".
    public static func firewallStealthMode(_ text: String) -> FactValue? {
        guard let word = firstMatch(#"(?i)stealth mode (?:is )?(on|off|enabled|disabled)\b"#, in: text)?.lowercased() else { return nil }
        return .string(word == "on" || word == "enabled" ? "on" : "off")
    }

    /// `netstat -anp tcp` → sorted, unique TCP ports listening on a non-loopback address (reachable from the
    /// network). Requires the "Active Internet connections" header; anything else is unrecognised (nil).
    public static func listeningTCPPorts(_ text: String) -> FactValue? {
        guard text.contains("Active Internet connections") else { return nil }
        var ports = Set<Int>()
        for line in text.split(separator: "\n") {
            let cols = line.split(whereSeparator: { $0 == " " || $0 == "\t" }).map(String.init)
            guard cols.count >= 6, cols[0].hasPrefix("tcp"), cols.last == "LISTEN" else { continue }
            let local = cols[3]
            guard let dot = local.lastIndex(of: "."), let port = Int(local[local.index(after: dot)...]) else { continue }
            let host = String(local[..<dot])
            if host.hasPrefix("127.") || host == "::1" || host == "localhost" || host.hasSuffix("%lo0") { continue }  // loopback only
            ports.insert(port)
        }
        return .array(ports.sorted().map { .int($0) })
    }

    /// `sw_vers` → { productName, productVersion, buildVersion }
    public static func swVers(_ text: String) -> FactValue? {
        var o: [String: FactValue] = [:]
        for line in text.split(separator: "\n") {
            let parts = line.split(separator: ":", maxSplits: 1).map { $0.trimmingCharacters(in: .whitespaces) }
            guard parts.count == 2 else { continue }
            switch parts[0] {
            case "ProductName": o["productName"] = .string(parts[1])
            case "ProductVersion": o["productVersion"] = .string(parts[1])
            case "BuildVersion": o["buildVersion"] = .string(parts[1])
            default: continue
            }
        }
        return o["productVersion"] == nil ? nil : .object(o)
    }

    /// `profiles status -type enrollment` → { dep, mdm, userApproved }
    public static func profilesEnrollment(_ text: String) -> FactValue? {
        guard let dep = firstMatch(#"Enrolled via DEP:\s*(\S+)"#, in: text),
              let mdmLine = firstMatch(#"MDM enrollment:\s*(.+)"#, in: text) else { return nil }
        // Only the known forms. Anything else ("Unknown", a new wording) is unparsed, not "not enrolled".
        let depValue: Bool
        switch dep {
        case "Yes": depValue = true
        case "No": depValue = false
        default: return nil
        }
        let mdm: Bool, approved: Bool
        switch mdmLine.trimmingCharacters(in: .whitespaces) {
        case "No": (mdm, approved) = (false, false)
        case "Yes": (mdm, approved) = (true, false)
        case "Yes (User Approved)": (mdm, approved) = (true, true)
        default: return nil
        }
        return .object(["dep": .bool(depValue), "mdm": .bool(mdm), "userApproved": .bool(approved)])
    }

    /// `profiles show -output stdout-xml` (as root) → sorted, unique payload types of the computer-level profiles.
    /// With no profiles installed, `profiles` prints a sentence instead of a plist; that's an empty list, not unknown.
    ///
    /// Strict, because an incomplete list would make a managed setting look unmanaged (and fixable): anything that
    /// isn't exactly that sentence or a plist with well-formed computer-level profiles is nil (unknown).
    public static func profilePayloadTypes(_ output: Data) -> FactValue? {
        let text = String(decoding: output, as: UTF8.self)
        guard let start = text.range(of: "<?xml") ?? text.range(of: "<plist") else {
            // Only the bare diagnostic counts; the same sentence inside profile metadata never reaches this point.
            let trimmed = text.trimmingCharacters(in: .whitespacesAndNewlines)
            return trimmed == "There are no configuration profiles installed" ? .array([]) : nil
        }
        guard let root = propertyList(Data(text[start.lowerBound...].utf8))?.object else { return nil }
        guard let profiles = root["_computerlevel"] else { return .array([]) }  // only user-level profiles
        guard let list = profiles.array else { return nil }
        var types = Set<String>()
        for profile in list {
            guard let items = profile.object?["ProfileItems"]?.array else { return nil }
            for item in items {
                guard let t = item.object?["PayloadType"]?.string, !t.isEmpty else { return nil }
                types.insert(t)
            }
        }
        return .array(types.sorted().map(FactValue.string))
    }

    /// The same output → the computer-level profiles: `[{ identifier, displayName, organization, payloadTypes,
    /// mdmServer }]`, sorted by identifier. `organization` and `mdmServer` (the host of the MDM payload's ServerURL,
    /// only on the enrollment profile) are left out when absent. As strict as `profilePayloadTypes`.
    public static func profileSummaries(_ output: Data) -> FactValue? {
        let text = String(decoding: output, as: UTF8.self)
        guard let start = text.range(of: "<?xml") ?? text.range(of: "<plist") else {
            let trimmed = text.trimmingCharacters(in: .whitespacesAndNewlines)
            return trimmed == "There are no configuration profiles installed" ? .array([]) : nil
        }
        guard let root = propertyList(Data(text[start.lowerBound...].utf8))?.object else { return nil }
        guard let profiles = root["_computerlevel"] else { return .array([]) }
        guard let list = profiles.array else { return nil }
        var summaries: [(String, FactValue)] = []
        for profile in list {
            guard let p = profile.object, let identifier = p["ProfileIdentifier"]?.string, !identifier.isEmpty,
                  let items = p["ProfileItems"]?.array else { return nil }
            var types = Set<String>()
            var server: String?
            for item in items {
                guard let t = item.object?["PayloadType"]?.string, !t.isEmpty else { return nil }
                types.insert(t)
                if t == "com.apple.mdm", let url = item.object?["PayloadContent"]?.object?["ServerURL"]?.string {
                    server = URL(string: url)?.host
                }
            }
            var o: [String: FactValue] = [
                "identifier": .string(identifier),
                "displayName": .string(p["ProfileDisplayName"]?.string ?? identifier),
                "payloadTypes": .array(types.sorted().map(FactValue.string)),
            ]
            if let org = p["ProfileOrganization"]?.string, !org.isEmpty { o["organization"] = .string(org) }
            if let server { o["mdmServer"] = .string(server) }
            summaries.append((identifier, .object(o)))
        }
        return .array(summaries.sorted { $0.0 < $1.0 }.map(\.1))
    }

    /// `systemextensionsctl list` → `[{ category, teamID, bundleID, version, name, state, enabled, active }]`.
    /// Strict: the "N extension(s)" count must match the rows read, or the output isn't trusted (nil).
    public static func systemExtensions(_ text: String) -> FactValue? {
        guard let countText = firstMatch(#"^(\d+) extension\(s\)"#, in: text), let count = Int(countText) else { return nil }
        guard let row = try? NSRegularExpression(pattern: #"^(\*?)\t(\*?)\t(\S+)\t(\S+) \(([^)]*)\)\t(.*)\t\[([^\]]*)\]\s*$"#) else { return nil }
        var category = ""
        var items: [FactValue] = []
        for line in text.split(separator: "\n", omittingEmptySubsequences: true).map(String.init) {
            if line.hasPrefix("--- ") { category = String(line.dropFirst(4)).trimmingCharacters(in: .whitespaces); continue }
            guard let m = row.firstMatch(in: line, range: NSRange(line.startIndex..., in: line)) else { continue }
            func g(_ i: Int) -> String { Range(m.range(at: i), in: line).map { String(line[$0]) } ?? "" }
            items.append(.object([
                "category": .string(category), "enabled": .bool(g(1) == "*"), "active": .bool(g(2) == "*"),
                "teamID": .string(g(3)), "bundleID": .string(g(4)), "version": .string(g(5)),
                "name": .string(g(6).trimmingCharacters(in: .whitespaces)), "state": .string(g(7)),
            ]))
        }
        return items.count == count ? .array(items) : nil
    }

    /// `dscl . -read /Groups/admin GroupMembership` → sorted member names. A group without the key has no members.
    public static func groupMembers(_ text: String) -> FactValue? {
        let trimmed = text.trimmingCharacters(in: .whitespacesAndNewlines)
        if trimmed.contains("No such key: GroupMembership") { return .array([]) }
        guard trimmed.hasPrefix("GroupMembership:") else { return nil }
        let names = trimmed.dropFirst("GroupMembership:".count).split(whereSeparator: \.isWhitespace).map(String.init)
        return .array(Set(names).sorted().map(FactValue.string))
    }

    /// A property list (XML or binary) → object. Dates become ISO 8601 strings, data becomes base64.
    public static func propertyList(_ data: Data) -> FactValue? {
        guard let value = try? PropertyListDecoder().decode(FactValue.self, from: data), value.object != nil else { return nil }
        return value
    }

    static func firstMatch(_ pattern: String, in text: String) -> String? {
        guard let re = try? NSRegularExpression(pattern: pattern),
              let m = re.firstMatch(in: text, range: NSRange(text.startIndex..., in: text)),
              m.numberOfRanges > 1, let r = Range(m.range(at: 1), in: text) else { return nil }
        return String(text[r]).trimmingCharacters(in: .whitespaces)
    }
}
