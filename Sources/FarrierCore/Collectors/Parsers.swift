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
