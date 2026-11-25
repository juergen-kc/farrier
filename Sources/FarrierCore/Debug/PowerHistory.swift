import Foundation

/// Sleep and wake history from `pmset -g log`, and what keeps the Mac awake now (`pmset -g assertions`).
public struct PowerEvent: Codable, Sendable, Equatable {
    public let time: String
    /// Sleep, Wake, DarkWake, Start, Shutdown, Wake Requests, …
    public let type: String
    /// Why, when the line says ("due to …").
    public let reason: String?
    public let detail: String
}

public struct PowerAssertion: Codable, Sendable, Equatable {
    public let process: String
    public let pid: Int?
    public let type: String
    public let name: String?
}

public struct PowerHistory: Codable, Sendable {
    /// Oldest first, within the window.
    public let events: [PowerEvent]
    public let counts: [String: Int]
    /// Wake and dark-wake reasons, most frequent first.
    public let wakeReasons: [ReasonCount]
    /// What prevents sleep right now.
    public let assertions: [PowerAssertion]
    public let truncated: Bool

    public struct ReasonCount: Codable, Sendable, Equatable {
        public let reason: String
        public let count: Int
    }
}

public enum PowerParser {
    static let types = ["Wake Requests", "DarkWake", "Wake", "Sleep", "Start", "Shutdown", "Restart", "HibernateStats", "Failure"]
    static let kept: Set<String> = ["DarkWake", "Wake", "Sleep", "Start", "Shutdown", "Restart", "Failure"]

    /// Lines look like `2026-11-25 08:31:12 -0800 Wake    \tWake from Deep Idle [CDNVA] : due to EC.LidOpen/Lid Open Using AC`.
    public static func events(_ output: String, since: Date? = nil) -> [PowerEvent] {
        let f = DateFormatter()
        f.locale = Locale(identifier: "en_US_POSIX")
        f.dateFormat = "yyyy-MM-dd HH:mm:ss Z"
        var out: [PowerEvent] = []
        for raw in output.split(separator: "\n") {
            let line = String(raw)
            guard line.count > 26, line.first?.isNumber == true else { continue }
            let stamp = String(line.prefix(25))
            guard let date = f.date(from: stamp) else { continue }
            if let since, date < since { continue }
            let rest = line.dropFirst(25).trimmingCharacters(in: .whitespaces)
            guard let type = types.first(where: { rest.hasPrefix($0) }), kept.contains(type) else { continue }
            let detail = rest.dropFirst(type.count).trimmingCharacters(in: .whitespaces)
            out.append(PowerEvent(time: stamp, type: type, reason: reason(detail), detail: String(detail.prefix(300))))
        }
        return out
    }

    /// The text after "due to", up to the next field (`Using AC`, a duration, a colon-separated detail).
    static func reason(_ detail: String) -> String? {
        guard let r = detail.range(of: "due to ") else { return nil }
        var s = String(detail[r.upperBound...])
        for stop in [" Using ", "\t", " (Charge", ":TCPKeepAlive", " ["] {
            if let cut = s.range(of: stop) { s = String(s[..<cut.lowerBound]) }
        }
        s = s.trimmingCharacters(in: CharacterSet(charactersIn: " '\":"))
        return s.isEmpty ? nil : s
    }

    /// `pmset -g assertions`, the "Listed by owning process" part:
    /// `   pid 375(coreaudiod): [0x00001] 00:10:00 PreventUserIdleSleep named: "com.apple.audio.context"`.
    public static func assertions(_ output: String) -> [PowerAssertion] {
        guard let start = output.range(of: "Listed by owning process:") else { return [] }
        var out: [PowerAssertion] = []
        for raw in output[start.upperBound...].split(separator: "\n") {
            let line = raw.trimmingCharacters(in: .whitespaces)
            if line.hasPrefix("Kernel Assertions") || line.hasPrefix("Idle sleep") { break }
            guard line.hasPrefix("pid "), let open = line.firstIndex(of: "("), let close = line.firstIndex(of: ")") , open < close else { continue }
            let pid = Int(line[line.index(line.startIndex, offsetBy: 4)..<open])
            let process = String(line[line.index(after: open)..<close])
            let after = line[line.index(after: close)...]
            let words = after.split(separator: " ").map(String.init)
            // [0x…] duration TYPE named: "name"
            let type = words.first { $0.first?.isUppercase == true && !$0.hasPrefix("[") } ?? "?"
            var name: String?
            if let n = after.range(of: "named: ") {
                name = String(after[n.upperBound...]).trimmingCharacters(in: CharacterSet(charactersIn: "\" "))
                if let nl = name?.firstIndex(where: \.isNewline) { name = String(name![..<nl]) }
            }
            out.append(PowerAssertion(process: process, pid: pid, type: type, name: name.map { String($0.prefix(200)) }))
        }
        return out
    }

    public static func history(log: String, assertions a: String, since: Date?, limit: Int = 300) -> PowerHistory {
        let all = events(log, since: since)
        var counts: [String: Int] = [:]
        for e in all { counts[e.type, default: 0] += 1 }
        var reasons: [String: Int] = [:]
        for e in all where e.type == "Wake" || e.type == "DarkWake" { if let r = e.reason { reasons[r, default: 0] += 1 } }
        let ranked = reasons.sorted { ($0.value, $1.key) > ($1.value, $0.key) }.prefix(15)
            .map { PowerHistory.ReasonCount(reason: $0.key, count: $0.value) }
        return PowerHistory(events: Array(all.suffix(limit)), counts: counts, wakeReasons: Array(ranked),
                            assertions: assertions(a), truncated: all.count > limit)
    }

    public static func run(days: Int, runner: CommandRunning = ProcessRunner(), now: Date = Date()) throws -> PowerHistory {
        guard days >= 1, days <= 30 else { throw PlanError("`days` must be between 1 and 30") }
        guard let log = runner.run("/usr/bin/pmset", ["-g", "log"], timeout: 60) else { throw PlanError("pmset isn't available here") }
        if log.timedOut { throw PlanError("pmset -g log took over 60 seconds") }
        let a = runner.run("/usr/bin/pmset", ["-g", "assertions"], timeout: 15)?.stdout ?? ""
        return history(log: log.stdout, assertions: a, since: now.addingTimeInterval(-Double(days) * 86_400))
    }
}
