import Foundation

/// A unified log query, built from structured filters: the predicate is assembled here with every value quoted
/// and escaped, so no caller (or text from the Mac) can inject predicate syntax.
public struct LogQuery: Sendable, Equatable {
    public enum Level: String, Sendable, CaseIterable { case `default`, info, debug, error, fault }

    public var subsystem: String?
    public var process: String?
    public var category: String?
    /// Only these and more severe: `error` and `fault` filter on the message type; `info` and `debug` include those
    /// levels (`log show --info/--debug`), which are otherwise left out.
    public var level: Level?
    /// Messages containing this (case-insensitive).
    public var text: String?
    /// How far back, in seconds (at most a day).
    public var lastSeconds: Int64
    public var limit: Int

    public static let maxWindow: Int64 = 86_400
    public static let maxLimit = 1_000
    /// Without a subsystem, process or text filter, the window is at most this (an unfiltered hour is huge).
    public static let unfilteredWindow: Int64 = 600

    public init(subsystem: String? = nil, process: String? = nil, category: String? = nil, level: Level? = nil,
                text: String? = nil, lastSeconds: Int64 = 3_600, limit: Int = 200) {
        self.subsystem = subsystem; self.process = process; self.category = category; self.level = level
        self.text = text; self.lastSeconds = lastSeconds; self.limit = limit
    }

    /// Checks the bounds; returns why the query can't run, or nil.
    public func problem() -> String? {
        for (name, v) in [("subsystem", subsystem), ("process", process), ("category", category), ("text", text)] {
            if let v, v.isEmpty || v.count > 200 { return "`\(name)` must be 1 to 200 characters" }
            if let v, v.contains(where: { $0.isNewline || $0 == "\u{0}" }) { return "`\(name)` must be one line" }
        }
        guard lastSeconds > 0, lastSeconds <= Self.maxWindow else { return "the window must be between 1 second and 24 hours" }
        guard limit > 0, limit <= Self.maxLimit else { return "`limit` must be between 1 and \(Self.maxLimit)" }
        if subsystem == nil, process == nil, text == nil, lastSeconds > Self.unfilteredWindow {
            return "without a subsystem, process or text filter, look back at most \(Self.unfilteredWindow / 60) minutes"
        }
        return nil
    }

    /// A predicate string literal: double quotes and backslashes escaped.
    static func quote(_ s: String) -> String {
        "\"" + s.replacingOccurrences(of: "\\", with: "\\\\").replacingOccurrences(of: "\"", with: "\\\"") + "\""
    }

    public var predicate: String? {
        var parts: [String] = []
        if let subsystem { parts.append("subsystem == \(Self.quote(subsystem))") }
        if let process { parts.append("process == \(Self.quote(process))") }
        if let category { parts.append("category == \(Self.quote(category))") }
        if let text { parts.append("eventMessage CONTAINS[c] \(Self.quote(text))") }
        switch level {
        case .error: parts.append("(messageType == error OR messageType == fault)")
        case .fault: parts.append("messageType == fault")
        default: break
        }
        return parts.isEmpty ? nil : parts.joined(separator: " AND ")
    }

    /// `log show` arguments (no shell: each is one argv entry).
    public var arguments: [String] {
        // `--last` takes m, h or d: whole minutes, rounded up.
        var args = ["show", "--style", "ndjson", "--last", "\(max(1, (lastSeconds + 59) / 60))m"]
        if level == .info { args.append("--info") }
        if level == .debug { args += ["--info", "--debug"] }
        if let predicate { args += ["--predicate", predicate] }
        return args
    }
}

public struct LogEntry: Codable, Sendable, Equatable {
    public let time: String
    public let process: String?
    public let subsystem: String?
    public let category: String?
    public let level: String?
    public let message: String
}

public struct LogQueryResult: Codable, Sendable {
    public let predicate: String?
    public let lastSeconds: Int64
    /// The newest `limit` entries, oldest first.
    public let entries: [LogEntry]
    /// More entries matched than were returned.
    public let truncated: Bool
    public let matched: Int
}

public enum LogParser {
    public static let maxMessage = 500

    /// `log show --style ndjson`: one JSON object per line; lines that aren't events (the trailer) are skipped.
    public static func parse(_ output: String, limit: Int) -> (entries: [LogEntry], matched: Int) {
        var all: [LogEntry] = []
        for line in output.split(separator: "\n") {
            guard line.first == "{", let o = try? JSONSerialization.jsonObject(with: Data(line.utf8)) as? [String: Any],
                  let message = o["eventMessage"] as? String else { continue }
            let path = o["processImagePath"] as? String
            var m = message
            if m.count > maxMessage { m = String(m.prefix(maxMessage)) + "…" }
            all.append(LogEntry(time: o["timestamp"] as? String ?? "?", process: path.map { ($0 as NSString).lastPathComponent },
                                subsystem: (o["subsystem"] as? String).flatMap { $0.isEmpty ? nil : $0 },
                                category: (o["category"] as? String).flatMap { $0.isEmpty ? nil : $0 },
                                level: o["messageType"] as? String, message: m))
        }
        return (Array(all.suffix(limit)), all.count)
    }

    public static func run(_ q: LogQuery, runner: CommandRunning = ProcessRunner()) throws -> LogQueryResult {
        if let problem = q.problem() { throw PlanError(problem) }
        guard let r = runner.run("/usr/bin/log", q.arguments, timeout: 90) else { throw PlanError("/usr/bin/log isn't available here") }
        if r.timedOut { throw PlanError("the log query took over 90 seconds; narrow it (a subsystem or process, a shorter window)") }
        guard r.status == 0 else {
            throw PlanError("log show failed (exit \(r.status)): \(r.stderr.trimmingCharacters(in: .whitespacesAndNewlines).prefix(200))")
        }
        let (entries, matched) = parse(r.stdout, limit: q.limit)
        return LogQueryResult(predicate: q.predicate, lastSeconds: q.lastSeconds, entries: entries,
                              truncated: matched > entries.count, matched: matched)
    }
}
