import Foundation

/// Crash, hang and panic reports (`.ips`) from the user's and the system's DiagnosticReports folders. The first
/// line of a report is a JSON header (app, version, time, bug type); the rest is the JSON body.
public struct CrashReportSummary: Codable, Sendable, Equatable {
    public let file: String
    public let path: String
    public let process: String
    public let version: String?
    public let time: String?
    /// crash, panic, hang, or the raw bug type.
    public let kind: String
    public let bugType: String?
    public let bytes: Int64
}

public struct CrashFrame: Codable, Sendable, Equatable {
    public let image: String?
    public let symbol: String?
}

public struct CrashReportDetail: Codable, Sendable {
    public let summary: CrashReportSummary
    public let exceptionType: String?
    public let signal: String?
    public let termination: String?
    /// The app's own note about why (Application Specific Information), when it left one.
    public let appSpecific: [String]?
    /// The crashed thread's top frames.
    public let crashedThread: Int?
    public let frames: [CrashFrame]
    /// For a kernel panic: the start of the panic string.
    public let panic: String?
    public let osVersion: String?
}

public struct CrashReportList: Codable, Sendable {
    public let reports: [CrashReportSummary]
    /// Folders that couldn't be read, with why.
    public let unreadable: [String]
}

public enum CrashReports {
    public static func folders(home: String) -> [String] {
        ["\(home)/Library/Logs/DiagnosticReports", "/Library/Logs/DiagnosticReports"]
    }

    static func kind(_ bugType: String?) -> String {
        switch bugType {
        case "309", "109": return "crash"
        case "210": return "panic"
        case "288", "298", "385": return "hang"
        case nil: return "unknown"
        case let t?: return "bug type \(t)"
        }
    }

    /// The header line of a report, parsed.
    static func header(_ data: Data) -> [String: Any]? {
        guard let nl = data.firstIndex(of: 0x0A) else { return try? JSONSerialization.jsonObject(with: data) as? [String: Any] }
        return try? JSONSerialization.jsonObject(with: data[..<nl]) as? [String: Any]
    }

    static func summary(path: String, data: Data, bytes: Int64) -> CrashReportSummary? {
        guard let h = header(data) else { return nil }
        let file = (path as NSString).lastPathComponent
        let bug = (h["bug_type"] as? String) ?? (h["bug_type"] as? Int).map(String.init)
        let process = (h["app_name"] as? String) ?? (h["name"] as? String) ?? (h["procName"] as? String)
            ?? String(file.split(separator: "-").first ?? "?")
        return CrashReportSummary(file: file, path: path, process: process, version: h["app_version"] as? String,
                                  time: h["timestamp"] as? String, kind: kind(bug), bugType: bug, bytes: bytes)
    }

    /// Reports newer than `since`, newest first (by file time). `process`: only that process (case-insensitive).
    /// `includeOther`: also bug types other than crashes, panics and hangs (analytics, resource reports, …).
    public static func list(home: String, since: Date, process: String? = nil, includeOther: Bool = false,
                            limit: Int = 50) -> CrashReportList {
        var found: [(Date, CrashReportSummary)] = []
        var unreadable: [String] = []
        let fm = FileManager.default
        for dir in folders(home: home) {
            guard fm.fileExists(atPath: dir) else { continue }
            guard let names = try? fm.contentsOfDirectory(atPath: dir) else { unreadable.append("\(dir): no permission"); continue }
            for name in names where name.hasSuffix(".ips") || name.hasSuffix(".panic") {
                let path = "\(dir)/\(name)"
                guard let attrs = try? fm.attributesOfItem(atPath: path), (attrs[.type] as? FileAttributeType) == .typeRegular,
                      let modified = attrs[.modificationDate] as? Date, modified >= since else { continue }
                guard let handle = FileHandle(forReadingAtPath: path) else { continue }
                let head = handle.readData(ofLength: 64 * 1024)
                try? handle.close()
                guard let s = summary(path: path, data: head, bytes: (attrs[.size] as? NSNumber)?.int64Value ?? 0) else { continue }
                if !includeOther && !["crash", "panic", "hang"].contains(s.kind) { continue }
                if let process, s.process.lowercased() != process.lowercased() { continue }
                found.append((modified, s))
            }
        }
        let sorted = found.sorted { $0.0 > $1.0 }.prefix(limit).map(\.1)
        return CrashReportList(reports: Array(sorted), unreadable: unreadable)
    }

    /// One report in detail. `name` is a file name from `list` (looked up in the report folders only, never a path).
    public static func detail(home: String, name: String, maxBytes: Int = 8 * 1024 * 1024) throws -> CrashReportDetail {
        guard !name.contains("/"), !name.hasPrefix("."), name.hasSuffix(".ips") || name.hasSuffix(".panic") else {
            throw PlanError("`report` is a report's file name as the list shows it")
        }
        guard let path = folders(home: home).map({ "\($0)/\(name)" }).first(where: { FileManager.default.fileExists(atPath: $0) }) else {
            throw PlanError("no report \(name) in the DiagnosticReports folders")
        }
        guard let attrs = try? FileManager.default.attributesOfItem(atPath: path), (attrs[.type] as? FileAttributeType) == .typeRegular,
              let size = (attrs[.size] as? NSNumber)?.int64Value, size <= maxBytes else {
            throw PlanError("\(name) is not a regular file under \(maxBytes / 1_048_576) MB")
        }
        guard let data = FileManager.default.contents(atPath: path) else { throw PlanError("\(name) can't be read") }
        return try parse(path: path, data: data, bytes: size)
    }

    public static func parse(path: String, data: Data, bytes: Int64) throws -> CrashReportDetail {
        guard let summary = summary(path: path, data: data, bytes: bytes) else { throw PlanError("not an .ips report") }
        let header = self.header(data) ?? [:]
        var body: [String: Any] = [:]
        if let nl = data.firstIndex(of: 0x0A) {
            body = (try? JSONSerialization.jsonObject(with: data[data.index(after: nl)...]) as? [String: Any]) ?? [:]
        }
        let exception = body["exception"] as? [String: Any]
        let termination = body["termination"] as? [String: Any]
        var appSpecific: [String]?
        if let asi = body["asi"] as? [String: Any] {
            appSpecific = asi.values.flatMap { ($0 as? [String]) ?? [] }.map { String($0.prefix(300)) }
        }
        let images = (body["usedImages"] as? [[String: Any]]) ?? []
        let threads = (body["threads"] as? [[String: Any]]) ?? []
        let faulting = body["faultingThread"] as? Int ?? threads.firstIndex { ($0["triggered"] as? Bool) == true }
        var frames: [CrashFrame] = []
        if let faulting, faulting < threads.count {
            for f in ((threads[faulting]["frames"] as? [[String: Any]]) ?? []).prefix(15) {
                let image = (f["imageIndex"] as? Int).flatMap { $0 < images.count ? images[$0]["name"] as? String : nil }
                frames.append(CrashFrame(image: image, symbol: f["symbol"] as? String))
            }
        }
        let panic = (body["panicString"] as? String) ?? (body["macOSPanicString"] as? String)
        let os = (header["os_version"] as? String) ?? ((body["osVersion"] as? [String: Any])?["train"] as? String)
        return CrashReportDetail(summary: summary, exceptionType: exception?["type"] as? String, signal: exception?["signal"] as? String,
                                 termination: termination?["indicator"] as? String, appSpecific: appSpecific,
                                 crashedThread: faulting, frames: frames, panic: panic.map { String($0.prefix(2_000)) }, osVersion: os)
    }
}
