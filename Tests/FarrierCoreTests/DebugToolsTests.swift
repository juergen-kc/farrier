import Foundation
import MCP
import Testing
@testable import FarrierCore
@testable import FarrierMCP

private let pmsetLog = """
Time stamp                Domain                 Message                                                                                                              Duration  Delay
==========                ======                 =======                                                                                                              ========  =====
2026-11-20 08:00:00 -0800 Sleep               \tEntering Sleep state due to 'Idle Sleep':TCPKeepAlive=active Using AC (Charge:100%)          120 secs
2026-11-24 22:10:01 -0800 Assertions          \tPID 375(coreaudiod) Created PreventUserIdleSleep "com.apple.audio.context" 00:00:00
2026-11-24 23:00:00 -0800 Sleep               \tEntering Sleep state due to 'Software Sleep pid=123':TCPKeepAlive=active Using Batt (Charge:80%) 300 secs
2026-11-24 23:05:00 -0800 DarkWake            \tDarkWake from Deep Idle [CDN] : due to EC.RTC/Maintenance Using AC (Charge:80%) 45 secs
2026-11-25 07:30:12 -0800 Wake                \tWake from Deep Idle [CDNVA] : due to EC.LidOpen/Lid Open Using AC (Charge:80%)
2026-11-25 07:31:00 -0800 Wake Requests       \t[*process=mDNSResponder request=Maintenance deltaSecs=7200 wakeAt=2026-11-25 09:31:00]
2026-11-25 12:00:00 -0800 DarkWake            \tDarkWake from Normal Sleep [CDN] : due to EC.RTC/Maintenance Using AC 30 secs
"""

private let assertions = """
Assertion status system-wide:
   PreventUserIdleSystemSleep     1
Listed by owning process:
   pid 375(coreaudiod): [0x0000a12b00018e2c] 00:10:00 PreventUserIdleSleep named: "com.apple.audio.context.active"
   pid 501(caffeinate): [0x0000a12b00018e2d] 01:00:00 PreventUserIdleSystemSleep named: "caffeinate command-line tool"
Kernel Assertions: 0x4=USB
"""

private func ips(_ header: [String: Any], body: [String: Any]) -> Data {
    var d = try! JSONSerialization.data(withJSONObject: header)
    d.append(0x0A)
    d.append(try! JSONSerialization.data(withJSONObject: body))
    return d
}

@Suite("Debugging tools")
struct DebugToolsTests {
    @Test func logPredicatesAreBuiltAndQuoted() {
        var q = LogQuery(subsystem: "com.apple.powermanagement", level: .error, lastSeconds: 3_600)
        #expect(q.predicate == "subsystem == \"com.apple.powermanagement\" AND (messageType == error OR messageType == fault)")
        #expect(q.arguments == ["show", "--style", "ndjson", "--last", "60m", "--predicate", q.predicate!])
        // Text from anywhere can't break out of its string literal.
        q = LogQuery(text: "x\" OR 1 == 1 OR eventMessage CONTAINS \"\\", lastSeconds: 600)
        #expect(q.predicate == #"eventMessage CONTAINS[c] "x\" OR 1 == 1 OR eventMessage CONTAINS \"\\""#)
        #expect(LogQuery(process: "kernel", level: .debug, lastSeconds: 90).arguments.contains("--debug"))
        #expect(LogQuery(process: "kernel", lastSeconds: 90).arguments[4] == "2m")
        // Bounds.
        #expect(LogQuery(lastSeconds: 3_600).problem()?.contains("10 minutes") == true)
        #expect(LogQuery(process: "a", lastSeconds: 90_000).problem() != nil)
        #expect(LogQuery(process: "a", limit: 5_000).problem() != nil)
        #expect(LogQuery(process: "a\nb").problem() != nil)
        #expect(LogQuery(lastSeconds: 300).problem() == nil)
    }

    @Test func logOutputIsParsedAndCut() {
        let long = String(repeating: "a", count: 900)
        let out = """
        {"timestamp":"2026-11-25 07:30:12.1-0800","processImagePath":"/usr/libexec/powerd","subsystem":"com.apple.powermanagement","category":"","messageType":"Default","eventMessage":"Wake reason: lid"}
        {"timestamp":"2026-11-25 07:30:13.0-0800","processImagePath":"/kernel","subsystem":"","messageType":"Error","eventMessage":"\(long)"}
        {"count":2,"finished":1}
        """
        let (entries, matched) = LogParser.parse(out, limit: 1)
        #expect(matched == 2 && entries.count == 1)
        #expect(entries[0].process == "kernel" && entries[0].subsystem == nil && entries[0].message.count == LogParser.maxMessage + 1)
        let all = LogParser.parse(out, limit: 10).entries
        #expect(all[0].process == "powerd" && all[0].category == nil && all[0].message == "Wake reason: lid")
    }

    @Test func powerHistoryEventsReasonsAndAssertions() {
        let since = ISO8601DateFormatter().date(from: "2026-11-24T00:00:00-08:00")!
        let h = PowerParser.history(log: pmsetLog, assertions: assertions, since: since)
        #expect(h.events.map(\.type) == ["Sleep", "DarkWake", "Wake", "DarkWake"])   // Assertions and Wake Requests left out
        #expect(h.counts == ["Sleep": 1, "DarkWake": 2, "Wake": 1])
        #expect(h.events[0].reason == "Software Sleep pid=123")
        #expect(h.wakeReasons.first == PowerHistory.ReasonCount(reason: "EC.RTC/Maintenance", count: 2))
        #expect(h.wakeReasons.contains(PowerHistory.ReasonCount(reason: "EC.LidOpen/Lid Open", count: 1)))
        #expect(h.assertions == [
            PowerAssertion(process: "coreaudiod", pid: 375, type: "PreventUserIdleSleep", name: "com.apple.audio.context.active"),
            PowerAssertion(process: "caffeinate", pid: 501, type: "PreventUserIdleSystemSleep", name: "caffeinate command-line tool"),
        ])
    }

    @Test func crashReportsAreListedAndRead() throws {
        let home = FakeHome()
        let dir = "\(home.root)/Library/Logs/DiagnosticReports"
        try FileManager.default.createDirectory(atPath: dir, withIntermediateDirectories: true)
        let crash = ips(["app_name": "Editor", "app_version": "2.1", "timestamp": "2026-11-25 07:00:00.00 -0800", "bug_type": "309",
                         "os_version": "macOS 27.2.1 (27C100)"],
                        body: ["exception": ["type": "EXC_BAD_ACCESS", "signal": "SIGSEGV"],
                               "termination": ["indicator": "Segmentation fault: 11"],
                               "asi": ["libsystem_c.dylib": ["assertion failed: buffer != NULL"]],
                               "faultingThread": 1,
                               "threads": [["frames": []], ["triggered": true, "frames": [
                                   ["imageIndex": 0, "symbol": "Editor.save()"], ["imageIndex": 1, "symbol": "start"]]]],
                               "usedImages": [["name": "Editor"], ["name": "dyld"]]])
        FileManager.default.createFile(atPath: "\(dir)/Editor-2026-11-25-070000.ips", contents: crash)
        FileManager.default.createFile(atPath: "\(dir)/Kernel-2026-11-24.panic.ips", contents: ips(["bug_type": "210", "timestamp": "2026-11-24"],
                                                                                                body: ["panicString": "panic(cpu 0): watchdog timeout"]))
        FileManager.default.createFile(atPath: "\(dir)/analytics.ips", contents: ips(["bug_type": "211", "name": "Analytics"], body: [:]))
        FileManager.default.createFile(atPath: "\(dir)/notes.txt", contents: Data("x".utf8))

        let list = CrashReports.list(home: home.root, since: Date(timeIntervalSince1970: 0))
        #expect(Set(list.reports.map(\.kind)) == ["crash", "panic"])
        #expect(CrashReports.list(home: home.root, since: Date(timeIntervalSince1970: 0), includeOther: true).reports.count == 3)
        #expect(CrashReports.list(home: home.root, since: Date(timeIntervalSince1970: 0), process: "editor").reports.map(\.process) == ["Editor"])
        #expect(CrashReports.list(home: home.root, since: Date().addingTimeInterval(3_600)).reports.isEmpty)

        let d = try CrashReports.detail(home: home.root, name: "Editor-2026-11-25-070000.ips")
        #expect(d.exceptionType == "EXC_BAD_ACCESS" && d.signal == "SIGSEGV" && d.termination == "Segmentation fault: 11")
        #expect(d.crashedThread == 1 && d.frames == [CrashFrame(image: "Editor", symbol: "Editor.save()"), CrashFrame(image: "dyld", symbol: "start")])
        #expect(d.appSpecific == ["assertion failed: buffer != NULL"] && d.osVersion == "macOS 27.2.1 (27C100)")
        #expect(try CrashReports.detail(home: home.root, name: "Kernel-2026-11-24.panic.ips").panic?.contains("watchdog") == true)
        // Only file names from the report folders: no paths, no other files.
        for bad in ["../../../etc/passwd", "/etc/hosts", "notes.txt", ".hidden.ips", "missing.ips"] {
            #expect(throws: PlanError.self) { try CrashReports.detail(home: home.root, name: bad) }
        }
    }

    @Test func mcpTools() throws {
        let home = FakeHome()
        let dir = FileManager.default.temporaryDirectory.appendingPathComponent("farrier-ctx-\(UUID().uuidString)")
        defer { try? FileManager.default.removeItem(at: dir) }
        var ctx = FarrierContext(
            collectFacts: { CollectionResult(facts: [:], notes: []) }, rulePaths: [],
            plans: PlanStore(directory: dir.appendingPathComponent("plans")),
            journal: Journal(url: dir.appendingPathComponent("j.jsonl")),
            host: { "H" }, applyThroughHelper: { _ in throw OperationError("none") }, actor: "mcp:test")
        let q = LogQuery(subsystem: "com.apple.powermanagement", lastSeconds: 3_600)
        ctx.debugRunner = RecordedRunner([
            (["/usr/bin/log"] + q.arguments).joined(separator: " "): CommandResult(status: 0, stdout:
                #"{"timestamp":"t","processImagePath":"/usr/libexec/powerd","subsystem":"com.apple.powermanagement","messageType":"Default","eventMessage":"hi"}"#),
            "/usr/bin/pmset -g log": CommandResult(status: 0, stdout: pmsetLog),
            "/usr/bin/pmset -g assertions": CommandResult(status: 0, stdout: assertions),
        ])
        ctx.crashHome = home.root

        let logs = try ToolCatalog.call("log_query", arguments: ["subsystem": .string("com.apple.powermanagement")], context: ctx)
        #expect(logs.isError != true)
        #expect(logs.structuredContent?.objectValue?["entries"]?.arrayValue?.count == 1)
        #expect(try ToolCatalog.call("log_query", arguments: ["minutes": .int(120)], context: ctx).isError == true)   // unfiltered, too long
        #expect(try ToolCatalog.call("log_query", arguments: ["process": .string("x"), "level": .string("loud")], context: ctx).isError == true)

        let power = try ToolCatalog.call("power_history", arguments: ["days": .int(30)], context: ctx)
        #expect(power.isError != true)
        #expect(power.structuredContent?.objectValue?["assertions"]?.arrayValue?.count == 2)
        #expect(try ToolCatalog.call("power_history", arguments: ["days": .int(90)], context: ctx).isError == true)

        let crashes = try ToolCatalog.call("crash_reports", arguments: [:], context: ctx)
        #expect(crashes.structuredContent?.objectValue?["reports"]?.arrayValue?.isEmpty == true)
        #expect(try ToolCatalog.call("crash_reports", arguments: ["report": .string("../x.ips")], context: ctx).isError == true)
        for name in ["log_query", "power_history", "crash_reports"] {
            #expect(try #require(ToolCatalog.tools.first { $0.name == name }).annotations.readOnlyHint == true)
        }
    }
}
