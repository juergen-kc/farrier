import Foundation
import Testing
@testable import FarrierCore

@Suite("Posture engine")
struct PostureEngineTests {
    func packs() throws -> [RulePack] {
        let (packs, issues) = RuleLinter.loadPacks(at: [repoRoot.appendingPathComponent("rules/posture").path], source: .bundled)
        try #require(issues.filter { $0.level == .error }.isEmpty, "\(issues)")
        return packs
    }

    func finding(_ report: PostureReport, _ id: String) throws -> Finding {
        try #require(report.findings.first { $0.ruleID == id })
    }

    @Test func sampleFactsEvaluateAsDocumented() throws {
        let data = try Data(contentsOf: repoRoot.appendingPathComponent("examples/facts-sample.json"))
        let report = PostureEngine.evaluate(try packs(), facts: try StaticFactStore(json: data))

        #expect(try finding(report, "posture.core.filevault").status == .pass)
        #expect(try finding(report, "posture.core.sip").status == .pass)

        let firewall = try finding(report, "posture.core.firewall")
        #expect(firewall.status == .fail)
        #expect(firewall.fixable)                 // automatic remediation, not managed

        let updates = try finding(report, "posture.core.auto-security-updates")
        #expect(updates.status == .fail)
        #expect(updates.managed)                  // a declaration enforces it…
        #expect(!updates.fixable)                 // …so Farrier must not touch it

        let launch = try finding(report, "posture.core.unsigned-launch-items")
        #expect(launch.status == .fail)
        #expect(launch.reason?.contains("item 1") == true)

        // Not collected → unknown, never pass or fail.
        #expect(try finding(report, "posture.core.gatekeeper").status == .unknown)
    }

    @Test func failuresComeFirstBySeverity() throws {
        let data = try Data(contentsOf: repoRoot.appendingPathComponent("examples/facts-sample.json"))
        let report = PostureEngine.evaluate(try packs(), facts: try StaticFactStore(json: data))
        let statuses = report.findings.map(\.status)
        let firstNonFail = statuses.firstIndex { $0 != .fail } ?? statuses.count
        #expect(statuses[firstNonFail...].allSatisfy { $0 != .fail })
        let failSeverities = report.findings.prefix(firstNonFail).map(\.severity)
        #expect(failSeverities == failSeverities.sorted(by: >))
    }

    @Test func emptyFactsAreAllUnknown() throws {
        let report = PostureEngine.evaluate(try packs(), facts: StaticFactStore([:]))
        #expect(!report.findings.isEmpty)
        #expect(report.findings.allSatisfy { $0.status == .unknown })
        #expect(report.summary["unknown"] == report.findings.count)
    }

    @Test func factFileMustBeAnObject() {
        #expect(throws: (any Error).self) { _ = try StaticFactStore(json: Data("[1,2]".utf8)) }
    }
}
