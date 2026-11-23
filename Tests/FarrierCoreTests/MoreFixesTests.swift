import Foundation
import Testing
@testable import FarrierCore

private func packs() throws -> [RulePack] {
    let (packs, issues) = RuleLinter.loadPacks(at: [repoRoot.appendingPathComponent("rules/posture").path], source: .bundled)
    try #require(issues.filter { $0.level == .error }.isEmpty, "\(issues)")
    return packs
}

private func plan(_ rule: String, _ facts: [String: FactValue]) throws -> (Plan?, [PlanSkip]) {
    let store = StaticFactStore(facts)
    let packs = try packs()
    let report = PostureEngine.evaluate(packs, facts: store)
    return Planner.plan(report: report, packs: packs, facts: store, ruleIDs: [rule], host: "H")
}

private let unmanaged: [String: FactValue] = ["mdm.payloadTypes": .array([]), "mdm.declarationTypes": .array([]),
                                              "mdm.managedPreferences": .object([:])]

@Suite("Gatekeeper and security auto-install fixes")
struct MoreFixesTests {
    @Test func gatekeeperIsPlannedThroughTheCatalog() throws {
        let (p, _) = try plan("posture.core.gatekeeper", unmanaged.merging(["gatekeeper.assessments": .string("disabled")]) { $1 })
        let item = try #require(p?.items.first)
        #expect(item.action == "gatekeeper.enable")
        #expect(item.tier == .t4)
        #expect(item.observed == .string("disabled"))
        #expect(try Plan.decodeCanonical(try #require(p).canonicalData()) == p)
        // A Gatekeeper profile means MDM owns it.
        let (managed, skipped) = try plan("posture.core.gatekeeper", ["gatekeeper.assessments": .string("disabled"),
            "mdm.payloadTypes": .array([.string("com.apple.systempolicy.control")]), "mdm.declarationTypes": .array([]),
            "mdm.managedPreferences": .object([:])])
        #expect(managed == nil)
        #expect(skipped.first?.reason.contains("managed by com.apple.systempolicy.control") == true)
    }

    @Test func securityAutoInstallIsPlannedWithTheWholeSettingsObserved() throws {
        let prefs: FactValue = .object(["CriticalUpdateInstall": .bool(false), "ConfigDataInstall": .bool(true),
                                        "AutomaticCheckEnabled": .bool(true)])
        let (p, _) = try plan("posture.core.auto-security-updates", unmanaged.merging(["softwareupdate.prefs": prefs]) { $1 })
        let item = try #require(p?.items.first)
        #expect(item.action == "softwareupdate.enableSecurityAutoInstall")
        #expect(item.observed == prefs)   // the helper refuses if anything in it changed
        #expect(item.description.contains("Security Responses"))
        #expect(RemediationCatalog.securityAutoInstallKeys == ["CriticalUpdateInstall", "ConfigDataInstall"])
    }

    @Test func securityAutoInstallIsNeverPlannedWhenDeclarationsAreUnknown() throws {
        // An MDM-enrolled Mac: payloads read, declarations not. A declaration could own the setting.
        let facts: [String: FactValue] = ["mdm.payloadTypes": .array([]), "mdm.managedPreferences": .object([:]),
                                          "softwareupdate.prefs": .object(["CriticalUpdateInstall": .bool(false), "ConfigDataInstall": .bool(true)])]
        let (p, skipped) = try plan("posture.core.auto-security-updates", facts)
        #expect(p == nil)
        #expect(skipped.first?.reason.contains("declarations") == true)
        // Gatekeeper's rule names no declaration, so it doesn't need them.
        let (gk, _) = try plan("posture.core.gatekeeper", ["mdm.payloadTypes": .array([]), "mdm.managedPreferences": .object([:]),
                                                            "gatekeeper.assessments": .string("disabled")])
        #expect(gk != nil)
    }

    @Test func keysThatAreNotSetAreUnknownNotFixed() throws {
        let (p, skipped) = try plan("posture.core.auto-security-updates",
                                    unmanaged.merging(["softwareupdate.prefs": .object(["ConfigDataInstall": .bool(true)])]) { $1 })
        #expect(p == nil)
        #expect(skipped.first?.reason.hasPrefix("status unknown") == true)
    }

    @Test func declarationTypesFollowEnrollment() {
        func collect(_ enrollment: String) -> CollectionResult {
            let runner = RecordedRunner(["/usr/bin/profiles status -type enrollment": CommandResult(status: 0, stdout: enrollment)])
            return SystemCollectors(runner: runner, readFile: { _ in nil }, fileExists: { _ in false }).collect()
        }
        let notEnrolled = collect("Enrolled via DEP: No\nMDM enrollment: No\n")
        #expect(notEnrolled.facts["mdm.declarationTypes"] == .array([]))
        let enrolled = collect("Enrolled via DEP: Yes\nMDM enrollment: Yes (User Approved)\n")
        #expect(enrolled.facts["mdm.declarationTypes"] == nil)
        #expect(enrolled.notes.first { $0.fact == "mdm.declarationTypes" }?.status == .unavailable)
        let unknown = collect("something new")
        #expect(unknown.facts["mdm.declarationTypes"] == nil)
    }

    @Test func softwareUpdateSettingsReportManagedOverrides() throws {
        func plist(_ d: [String: Bool]) -> Data {
            try! PropertyListSerialization.data(fromPropertyList: d, format: .xml, options: 0)
        }
        let files: [String: Data] = [
            "/Library/Preferences/com.apple.SoftwareUpdate.plist": plist(["CriticalUpdateInstall": true, "ConfigDataInstall": true]),
            // A custom-settings profile forcing one key off: the managed value is the effective one.
            "/Library/Managed Preferences/com.apple.SoftwareUpdate.plist": plist(["CriticalUpdateInstall": false]),
        ]
        let collector = SystemCollectors(runner: RecordedRunner([:]), readFile: { files[$0] }, fileExists: { files[$0] != nil })
        let settings = try #require(collector.softwareUpdateSettings())
        #expect(settings.prefs["CriticalUpdateInstall"] == .bool(false))
        #expect(settings.prefs["ConfigDataInstall"] == .bool(true))
        #expect(settings.managedKeys == ["CriticalUpdateInstall"])
        let none = SystemCollectors(runner: RecordedRunner([:]), readFile: { _ in nil }, fileExists: { _ in false })
        #expect(none.softwareUpdateSettings() == nil)
    }
}
