import Foundation
import Testing
@testable import FarrierCore

private func packs() throws -> [RulePack] {
    let (packs, issues) = RuleLinter.loadPacks(at: [repoRoot.appendingPathComponent("rules/posture").path], source: .bundled)
    try #require(issues.filter { $0.level == .error }.isEmpty, "\(issues)")
    return packs
}

private func finding(_ id: String, _ facts: [String: FactValue]) throws -> Finding {
    try #require(PostureEngine.evaluate(try packs(), facts: StaticFactStore(facts)).findings.first { $0.ruleID == id })
}

/// `profiles show -output stdout-xml`, shortened: an MDM enrollment profile and a firewall profile.
private let profilesXML = """
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict><key>_computerlevel</key><array>
  <dict>
    <key>ProfileIdentifier</key><string>com.example.mdm</string>
    <key>ProfileDisplayName</key><string>MDM Profile</string>
    <key>ProfileOrganization</key><string>Example Corp</string>
    <key>ProfileItems</key><array>
      <dict><key>PayloadType</key><string>com.apple.mdm</string>
        <key>PayloadContent</key><dict><key>ServerURL</key><string>https://mdm.example.com/mdm/checkin</string></dict></dict>
      <dict><key>PayloadType</key><string>com.apple.security.scep</string></dict>
    </array>
  </dict>
  <dict>
    <key>ProfileIdentifier</key><string>com.example.baseline</string>
    <key>ProfileDisplayName</key><string>Security Baseline</string>
    <key>ProfileItems</key><array><dict><key>PayloadType</key><string>com.apple.security.firewall</string></dict></array>
  </dict>
</array></dict></plist>
"""

private let base: [String: FactValue] = ["mdm.payloadTypes": .array([]), "mdm.declarationTypes": .array([]),
                                         "mdm.managedPreferences": .object([:])]

@Suite("Managed-device detection")
struct ManagedDeviceTests {
    @Test func profileSummaries() throws {
        let value = try #require(Parsers.profileSummaries(Data(profilesXML.utf8)))
        #expect(value == .array([
            .object(["identifier": .string("com.example.baseline"), "displayName": .string("Security Baseline"),
                     "payloadTypes": .array([.string("com.apple.security.firewall")])]),
            .object(["identifier": .string("com.example.mdm"), "displayName": .string("MDM Profile"),
                     "organization": .string("Example Corp"), "mdmServer": .string("mdm.example.com"),
                     "payloadTypes": .array([.string("com.apple.mdm"), .string("com.apple.security.scep")])]),
        ]))
        #expect(Parsers.profileSummaries(Data("There are no configuration profiles installed\n".utf8)) == .array([]))
        // A profile without an identifier, or an item without a type, makes the whole list unknown.
        #expect(Parsers.profileSummaries(Data(profilesXML.replacingOccurrences(of: "<key>ProfileIdentifier</key><string>com.example.baseline</string>", with: "").utf8)) == nil)
        #expect(Parsers.profileSummaries(Data("garbage".utf8)) == nil)
    }

    @Test func managedPreferencesAreCollected() {
        func plist(_ d: [String: Any]) -> Data { try! PropertyListSerialization.data(fromPropertyList: d, format: .xml, options: 0) }
        let dir = "/Library/Managed Preferences"
        let files: [String: Data] = [
            "\(dir)/com.apple.SoftwareUpdate.plist": plist(["CriticalUpdateInstall": false, "AutomaticCheckEnabled": true]),
            "\(dir)/com.apple.security.firewall.plist": plist(["EnableFirewall": true, "PayloadUUID": "X", "_manualProfile": true]),
        ]
        func collector(_ files: [String: Data], dirExists: Bool = true) -> SystemCollectors {
            SystemCollectors(runner: RecordedRunner([:]), readFile: { files[$0] },
                             fileExists: { $0 == dir ? dirExists : files[$0] != nil || $0.hasSuffix("broken.plist") },
                             listDirectory: { _ in files.keys.map { ($0 as NSString).lastPathComponent } + ["juergen"] })
        }
        #expect(collector(files).collect().facts["mdm.managedPreferences"] == .object([
            "com.apple.SoftwareUpdate": .array([.string("AutomaticCheckEnabled"), .string("CriticalUpdateInstall")]),
            "com.apple.security.firewall": .array([.string("EnableFirewall")]),
        ]))
        #expect(collector(files).managedPreferences()?["com.apple.security.firewall"] == ["EnableFirewall"])
        // No directory: nothing is managed.
        #expect(collector([:], dirExists: false).collect().facts["mdm.managedPreferences"] == .object([:]))
        // A domain that can't be read could hide a managed key: the fact is unknown, not partial.
        var broken = files
        broken["\(dir)/com.example.broken.plist"] = Data("not a plist".utf8)
        let result = collector(broken).collect()
        #expect(result.facts["mdm.managedPreferences"] == nil)
        #expect(result.notes.first { $0.fact == "mdm.managedPreferences" }?.status == .failed)
    }

    @Test func aManagedPreferenceKeyMakesTheRuleManaged() throws {
        var facts = base
        facts["softwareupdate.prefs"] = .object(["CriticalUpdateInstall": .bool(false), "ConfigDataInstall": .bool(true)])
        #expect(try finding("posture.core.auto-security-updates", facts).fixable)
        // A Custom Settings profile for the domain, but only for an unrelated key: still not managed.
        facts["mdm.managedPreferences"] = .object(["com.apple.SoftwareUpdate": .array([.string("AutomaticCheckEnabled")])])
        #expect(try finding("posture.core.auto-security-updates", facts).fixable)
        // The key itself is managed: reported, never fixed.
        facts["mdm.managedPreferences"] = .object(["com.apple.SoftwareUpdate": .array([.string("AutomaticCheckEnabled"), .string("CriticalUpdateInstall")])])
        let f = try finding("posture.core.auto-security-updates", facts)
        #expect(f.managed)
        #expect(!f.fixable)
        #expect(f.managedBy == "managed preferences com.apple.SoftwareUpdate (CriticalUpdateInstall)")
        // Not collected (or malformed): management unknown.
        facts["mdm.managedPreferences"] = .array([])
        #expect(try finding("posture.core.auto-security-updates", facts).managementUnknown)
    }

    @Test func managedFindingsNameTheProfile() throws {
        var facts = base
        facts["firewall.globalState"] = .string("off")
        facts["mdm.payloadTypes"] = .array([.string("com.apple.mdm"), .string("com.apple.security.firewall"), .string("com.apple.security.scep")])
        facts["mdm.profiles"] = try #require(Parsers.profileSummaries(Data(profilesXML.utf8)))
        let f = try finding("posture.core.firewall", facts)
        #expect(f.managedBy == "com.apple.security.firewall")
        #expect(f.managedByProfile == "Security Baseline")
        let store = StaticFactStore(facts)
        let packs = try packs()
        let (plan, skipped) = Planner.plan(report: PostureEngine.evaluate(packs, facts: store), packs: packs, facts: store,
                                           ruleIDs: ["posture.core.firewall"], host: "H")
        #expect(plan == nil)
        #expect(skipped.first?.reason.contains("profile Security Baseline") == true)
        #expect(skipped.first?.reason.contains("change it in your MDM") == true)  // enrollment unknown
        // Not enrolled: the profile was installed by hand, so that's where it's changed.
        facts["mdm.enrollment"] = .object(["dep": .bool(false), "mdm": .bool(false), "userApproved": .bool(false)])
        let local = StaticFactStore(facts)
        let (_, localSkips) = Planner.plan(report: PostureEngine.evaluate(packs, facts: local), packs: packs, facts: local,
                                           ruleIDs: ["posture.core.firewall"], host: "H")
        #expect(localSkips.first?.reason.contains("Device Management") == true)
    }

    @Test func managementSummary() throws {
        var facts = base
        facts["mdm.enrollment"] = .object(["dep": .bool(true), "mdm": .bool(true), "userApproved": .bool(true)])
        facts["mdm.profiles"] = try #require(Parsers.profileSummaries(Data(profilesXML.utf8)))
        let s = ManagementSummary(facts: StaticFactStore(facts))
        #expect(s.mdmEnrolled == true)
        #expect(s.mdmServer == "mdm.example.com")
        #expect(s.profiles == ["Security Baseline", "MDM Profile (Example Corp)"])
        #expect(s.description == "MDM-enrolled (Automated Device Enrollment) with mdm.example.com; 2 configuration profile(s)")
        let none = ManagementSummary(facts: StaticFactStore([:]))
        #expect(none.description == "MDM enrollment unknown; configuration profiles not checked (needs the helper)")
    }

    @Test func preferenceSelectorsAreValidated() {
        func parse(_ managedBy: String) -> [String] {
            let yaml = """
                pack: { id: p, title: P, version: 1 }
                rules:
                  - id: p.su
                    title: Updates
                    kind: check
                    severity: high
                    collect: { fact: softwareupdate.prefs }
                    expect: { path: CriticalUpdateInstall, equals: true }
                    managedBy:
                      - \(managedBy)
                    remediation: { automatic: false, guidance: Turn it on. }
                """
            return RulePackParser.parse(yaml: yaml, file: "t.yaml", source: .bundled).issues.filter { $0.level == .error }.map(\.message)
        }
        #expect(parse("{ preference: com.apple.SoftwareUpdate, keys: [CriticalUpdateInstall] }").isEmpty)
        #expect(parse("{ preference: com.apple.SoftwareUpdate }").isEmpty)
        #expect(parse("{ payloadType: x, keys: [A] }").contains { $0.contains("only goes with `preference`") })
        #expect(parse("{ preference: d, keys: A }").contains { $0.contains("list of key names") })
        #expect(parse("{ preference: d, payloadType: x }").contains { $0.contains("exactly one of") })
    }
}
