import Foundation
import Testing
@testable import FarrierCore

/// Golden tests for the CLI parsers. The inputs are real outputs (LANG=C). When a macOS version changes an
/// output, add it here as a new case rather than replacing the old one.
@Suite("Parsers")
struct ParserTests {
    @Test(arguments: [
        ("FileVault is On.\n", "On"),
        ("FileVault is Off.\n", "Off"),
        ("FileVault is On.\nDeferred enablement appears to be active for user 'x'.\n", "On"),
        ("Encryption in progress: Percent completed = 12.3\n", "Encrypting"),
        ("Decryption in progress: Percent completed = 80.0\n", "Decrypting"),
    ])
    func fdesetup(input: String, expected: String) {
        #expect(Parsers.fdesetupStatus(input) == .string(expected))
    }

    @Test(arguments: [
        ("System Integrity Protection status: enabled.\n", "enabled"),
        ("System Integrity Protection status: disabled.\n", "disabled"),
        ("System Integrity Protection status: unknown (Custom Configuration).\n\nConfiguration:\n\tApple Internal: disabled\n", "custom"),
    ])
    func csrutil(input: String, expected: String) {
        #expect(Parsers.csrutilStatus(input) == .string(expected))
    }

    @Test(arguments: [
        ("assessments enabled\n", "enabled"),
        ("assessments disabled\n", "disabled"),
    ])
    func spctl(input: String, expected: String) {
        #expect(Parsers.spctlStatus(input) == .string(expected))
    }

    @Test(arguments: [
        ("Firewall is disabled. (State = 0)\n", "off"),
        ("Firewall is enabled. (State = 1)\n", "on"),
        ("Firewall is blocking all non-essential incoming connections. (State = 2)\n", "blockAll"),
        ("Firewall is enabled.\n", "on"),
    ])
    func firewall(input: String, expected: String) {
        #expect(Parsers.firewallGlobalState(input) == .string(expected))
    }

    @Test func swVers() throws {
        let v = try #require(Parsers.swVers("ProductName:\t\tmacOS\nProductVersion:\t\t15.2\nBuildVersion:\t\t24C101\n"))
        #expect(v.value(at: "productVersion") == .string("15.2"))
        #expect(v.value(at: "buildVersion") == .string("24C101"))
        #expect(v.value(at: "productName") == .string("macOS"))
    }

    @Test func profilesEnrollment() throws {
        let none = try #require(Parsers.profilesEnrollment("Enrolled via DEP: No\nMDM enrollment: No\n"))
        #expect(none.value(at: "mdm") == .bool(false))
        #expect(none.value(at: "dep") == .bool(false))
        let managed = try #require(Parsers.profilesEnrollment("Enrolled via DEP: Yes\nMDM enrollment: Yes (User Approved)\n"))
        #expect(managed.value(at: "mdm") == .bool(true))
        #expect(managed.value(at: "dep") == .bool(true))
        #expect(managed.value(at: "userApproved") == .bool(true))
    }

    @Test func profilePayloadTypes() throws {
        // Structure of `profiles show -output stdout-xml` as root: computer-level profiles under _computerlevel,
        // each with ProfileItems carrying a PayloadType.
        let xml = """
            <?xml version="1.0" encoding="UTF-8"?>
            <plist version="1.0"><dict>
              <key>_computerlevel</key>
              <array>
                <dict>
                  <key>ProfileIdentifier</key><string>com.jumpcloud.mdm.security</string>
                  <key>ProfileItems</key>
                  <array>
                    <dict><key>PayloadType</key><string>com.apple.security.firewall</string></dict>
                    <dict><key>PayloadType</key><string>com.apple.MCX.FileVault2</string></dict>
                  </array>
                </dict>
                <dict>
                  <key>ProfileItems</key>
                  <array><dict><key>PayloadType</key><string>com.apple.security.firewall</string></dict></array>
                </dict>
              </array>
            </dict></plist>
            """
        let v = try #require(Parsers.profilePayloadTypes(Data(xml.utf8)))
        #expect(v == .array([.string("com.apple.MCX.FileVault2"), .string("com.apple.security.firewall")]))  // sorted, unique
        // No profiles: profiles prints a sentence, which means an empty list (known), not unknown.
        #expect(Parsers.profilePayloadTypes(Data("There are no configuration profiles installed\n".utf8)) == .array([]))
        // Only user-level profiles: no _computerlevel key → empty.
        let userOnly = #"<?xml version="1.0"?><plist version="1.0"><dict><key>_user</key><array/></dict></plist>"#
        #expect(Parsers.profilePayloadTypes(Data(userOnly.utf8)) == .array([]))
        // Anything else stays unknown.
        #expect(Parsers.profilePayloadTypes(Data("profiles: this command requires root\n".utf8)) == nil)
        #expect(Parsers.profilePayloadTypes(Data("Error: There are no configuration profiles installed? maybe\n".utf8)) == nil)
    }

    @Test func profilePayloadTypesFailClosed() {
        func plist(_ profiles: String) -> Data {
            Data(#"<?xml version="1.0"?><plist version="1.0"><dict><key>_computerlevel</key><array>\#(profiles)</array></dict></plist>"#.utf8)
        }
        let firewall = "<dict><key>PayloadType</key><string>com.apple.security.firewall</string></dict>"
        // The no-profiles sentence inside a real profile's metadata must not empty the inventory.
        let named = plist("<dict><key>ProfileDisplayName</key><string>There are no configuration profiles installed</string>"
                          + "<key>ProfileItems</key><array>\(firewall)</array></dict>")
        #expect(Parsers.profilePayloadTypes(named) == .array([.string("com.apple.security.firewall")]))
        // A profile without ProfileItems, ProfileItems that isn't a list, or an item without a string PayloadType:
        // the inventory would be incomplete, so it's unknown.
        #expect(Parsers.profilePayloadTypes(plist("<dict><key>ProfileIdentifier</key><string>x</string></dict>")) == nil)
        #expect(Parsers.profilePayloadTypes(plist("<dict><key>ProfileItems</key><string>x</string></dict>")) == nil)
        #expect(Parsers.profilePayloadTypes(plist("<dict><key>ProfileItems</key><array>\(firewall)<dict/></array></dict>")) == nil)
        #expect(Parsers.profilePayloadTypes(plist("<dict><key>ProfileItems</key><array><dict><key>PayloadType</key><integer>1</integer></dict></array></dict>")) == nil)
        // A profile with an empty ProfileItems list is well-formed.
        #expect(Parsers.profilePayloadTypes(plist("<dict><key>ProfileItems</key><array/></dict>")) == .array([]))
    }

    @Test func unrecognisedValuesAreNil() {
        // PR #3 review: values outside the known set must be unknown, not guessed.
        #expect(Parsers.firewallGlobalState("Firewall is enabled. (State = 10)\n") == nil)          // not "on"
        #expect(Parsers.csrutilStatus("System Integrity Protection status: unknown.\n") == nil)    // not "custom"
        #expect(Parsers.csrutilStatus("System Integrity Protection status: pending.\n") == nil)
        #expect(Parsers.profilesEnrollment("Enrolled via DEP: Unknown\nMDM enrollment: No\n") == nil)
        #expect(Parsers.profilesEnrollment("Enrolled via DEP: No\nMDM enrollment: Unknown\n") == nil)
        #expect(Parsers.profilesEnrollment("Enrolled via DEP: No\nMDM enrollment: Yes\n")?.value(at: "userApproved") == .bool(false))
    }

    @Test func unrecognisedOutputIsNil() {
        // Never guess: an unknown output must make the fact unknown, not pass or fail.
        #expect(Parsers.fdesetupStatus("something new") == nil)
        #expect(Parsers.csrutilStatus("") == nil)
        #expect(Parsers.spctlStatus("Error: …") == nil)
        #expect(Parsers.firewallGlobalState("(State = 7)") == nil)
        #expect(Parsers.swVers("") == nil)
        #expect(Parsers.profilesEnrollment("profiles: error") == nil)
    }

    @Test func propertyListKeepsTypesAndConvertsDates() throws {
        let xml = """
            <?xml version="1.0" encoding="UTF-8"?>
            <!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
            <plist version="1.0">
            <dict>
                <key>AutomaticCheckEnabled</key><true/>
                <key>ConfigDataInstall</key><false/>
                <key>LastResultCode</key><integer>2</integer>
                <key>LastSuccessfulDate</key><date>2026-11-20T09:00:00Z</date>
                <key>LastRecommendedMajorOSBundleIdentifier</key><string>com.apple.InstallAssistant.macOSTahoe</string>
            </dict>
            </plist>
            """
        let v = try #require(Parsers.propertyList(Data(xml.utf8)))
        #expect(v.value(at: "AutomaticCheckEnabled") == .bool(true))
        #expect(v.value(at: "ConfigDataInstall") == .bool(false))
        #expect(v.value(at: "LastResultCode")?.number == 2)
        #expect(v.value(at: "LastSuccessfulDate")?.string?.hasPrefix("2026-11-20") == true)
    }
}

@Suite("System collectors")
struct SystemCollectorTests {
    let recorded = RecordedRunner([
        "/usr/bin/sw_vers": CommandResult(status: 0, stdout: "ProductName:\tmacOS\nProductVersion:\t26.1\nBuildVersion:\t25B78\n"),
        "/usr/bin/fdesetup status": CommandResult(status: 0, stdout: "FileVault is On.\n"),
        "/usr/bin/csrutil status": CommandResult(status: 0, stdout: "System Integrity Protection status: enabled.\n"),
        "/usr/sbin/spctl --status": CommandResult(status: 0, stdout: "", stderr: "assessments enabled\n"),
        "/usr/libexec/ApplicationFirewall/socketfilterfw --getglobalstate":
            CommandResult(status: 0, stdout: "Firewall is disabled. (State = 0)\n"),
        // profiles: deliberately unrecognised output → unparsed, not a guess
        "/usr/bin/profiles status -type enrollment": CommandResult(status: 0, stdout: "Something new\n"),
    ])

    let plist = Data("""
        <?xml version="1.0" encoding="UTF-8"?>
        <plist version="1.0"><dict>
          <key>AutomaticCheckEnabled</key><true/>
          <key>CriticalUpdateInstall</key><true/>
          <key>ConfigDataInstall</key><false/>
        </dict></plist>
        """.utf8)

    let managedPlist = Data("""
        <?xml version="1.0" encoding="UTF-8"?>
        <plist version="1.0"><dict><key>ConfigDataInstall</key><true/></dict></plist>
        """.utf8)

    @Test func collectsRecordedOutputs() throws {
        let plist = self.plist
        let collectors = SystemCollectors(runner: recorded,
                                          readFile: { path in path == SystemCollectors.softwareUpdatePlist ? plist : nil },
                                          fileExists: { $0 == SystemCollectors.softwareUpdatePlist })
        let result = collectors.collect()
        #expect(result.facts["filevault.status"] == .string("On"))
        #expect(result.facts["gatekeeper.assessments"] == .string("enabled"))  // answer on stderr
        #expect(result.facts["firewall.globalState"] == .string("off"))
        #expect(result.facts["os.version"]?.value(at: "productVersion") == .string("26.1"))
        #expect(result.facts["mdm.enrollment"] == nil)
        #expect(result.notes.first { $0.fact == "mdm.enrollment" }?.status == .unparsed)
        #expect(result.facts["softwareupdate.prefs"]?.value(at: "ConfigDataInstall") == .bool(false))
    }

    @Test func managedPreferencesWin() throws {
        let (plist, managed) = (self.plist, managedPlist)
        let collectors = SystemCollectors(runner: recorded, readFile: { path in
            switch path {
            case SystemCollectors.softwareUpdatePlist: return plist
            case SystemCollectors.softwareUpdateManagedPlist: return managed
            default: return nil
            }
        }, fileExists: { _ in true })
        let result = collectors.collect()
        #expect(result.facts["softwareupdate.prefs"]?.value(at: "ConfigDataInstall") == .bool(true))
        #expect(result.facts["softwareupdate.managedKeys"] == .array([.string("ConfigDataInstall")]))
    }

    @Test func unreadableManagedPreferencesMakeTheFactUnknown() {
        // PR #3 review: a managed plist that exists but can't be read or parsed must not fall back to local values.
        let plist = self.plist
        for managedData: Data? in [nil, Data("not a plist".utf8)] {
            let result = SystemCollectors(runner: recorded, readFile: { path in
                path == SystemCollectors.softwareUpdatePlist ? plist : managedData
            }, fileExists: { _ in true }).collect()
            #expect(result.facts["softwareupdate.prefs"] == nil)
            #expect(result.notes.first { $0.fact == "softwareupdate.prefs" }?.status == .failed)
        }
    }

    @Test func missingToolsAreUnavailable() {
        let result = SystemCollectors(runner: RecordedRunner([:]), readFile: { _ in nil }, fileExists: { _ in false }).collect()
        // No /Library/Managed Preferences means no managed preferences: the one fact that's known without tools.
        #expect(result.facts == ["mdm.managedPreferences": .object([:])])
        #expect(result.notes.filter { $0.fact != "mdm.managedPreferences" }.allSatisfy { $0.status == .unavailable })
    }

    @Test func liveFactsDriveThePostureEngine() throws {
        let plist = self.plist
        let collected = SystemCollectors(runner: recorded,
                                         readFile: { path in path == SystemCollectors.softwareUpdatePlist ? plist : nil },
                                         fileExists: { $0 == SystemCollectors.softwareUpdatePlist }).collect()
        let (packs, _) = RuleLinter.loadPacks(at: [repoRoot.appendingPathComponent("rules/posture").path], source: .bundled)
        let report = PostureEngine.evaluate(packs, facts: StaticFactStore(collected))
        let firewall = try #require(report.findings.first { $0.ruleID == "posture.core.firewall" })
        #expect(firewall.status == .fail)
        // MDM enrollment unknown and profiles not collected → Farrier must not offer to fix it.
        #expect(firewall.managementUnknown)
        #expect(!firewall.fixable)
        let fv = try #require(report.findings.first { $0.ruleID == "posture.core.filevault" })
        #expect(fv.status == .pass)
    }
}
