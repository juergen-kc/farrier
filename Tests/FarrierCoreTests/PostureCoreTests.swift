import Foundation
import Testing
@testable import FarrierCore

private func packs() throws -> [RulePack] {
    let (packs, issues) = RuleLinter.loadPacks(at: [repoRoot.appendingPathComponent("rules/posture").path], source: .bundled)
    try #require(issues.filter { $0.level == .error }.isEmpty, "\(issues)")
    return packs
}

private func status(_ id: String, _ facts: [String: FactValue]) throws -> Finding.Status {
    try #require(PostureEngine.evaluate(try packs(), facts: StaticFactStore(facts)).findings.first { $0.ruleID == id }).status
}

private func plist(_ d: [String: Any]) -> Data { try! PropertyListSerialization.data(fromPropertyList: d, format: .xml, options: 0) }

@Suite("posture.core: the 25 checks")
struct PostureCoreTests {
    @Test func packHas25ChecksWithGuidanceAndMappings() throws {
        let rules = try packs().flatMap(\.rules).compactMap { r -> CheckRule? in if case .check(let c) = r { return c } else { return nil } }
        #expect(rules.count == 25)
        #expect(Set(rules.map(\.id)).count == 25)
        // Every rule either fixes itself or tells the user how.
        for r in rules { #expect(r.remediation.automatic || r.remediation.guidance?.isEmpty == false, "\(r.id)") }
        #expect(rules.filter { $0.mappings["mscp"] != nil }.count >= 20)
    }

    @Test func parsers() {
        #expect(Parsers.authenticatedRoot("Authenticated Root status: enabled\n") == .string("enabled"))
        #expect(Parsers.authenticatedRoot("Authenticated Root status: disabled") == .string("disabled"))
        #expect(Parsers.authenticatedRoot("csrutil: unknown") == nil)
        #expect(Parsers.rootAccountEnabled("No such key: AuthenticationAuthority\n") == .bool(false))
        #expect(Parsers.rootAccountEnabled("AuthenticationAuthority: ;ShadowHash;HASHLIST:<SALTED-SHA512-PBKDF2>\n") == .bool(true))
        #expect(Parsers.rootAccountEnabled("AuthenticationAuthority: ;DisabledUser;;ShadowHash;\n") == .bool(false))
        #expect(Parsers.rootAccountEnabled("DS Error: -14009") == nil)
        let ts = "2026-11-23 22:10:01.123 sysadminctl[812:1234] "
        #expect(Parsers.screenLock(ts + "screenLock delay is immediate.\n") == .object(["enabled": .bool(true), "delaySeconds": .int(0)]))
        #expect(Parsers.screenLock(ts + "screenLock delay is 300 seconds\n") == .object(["enabled": .bool(true), "delaySeconds": .int(300)]))
        #expect(Parsers.screenLock(ts + "screenLock is off\n") == .object(["enabled": .bool(false)]))
        #expect(Parsers.screenLock("usage: sysadminctl …") == nil)
    }

    @Test func loginWindowSettingsKeepNoUserNames() {
        let files: [String: Data] = [
            "/Library/Preferences/com.apple.loginwindow.plist": plist(["GuestEnabled": true, "autoLoginUser": "juergen", "RetriesUntilHint": 3]),
            "/Library/Managed Preferences/com.apple.loginwindow.plist": plist(["RetriesUntilHint": 0]),
        ]
        let r = SystemCollectors(runner: RecordedRunner([:]), readFile: { files[$0] }, fileExists: { files[$0] != nil }).collect()
        // Managed values win; the auto-login user is only a yes/no.
        #expect(r.facts["loginwindow.prefs"] == .object(["GuestEnabled": .bool(true), "autoLogin": .bool(true), "RetriesUntilHint": .int(0)]))
        let none = SystemCollectors(runner: RecordedRunner([:]), readFile: { _ in nil }, fileExists: { _ in false }).collect()
        #expect(none.facts["loginwindow.prefs"] == nil)
    }

    @Test func newChecksEvaluate() throws {
        #expect(try status("posture.core.authenticated-root", ["sip.authenticatedRoot": .string("enabled")]) == .pass)
        #expect(try status("posture.core.authenticated-root", ["sip.authenticatedRoot": .string("disabled")]) == .fail)
        #expect(try status("posture.core.root-account-disabled", ["accounts.rootEnabled": .bool(true)]) == .fail)
        let login: FactValue = .object(["autoLogin": .bool(false), "GuestEnabled": .bool(false)])
        #expect(try status("posture.core.guest-account-off", ["loginwindow.prefs": login]) == .pass)
        #expect(try status("posture.core.automatic-login-off", ["loginwindow.prefs": login]) == .pass)
        #expect(try status("posture.core.password-hints-off", ["loginwindow.prefs": login]) == .unknown)   // not set: Apple's default
        #expect(try status("posture.core.screen-lock", ["screenlock": .object(["enabled": .bool(true), "delaySeconds": .int(5)])]) == .pass)
        #expect(try status("posture.core.screen-lock", ["screenlock": .object(["enabled": .bool(true), "delaySeconds": .int(300)])]) == .fail)
        #expect(try status("posture.core.screen-lock", ["screenlock": .object(["enabled": .bool(false)])]) == .fail)
        let ports: FactValue = .array([.int(445), .int(631), .int(3031), .int(7000)])
        for id in ["file-sharing-off", "printer-sharing-off", "remote-apple-events-off", "airplay-receiver-off"] {
            #expect(try status("posture.core.\(id)", ["network.listeningTCP": ports]) == .fail, "\(id)")
            #expect(try status("posture.core.\(id)", ["network.listeningTCP": .array([])]) == .pass, "\(id)")
        }
        let prefs: FactValue = .object(["AutomaticCheckEnabled": .bool(true), "AutomaticDownload": .bool(false)])
        #expect(try status("posture.core.update-check", ["softwareupdate.prefs": prefs]) == .pass)
        #expect(try status("posture.core.update-download", ["softwareupdate.prefs": prefs]) == .fail)
        #expect(try status("posture.core.install-macos-updates", ["softwareupdate.prefs": prefs]) == .unknown)
    }
}
