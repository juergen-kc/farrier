import Foundation
import MCP
import Testing
@testable import FarrierCore
@testable import FarrierMCP

/// `systemextensionsctl list` on a Mac with an endpoint security and a network extension (tab-separated).
private let sysext = """
2 extension(s)
--- com.apple.system_extension.endpoint_security
enabled\tactive\tteamID\tbundleID (version)\tname\t[state]
*\t*\tUBF8T346G9\tcom.microsoft.wdav.epsext (101.24.1/101.24.1)\tMicrosoft Defender Endpoint Security Extension\t[activated enabled]
--- com.apple.system_extension.network_extension
enabled\tactive\tteamID\tbundleID (version)\tname\t[state]
\t\tABCDE12345\tcom.example.vpn.ext (2.0/200)\tExample VPN\t[terminated waiting to uninstall on reboot]

"""

private func plist(_ d: [String: Any]) -> Data { try! PropertyListSerialization.data(fromPropertyList: d, format: .xml, options: 0) }

@Suite("Inventory")
struct InventoryTests {
    @Test func systemExtensionsParser() throws {
        let value = try #require(Parsers.systemExtensions(sysext))
        let items = try #require(value.array)
        #expect(items.count == 2)
        #expect(items[0] == .object(["category": .string("com.apple.system_extension.endpoint_security"), "enabled": .bool(true),
                                     "active": .bool(true), "teamID": .string("UBF8T346G9"), "bundleID": .string("com.microsoft.wdav.epsext"),
                                     "version": .string("101.24.1/101.24.1"), "name": .string("Microsoft Defender Endpoint Security Extension"),
                                     "state": .string("activated enabled")]))
        #expect(items[1].object?["enabled"] == .bool(false))
        #expect(Parsers.systemExtensions("0 extension(s)\n") == .array([]))
        // The count says 2 but a row can't be read: not trusted.
        #expect(Parsers.systemExtensions(sysext.replacingOccurrences(of: "\tExample VPN\t", with: " Example VPN ")) == nil)
        #expect(Parsers.systemExtensions("systemextensionsctl: unknown command") == nil)
    }

    @Test func adminMembersParser() {
        #expect(Parsers.groupMembers("GroupMembership: root juergen\n") == .array([.string("juergen"), .string("root")]))
        #expect(Parsers.groupMembers("No such key: GroupMembership\n") == .array([]))
        #expect(Parsers.groupMembers("<dscl_cmd> DS Error: -14136") == nil)
    }

    @Test func appsAreListedWithSignatures() throws {
        let files: [String: Data] = [
            "/Applications/Good.app/Contents/Info.plist": plist(["CFBundleName": "Good", "CFBundleIdentifier": "com.example.good",
                                                                  "CFBundleShortVersionString": "1.2"]),
            "/Applications/Utilities/Tool.app/Contents/Info.plist": plist(["CFBundleDisplayName": "Tool", "CFBundleIdentifier": "com.example.tool"]),
        ]
        let dirs: [String: [String]] = ["/Applications": ["Good.app", "Utilities", "Broken.app", ".hidden.app", "GoodLink.app"],
                                        "/Applications/Utilities": ["Tool.app", "readme.txt"]]
        let sigs = FakeSignatures([
            "/Applications/Good.app": CodeSignatureInfo(valid: true, notarized: true, teamID: "ABCDE12345"),
            "/Applications/Utilities/Tool.app": CodeSignatureInfo(valid: true, notarized: false, teamID: "ZZZZZ99999"),
            "/Applications/Broken.app": CodeSignatureInfo(valid: false, notarized: false, error: "unsigned"),
        ])
        let collector = InventoryCollector(runner: RecordedRunner([:]), readFile: { files[$0] },
                                           fileExists: { $0 == "/Applications" }, listDirectory: { dirs[$0] },
                                           signatures: sigs, appFolders: ["/Applications", "/Users/t/Applications"],
                                           resolve: { $0 == "/Applications/GoodLink.app" ? "/Applications/Good.app" : $0 },
                                           isDirectory: { $0 == "/Applications/Utilities" })
        let result = collector.collect()
        let apps = try #require(result.facts["apps.installed"]?.array)
        #expect(apps.map { $0.object?["path"]?.string } == ["/Applications/Broken.app", "/Applications/Good.app", "/Applications/Utilities/Tool.app"])
        #expect(apps[0].object?["error"] == .string("cannot read Info.plist"))   // still listed, by its file name
        #expect(apps[0].object?["name"] == .string("Broken"))
        #expect(apps[1].object?["version"] == .string("1.2"))
        #expect(apps.map(Inventory.needsALook) == [true, false, true])
        // Missing tools: unavailable, never empty lists.
        #expect(result.facts["system.extensions"] == nil)
        #expect(result.notes.first { $0.fact == "accounts.admins" }?.status == .unavailable)
    }

    @Test func appScanNeverLooksCompleteWhenItIsnt() throws {
        func collector(roots: Set<String>, dirs: [String: [String]], resolve: @escaping @Sendable (String) -> String? = { $0 })
            -> InventoryCollector {
            InventoryCollector(runner: RecordedRunner([:]), readFile: { _ in nil }, fileExists: { roots.contains($0) },
                               listDirectory: { dirs[$0] }, signatures: FakeSignatures([:]),
                               appFolders: ["/Applications", "/Users/t/Applications"], resolve: resolve,
                               isDirectory: { dirs[$0] != nil })
        }
        // No app folder at all: unavailable, not an empty list.
        let none = collector(roots: [], dirs: [:]).collect()
        #expect(none.facts["apps.installed"] == nil)
        #expect(none.notes.first { $0.fact == "apps.installed" }?.status == .unavailable)
        // /Applications exists but can't be listed: failed.
        let unlistable = collector(roots: ["/Applications"], dirs: [:]).collect()
        #expect(unlistable.facts["apps.installed"] == nil)
        #expect(unlistable.notes.first { $0.fact == "apps.installed" }?.status == .failed)
        // A sub-folder that can't be listed, and links into privacy-protected folders: named, never followed.
        let partial = collector(roots: ["/Applications"],
                                dirs: ["/Applications": ["Locked", "Docs.app", "DocsFolder", "A.app"], "/Applications/Locked": []],
                                resolve: { $0.contains("Docs") ? nil : $0 })
        let dirs2: [String: [String]] = ["/Applications": ["Locked", "Docs.app", "DocsFolder", "A.app"]]
        let c = InventoryCollector(runner: RecordedRunner([:]), readFile: { _ in nil }, fileExists: { $0 == "/Applications" },
                                   listDirectory: { dirs2[$0] }, signatures: FakeSignatures([:]),
                                   appFolders: ["/Applications"], resolve: { $0.contains("Docs") ? nil : $0 },
                                   isDirectory: { $0 == "/Applications/Locked" })
        let result = c.collect()
        let apps = try #require(result.facts["apps.installed"]?.array)
        #expect(apps.compactMap { $0.object?["path"]?.string } == ["/Applications/A.app", "/Applications/Docs.app"])
        #expect(apps[1].object?["error"]?.string?.contains("privacy-protected") == true)
        #expect(apps.allSatisfy(Inventory.needsALook))   // nothing was checked, so nothing is vouched for
        let detail = try #require(result.notes.first { $0.fact == "apps.installed" }?.detail)
        #expect(detail.contains("cannot list /Applications/Locked"))
        #expect(partial.collect().facts["apps.installed"] != nil)
    }

    @Test func reportCountsWhatNeedsALookAndSaysWhatsMissing() throws {
        let apple = CodeSignatureInfo(valid: true, notarized: true, appleSigned: true).factValue
        let unnotarized = CodeSignatureInfo(valid: true, notarized: false, teamID: "4C6364ACXT").factValue
        let facts: [String: FactValue] = [
            "apps.installed": .array([.object(["path": .string("/Applications/Safari.app"), "name": .string("Safari"), "signature": apple]),
                                      .object(["path": .string("/Applications/X.app"), "name": .string("X"), "signature": unnotarized])]),
            "launchd.items": .array([.object(["label": .string("com.parallels.copypaste"), "scope": .string("agent"), "signature": unnotarized]),
                                     .object(["plist": .string("/Library/LaunchDaemons/x.plist"), "error": .string("cannot read the plist")])]),
            "accounts.admins": .array([.string("juergen"), .string("root")]),
            "network.listeningTCP": .array([.int(22)]),
        ]
        let notes = [CollectionNote(fact: "tcc.grants", status: .unavailable, source: "helper", detail: FullDiskAccess.missingHint)]
        let report = Inventory.build(facts: facts, notes: notes)
        func section(_ id: String) -> InventorySection? { report.sections.first { $0.id == id } }
        #expect(report.sections.map(\.id) == Inventory.sectionIDs)
        #expect(section("apps")?.flagged == 1)
        #expect(section("launchItems")?.flagged == 2)   // unnotarized, and one that couldn't be inspected
        #expect(section("admins")?.flagged == 0)
        #expect(section("privacyGrants")?.available == false)
        #expect(section("privacyGrants")?.note == FullDiskAccess.missingHint)
        #expect(section("loginItems")?.note?.contains("Background Task Management") == true)
        #expect(Inventory.describe(facts["apps.installed"]!.array![1], section: "apps") == "X — Unnotarized Developer ID, team 4C6364ACXT")
        #expect(Inventory.describe(.string("root"), section: "admins") == "root")
        let dev = CodeSignatureInfo(valid: true, notarized: false, teamID: "E89Q3796E9", developerID: false)
        #expect(dev.source == "Development-signed")
        let broken = CodeSignatureInfo(valid: false, notarized: false, error: "a sealed resource is missing or invalid").factValue
        #expect(Inventory.describe(.object(["path": .string("/A.app"), "name": .string("A"), "signature": broken]), section: "apps")
                == "A — Invalid signature (a sealed resource is missing or invalid)")
        #expect(Inventory.describe(.int(22), section: "listeningPorts") == "22")
        let flagged = Inventory.build(facts: facts, notes: notes, only: ["apps"], flaggedOnly: true)
        #expect(flagged.sections.map(\.id) == ["apps"])
        #expect(flagged.sections.first?.items.count == 1)
    }

    @Test func spctlAssessmentParser() throws {
        let edge = "/Applications/Microsoft Edge.app"
        let ok = try #require(Parsers.spctlAssessment("\(edge): accepted\nsource=Notarized Developer ID\norigin=Developer ID Application: Microsoft Corporation (UBF8T346G9)\n", path: edge))
        #expect(ok.accepted && ok.source == "Notarized Developer ID")
        let no = try #require(Parsers.spctlAssessment("/Applications/PowerShell.app: rejected\nsource=no usable signature\n", path: "/Applications/PowerShell.app"))
        #expect(!no.accepted && no.source == "no usable signature")
        #expect(Parsers.spctlAssessment("/Applications/X.app: a sealed resource is missing or invalid\n", path: "/Applications/X.app") == nil)
        // The verdict must be for this path, not a lookalike line.
        #expect(Parsers.spctlAssessment("/Applications/Other.app: accepted\n", path: "/Applications/X.app") == nil)
    }

    @Test func gatekeepersVerdictWins() {
        // Offline the ticket isn't found, but Gatekeeper (online) says notarized: shown in its words, not flagged.
        let edge = CodeSignatureInfo(valid: true, notarized: true, teamID: "UBF8T346G9", gatekeeperAccepted: true,
                                     gatekeeperSource: "Notarized Developer ID")
        #expect(edge.source == "Notarized Developer ID")
        #expect(!Inventory.needsALook(.object(["path": .string("/Applications/Microsoft Edge.app"), "signature": edge.factValue])))
        // The strict static check rejects a script-based bundle that Gatekeeper accepts.
        let idle = CodeSignatureInfo(valid: true, notarized: true, error: "unsigned", gatekeeperAccepted: true,
                                     gatekeeperSource: "Notarized Developer ID", staticValid: false)
        #expect(!Inventory.needsALook(.object(["path": .string("/Applications/Python 3.11/IDLE.app"), "signature": idle.factValue])))
        #expect(idle.factValue.object?["staticValid"] == .bool(false))   // the static check's verdict is kept
        // The posture rule agrees with the inventory: a launch job Gatekeeper accepts as notarized passes.
        let (packs, _) = RuleLinter.loadPacks(at: [repoRoot.appendingPathComponent("rules/posture").path], source: .bundled)
        let job: FactValue = .object(["label": .string("org.python.idle-helper"), "inspected": .bool(true), "signature": idle.factValue])
        let finding = PostureEngine.evaluate(packs, facts: StaticFactStore(["launchd.items": .array([job])])).findings
            .first { $0.ruleID == "posture.core.unsigned-launch-items" }
        #expect(finding?.status == .pass)
        // Gatekeeper rejects it too: flagged, in the static check's words.
        let ps = CodeSignatureInfo(valid: false, notarized: false, error: "unsigned", gatekeeperAccepted: false,
                                   gatekeeperSource: "no usable signature")
        #expect(ps.source == "Unsigned")
        #expect(Inventory.needsALook(.object(["path": .string("/Applications/PowerShell.app"), "signature": ps.factValue])))
    }

    @Test func mcpToolReturnsTheReport() throws {
        let dir = FileManager.default.temporaryDirectory.appendingPathComponent("farrier-inv-\(UUID().uuidString)")
        var ctx = FarrierContext(
            collectFacts: { CollectionResult(facts: ["network.listeningTCP": .array([.int(22)])], notes: []) },
            rulePaths: [repoRoot.appendingPathComponent("rules").path],
            plans: PlanStore(directory: dir.appendingPathComponent("plans")),
            journal: Journal(url: dir.appendingPathComponent("j.jsonl")),
            host: { "H" }, applyThroughHelper: { _ in throw OperationError("none") }, actor: "mcp:test")
        ctx.collectInventory = { CollectionResult(facts: ["accounts.admins": .array([.string("root")])], notes: []) }
        let r = try ToolCatalog.call("inventory", arguments: ["sections": .array([.string("admins"), .string("listeningPorts")])], context: ctx)
        let sections = try #require(r.structuredContent?.objectValue?["sections"]?.arrayValue)
        #expect(sections.count == 2)
        #expect(r.isError != true)
        let bad = try ToolCatalog.call("inventory", arguments: ["sections": .array([.string("nope")])], context: ctx)
        #expect(bad.isError == true)
    }
}
