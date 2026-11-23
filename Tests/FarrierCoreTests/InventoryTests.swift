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
                                           resolve: { $0 == "/Applications/GoodLink.app" ? "/Applications/Good.app" : $0 })
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
        #expect(Inventory.describe(.int(22), section: "listeningPorts") == "22")
        let flagged = Inventory.build(facts: facts, notes: notes, only: ["apps"], flaggedOnly: true)
        #expect(flagged.sections.map(\.id) == ["apps"])
        #expect(flagged.sections.first?.items.count == 1)
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
