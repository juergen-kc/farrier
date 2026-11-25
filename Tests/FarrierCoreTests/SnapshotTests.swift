import Foundation
import MCP
import Testing
@testable import FarrierCore
@testable import FarrierMCP

private func app(_ id: String, version: String, team: String = "T1", notarized: Bool = true) -> FactValue {
    .object(["name": .string(id), "bundleID": .string(id), "path": .string("/Applications/\(id).app"), "version": .string(version),
             "signature": .object(["valid": .bool(true), "notarized": .bool(notarized), "teamID": .string(team),
                                   "source": .string("Notarized Developer ID")])])
}

private func collected(apps: [FactValue], admins: [String] = ["root", "juergen"], firewall: String = "on",
                       ports: [Int] = [22], profilesMissing: Bool = false) -> CollectionResult {
    var facts: [String: FactValue] = [
        "apps.installed": .array(apps), "accounts.admins": .array(admins.map(FactValue.string)),
        "network.listeningTCP": .array(ports.map(FactValue.int)), "firewall.globalState": .string(firewall),
        "os.version": .string("27.2.1"), "launchd.items": .array([]), "system.extensions": .array([]), "tcc.grants": .array([]),
    ]
    var notes: [CollectionNote] = []
    if profilesMissing {
        notes.append(CollectionNote(fact: CoreFacts.profiles, status: .unavailable, source: "helper", detail: "the helper isn't running"))
    } else {
        facts[CoreFacts.profiles] = .array([])
    }
    return CollectionResult(facts: facts, notes: notes)
}

@Suite("Snapshots")
struct SnapshotTests {
    @Test func diffFindsAddedRemovedChangedAndSettings() throws {
        let a = Snapshot.take(collected(apps: [app("one", version: "1.0"), app("gone", version: "2")]), host: "H", label: "before")
        let b = Snapshot.take(collected(apps: [app("one", version: "1.1", team: "T2"), app("new", version: "1")],
                                        admins: ["root", "juergen", "intruder"], firewall: "off", ports: [22, 5900]), host: "H", label: nil)
        let d = SnapshotDiffer.diff(a, b)
        let apps = try #require(d.sections.first { $0.id == "apps" })
        #expect(apps.added.count == 1 && apps.added[0].contains("new"))
        #expect(apps.removed.count == 1 && apps.removed[0].contains("gone"))
        let changed = try #require(apps.changed.first)
        #expect(Set(changed.fields.map(\.field)) == ["version", "signature.teamID"])
        #expect(changed.fields.first { $0.field == "version" }?.before == .string("1.0"))
        #expect(d.sections.first { $0.id == "admins" }?.added == ["intruder"])
        #expect(d.sections.first { $0.id == "listeningPorts" }?.added == ["5900"])
        #expect(d.facts == [FieldChange(field: "firewall.globalState", before: .string("on"), after: .string("off"))])
        #expect(d.changes == 6)
        #expect(SnapshotDiffer.diff(a, a).changes == 0)
    }

    @Test func unreadableSectionsAreNotComparedNotRemoved() throws {
        let a = Snapshot.take(collected(apps: [app("one", version: "1")]), host: "H", label: nil)
        let b = Snapshot.take(collected(apps: [app("one", version: "1")], profilesMissing: true), host: "H", label: nil)
        let profiles = try #require(SnapshotDiffer.diff(a, b).sections.first { $0.id == "profiles" })
        #expect(profiles.notCompared == "the helper isn't running" && profiles.removed.isEmpty)
        // Section facts aren't repeated as settings.
        #expect(a.facts["apps.installed"] == nil && a.facts["os.version"] == .string("27.2.1"))
    }

    @Test func storeKeepsTheNewestAndIsPrivate() throws {
        let home = FakeHome()
        let store = SnapshotStore(directory: "\(home.root)/snaps", limit: 3)
        var ids: [String] = []
        for i in 0..<5 {
            let s = Snapshot.take(collected(apps: []), host: "H", label: "s\(i)", now: Date(timeIntervalSince1970: TimeInterval(1_000 + i)))
            try store.save(s)
            ids.append(s.id)
        }
        let kept = store.list()
        #expect(kept.map(\.label) == ["s4", "s3", "s2"])
        #expect(try store.load("latest").label == "s4")
        #expect(try store.load(String(ids[3].prefix(8))).label == "s3")
        #expect(try store.load("s2").id == ids[2])                    // by label
        #expect(throws: PlanError.self) { try store.load("nope") }
        #expect(throws: PlanError.self) { try store.load(ids[0]) }   // pruned
        let attrs = try FileManager.default.attributesOfItem(atPath: "\(store.directory)/\(ids[4]).json")
        #expect((attrs[.posixPermissions] as? NSNumber)?.intValue == 0o600)
        _ = try store.delete("latest")
        #expect(store.list().count == 2)
    }

    @Test func mcpCreateListDiffAndResource() throws {
        let home = FakeHome()
        let dir = FileManager.default.temporaryDirectory.appendingPathComponent("farrier-ctx-\(UUID().uuidString)")
        defer { try? FileManager.default.removeItem(at: dir) }
        var now = collected(apps: [app("one", version: "1")])
        var ctx = FarrierContext(
            collectFacts: { now }, rulePaths: [],
            plans: PlanStore(directory: dir.appendingPathComponent("plans")),
            journal: Journal(url: dir.appendingPathComponent("j.jsonl")),
            host: { "H" }, applyThroughHelper: { _ in throw OperationError("none") }, actor: "mcp:test")
        ctx.collectInventory = { CollectionResult(facts: [:], notes: []) }
        ctx.snapshots = SnapshotStore(directory: "\(home.root)/snaps")

        #expect(try ToolCatalog.call("snapshot_diff", arguments: [:], context: ctx).isError == true)   // none yet
        let created = try ToolCatalog.call("snapshot_create", arguments: ["label": .string("before")], context: ctx)
        let id = try #require(created.structuredContent?.objectValue?["id"]?.stringValue)
        #expect(created.structuredContent?.objectValue?["counts"]?.objectValue?["apps"]?.intValue == 1)

        now = collected(apps: [app("one", version: "2")])
        let diff = try ToolCatalog.call("snapshot_diff", arguments: [:], context: ctx)
        let sections = try #require(diff.structuredContent?.objectValue?["sections"]?.arrayValue)
        let apps = try #require(sections.first { $0.objectValue?["id"]?.stringValue == "apps" }?.objectValue)
        #expect(apps["changed"]?.arrayValue?.count == 1)
        #expect(diff.structuredContent?.objectValue?["to"]?.objectValue?["label"]?.stringValue == "now")

        let list = try ToolCatalog.call("snapshot_list", arguments: [:], context: ctx)
        #expect(list.structuredContent?.arrayValue?.count == 1)
        #expect(ResourceCatalog.list(ctx).contains { $0.uri == "farrier://snapshot/\(id)" })
        let content = try ResourceCatalog.read("farrier://snapshot/latest", ctx)
        #expect(content.count == 1)
        #expect(throws: MCPError.self) { try ResourceCatalog.read("farrier://snapshot/nope", ctx) }
        #expect(try #require(ToolCatalog.tools.first { $0.name == "snapshot_diff" }).annotations.readOnlyHint == true)
    }
}
