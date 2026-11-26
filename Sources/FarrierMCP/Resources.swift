import FarrierCore
import FarrierHelperKit
import Foundation
import MCP

/// Read-only MCP resources: the saved plans and the journals, as JSON. The same data as `plan_show` and
/// `journal_recent`, for clients that attach context by URI rather than calling a tool.
public enum ResourceCatalog {
    static let userJournalURI = "farrier://journal/recent"
    static let helperJournalURI = "farrier://journal/helper"
    static let planPrefix = "farrier://plan/"
    static let snapshotPrefix = "farrier://snapshot/"
    static let journalEntries = 50

    public static let templates: [Resource.Template] = [
        .init(uriTemplate: "farrier://plan/{id}", name: "plan", title: "Saved plan",
              description: "A saved plan by id (or a unique prefix of at least 4 characters): its items, tier, hash, expiry "
                  + "and whether applying it needs approval on the Mac.",
              mimeType: "application/json"),
        .init(uriTemplate: "farrier://snapshot/{id}", name: "snapshot", title: "Saved snapshot",
              description: "A saved snapshot by id, unique prefix or `latest`: the inventory and settings as they were then.",
              mimeType: "application/json"),
    ]

    /// The journals, and every saved plan that hasn't expired.
    public static func list(_ ctx: FarrierContext, now: Date = Date()) -> [Resource] {
        var resources: [Resource] = [
            Resource(name: "journal-recent", uri: userJournalURI, title: "Farrier journal",
                     description: "The latest \(journalEntries) entries of the user's journal of planned and applied changes, "
                         + "and whether its hash chain is intact.", mimeType: "application/json"),
            Resource(name: "journal-helper", uri: helperJournalURI, title: "Helper journal",
                     description: "The latest \(journalEntries) entries of the privileged helper's root-owned journal: what was "
                         + "approved and changed, with the state each change replaced.", mimeType: "application/json"),
        ]
        for id in ctx.plans.ids() {
            // One directory listing (`ids()`), then each file read directly: no prefix lookup per plan.
            guard let plan = try? ctx.plans.load(exactID: id), plan.expiresAt > Int64(now.timeIntervalSince1970) else { continue }
            resources.append(Resource(name: "plan-\(id.prefix(8))", uri: planPrefix + id, title: "Plan \(id.prefix(8))",
                                      description: "\(plan.items.count) item(s), \(plan.tier.rawValue): "
                                          + plan.items.map(\.description).joined(separator: "; "),
                                      mimeType: "application/json"))
        }
        for snap in ctx.snapshots.list().prefix(10) {
            let when = ISO8601DateFormatter().string(from: Date(timeIntervalSince1970: TimeInterval(snap.createdAt)))
            resources.append(Resource(name: "snapshot-\(snap.id.prefix(8))", uri: snapshotPrefix + snap.id,
                                      title: "Snapshot \(snap.id.prefix(8))\(snap.label.map { ": \($0)" } ?? "")",
                                      description: "Inventory and settings saved \(when).", mimeType: "application/json"))
        }
        return resources
    }

    /// The JSON for a resource URI. Unknown URIs and plans are invalid parameters.
    public static func read(_ uri: String, _ ctx: FarrierContext, helperJournal: Journal = FarrierMCP.helperJournal,
                            now: Date = Date()) throws -> [Resource.Content] {
        let data: Data
        switch uri {
        case userJournalURI:
            data = try encode(Operations.journal(ctx.journal, name: "user", last: journalEntries))
        case helperJournalURI:
            data = try encode(Operations.journal(helperJournal, name: "helper", last: journalEntries))
        case _ where uri.hasPrefix(planPrefix):
            let id = String(uri.dropFirst(planPrefix.count))
            do { data = try encode(Operations.show(ctx, id: id, now: now)) } catch {
                throw MCPError.invalidParams("\(error)")
            }
        case _ where uri.hasPrefix(snapshotPrefix):
            do { data = try encode(Operations.snapshotLoad(ctx, String(uri.dropFirst(snapshotPrefix.count)))) } catch {
                throw MCPError.invalidParams("\(error)")
            }
        default:
            throw MCPError.invalidParams("unknown resource \(uri)")
        }
        return [.text(String(decoding: data, as: UTF8.self), uri: uri, mimeType: "application/json")]
    }

    static func encode<T: Encodable>(_ value: T) throws -> Data {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
        return try encoder.encode(value)
    }
}

/// What a tool is doing while it runs, for progress notifications: long calls (collection, the inventory's
/// signature checks, and above all `apply_plan`, which waits for the user at the Mac) say so every few seconds.
public enum ToolProgress {
    public static let interval: UInt64 = 5_000_000_000

    public static func message(tool: String, seconds: Int) -> String {
        let what: String
        switch tool {
        case "apply_plan": what = "waiting for the user to approve on the Mac (Touch ID or password), then applying"
        case "inventory": what = "collecting the inventory (apps and their signatures)"
        case "snapshot_create", "snapshot_diff": what = "collecting the inventory and settings"
        case "log_query": what = "searching the unified log"
        case "power_history": what = "reading the power management log"
        case "cleanup_scan": what = "measuring caches and logs"
        case "disk_usage": what = "measuring caches, developer data and apps"
        case "cleanup_plan": what = "measuring caches and logs, then planning"
        case "facts_collect": what = "collecting facts"
        case "posture_check": what = "checking posture"
        case "posture_plan_remediation", "posture_plan_exception", "plan_undo": what = "collecting facts and planning"
        default: what = "working"
        }
        return seconds > 0 ? "\(what) (\(seconds) s)" : what
    }
}
