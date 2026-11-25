import Foundation
#if canImport(Glibc)
import Glibc
#elseif canImport(Darwin)
import Darwin
#endif

/// The parameters of a `cleanup.quarantine` item: the path, and the fingerprint it had when planned.
public enum CleanupItemRules {
    public struct Parameters: Sendable, Equatable {
        public let path: String
        public let fingerprint: String
    }

    public static func validate(_ parameters: [String: String]?) throws -> Parameters {
        guard let parameters, parameters.count == 2, let path = parameters["path"], let fp = parameters["fingerprint"] else {
            throw PlanError("a cleanup item takes exactly the parameters `path` and `fingerprint`")
        }
        guard path.hasPrefix("/"), path.count <= 4096, ProtectedPaths.isCanonical(path), path != "/",
              !path.split(separator: "/").contains(where: { $0 == ".." || $0 == "." }),
              !path.contains("\u{0}") else {
            throw PlanError("`path` must be an absolute, canonical path")
        }
        let parts = fp.split(separator: ":", omittingEmptySubsequences: false)
        guard parts.count == 4, UInt64(parts[0]) != nil, UInt64(parts[1]) != nil, Int64(parts[2]) != nil,
              ["f", "d", "l"].contains(parts[3]) else {
            throw PlanError("`fingerprint` must be device:inode:changed:type")
        }
        return Parameters(path: path, fingerprint: fp)
    }
}

extension Planner {
    /// The most items one cleanup plan holds; the rest are listed as left out (plan them next time).
    public static let maxCleanupItems = 500

    /// Plans moving the scan's candidates into the quarantine: all of them, or only `paths`. Each item records the
    /// path, its fingerprint now, and its size and last use (what the reviewer sees).
    public static func planCleanup(report: CleanupReport, paths: Set<String>? = nil, host: String, now: Date = Date(),
                                   ttl: Int64 = Plan.defaultTTL,
                                   id: String = UUID().uuidString.lowercased()) -> (plan: Plan?, skipped: [PlanSkip]) {
        let action = RemediationCatalog.cleanupQuarantine
        var items: [PlanItem] = []
        var skipped: [PlanSkip] = []
        var planned = Set<String>()
        for rule in report.rules {
            if let reason = rule.skipped {
                if paths == nil { skipped.append(PlanSkip(ruleID: rule.ruleID, reason: reason)) }
                continue
            }
            if let n = rule.incomplete, paths == nil {
                skipped.append(PlanSkip(ruleID: rule.ruleID,
                                        reason: "\(n) item(s) couldn't be read completely, so when they were last used isn't known"))
            }
            for c in rule.candidates where paths?.contains(c.path) ?? true {
                guard items.count < maxCleanupItems else {
                    skipped.append(PlanSkip(ruleID: rule.ruleID, reason: "\(c.path): more than \(maxCleanupItems) items; plan again after this one"))
                    continue
                }
                guard let entry = FileStat.lstat(c.path) else {
                    skipped.append(PlanSkip(ruleID: rule.ruleID, reason: "\(c.path): gone since the scan"))
                    continue
                }
                planned.insert(c.path)
                items.append(PlanItem(
                    ruleID: rule.ruleID, action: action.id, tier: action.tier, summary: action.summary, fact: action.fact,
                    observed: .object(["bytes": .int(Int(c.bytes)), "lastUsed": .int(Int(c.lastUsed)), "ageDays": .int(c.ageDays),
                                       "regenerable": .bool(rule.regenerable)]),
                    parameters: ["path": c.path, "fingerprint": entry.fingerprint]))
            }
        }
        for path in (paths ?? []).subtracting(planned).sorted() {
            skipped.append(PlanSkip(ruleID: "-", reason: "\(path): not a cleanup candidate now (see `farrier cleanup scan`)"))
        }
        guard !items.isEmpty else { return (nil, skipped) }
        let created = Int64(now.timeIntervalSince1970)
        return (Plan(id: id, createdAt: created, expiresAt: created + ttl, host: host, items: items), skipped)
    }
}

// MARK: - Quarantine

/// One quarantined item, as the manifest records it.
public struct QuarantineItem: Codable, Sendable, Equatable {
    public enum State: String, Codable, Sendable {
        /// Recorded just before the move, so a crash between the two can't lose track of an item.
        case moving
        case quarantined
        case restored
        /// Deleted for good by an expiry plan.
        case deleted

        /// Still in the quarantine (or possibly: an interrupted move).
        public var isHeld: Bool { self == .moving || self == .quarantined }
    }
    public let index: Int
    public let ruleID: String
    public let original: String
    /// Relative to the plan's quarantine folder: `items/<index>/<name>`.
    public let stored: String
    public let bytes: Int64
    public var state: State
    public var restoredAt: Int64?
    public var deletedAt: Int64?
}

/// `manifest.json` in a plan's quarantine folder.
public struct QuarantineManifest: Codable, Sendable, Equatable {
    public static let currentFormat = 1
    public let format: Int
    public let planID: String
    public let createdAt: Int64
    /// When the items may be deleted for good (an expiry is a T3 plan of its own; nothing deletes them before).
    public let expiresAt: Int64
    public var items: [QuarantineItem]

    public var quarantinedBytes: Int64 { held.reduce(0) { $0 + $1.bytes } }
    /// The items still in the quarantine.
    public var held: [QuarantineItem] { items.filter { $0.state.isHeld } }
}

/// The user's quarantine: `~/Library/Application Support/Farrier/Quarantine/<plan-id>/` (docs/ARCHITECTURE.md).
/// Folders are 0700 and manifests 0600; items are renamed in and out, never copied.
public struct Quarantine: Sendable {
    public static let retention: Int64 = 7 * 86_400

    public let root: String

    public init(root: String) { self.root = root }

    public static var `default`: Quarantine {
        Quarantine(root: FileManager.default.homeDirectoryForCurrentUser
            .appendingPathComponent("Library/Application Support/Farrier/Quarantine").path)
    }

    public func folder(_ planID: String) -> String { "\(root)/\(planID)" }

    public func load(_ planID: String) throws -> QuarantineManifest {
        guard UUID(uuidString: planID) != nil, planID == planID.lowercased() else { throw PlanError("`\(planID)` is not a plan id") }
        let data = try Data(contentsOf: URL(fileURLWithPath: "\(folder(planID))/manifest.json"))
        let m = try JSONDecoder().decode(QuarantineManifest.self, from: data)
        guard m.planID == planID, m.format == QuarantineManifest.currentFormat else {
            throw PlanError("the manifest in \(folder(planID)) doesn't belong to plan \(planID)")
        }
        return m
    }

    /// Writes the manifest atomically (a temporary file renamed over it).
    public func save(_ m: QuarantineManifest) throws {
        let dir = folder(m.planID)
        try FileManager.default.createDirectory(atPath: dir, withIntermediateDirectories: true,
                                                attributes: [.posixPermissions: NSNumber(value: 0o700)])
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes, .prettyPrinted]
        let tmp = "\(dir)/.manifest.json.tmp"
        guard FileManager.default.createFile(atPath: tmp, contents: try encoder.encode(m),
                                             attributes: [.posixPermissions: NSNumber(value: 0o600)]),
              rename(tmp, "\(dir)/manifest.json") == 0 else {
            throw PlanError("could not write the quarantine manifest in \(dir) (errno \(errno))")
        }
    }

    /// Every plan with a manifest, newest first. Unreadable ones are skipped.
    public func list() -> [QuarantineManifest] {
        let names = (try? FileManager.default.contentsOfDirectory(atPath: root)) ?? []
        return names.compactMap { try? load($0) }.sorted { $0.createdAt > $1.createdAt }
    }

    /// A plan id or unique prefix (at least 4 characters) among the quarantined plans.
    public func resolve(_ idOrPrefix: String) throws -> String {
        let wanted = idOrPrefix.lowercased()
        guard wanted.count >= 4 else { throw PlanError("give at least 4 characters of the plan id") }
        let ids = list().map(\.planID).filter { $0.hasPrefix(wanted) }
        guard let id = ids.first else { throw PlanError("no quarantined plan \(idOrPrefix) (see `farrier quarantine list`)") }
        guard ids.count == 1 else { throw PlanError("\(idOrPrefix) matches \(ids.count) quarantined plans; give more of the id") }
        return id
    }
}

// MARK: - Applying and restoring

public struct CleanupItemResult: Sendable, Equatable {
    public enum Outcome: String, Sendable { case applied, refused, failed }
    public let ruleID: String
    public let path: String
    public let outcome: Outcome
    public let detail: String
}

public enum CleanupApplier {
    /// Moves a cleanup plan's items into the quarantine. Each item is checked again first: it must still be a
    /// candidate of its rule now (the rule exists in a bundled pack, it matches, the item is old enough, no protected
    /// path, no app that rules out the cleanup is running), have the fingerprint it had when planned, sit below no
    /// symlink, and be on the quarantine's volume. Anything else is refused and left where it is.
    public static func apply(_ plan: Plan, packs: [RulePack], scanner: CleanupScanner, quarantine: Quarantine,
                             now: Date = Date()) throws -> [CleanupItemResult] {
        guard plan.items.allSatisfy({ $0.action == RemediationCatalog.cleanupQuarantine.id }) else {
            throw PlanError("a cleanup plan only holds cleanup items")
        }
        let bundled = packs.filter { $0.source == .bundled }
        let ruleIDs = Set(plan.items.map(\.ruleID))
        let current = scanner.scan(bundled, ruleIDs: ruleIDs)
        var owner: [String: String] = [:]
        var why: [String: String] = [:]
        for rule in current.rules {
            for c in rule.candidates { owner[c.path] = rule.ruleID }
            if let s = rule.skipped { why[rule.ruleID] = s }
        }

        let created = Int64(now.timeIntervalSince1970)
        var manifest = (try? quarantine.load(plan.id))
            ?? QuarantineManifest(format: QuarantineManifest.currentFormat, planID: plan.id, createdAt: created,
                                  expiresAt: created + Quarantine.retention, items: [])
        let folder = quarantine.folder(plan.id)
        var results: [CleanupItemResult] = []
        var quarantineDevice: UInt64?

        for item in plan.items {
            func result(_ o: CleanupItemResult.Outcome, _ path: String, _ d: String) {
                results.append(CleanupItemResult(ruleID: item.ruleID, path: path, outcome: o, detail: d))
            }
            let p: CleanupItemRules.Parameters
            do { p = try CleanupItemRules.validate(item.parameters) } catch { result(.refused, "?", "\(error)"); continue }
            if manifest.items.contains(where: { $0.original == p.path && $0.state.isHeld }) {
                result(.refused, p.path, "already in this plan's quarantine"); continue
            }
            guard owner[p.path] == item.ruleID else {
                let reason = why[item.ruleID].map { "the rule is skipped now: \($0)" }
                    ?? "it's no longer a candidate of \(item.ruleID) (used since planning, or changed)"
                result(.refused, p.path, reason); continue
            }
            guard let entry = FileStat.lstat(p.path), entry.fingerprint == p.fingerprint else {
                result(.refused, p.path, "it changed since planning (another file or folder at that path); make a new plan"); continue
            }
            let parent = (p.path as NSString).deletingLastPathComponent
            guard CleanupScanner.realPath(parent) == parent else {
                result(.refused, p.path, "a folder above it is a symlink now"); continue
            }
            do {
                if quarantineDevice == nil {
                    try FileManager.default.createDirectory(atPath: "\(folder)/items", withIntermediateDirectories: true,
                                                            attributes: [.posixPermissions: NSNumber(value: 0o700)])
                    quarantineDevice = FileStat.lstat("\(folder)/items")?.device
                }
            } catch {
                result(.failed, p.path, "could not create the quarantine folder: \(error)"); continue
            }
            guard entry.device == quarantineDevice else {
                result(.refused, p.path, "it's on another volume than the quarantine; Farrier moves items, it never copies and deletes"); continue
            }
            let index = (manifest.items.map(\.index).max() ?? 0) + 1
            let name = (p.path as NSString).lastPathComponent
            let stored = "items/\(index)/\(name)"
            let bytes = Int64(item.observed.object?["bytes"]?.number ?? 0)
            manifest.items.append(QuarantineItem(index: index, ruleID: item.ruleID, original: p.path, stored: stored,
                                                 bytes: bytes, state: .moving, restoredAt: nil))
            do {
                try FileManager.default.createDirectory(atPath: "\(folder)/items/\(index)", withIntermediateDirectories: false,
                                                        attributes: [.posixPermissions: NSNumber(value: 0o700)])
                try quarantine.save(manifest)
            } catch {
                manifest.items.removeLast()
                result(.failed, p.path, "could not record it in the quarantine manifest: \(error)"); continue
            }
            if rename(p.path, "\(folder)/\(stored)") != 0 {
                let err = errno
                manifest.items.removeLast()
                try? quarantine.save(manifest)
                try? FileManager.default.removeItem(atPath: "\(folder)/items/\(index)")
                result(.failed, p.path, "could not move it (\(String(cString: strerror(err))))"); continue
            }
            manifest.items[manifest.items.count - 1].state = .quarantined
            try? quarantine.save(manifest)   // "moving" with the item in place is read as quarantined anyway
            result(.applied, p.path, "moved to the quarantine (\(ByteCount.format(bytes)))")
        }
        return results
    }

    /// Puts a plan's quarantined items back where they were: all of them, or only `paths` (original paths).
    /// An item whose original path is taken again is left in the quarantine.
    public static func restore(planID: String, paths: Set<String>? = nil, quarantine: Quarantine,
                               now: Date = Date()) throws -> [CleanupItemResult] {
        var manifest = try quarantine.load(planID)
        let folder = quarantine.folder(planID)
        var results: [CleanupItemResult] = []
        if let paths {
            for missing in paths.subtracting(manifest.items.map(\.original)).sorted() {
                results.append(CleanupItemResult(ruleID: "-", path: missing, outcome: .refused, detail: "not in this plan's quarantine"))
            }
        }
        for i in manifest.items.indices where paths?.contains(manifest.items[i].original) ?? true {
            let item = manifest.items[i]
            func result(_ o: CleanupItemResult.Outcome, _ d: String) {
                results.append(CleanupItemResult(ruleID: item.ruleID, path: item.original, outcome: o, detail: d))
            }
            if item.state == .restored {
                if paths != nil { result(.refused, "already restored") }   // asked for by name: say so
                continue
            }
            if item.state == .deleted {
                if paths != nil { result(.refused, "deleted for good when the quarantine expired") }
                continue
            }
            let stored = "\(folder)/\(item.stored)"
            if item.state == .moving, FileStat.lstat(stored) == nil, FileStat.lstat(item.original) != nil {
                manifest.items[i].state = .restored   // interrupted before the move: it never left
                result(.applied, "it was never moved (still in place)"); continue
            }
            guard item.stored.hasPrefix("items/\(item.index)/"), !item.stored.contains(".."),
                  FileStat.lstat(stored) != nil else {
                result(.failed, "it isn't in the quarantine any more (\(item.stored))"); continue
            }
            guard FileStat.lstat(item.original) == nil else {
                result(.refused, "something is at that path again; move it away, then restore"); continue
            }
            let parent = (item.original as NSString).deletingLastPathComponent
            do { try FileManager.default.createDirectory(atPath: parent, withIntermediateDirectories: true) } catch {
                result(.failed, "could not recreate \(parent): \(error)"); continue
            }
            guard CleanupScanner.realPath(parent) == parent else { result(.refused, "a folder above it is a symlink now"); continue }
            guard rename(stored, item.original) == 0 else {
                result(.failed, "could not move it back (\(String(cString: strerror(errno))))"); continue
            }
            manifest.items[i].state = .restored
            manifest.items[i].restoredAt = Int64(now.timeIntervalSince1970)
            try? FileManager.default.removeItem(atPath: "\(folder)/items/\(item.index)")
            result(.applied, "restored")
        }
        try quarantine.save(manifest)
        if results.isEmpty {
            results.append(CleanupItemResult(ruleID: "-", path: folder, outcome: .refused, detail: "nothing left to restore"))
        }
        return results
    }
}


// MARK: - Expiry

/// The one parameter of a `quarantine.expire` item: the cleanup plan whose quarantine it empties.
public enum QuarantineExpiryRules {
    public static func validate(_ parameters: [String: String]?) throws -> String {
        guard let parameters, parameters.count == 1, let planID = parameters["plan"] else {
            throw PlanError("an expiry item takes exactly one parameter, `plan`")
        }
        guard planID.count == 36, UUID(uuidString: planID) != nil, planID == planID.lowercased() else {
            throw PlanError("`plan` must be a plan id")
        }
        return planID
    }
}

extension Planner {
    /// Plans deleting quarantined items for good: by default every cleanup plan past its 7 days; with `planIDs`,
    /// those plans (also before their time: the approval on the Mac covers it). Each item records how many items
    /// and bytes it deletes; applying refuses if that changed (something was restored since).
    public static func planExpiry(quarantine: Quarantine, planIDs: [String]? = nil, host: String, now: Date = Date(),
                                  ttl: Int64 = Plan.defaultTTL,
                                  id: String = UUID().uuidString.lowercased()) -> (plan: Plan?, skipped: [PlanSkip]) {
        let t = Int64(now.timeIntervalSince1970)
        let action = RemediationCatalog.quarantineExpire
        var items: [PlanItem] = []
        var skipped: [PlanSkip] = []
        let manifests: [QuarantineManifest]
        if let planIDs {
            manifests = planIDs.compactMap { pid in
                do { return try quarantine.load(pid) } catch {
                    skipped.append(PlanSkip(ruleID: "quarantine", reason: "\(pid.prefix(8)): no such quarantined plan"))
                    return nil
                }
            }
        } else {
            manifests = quarantine.list()
        }
        for m in manifests {
            let held = m.held
            if held.isEmpty {
                if planIDs != nil { skipped.append(PlanSkip(ruleID: "quarantine", reason: "\(m.planID.prefix(8)): holds nothing any more")) }
                continue
            }
            if planIDs == nil && t < m.expiresAt { continue }   // not due yet
            items.append(PlanItem(
                ruleID: "quarantine", action: action.id, tier: action.tier, summary: action.summary, fact: action.fact,
                observed: .object(["items": .int(held.count), "bytes": .int(Int(m.quarantinedBytes)),
                                   "expiresAt": .int(Int(m.expiresAt)), "due": .bool(t >= m.expiresAt)]),
                parameters: ["plan": m.planID]))
        }
        guard !items.isEmpty else { return (nil, skipped) }
        let created = Int64(now.timeIntervalSince1970)
        return (Plan(id: id, createdAt: created, expiresAt: created + ttl, host: host, items: items), skipped)
    }
}

extension CleanupApplier {
    /// Deletes what an expiry plan covers. The caller has had the plan approved on the Mac. Each quarantined plan
    /// must still hold exactly what the expiry plan says (same number of items and bytes), and its folder must be
    /// a real folder inside the quarantine (no symlink anywhere on the way).
    public static func expire(_ plan: Plan, quarantine: Quarantine, now: Date = Date()) throws -> [CleanupItemResult] {
        guard plan.items.allSatisfy({ $0.action == RemediationCatalog.quarantineExpire.id }) else {
            throw PlanError("an expiry plan only holds expiry items")
        }
        var results: [CleanupItemResult] = []
        for item in plan.items {
            func result(_ o: CleanupItemResult.Outcome, _ path: String, _ d: String) {
                results.append(CleanupItemResult(ruleID: item.ruleID, path: path, outcome: o, detail: d))
            }
            let planID: String
            do { planID = try QuarantineExpiryRules.validate(item.parameters) } catch { result(.refused, "?", "\(error)"); continue }
            let folder = quarantine.folder(planID)
            guard var m = try? quarantine.load(planID) else { result(.refused, folder, "no such quarantined plan any more"); continue }
            let o = item.observed.object ?? [:]
            guard m.held.count == Int(o["items"]?.number ?? -1), Int(m.quarantinedBytes) == Int(o["bytes"]?.number ?? -1) else {
                result(.refused, folder, "it holds something else than when this was planned (restored since?); make a new plan"); continue
            }
            guard CleanupScanner.realPath(folder) == folder, FileStat.lstat(folder)?.isSymlink == false else {
                result(.refused, folder, "the quarantine folder isn't where it should be (a symlink?)"); continue
            }
            var deleted = 0, freed: Int64 = 0, problems: [String] = []
            for i in m.items.indices where m.items[i].state.isHeld {
                let dir = "\(folder)/items/\(m.items[i].index)"
                if FileStat.lstat(dir) != nil, let problem = removeTree(dir) {
                    problems.append("\(m.items[i].original): \(problem)")
                    continue
                }
                m.items[i].state = .deleted
                m.items[i].deletedAt = Int64(now.timeIntervalSince1970)
                deleted += 1
                freed += m.items[i].bytes
            }
            try? quarantine.save(m)
            if problems.isEmpty {
                result(.applied, folder, "deleted \(deleted) item(s) for good, \(ByteCount.format(freed)) freed")
            } else {
                result(.failed, folder, "deleted \(deleted) item(s); could not delete \(problems.count): \(problems.prefix(3).joined(separator: "; "))")
            }
        }
        return results
    }

    /// Deletes a tree without following symlinks. Read-only folders (Go's module cache, some package caches) are
    /// made writable first, or their entries couldn't be removed. Returns why it stopped, or nil when it's gone.
    static func removeTree(_ path: String) -> String? {
        guard let entry = FileStat.lstat(path) else { return nil }
        if entry.isDirectory && !entry.isSymlink {
            _ = chmod(path, 0o700)
            for name in (try? FileManager.default.contentsOfDirectory(atPath: path)) ?? [] {
                if let problem = removeTree("\(path)/\(name)") { return problem }
            }
            guard rmdir(path) == 0 else { return "\(String(cString: strerror(errno))) (\(path))" }
        } else {
            guard unlink(path) == 0 else { return "\(String(cString: strerror(errno))) (\(path))" }
        }
        return nil
    }
}
