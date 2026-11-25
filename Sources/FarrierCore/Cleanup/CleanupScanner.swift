import Foundation
#if canImport(Glibc)
import Glibc
#elseif canImport(Darwin)
import Darwin
#endif

/// One file or folder a cleanup rule matched, with what it would free.
public struct CleanupCandidate: Sendable, Codable, Equatable {
    public let path: String
    /// Space on disk (allocated blocks), symlinks not followed.
    public let bytes: Int64
    /// The most recent use the scan could see: the newest modification or file access inside it.
    public let lastUsed: Int64
    public let ageDays: Int
    /// The folder couldn't be read completely (more entries than the scan counts, or no permission); `bytes` is a
    /// lower bound. Only for rules without a minimum age: with one, such folders are left out (`incomplete`).
    public let sizeIsLowerBound: Bool?
}

/// A cleanup rule's result: its candidates, or why it was skipped.
public struct CleanupRuleResult: Sendable, Codable {
    public let ruleID: String
    public let title: String
    public let tier: Tier
    public let regenerable: Bool
    public let evidence: String
    public let minAgeDays: Int?
    public let candidates: [CleanupCandidate]
    public let bytes: Int64
    /// Why the rule didn't run (an app is running, its targets need a collector, …); nil when it did.
    public let skipped: String?
    /// Matches left out because they couldn't be read completely (no permission, or more entries than the scan
    /// counts), so when they were last used isn't known. Nil when there were none.
    public let incomplete: Int?
}

public struct CleanupReport: Sendable, Codable {
    public let rules: [CleanupRuleResult]
    /// What the candidates take up together. Nothing is freed until they're quarantined and the quarantine expires.
    public let bytes: Int64
    public let candidates: Int
}

/// What the scanner needs from the file system, so tests can use a temporary folder and the real code paths.
public struct FileEntry: Sendable, Equatable {
    public let isDirectory: Bool
    public let isSymlink: Bool
    public let allocatedBytes: Int64
    public let modified: Int64
    public let accessed: Int64
    public var device: UInt64 = 0
    public var inode: UInt64 = 0
    /// The status change time (creation, rename, permission change), in nanoseconds.
    public var changed: Int64 = 0

    /// What a plan records to recognise the item when it's applied: one swapped in since planning (another inode,
    /// or the same inode reused for a new entry, which gets a new change time, or a link where a folder was)
    /// doesn't match.
    public var fingerprint: String { "\(device):\(inode):\(changed):\(isSymlink ? "l" : isDirectory ? "d" : "f")" }
}

public enum FileStat {
    /// `lstat`: the entry itself, never what a symlink points to.
    public static func lstat(_ path: String) -> FileEntry? {
        var st = stat()
        guard systemLstat(path, &st) == 0 else { return nil }
        #if os(Linux)
        let m = Int64(st.st_mtim.tv_sec), a = Int64(st.st_atim.tv_sec)
        let c = Int64(st.st_ctim.tv_sec) &* 1_000_000_000 &+ Int64(st.st_ctim.tv_nsec)
        #else
        let m = Int64(st.st_mtimespec.tv_sec), a = Int64(st.st_atimespec.tv_sec)
        let c = Int64(st.st_ctimespec.tv_sec) &* 1_000_000_000 &+ Int64(st.st_ctimespec.tv_nsec)
        #endif
        let type = st.st_mode & S_IFMT
        var e = FileEntry(isDirectory: type == S_IFDIR, isSymlink: type == S_IFLNK,
                          allocatedBytes: Int64(st.st_blocks) * 512, modified: m, accessed: a)
        e.device = UInt64(truncatingIfNeeded: st.st_dev)
        e.inode = UInt64(truncatingIfNeeded: st.st_ino)
        e.changed = c
        return e
    }

    private static func systemLstat(_ path: String, _ st: inout stat) -> Int32 {
        #if canImport(Glibc)
        return Glibc.lstat(path, &st)
        #else
        return Darwin.lstat(path, &st)
        #endif
    }
}

/// Evaluates cleanup rules without changing anything: expands each rule's globs under the user's home, applies its
/// filters and conditions, and measures what matched. Protected paths (ProtectedPaths) are never matched, whatever a
/// rule says; symlinks are never followed into; collector-provided targets are reported as not available yet.
public struct CleanupScanner: Sendable {
    public let home: String
    public let now: Int64
    /// Names of the running processes (for `when.processNotRunning`).
    public let runningProcesses: @Sendable () -> Set<String>
    /// Whether an app is installed (for `when.appInstalled` / `appNotInstalled`).
    public let appInstalled: @Sendable (String) -> Bool
    /// The most entries counted inside one candidate before its size is reported as a lower bound.
    public let entryLimit: Int

    public init(home: String = FileManager.default.homeDirectoryForCurrentUser.path, now: Date = Date(),
                runningProcesses: @escaping @Sendable () -> Set<String> = CleanupScanner.liveProcesses,
                appInstalled: @escaping @Sendable (String) -> Bool = CleanupScanner.liveAppInstalled,
                entryLimit: Int = 200_000) {
        self.home = Self.realPath(home)
        self.now = Int64(now.timeIntervalSince1970)
        self.runningProcesses = runningProcesses
        self.appInstalled = appInstalled
        self.entryLimit = entryLimit
    }

    /// The home folder with its own symlinks resolved (`/var` is `/private/var` on macOS): links above the home folder
    /// are the system's, while every link below it is refused.
    public static func realPath(_ path: String) -> String {
        guard let resolved = realpath(path, nil) else { return path }
        defer { free(resolved) }
        return String(cString: resolved)
    }

    /// `minAge` overrides every rule's own minimum age (never below it); `ruleIDs` limits the rules.
    public func scan(_ packs: [RulePack], ruleIDs: Set<String>? = nil, minAge: RuleDuration? = nil) -> CleanupReport {
        var results: [CleanupRuleResult] = []
        var claimed: [String: (specificity: Int, rule: String)] = [:]   // path → the rule that took it
        var pending: [(rule: CleanupRule, found: [CleanupCandidate], skipped: String?, incomplete: Int)] = []
        lazy var processes = runningProcesses()
        for pack in packs {
            for case .cleanup(let rule) in pack.rules where ruleIDs?.contains(rule.id) ?? true {
                if let reason = skipReason(rule, processes: &processes) {
                    pending.append((rule, [], reason, 0)); continue
                }
                let ageLimit = max(rule.minAge?.seconds ?? 0, minAge?.seconds ?? 0)
                var found: [CleanupCandidate] = []
                var incomplete = 0
                var factOnly = true
                for target in rule.targets {
                    guard let pattern = target.path else { continue }
                    factOnly = false
                    // The most specific target claims a path matched by several (Homebrew's cache over all caches),
                    // measured by the target that matched it, not the rule's longest one.
                    let specificity = ProtectedPaths.literalPrefix(of: pattern).count
                    for path in expand(pattern) {
                        switch candidate(path, target: target, ageLimit: ageLimit, minSize: rule.minSize) {
                        case .candidate(let c):
                            found.append(c)
                            if (claimed[c.path]?.specificity ?? -1) < specificity { claimed[c.path] = (specificity, rule.id) }
                        case .incomplete: incomplete += 1
                        case .none: break
                        }
                    }
                }
                if factOnly && !rule.targets.isEmpty {
                    pending.append((rule, [], "its targets come from a collector that isn't available yet", 0)); continue
                }
                pending.append((rule, found, nil, incomplete))
            }
        }
        // A candidate inside another one is already counted (and would be moved) with it.
        let winners = Set(claimed.keys)
        func insideAnother(_ path: String) -> Bool {
            var p = (path as NSString).deletingLastPathComponent
            while p.count > 1 {
                if winners.contains(p) { return true }
                p = (p as NSString).deletingLastPathComponent
            }
            return false
        }
        for (rule, found, skipped, incomplete) in pending {
            var seen = Set<String>()
            let kept = found.filter { claimed[$0.path]?.rule == rule.id && !insideAnother($0.path) && seen.insert($0.path).inserted }.sorted { $0.bytes > $1.bytes }
            results.append(CleanupRuleResult(
                ruleID: rule.id, title: rule.title, tier: rule.tier, regenerable: rule.regenerable,
                evidence: rule.evidence.trimmingCharacters(in: .whitespacesAndNewlines),
                minAgeDays: rule.minAge.map { Int($0.seconds / 86_400) }, candidates: kept,
                bytes: kept.reduce(0) { $0 + $1.bytes }, skipped: skipped, incomplete: incomplete > 0 ? incomplete : nil))
        }
        let all = results.flatMap(\.candidates)
        return CleanupReport(rules: results, bytes: all.reduce(0) { $0 + $1.bytes }, candidates: all.count)
    }

    func skipReason(_ rule: CleanupRule, processes: inout Set<String>) -> String? {
        if rule.privileged { return "needs the privileged helper (not part of cleanup yet)" }
        if let running = rule.when.processNotRunning.first(where: { processes.contains($0) }) {
            return "\(running) is running"
        }
        if let missing = rule.when.appInstalled.first(where: { !appInstalled($0) }) { return "\(missing) isn't installed" }
        if let present = rule.when.appNotInstalled.first(where: appInstalled) { return "\(present) is installed" }
        return nil
    }

    // MARK: Globs

    /// The paths a pattern matches: `~` is the home folder, `*` and `?` match within one component, `**` matches any
    /// number of folders. Protected paths and anything below them are dropped, and symlinked folders aren't entered.
    public func expand(_ pattern: String) -> [String] {
        let full = pattern.hasPrefix("~/") ? home + pattern.dropFirst(1) : pattern
        guard full.hasPrefix("/") else { return [] }
        let components = full.split(separator: "/").map(String.init)
        var paths: [String] = []
        walk("", components[...], into: &paths, depth: 0)
        return paths.filter { !isProtected($0) }
    }

    private func walk(_ base: String, _ rest: ArraySlice<String>, into paths: inout [String], depth: Int) {
        guard let component = rest.first else { paths.append(base.isEmpty ? "/" : base); return }
        let remaining = rest.dropFirst()
        if isProtected(base.isEmpty ? "/" : base) && !base.isEmpty { return }
        if component == "**" {
            walk(base, remaining, into: &paths, depth: depth)   // zero folders
            guard depth < 12 else { return }
            for name in children(base) {
                let next = "\(base)/\(name)"
                guard let entry = FileStat.lstat(next) else { continue }
                if entry.isDirectory && !entry.isSymlink {
                    walk(next, rest, into: &paths, depth: depth + 1)        // one more folder, `**` still open
                } else if remaining.isEmpty {
                    paths.append(next)   // a file or link matches a final `**`; nothing is ever looked up through it
                }
            }
            return
        }
        if !component.contains(where: { "*?[".contains($0) }) {
            let next = "\(base)/\(component)"
            guard let entry = FileStat.lstat(next) else { return }
            if !remaining.isEmpty && (!entry.isDirectory || entry.isSymlink) { return }
            walk(next, remaining, into: &paths, depth: depth)
            return
        }
        for name in children(base) where fnmatch(component, name, FNM_PERIOD) == 0 {
            let next = "\(base)/\(name)"
            if !remaining.isEmpty, FileStat.lstat(next)?.isDirectory != true { continue }
            walk(next, remaining, into: &paths, depth: depth)
        }
    }

    private func children(_ dir: String) -> [String] {
        ((try? FileManager.default.contentsOfDirectory(atPath: dir.isEmpty ? "/" : dir)) ?? []).sorted()
    }

    /// Whether a path holds a protected folder (`~/Library` holds `~/Library/Mail`), existing or not.
    func containsProtected(_ path: String) -> Bool {
        ProtectedPaths.roots.contains { root in
            let expanded = root.hasPrefix("~/") ? home + root.dropFirst(1) : root
            return ProtectedPaths.isSameOrInside(expanded, path)
        }
    }

    func isProtected(_ path: String) -> Bool {
        ProtectedPaths.roots.contains { root in
            let expanded = root.hasPrefix("~/") ? home + root.dropFirst(1) : root
            return ProtectedPaths.isSameOrInside(path, expanded)
        }
    }

    // MARK: Candidates

    enum Match { case candidate(CleanupCandidate), incomplete }

    func candidate(_ path: String, target: CleanupTarget, ageLimit: Int64, minSize: Int64?) -> Match? {
        let name = (path as NSString).lastPathComponent
        if target.exclude.contains(where: { fnmatch($0, name, 0) == 0 }) { return nil }
        guard !containsProtected(path), let entry = FileStat.lstat(path) else { return nil }
        switch target.type {
        case .file where entry.isDirectory: return nil
        case .directory where !entry.isDirectory: return nil
        default: break
        }
        // Marker files must sit next to the target (package.json next to node_modules).
        let parent = (path as NSString).deletingLastPathComponent
        for marker in target.contains where FileStat.lstat("\(parent)/\(marker)") == nil { return nil }
        let (bytes, lastUsed, truncated) = measure(path, entry)
        let age = max(0, now - lastUsed)
        guard age >= ageLimit else { return nil }       // something seen inside is recent: in use, whatever else is
        if truncated && ageLimit > 0 { return .incomplete }   // what wasn't seen could be recent
        if let minSize, bytes < minSize, !truncated { return nil }
        return .candidate(CleanupCandidate(path: path, bytes: bytes, lastUsed: lastUsed, ageDays: Int(age / 86_400),
                                           sizeIsLowerBound: truncated ? true : nil))
    }

    /// When anything in it was last used: a file's newest modification or access, a folder's newest modification.
    /// A folder's access time isn't used: listing it (this scan, Spotlight, a backup) changes it.
    static func lastUsed(_ e: FileEntry) -> Int64 { e.isDirectory ? e.modified : max(e.modified, e.accessed) }

    /// Allocated size and last use of a tree, without following symlinks. `truncated` when part of it wasn't seen:
    /// past `entryLimit` entries, or a folder that can't be listed or an entry that can't be read.
    func measure(_ path: String, _ root: FileEntry) -> (bytes: Int64, newest: Int64, truncated: Bool) {
        var bytes = root.allocatedBytes, newest = Self.lastUsed(root), count = 0
        guard root.isDirectory && !root.isSymlink else { return (bytes, newest, false) }
        var stack = [path]
        while let dir = stack.popLast() {
            guard let names = try? FileManager.default.contentsOfDirectory(atPath: dir) else { return (bytes, newest, true) }
            for name in names {
                count += 1
                if count > entryLimit { return (bytes, newest, true) }
                let child = "\(dir)/\(name)"
                guard let e = FileStat.lstat(child) else { return (bytes, newest, true) }
                bytes += e.allocatedBytes
                newest = max(newest, Self.lastUsed(e))
                if e.isDirectory && !e.isSymlink { stack.append(child) }
            }
        }
        return (bytes, newest, false)
    }

    // MARK: Live conditions

    /// `ps -Ac -o comm`: process names, as `processNotRunning` names them.
    public static let liveProcesses: @Sendable () -> Set<String> = {
        guard let r = ProcessRunner().run("/bin/ps", ["-A", "-c", "-o", "comm="], timeout: 10) else { return [] }
        return Set(r.stdout.split(separator: "\n").map { $0.trimmingCharacters(in: .whitespaces) })
    }

    /// An app named `name` (or with that bundle id's last part) in /Applications or ~/Applications.
    public static let liveAppInstalled: @Sendable (String) -> Bool = { name in
        let home = FileManager.default.homeDirectoryForCurrentUser.path
        return ["/Applications", "\(home)/Applications"].contains { FileManager.default.fileExists(atPath: "\($0)/\(name).app") }
    }
}

/// Sizes as Finder shows them (1000-based).
public enum ByteCount {
    public static func format(_ bytes: Int64) -> String {
        let units = ["bytes", "KB", "MB", "GB", "TB"]
        var value = Double(bytes), unit = 0
        while value >= 1000 && unit < units.count - 1 { value /= 1000; unit += 1 }
        if unit == 0 { return "\(bytes) bytes" }
        return String(format: value < 10 ? "%.1f" : "%.0f", value) + " " + units[unit]
    }
}
