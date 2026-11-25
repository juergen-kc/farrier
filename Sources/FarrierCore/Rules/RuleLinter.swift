import Foundation

/// Paths no cleanup rule may ever touch. This list is compiled into the binary, so no rule pack can override it
/// (THREAT_MODEL.md, T-1 and T-5).
public enum ProtectedPaths {
    public static let roots: [String] = [
        "~/Documents", "~/Desktop", "~/Pictures", "~/Movies", "~/Music",
        "~/Library/Mobile Documents", "~/Library/CloudStorage",
        "~/Library/Mail", "~/Library/Messages", "~/Library/Keychains",
        "~/Library/Containers/com.apple.mail", "~/Library/Group Containers/group.com.apple.notes",
        "/System", "/bin", "/sbin", "/usr/bin", "/usr/sbin", "/usr/lib", "/usr/libexec", "/usr/share",
        "/Library/Keychains", "/private/var/db",
        // Farrier's own state: the quarantine, the journal, the approval key's public half.
        "~/Library/Application Support/Farrier", "/Library/Application Support/Farrier",
    ]

    /// The longest literal leading part of a glob, up to the first component with a wildcard.
    public static func literalPrefix(of pattern: String) -> String {
        var parts: [Substring] = []
        for component in pattern.split(separator: "/", omittingEmptySubsequences: false) {
            if component.contains(where: { "*?[{".contains($0) }) { break }
            parts.append(component)
        }
        let joined = parts.joined(separator: "/")
        return joined.isEmpty ? "/" : joined
    }

    /// Returns the protected root a pattern could reach, or nil if it's safe. A pattern conflicts if its literal
    /// prefix is a protected root or inside one, or if a protected root lies inside the prefix (`~/**` reaches
    /// `~/Documents`). The prefix is normalised first (`~/./Documents`, `~//Documents`), and the comparison ignores
    /// case, because the default macOS volume is case-insensitive (`~/documents` is `~/Documents`).
    public static func conflict(for pattern: String) -> String? {
        let prefix = normalize(literalPrefix(of: pattern))
        for root in roots where isSameOrInside(prefix, root) || isSameOrInside(root, prefix) {
            return root
        }
        return nil
    }

    /// Whether a pattern is written canonically: no empty (`//`) or `.` components, no trailing slash.
    /// Non-canonical spellings are rejected by the linter outright, on top of being normalised for the check above.
    public static func isCanonical(_ pattern: String) -> Bool {
        let parts = pattern.split(separator: "/", omittingEmptySubsequences: false)
        for (i, part) in parts.enumerated() {
            if part == "." { return false }
            if part.isEmpty && i != 0 { return false }  // "//" or a trailing "/" (a leading "/" is fine)
        }
        return true
    }

    /// Drops empty and `.` components. (`..` is rejected by the linter, so it never reaches here in a valid pack.)
    static func normalize(_ path: String) -> String {
        let absolute = path.hasPrefix("/")
        let parts = path.split(separator: "/").filter { $0 != "." }
        let joined = parts.joined(separator: "/")
        return absolute ? "/" + joined : joined
    }

    /// Case-insensitive, component-wise "is `path` the same as or inside `base`".
    static func isSameOrInside(_ path: String, _ base: String) -> Bool {
        let p = path.lowercased(), b = base.lowercased()
        if p == b { return true }
        if b == "/" { return p.hasPrefix("/") }
        return p.hasPrefix(b.hasSuffix("/") ? b : b + "/")
    }
}

/// Semantic checks on parsed packs: ids, protected paths, and the restrictions on user packs.
public enum RuleLinter {
    /// Where user packs may point cleanup rules (THREAT_MODEL.md, T-5): caches, logs, and an explicit list of
    /// developer artifact locations. Not all of `~/Library/Developer`: `Xcode/UserData` holds user-authored
    /// snippets and themes, and `Xcode/Archives` holds the dSYMs needed to symbolicate crash reports.
    public static let userCleanupRoots = [
        "~/Library/Caches", "~/Library/Logs",
        "~/Library/Developer/Xcode/DerivedData",
        "~/Library/Developer/Xcode/iOS DeviceSupport",
        "~/Library/Developer/Xcode/macOS DeviceSupport",
        "~/Library/Developer/CoreSimulator/Caches",
    ]

    /// Where privileged (root) cleanup rules may point, bundled packs included: system caches and logs, never
    /// anything else the helper could reach as root.
    public static let systemCleanupRoots = ["/Library/Caches", "/Library/Logs"]

    public static func lint(_ packs: [RulePack]) -> [LintIssue] {
        var issues: [LintIssue] = []
        var seen: [String: String] = [:]  // rule id → file

        for pack in packs {
            for rule in pack.rules {
                func error(_ m: String) { issues.append(LintIssue(.error, file: pack.file, ruleID: rule.id, m)) }
                func warning(_ m: String) { issues.append(LintIssue(.warning, file: pack.file, ruleID: rule.id, m)) }

                if let other = seen[rule.id] { error("duplicate rule id (also in \(other))") }
                seen[rule.id] = pack.file
                if !rule.id.hasPrefix(pack.id + ".") { error("rule id must start with the pack id `\(pack.id).`") }

                switch rule {
                case .check(let c):
                    if pack.source == .user && c.remediation.automatic {
                        error("user packs cannot declare automatic remediation")
                    }
                case .cleanup(let c):
                    if c.evidence.count < 20 { warning("`evidence` is very short; explain why removal is safe") }
                    if !c.regenerable && c.minAge == nil { warning("non-regenerable data without `minAge`") }
                    for target in c.targets {
                        if let path = target.path {
                            if !(path.hasPrefix("~/") || path.hasPrefix("/")) {
                                error("target path must start with `~/` or `/`: \(path)")
                            }
                            if path.split(separator: "/").contains("..") { error("target path must not contain `..`: \(path)") }
                            if !ProtectedPaths.isCanonical(path) {
                                error("target path must be canonical (no `//`, `/./` or trailing `/`): \(path)")
                            }
                            if let root = ProtectedPaths.conflict(for: path) {
                                error("target `\(path)` can reach the protected path `\(root)`")
                            }
                        }
                    }
                    if c.privileged {
                        if c.tier != .t2 { error("privileged cleanup must be T2 (it goes to the system quarantine)") }
                        for target in c.targets {
                            if target.fact != nil { error("privileged rules cannot use collector `fact` targets") }
                            if let path = target.path {
                                let prefix = ProtectedPaths.normalize(ProtectedPaths.literalPrefix(of: path))
                                // Inside a root, and never the root folder itself.
                                let inside = systemCleanupRoots.contains { ProtectedPaths.isSameOrInside(prefix, $0) }
                                let isRoot = systemCleanupRoots.contains { ProtectedPaths.normalize(path).lowercased() == $0.lowercased() }
                                if !inside || isRoot {
                                    error("privileged target must be inside \(systemCleanupRoots.joined(separator: " or ")): \(path)")
                                }
                            }
                        }
                    } else {
                        for target in c.targets where target.path?.hasPrefix("/") == true {
                            error("system paths need `privileged: true` (the helper moves them): \(target.path!)")
                        }
                    }
                    if pack.source == .user {
                        if c.tier != .t2 { error("user packs may only declare T2 (reversible) cleanup") }
                        if c.privileged { error("user packs cannot set `privileged: true`") }
                        for target in c.targets {
                            if target.fact != nil { error("user packs cannot use collector `fact` targets") }
                            if let path = target.path {
                                let prefix = ProtectedPaths.normalize(ProtectedPaths.literalPrefix(of: path))
                                if !userCleanupRoots.contains(where: { ProtectedPaths.isSameOrInside(prefix, $0) }) {
                                    error("user pack target must be inside \(userCleanupRoots.joined(separator: ", ")): \(path)")
                                }
                            }
                        }
                    }
                }
            }
        }
        return issues
    }

    /// Loads every `*.yaml` / `*.yml` file under the given paths (files or directories).
    public static func loadPacks(at paths: [String], source: RulePack.Source) -> (packs: [RulePack], issues: [LintIssue]) {
        var packs: [RulePack] = []
        var issues: [LintIssue] = []
        // Every path the caller asked for must exist: silently dropping one would skip checks without telling anyone.
        for path in paths where !FileManager.default.fileExists(atPath: path) {
            issues.append(LintIssue(.error, file: path, "no such file or directory"))
        }
        for file in yamlFiles(at: paths) {
            let result = RulePackParser.parse(file: file, source: source)
            if let p = result.pack { packs.append(p) }
            issues += result.issues
        }
        if packs.isEmpty && issues.isEmpty {
            issues.append(LintIssue(.error, file: paths.joined(separator: ", "), "no rule packs found"))
        }
        return (packs, issues)
    }

    static func yamlFiles(at paths: [String]) -> [URL] {
        let fm = FileManager.default
        var files: [URL] = []
        for path in paths {
            var isDir: ObjCBool = false
            guard fm.fileExists(atPath: path, isDirectory: &isDir) else { continue }
            if !isDir.boolValue {
                files.append(URL(fileURLWithPath: path))
                continue
            }
            guard let walker = fm.enumerator(atPath: path) else { continue }
            while let rel = walker.nextObject() as? String {
                if rel.hasSuffix(".yaml") || rel.hasSuffix(".yml") {
                    files.append(URL(fileURLWithPath: path).appendingPathComponent(rel))
                }
            }
        }
        return files.sorted { $0.path < $1.path }
    }
}
