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
    /// `~/Documents`).
    public static func conflict(for pattern: String) -> String? {
        let prefix = literalPrefix(of: pattern)
        for root in roots where isSameOrInside(prefix, root) || isSameOrInside(root, prefix) {
            return root
        }
        return nil
    }

    static func isSameOrInside(_ path: String, _ base: String) -> Bool {
        if path == base { return true }
        let b = base.hasSuffix("/") ? base : base + "/"
        return path.hasPrefix(b)
    }
}

/// Semantic checks on parsed packs: ids, protected paths, and the restrictions on user packs.
public enum RuleLinter {
    /// Where user packs may point cleanup rules (THREAT_MODEL.md, T-5).
    public static let userCleanupRoots = ["~/Library/Caches", "~/Library/Logs", "~/Library/Developer"]

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
                            if let root = ProtectedPaths.conflict(for: path) {
                                error("target `\(path)` can reach the protected path `\(root)`")
                            }
                        }
                    }
                    if pack.source == .user {
                        if c.tier != .t2 { error("user packs may only declare T2 (reversible) cleanup") }
                        if c.privileged { error("user packs cannot set `privileged: true`") }
                        for target in c.targets {
                            if target.fact != nil { error("user packs cannot use collector `fact` targets") }
                            if let path = target.path {
                                let prefix = ProtectedPaths.literalPrefix(of: path)
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
