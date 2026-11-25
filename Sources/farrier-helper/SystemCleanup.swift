#if os(macOS)
import FarrierCore
import FarrierHelperKit
import Foundation

/// System cleanup, run by the helper as root. The rules come only from the packs inside the helper's own app bundle
/// (sealed by its signature), never from the client; only privileged rules are evaluated, and the linter limits
/// those to /Library/Caches and /Library/Logs. Items go to the root-only quarantine.
enum SystemCleanup {
    /// The packs in Farrier.app/Contents/Resources/rules, next to this executable. Any lint error refuses them all.
    static func packs() throws -> [RulePack] {
        // The executable's real location (argv[0] can be relative when launchd starts the daemon).
        guard let path = Bundle.main.executableURL?.resolvingSymlinksInPath() else { throw PlanError("can't tell where the helper runs from") }
        let exe = path
        let rules = exe.deletingLastPathComponent().deletingLastPathComponent().appendingPathComponent("Resources/rules").path
        guard FileManager.default.fileExists(atPath: rules) else { throw PlanError("the helper's rule packs aren't in its bundle (\(rules))") }
        let (packs, issues) = RuleLinter.loadPacks(at: [rules], source: .bundled)
        let errors = (issues + RuleLinter.lint(packs)).filter { $0.level == .error }
        guard errors.isEmpty else { throw PlanError("the bundled rule packs have errors: \(errors.map { "\($0)" }.joined(separator: "; "))") }
        return packs
    }

    static var scanner: CleanupScanner {
        var s = CleanupScanner(home: "/var/root")
        s.privilegedOnly = true
        return s
    }

    static func scan() throws -> CleanupReport {
        scanner.scan(try packs())
    }

    static func apply(_ plan: Plan) -> [ItemResult] {
        guard let first = plan.items.first?.action, plan.items.allSatisfy({ $0.action == first }) else {
            return plan.items.map { ItemResult(ruleID: $0.ruleID, action: $0.action, outcome: .refused,
                                               detail: "a system plan holds one kind of item") }
        }
        func map(_ results: [CleanupItemResult], _ action: String) -> [ItemResult] {
            results.map { r in
                ItemResult(ruleID: r.ruleID, action: action,
                           outcome: r.outcome == .applied ? .applied : r.outcome == .refused ? .refused : .failed,
                           detail: "\(r.path): \(r.detail)")
            }
        }
        do {
            switch first {
            case RemediationCatalog.cleanupQuarantineSystem.id:
                return map(try CleanupApplier.apply(plan, packs: try packs(), scanner: scanner, quarantine: .system, system: true), first)
            case RemediationCatalog.quarantineRestoreSystem.id:
                return plan.items.flatMap { map(CleanupApplier.restoreSystem($0, quarantine: .system), first) }
            case RemediationCatalog.quarantineExpireSystem.id:
                return map(try CleanupApplier.expire(plan, quarantine: .system), first)
            default:
                return plan.items.map { ItemResult(ruleID: $0.ruleID, action: $0.action, outcome: .refused, detail: "not a system cleanup action") }
            }
        } catch {
            return plan.items.map { ItemResult(ruleID: $0.ruleID, action: $0.action, outcome: .failed, detail: "\(error)") }
        }
    }
}
#endif
