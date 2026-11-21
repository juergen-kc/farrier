#if os(macOS)
import FarrierCore
import FarrierHelperKit
import Foundation

/// Carries out approved plan items. Each action is fixed code for one `RemediationCatalog` entry: the helper
/// re-checks the Mac itself (MDM ownership, current state) and takes no commands, paths or values from the plan.
enum Remediator {
    static let socketfilterfw = "/usr/libexec/ApplicationFirewall/socketfilterfw"

    static func apply(_ item: PlanItem, planID: String, runner: CommandRunning = ProcessRunner()) -> ItemResult {
        func result(_ outcome: ItemResult.Outcome, _ detail: String?) -> ItemResult {
            ItemResult(ruleID: item.ruleID, action: item.action, outcome: outcome, detail: detail)
        }
        guard let action = RemediationCatalog.action(item.action) else { return result(.refused, "unknown action") }

        // MDM owns the setting? Then the change belongs in the MDM, and Farrier must not fight it.
        // Not knowing counts as owned: the helper never guesses.
        if !action.managedPayloadTypes.isEmpty {
            let (payloads, error) = PrivilegedFacts.read(.mdmPayloadTypes)
            guard let types = payloads?.array?.compactMap(\.string) else {
                return result(.refused, "could not check MDM profiles: \(error ?? "no value")")
            }
            if let managed = action.managedPayloadTypes.first(where: types.contains) {
                return result(.refused, "managed by MDM (\(managed)); change it there")
            }
        }

        switch action.id {
        case RemediationCatalog.firewallEnable.id:
            return enableFirewall(item, action, runner, result)
        case RemediationCatalog.exceptionAdd.id, RemediationCatalog.exceptionRemove.id:
            return changeException(item, planID: planID, adding: action.id == RemediationCatalog.exceptionAdd.id, result)
        default:
            return result(.refused, "no implementation for \(action.id)")
        }
    }

    /// Adds or removes an exception in the root-owned exceptions file. The parameters are validated here again;
    /// the plan's text is never trusted.
    /// Serialises the load–modify–write of the exceptions file across all helper connections (one helper process).
    private static let exceptionLock = NSLock()

    private static func changeException(_ item: PlanItem, planID: String, adding: Bool,
                                        _ result: (ItemResult.Outcome, String?) -> ItemResult) -> ItemResult {
        exceptionLock.lock()
        defer { exceptionLock.unlock() }
        let p: ExceptionRules.Parameters
        do {
            p = try ExceptionRules.validate(ruleID: item.ruleID, item.parameters, requireReason: adding)
        } catch {
            return result(.refused, "\(error)")
        }
        let store = ExceptionStore()
        let (current, problem) = store.load()
        // A file that can't be trusted isn't silently replaced: someone should look at it first.
        if let problem, FileManager.default.fileExists(atPath: store.path) { return result(.refused, problem) }
        let wanted = PostureException(ruleID: item.ruleID, teamID: p.teamID, identifier: p.identifier, reason: p.reason,
                                      acceptedAt: Int64(Date().timeIntervalSince1970), planID: planID)
        var updated = current
        if adding {
            if current.contains(where: { $0.sameScope(as: wanted) }) { return result(.alreadyCompliant, "the exception already exists") }
            updated.append(wanted)
        } else {
            updated.removeAll { $0.sameScope(as: wanted) }
            if updated.count == current.count { return result(.alreadyCompliant, "no such exception") }
        }
        do {
            try HelperService.writeRootFile(try ExceptionStore.encode(updated), to: store.path)
        } catch {
            return result(.failed, "could not write \(store.path): \(error)")
        }
        let scope = "team \(p.teamID)" + (p.identifier.map { " (\($0))" } ?? "")
        return result(.applied, adding ? "accepted \(scope) for \(item.ruleID)" : "removed the exception for \(scope)")
    }

    private static func firewallState(_ runner: CommandRunning) -> String? {
        guard let r = runner.run(socketfilterfw, ["--getglobalstate"], timeout: 15), !r.timedOut else { return nil }
        return Parsers.firewallGlobalState(r.combined)?.string
    }

    private static func enableFirewall(_ item: PlanItem, _ action: RemediationAction, _ runner: CommandRunning,
                                       _ result: (ItemResult.Outcome, String?) -> ItemResult) -> ItemResult {
        guard let before = firewallState(runner) else { return result(.failed, "could not read the firewall state") }
        if action.compliantValues.contains(before) { return result(.alreadyCompliant, "firewall is already \(before)") }
        // The Mac changed since the plan was reviewed: don't act on a picture the user didn't see.
        guard item.observed.string == before else {
            return result(.refused, "the firewall state changed since planning (\(item.observed) → \(before)); make a new plan")
        }
        guard let r = runner.run(socketfilterfw, ["--setglobalstate", "on"], timeout: 30) else {
            return result(.failed, "\(socketfilterfw) not found")
        }
        if r.timedOut { return result(.failed, "socketfilterfw timed out") }
        // Trust the state, not the exit code or the message.
        guard let after = firewallState(runner) else { return result(.failed, "could not read the firewall state afterwards") }
        guard action.compliantValues.contains(after) else {
            let snippet = r.combined.trimmingCharacters(in: .whitespacesAndNewlines).prefix(160)
            return result(.failed, "firewall is still \(after) (exit \(r.status)): \(snippet)")
        }
        return result(.applied, "firewall \(before) → \(after)")
    }
}
#endif
