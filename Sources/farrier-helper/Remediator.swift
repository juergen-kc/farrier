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

        // Managed preferences win over local ones, whichever profile set them (Custom Settings too).
        if let mp = action.managedPreference, let domain = mp.preference {
            guard let managed = SystemCollectors(runner: runner).managedPreferences() else {
                return result(.refused, "could not read the managed preferences, so a profile might manage this")
            }
            let set = (mp.keys ?? []).filter { managed[domain]?.contains($0) ?? false }
            if !set.isEmpty {
                return result(.refused, "managed by a profile (\(domain): \(set.joined(separator: ", "))); change it in the profile or MDM")
            }
        }

        // Declarations (DDM) can't be read yet, and only MDM delivers them: on an enrolled Mac, or if enrollment
        // can't be read, a setting a declaration could own isn't touched.
        if !action.managedDeclarationTypes.isEmpty {
            let r = runner.run("/usr/bin/profiles", ["status", "-type", "enrollment"], timeout: 15)
            guard let r, !r.timedOut, case .bool(let enrolled)? = Parsers.profilesEnrollment(r.combined)?.object?["mdm"] else {
                return result(.refused, "could not check MDM enrollment, so a declaration might manage this; change it in System Settings")
            }
            if enrolled {
                return result(.refused, "this Mac is MDM-enrolled and Farrier can't read its declarations yet; change it in your MDM or System Settings")
            }
        }

        if let forward = action.reverses {
            return undo(item, action, forward: forward, runner, result)
        }

        switch action.id {
        case RemediationCatalog.gatekeeperEnable.id:
            return setGatekeeper(item, action, runner, result)
        case RemediationCatalog.securityAutoInstall.id:
            return setSecurityAutoInstall(item, runner, result)
        case RemediationCatalog.firewallEnable.id:
            return setFirewall(item, action, runner, result, name: "firewall", get: "--getglobalstate",
                               set: ["--setglobalstate", "on"], parse: Parsers.firewallGlobalState)
        case RemediationCatalog.firewallStealthEnable.id:
            return setFirewall(item, action, runner, result, name: "stealth mode", get: "--getstealthmode",
                               set: ["--setstealthmode", "on"], parse: Parsers.firewallStealthMode)
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

    // MARK: Undo

    /// Reverses a change only if the helper's own journal shows that plan applied it, with the state it replaced,
    /// and it hasn't been undone already. The target state comes from the journal (root-owned), never the plan.
    private static func undo(_ item: PlanItem, _ action: RemediationAction, forward: String, _ runner: CommandRunning,
                             _ result: (ItemResult.Outcome, String?) -> ItemResult) -> ItemResult {
        let planID: String
        do { planID = try UndoRules.validate(item.parameters) } catch { return result(.refused, "\(error)") }
        let history: [JournalRecord]
        do { history = try HelperService.journal.entries().map(\.record) } catch {
            return result(.refused, "can't read the helper's journal: \(error)")
        }
        guard let applied = history.last(where: { $0.planID == planID && $0.ruleID == item.ruleID && $0.action == forward
                                                 && $0.outcome == "applied" }),
              let previous = applied.previous else {
            return result(.refused, "the helper's journal shows no change by plan \(planID.prefix(8)) to undo here")
        }
        if history.contains(where: { $0.reverts == planID && $0.ruleID == item.ruleID && $0.action == action.id && $0.outcome == "applied" }) {
            return result(.alreadyCompliant, "plan \(planID.prefix(8)) was already undone")
        }
        switch action.id {
        case RemediationCatalog.firewallRestore.id:
            return restoreFirewall(item, previous, runner, result, name: "firewall", get: "--getglobalstate",
                                   set: "--setglobalstate", parse: Parsers.firewallGlobalState)
        case RemediationCatalog.firewallStealthRestore.id:
            return restoreFirewall(item, previous, runner, result, name: "stealth mode", get: "--getstealthmode",
                                   set: "--setstealthmode", parse: Parsers.firewallStealthMode)
        case RemediationCatalog.securityAutoInstallRestore.id:
            return restoreSecurityAutoInstall(item, previous, runner, result)
        default:
            return result(.refused, "no implementation for \(action.id)")
        }
    }

    /// Puts a firewall setting back to `previous` ("off": the forward action only ever turned it on from off).
    private static func restoreFirewall(_ item: PlanItem, _ previous: FactValue, _ runner: CommandRunning,
                                        _ result: (ItemResult.Outcome, String?) -> ItemResult,
                                        name: String, get: String, set: String, parse: (String) -> FactValue?) -> ItemResult {
        guard previous == .string("off") else { return result(.refused, "the recorded earlier \(name) state (\(previous)) can't be restored") }
        func read() -> String? {
            guard let r = runner.run(socketfilterfw, [get], timeout: 15), !r.timedOut else { return nil }
            return parse(r.combined)?.string
        }
        guard let before = read() else { return result(.failed, "could not read the \(name) state") }
        if before == "off" { return result(.alreadyCompliant, "\(name) is already off") }
        guard item.observed.string == before else {
            return result(.refused, "the \(name) state changed since planning (\(item.observed) → \(before)); make a new plan")
        }
        guard let r = runner.run(socketfilterfw, [set, "off"], timeout: 30) else { return result(.failed, "\(socketfilterfw) not found") }
        if r.timedOut { return result(.failed, "socketfilterfw timed out") }
        guard let after = read() else { return result(.failed, "could not read the \(name) state afterwards") }
        guard after == "off" else { return result(.failed, "\(name) is still \(after) (exit \(r.status))") }
        return result(.applied, "\(name) \(before) → off (restored)")
    }

    /// Puts the security auto-install keys back as they were: the earlier value, or not set at all.
    private static func restoreSecurityAutoInstall(_ item: PlanItem, _ previous: FactValue, _ runner: CommandRunning,
                                                   _ result: (ItemResult.Outcome, String?) -> ItemResult) -> ItemResult {
        guard let earlier = previous.object else { return result(.refused, "the recorded earlier settings can't be read") }
        let keys = RemediationCatalog.securityAutoInstallKeys
        let collector = SystemCollectors(runner: runner)
        guard let (before, managedKeys) = collector.softwareUpdateSettings() else {
            return result(.failed, "could not read the software update settings")
        }
        let managed = keys.filter(managedKeys.contains)
        if !managed.isEmpty { return result(.refused, "managed by a profile (\(managed.joined(separator: ", "))); change it there") }
        let changes = keys.filter { before[$0] != earlier[$0] }
        if changes.isEmpty { return result(.alreadyCompliant, "the settings are already as they were") }
        guard item.observed == .object(before) else {
            return result(.refused, "the software update settings changed since planning; make a new plan")
        }
        for key in changes {
            let args: [String]
            switch earlier[key] {
            case .bool(let b)?: args = ["write", softwareUpdateDomain, key, "-bool", b ? "true" : "false"]
            case nil: args = ["delete", softwareUpdateDomain, key]
            case let other?: return result(.refused, "the recorded earlier value of \(key) (\(other)) isn't a boolean")
            }
            guard let r = runner.run("/usr/bin/defaults", args, timeout: 15), !r.timedOut, r.status == 0 else {
                return result(.failed, "could not restore \(key)")
            }
        }
        guard let after = collector.softwareUpdateSettings() else {
            return result(.failed, "could not read the software update settings afterwards")
        }
        let wrong = keys.filter { after.prefs[$0] != earlier[$0] }
        guard wrong.isEmpty else { return result(.failed, "\(wrong.joined(separator: " and ")) didn't go back to the earlier value") }
        return result(.applied, "restored \(changes.joined(separator: " and "))")
    }

    static let spctl = "/usr/sbin/spctl"

    /// Gatekeeper on: `spctl --global-enable` (macOS 15 and later), or `--master-enable` where that's the name, as
    /// long as reading `spctl --status` back doesn't say "enabled".
    private static func setGatekeeper(_ item: PlanItem, _ action: RemediationAction, _ runner: CommandRunning,
                                      _ result: (ItemResult.Outcome, String?) -> ItemResult) -> ItemResult {
        func read() -> String? {
            guard let r = runner.run(spctl, ["--status"], timeout: 15), !r.timedOut else { return nil }
            return Parsers.spctlStatus(r.combined)?.string
        }
        guard let before = read() else { return result(.failed, "could not read the Gatekeeper state") }
        if action.compliantValues.contains(before) { return result(.alreadyCompliant, "Gatekeeper is already \(before)") }
        guard item.observed.string == before else {
            return result(.refused, "the Gatekeeper state changed since planning (\(item.observed) → \(before)); make a new plan")
        }
        var output = ""
        for flag in ["--global-enable", "--master-enable"] {
            guard let r = runner.run(spctl, [flag], timeout: 30) else { return result(.failed, "\(spctl) not found") }
            if r.timedOut { return result(.failed, "spctl \(flag) timed out") }
            output = "\(flag): exit \(r.status) \(r.combined.trimmingCharacters(in: .whitespacesAndNewlines).prefix(120))"
            if let after = read(), action.compliantValues.contains(after) {
                return result(.applied, "Gatekeeper \(before) → \(after)")
            }
        }
        return result(.failed, "Gatekeeper is still \(read() ?? "unreadable") (\(output))")
    }

    static let softwareUpdateDomain = "/Library/Preferences/com.apple.SoftwareUpdate"

    /// Sets the security auto-install keys to true with `defaults`, only if the settings are still exactly what the
    /// plan showed, and reports success only if reading each key back gives true.
    private static func setSecurityAutoInstall(_ item: PlanItem, _ runner: CommandRunning,
                                               _ result: (ItemResult.Outcome, String?) -> ItemResult) -> ItemResult {
        let keys = RemediationCatalog.securityAutoInstallKeys
        let collector = SystemCollectors(runner: runner)
        guard let (before, managedKeys) = collector.softwareUpdateSettings() else {
            return result(.failed, "could not read the software update settings")
        }
        // Any profile can set these keys as managed preferences (a custom-settings payload, not only
        // com.apple.SoftwareUpdate). The managed value wins, so a local change would do nothing.
        let managed = keys.filter(managedKeys.contains)
        if !managed.isEmpty {
            return result(.refused, "managed by a profile (\(managed.joined(separator: ", "))); change it in the profile or MDM")
        }
        let missing = keys.filter { before[$0] != .bool(true) }
        if missing.isEmpty { return result(.alreadyCompliant, "\(keys.joined(separator: " and ")) are already on") }
        guard item.observed == .object(before) else {
            return result(.refused, "the software update settings changed since planning; make a new plan")
        }
        func readBack(_ key: String) -> Bool {
            guard let r = runner.run("/usr/bin/defaults", ["read", softwareUpdateDomain, key], timeout: 15), !r.timedOut else { return false }
            return r.status == 0 && r.stdout.trimmingCharacters(in: .whitespacesAndNewlines) == "1"
        }
        for key in missing {
            guard let r = runner.run("/usr/bin/defaults", ["write", softwareUpdateDomain, key, "-bool", "true"], timeout: 15) else {
                return result(.failed, "/usr/bin/defaults not found")
            }
            if r.timedOut || r.status != 0 {
                return result(.failed, "could not set \(key): \(r.combined.trimmingCharacters(in: .whitespacesAndNewlines).prefix(120))")
            }
            guard readBack(key) else { return result(.failed, "\(key) is still not on after setting it") }
        }
        // The effective settings, as posture reads them (managed preferences included), must now be on too.
        guard let after = collector.softwareUpdateSettings() else {
            return result(.failed, "could not read the software update settings afterwards")
        }
        let stillOff = keys.filter { after.prefs[$0] != .bool(true) }
        guard stillOff.isEmpty else {
            return result(.failed, "\(stillOff.joined(separator: " and ")) still reads as off"
                          + (after.managedKeys.isEmpty ? "" : " (managed keys: \(after.managedKeys.sorted().joined(separator: ", ")))"))
        }
        return result(.applied, "turned on \(missing.joined(separator: " and "))")
    }

    /// One application-firewall setting: read it, check it still is what the plan saw, change it with
    /// socketfilterfw, and report success only if reading it back shows the compliant value.
    private static func setFirewall(_ item: PlanItem, _ action: RemediationAction, _ runner: CommandRunning,
                                    _ result: (ItemResult.Outcome, String?) -> ItemResult,
                                    name: String, get: String, set: [String], parse: (String) -> FactValue?) -> ItemResult {
        func read() -> String? {
            guard let r = runner.run(socketfilterfw, [get], timeout: 15), !r.timedOut else { return nil }
            return parse(r.combined)?.string
        }
        guard let before = read() else { return result(.failed, "could not read the \(name) state") }
        if action.compliantValues.contains(before) { return result(.alreadyCompliant, "\(name) is already \(before)") }
        // The Mac changed since the plan was reviewed: don't act on a picture the user didn't see.
        guard item.observed.string == before else {
            return result(.refused, "the \(name) state changed since planning (\(item.observed) → \(before)); make a new plan")
        }
        guard let r = runner.run(socketfilterfw, set, timeout: 30) else { return result(.failed, "\(socketfilterfw) not found") }
        if r.timedOut { return result(.failed, "socketfilterfw timed out") }
        // Trust the state, not the exit code or the message.
        guard let after = read() else { return result(.failed, "could not read the \(name) state afterwards") }
        guard action.compliantValues.contains(after) else {
            let snippet = r.combined.trimmingCharacters(in: .whitespacesAndNewlines).prefix(160)
            return result(.failed, "\(name) is still \(after) (exit \(r.status)): \(snippet)")
        }
        return result(.applied, "\(name) \(before) → \(after)")
    }
}
#endif
