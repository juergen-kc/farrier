#if canImport(CryptoKit)
import CryptoKit
#else
import Crypto
#endif
import Foundation
import Testing
@testable import FarrierCore
@testable import FarrierHelperKit
@testable import FarrierMCP

private let host = "8E5C0F3A-0000-4000-8000-000000000001"

/// Signs like the approval key does (ECDSA P-256, DER signature).
private func sign(_ key: P256.Signing.PrivateKey, _ payload: Data) throws -> Data {
    try key.signature(for: payload).derRepresentation
}

private func policy(_ key: P256.Signing.PrivateKey, days: Int = 7, approvedAt: Int64 = 1_000, host: String = host) throws -> AutoExpiryPolicy {
    let payload = AutoExpiryPolicy.payload(retentionDays: days, approvedAt: approvedAt, host: host)
    return AutoExpiryPolicy(retentionDays: days, approvedAt: approvedAt, host: host,
                            publicKey: key.publicKey.derRepresentation, signature: try sign(key, payload))
}

private func fingerprint(_ key: P256.Signing.PrivateKey) -> String { FarrierCrypto.sha256(key.publicKey.derRepresentation).hexString }

@Suite("Automatic quarantine expiry")
struct AutoExpiryTests {
    @Test func aPolicyHoldsOnlyForTheEnrolledKeyThisMacAndTheRetention() throws {
        let key = P256.Signing.PrivateKey()
        let p = try policy(key)
        #expect(p.problem(enrolledFingerprint: fingerprint(key), host: host) == nil)
        // The key was rotated since: the enrolled one is another.
        #expect(p.problem(enrolledFingerprint: fingerprint(P256.Signing.PrivateKey()), host: host)?.contains("earlier approval key") == true)
        #expect(p.problem(enrolledFingerprint: nil, host: host)?.contains("can't be checked") == true)
        #expect(p.problem(enrolledFingerprint: fingerprint(key), host: "OTHER")?.contains("another Mac") == true)
        #expect(try policy(key, days: 1).problem(enrolledFingerprint: fingerprint(key), host: host)?.contains("approved for 1 days") == true)

        // A policy someone wrote themselves: right public key, but they can't sign with it.
        let forger = P256.Signing.PrivateKey()
        let forged = AutoExpiryPolicy(retentionDays: 7, approvedAt: 5, host: host, publicKey: key.publicKey.derRepresentation,
                                      signature: try sign(forger, AutoExpiryPolicy.payload(retentionDays: 7, approvedAt: 5, host: host)))
        #expect(forged.problem(enrolledFingerprint: fingerprint(key), host: host)?.contains("doesn't verify") == true)
        // Or a real signature with an edited field.
        let edited = try JSONSerialization.jsonObject(with: JSONEncoder().encode(p)) as! [String: Any]
        var e = edited; e["approvedAt"] = 2_000
        let tampered = try JSONDecoder().decode(AutoExpiryPolicy.self, from: JSONSerialization.data(withJSONObject: e))
        #expect(tampered.problem(enrolledFingerprint: fingerprint(key), host: host)?.contains("doesn't verify") == true)
    }

    @Test func theStoreIsPrivate() throws {
        let home = FakeHome()
        let store = AutoExpiryStore(path: "\(home.root)/Library/Application Support/Farrier/auto-expiry.json")
        #expect(store.load() == nil && !store.exists)
        let p = try policy(P256.Signing.PrivateKey())
        try store.save(p)
        #expect(store.load() == p)
        let attrs = try FileManager.default.attributesOfItem(atPath: store.path)
        #expect((attrs[.posixPermissions] as? NSNumber)?.intValue == 0o600)
        try store.remove()
        #expect(!store.exists)
    }

    @Test func theLaunchAgentRunsExpireDueDaily() throws {
        let data = try ExpirySchedule.plist(executable: "/Applications/Farrier.app/Contents/MacOS/farrier", logDirectory: "/tmp/l")
        let plist = try #require(try PropertyListSerialization.propertyList(from: data, format: nil) as? [String: Any])
        #expect(plist["Label"] as? String == ExpirySchedule.label)
        #expect(plist["ProgramArguments"] as? [String] == ["/Applications/Farrier.app/Contents/MacOS/farrier", "quarantine", "expire-due"])
        #expect((plist["StartCalendarInterval"] as? [String: Int])?["Hour"] != nil)
        #expect(plist["RunAtLoad"] as? Bool == false)
    }

    @Test func enableRunAndDisable() throws {
        let home = FakeHome()
        home.file("Library/Caches/old/blob", bytes: 20_000, daysAgo: 60)
        home.dir("Library/Caches/old", daysAgo: 60)
        home.file("Library/Caches/new/blob", bytes: 20_000, daysAgo: 60)
        home.dir("Library/Caches/new", daysAgo: 60)
        let packs = [try pack(packYAML(rule("caches", "targets:\n  - path: ~/Library/Caches/*\nminAge: 30d\n")))]
        let quarantine = Quarantine(root: "\(home.root)/q")
        // Two cleanups: one 8 days ago (due), one now (not due).
        let eightDaysAgo = home.now.addingTimeInterval(-8 * 86_400)
        let report = home.scanner().scan(packs)
        let first = try #require(Planner.planCleanup(report: report, paths: ["\(home.root)/Library/Caches/old"], host: host, now: eightDaysAgo).plan)
        _ = try CleanupApplier.apply(first, packs: packs, scanner: home.scanner(), quarantine: quarantine, now: eightDaysAgo)
        let second = try #require(Planner.planCleanup(report: report, paths: ["\(home.root)/Library/Caches/new"], host: host, now: home.now).plan)
        _ = try CleanupApplier.apply(second, packs: packs, scanner: home.scanner(), quarantine: quarantine, now: home.now)

        let dir = FileManager.default.temporaryDirectory.appendingPathComponent("farrier-ctx-\(UUID().uuidString)")
        defer { try? FileManager.default.removeItem(at: dir) }
        var ctx = FarrierContext(
            collectFacts: { CollectionResult(facts: [:], notes: []) }, rulePaths: [],
            plans: PlanStore(directory: dir.appendingPathComponent("plans")),
            journal: Journal(url: dir.appendingPathComponent("j.jsonl")),
            host: { host }, applyThroughHelper: { _ in throw OperationError("none") }, actor: "cli")
        ctx.quarantine = quarantine
        ctx.autoExpiry = AutoExpiryStore(path: dir.appendingPathComponent("auto-expiry.json").path)
        var key = P256.Signing.PrivateKey()
        ctx.enrolledKeyFingerprint = { fingerprint(key) }
        var scheduled = false
        ctx.installExpirySchedule = { _ in scheduled = true }
        ctx.uninstallExpirySchedule = { scheduled = false }
        ctx.expiryScheduleInstalled = { scheduled }

        // Off: the scheduled run does nothing.
        #expect(Operations.runDueExpiry(ctx, now: home.now).error == "automatic expiry is off")

        // Cancelled on the Mac: nothing saved, nothing scheduled.
        ctx.signWithApprovalKey = { _, _ in throw OperationError("the approval prompt was cancelled; nothing changed") }
        #expect(throws: OperationError.self) { try Operations.enableAutoExpiry(ctx, executable: "/x", now: home.now) }
        #expect(!ctx.autoExpiry.exists && !scheduled)

        // Approved: signed with the enrolled key.
        var reason = ""
        ctx.signWithApprovalKey = { payload, r in reason = r; return (try sign(key, payload), key.publicKey.derRepresentation) }
        let on = try Operations.enableAutoExpiry(ctx, executable: "/x", now: home.now)
        #expect(on.enabled && on.active == true && on.scheduled && reason.contains("7 days"))

        // The run deletes only what's past its 7 days.
        let out = Operations.runDueExpiry(ctx, now: home.now)
        #expect(out.error == nil && out.results.map(\.outcome) == [.applied])
        #expect(try quarantine.load(first.id).held.isEmpty)
        #expect(try quarantine.load(second.id).held.count == 1)
        #expect(Operations.runDueExpiry(ctx, now: home.now).results.isEmpty)   // nothing more due

        // After the key's rotation the approval no longer holds, and nothing is deleted.
        key = P256.Signing.PrivateKey()
        let later = home.now.addingTimeInterval(8 * 86_400)
        let stale = Operations.runDueExpiry(ctx, now: later)
        #expect(stale.error?.contains("earlier approval key") == true)
        #expect(try quarantine.load(second.id).held.count == 1)
        #expect(Operations.quarantineList(ctx, now: later).autoExpiry.active == false)

        // Off needs no approval.
        ctx.signWithApprovalKey = { _, _ in Issue.record("off must not ask"); throw OperationError("no") }
        let off = try Operations.disableAutoExpiry(ctx)
        #expect(!off.enabled && !off.scheduled && !ctx.autoExpiry.exists)

        let records = try ctx.journal.entries().map(\.record)
        #expect(records.map(\.outcome) == ["notApplied", "approved", "planned", "applied", "notApplied", "removed"])
        #expect(records.filter { $0.outcome == "applied" }.allSatisfy { $0.actor == "schedule" })
    }
}
