#if canImport(CryptoKit)
import CryptoKit
#else
import Crypto
#endif
import Foundation
import Testing
@testable import FarrierCore

private let host = "8E5C0F3A-0000-4000-8000-000000000001"

private func postureFacts(firewall: String = "off", payloadTypes: [String]? = []) -> StaticFactStore {
    var facts: [String: FactValue] = [
        "filevault.status": .string("On"),
        "sip.status": .string("enabled"),
        "gatekeeper.assessments": .string("enabled"),
        "firewall.globalState": .string(firewall),
        "softwareupdate.prefs": .object(["CriticalUpdateInstall": .bool(true), "ConfigDataInstall": .bool(true)]),
        "mdm.declarationTypes": .array([]),
    ]
    if let payloadTypes { facts["mdm.payloadTypes"] = .array(payloadTypes.map { .string($0) }) }
    return StaticFactStore(facts)
}

private func posturePacks() throws -> [RulePack] {
    let (packs, issues) = RuleLinter.loadPacks(at: [repoRoot.appendingPathComponent("rules/posture").path], source: .bundled)
    try #require(issues.filter { $0.level == .error }.isEmpty, "\(issues)")
    return packs
}

private func makePlan(facts: StaticFactStore = postureFacts(), ruleIDs: Set<String>? = nil,
                      now: Date = Date()) throws -> (Plan?, [PlanSkip]) {
    let packs = try posturePacks()
    let report = PostureEngine.evaluate(packs, facts: facts)
    return Planner.plan(report: report, packs: packs, facts: facts, ruleIDs: ruleIDs, host: host, now: now,
                        id: "0f1e2d3c-4b5a-4968-8776-655443322110")
}

@Suite("Plans")
struct PlanTests {
    @Test func firewallFailureBecomesAT4Item() throws {
        let (plan, _) = try makePlan()
        let p = try #require(plan)
        #expect(p.items.count == 1)
        #expect(p.items[0].action == "firewall.enable")
        #expect(p.items[0].observed == .string("off"))
        #expect(p.tier == .t4)
        #expect(p.tier.needsApproval)
        #expect(p.host == host)
        #expect(p.expiresAt - p.createdAt == Plan.defaultTTL)
    }

    @Test func managedOrUncheckedSettingsAreLeftOut() throws {
        let (managed, managedSkips) = try makePlan(facts: postureFacts(payloadTypes: ["com.apple.security.firewall"]))
        #expect(managed == nil)
        #expect(managedSkips.contains { $0.ruleID == "posture.core.firewall" && $0.reason.contains("managed by com.apple.security.firewall") })

        let (unchecked, uncheckedSkips) = try makePlan(facts: postureFacts(payloadTypes: nil))
        #expect(unchecked == nil)
        #expect(uncheckedSkips.contains { $0.ruleID == "posture.core.firewall" && $0.reason.contains("could not be checked") })
    }

    @Test func ruleSelectionReportsUnknownAndPassingRules() throws {
        let (plan, skips) = try makePlan(ruleIDs: ["posture.core.firewall", "posture.core.sip", "posture.core.nope"])
        #expect(try #require(plan).items.map(\.ruleID) == ["posture.core.firewall"])
        #expect(skips.contains(PlanSkip(ruleID: "posture.core.nope", reason: "no such posture rule")))
        #expect(skips.contains(PlanSkip(ruleID: "posture.core.sip", reason: "already passes")))

        let (none, _) = try makePlan(facts: postureFacts(firewall: "on"), ruleIDs: ["posture.core.firewall"])
        #expect(none == nil)
    }

    @Test func canonicalEncodingIsStableAndStrict() throws {
        let plan = try #require(try makePlan(now: Date(timeIntervalSince1970: 1_800_000_000)).0)
        let data = try plan.canonicalData()
        #expect(try plan.canonicalData() == data)
        #expect(try Plan.decodeCanonical(data) == plan)
        #expect(try plan.hash() == FarrierCrypto.sha256(data))
        #expect(String(decoding: data, as: UTF8.self).hasPrefix(#"{"createdAt":1800000000,"expiresAt":1800000900,"format":1,"#))

        // Same content, other bytes: pretty-printed, an extra key, or a tier that doesn't match the items.
        let pretty = JSONEncoder()
        pretty.outputFormatting = [.prettyPrinted, .sortedKeys]
        #expect(throws: PlanError.self) { try Plan.decodeCanonical(try pretty.encode(plan)) }
        let extra = Data(String(decoding: data, as: UTF8.self).replacingOccurrences(of: #"{"createdAt""#, with: #"{"a":1,"createdAt""#).utf8)
        #expect(throws: PlanError.self) { try Plan.decodeCanonical(extra) }
        // Only the plan's own tier (the last key), not the item's.
        let text = String(decoding: data, as: UTF8.self)
        #expect(text.hasSuffix(#""tier":"T4"}"#))
        let lowered = Data((text.dropLast(#""tier":"T4"}"#.count) + #""tier":"T0"}"#).utf8)
        #expect(lowered != data)
        #expect(throws: PlanError.self) { try Plan.decodeCanonical(lowered) }
    }

    @Test func hexParsingIsStrict() {
        #expect(Data(hexString: "00ff10") == Data([0x00, 0xFF, 0x10]))
        #expect(Data(hexString: "00FF") == Data([0x00, 0xFF]))
        #expect(Data(hexString: "+f") == nil)
        #expect(Data(hexString: "abc") == nil)
        #expect(Data(hexString: "zz") == nil)
        #expect(Data([0xAB, 0x01]).hexString == "ab01")
    }

    @Test func storeSavesAndLoadsByPrefix() throws {
        let dir = FileManager.default.temporaryDirectory.appendingPathComponent("farrier-plans-\(UUID().uuidString)")
        defer { try? FileManager.default.removeItem(at: dir) }
        let store = PlanStore(directory: dir)
        let plan = try #require(try makePlan().0)
        let url = try store.save(plan)
        #expect(try Data(contentsOf: url) == plan.canonicalData())
        #expect(try store.load("0f1e2d3c") == plan)
        #expect(throws: PlanError.self) { try store.load("../../etc/passwd") }
        #expect(throws: PlanError.self) { try store.load("0f1") }
        #expect(throws: PlanError.self) { try store.load("ffffffff") }
    }
}

@Suite("Approval")
struct ApprovalTests {
    struct Fixture {
        let key = P256.Signing.PrivateKey()
        let book = ApprovalBook(ttl: 300)
        let plan: Plan
        let data: Data
        let now: Int64

        init() throws {
            let now = Int64(Date().timeIntervalSince1970)
            self.now = now
            plan = try #require(try makePlan(now: Date(timeIntervalSince1970: TimeInterval(now))).0)
            data = try plan.canonicalData()
        }

        var publicKey: Data { key.publicKey.derRepresentation }

        /// Issues a nonce for `hash` (default: the plan's) and signs the payload, like `PlanApplier.apply`.
        func approve(hash: Data? = nil) throws -> (payload: Data, signature: Data) {
            let h = hash ?? FarrierCrypto.sha256(data)
            let grant = book.issue(planHash: h, now: now)
            let payload = ApprovalPayload.build(planHash: h, nonce: try #require(Data(hexString: grant.nonce)), expiresAt: grant.expiresAt)
            return (payload, try key.signature(for: payload).derRepresentation)
        }

        func verify(_ a: (payload: Data, signature: Data), planData: Data? = nil, publicKey: Data? = nil,
                    host h: String = host, at: Int64? = nil) -> Result<Plan, PlanError> {
            PlanApproval.verify(planData: planData ?? data, payload: a.payload, signature: a.signature,
                                publicKeyDER: publicKey ?? self.publicKey, book: book, host: h, now: at ?? now)
        }
    }

    func refusal(_ r: Result<Plan, PlanError>) -> String? {
        if case .failure(let e) = r { return e.description }
        return nil
    }

    @Test func payloadRoundTrip() throws {
        let hash = Data(repeating: 0xAA, count: 32), nonce = Data(repeating: 0x55, count: 32)
        let payload = ApprovalPayload.build(planHash: hash, nonce: nonce, expiresAt: 1_800_000_300)
        #expect(payload.count == "farrier-plan-approval-v1".utf8.count + 1 + 72)
        let parsed = try #require(ApprovalPayload.parse(payload))
        #expect(parsed == ApprovalPayload.Parsed(planHash: hash, nonce: nonce, expiresAt: 1_800_000_300))
        #expect(ApprovalPayload.parse(payload.dropLast()) == nil)
        #expect(ApprovalPayload.parse(Data("farrier-plan-approval-v2".utf8) + payload.dropFirst(24)) == nil)
        // A slice that doesn't start at index 0 parses the same.
        #expect(ApprovalPayload.parse((Data([0]) + payload).dropFirst()) == parsed)
    }

    @Test func validApprovalPassesOnce() throws {
        let f = try Fixture()
        let a = try f.approve()
        #expect(try f.verify(a).get() == f.plan)
        #expect(refusal(f.verify(a))?.contains("already used") == true)   // replay
    }

    @Test func anySubmissionConsumesTheNonce() throws {
        let f = try Fixture()
        let a = try f.approve()
        var bad = a.signature
        bad[bad.index(before: bad.endIndex)] ^= 0x01
        #expect(refusal(f.verify((a.payload, bad))) == "invalid approval signature")
        #expect(refusal(f.verify(a))?.contains("already used") == true)   // the good signature is now useless too
    }

    @Test func refusesWhatTheApprovalDoesNotCover() throws {
        let f = try Fixture()
        // Signed by another key.
        #expect(refusal(f.verify(try f.approve(), publicKey: P256.Signing.PrivateKey().publicKey.derRepresentation)) == "invalid approval signature")
        // No key enrolled.
        let a = try f.approve()
        #expect(refusal(PlanApproval.verify(planData: f.data, payload: a.payload, signature: a.signature, publicKeyDER: nil,
                                            book: f.book, host: host, now: f.now))?.contains("no approval key") == true)
        // A different plan than the approved hash.
        let other = try #require(try makePlan(now: Date(timeIntervalSince1970: TimeInterval(f.now + 1))).0)
        #expect(refusal(f.verify(try f.approve(), planData: try other.canonicalData())) == "the plan does not match the approved hash")
        // Another Mac.
        #expect(refusal(f.verify(try f.approve(), host: "SOMEONE-ELSE")) == "the plan was made for another Mac")
        // Garbage payload.
        #expect(refusal(f.verify((Data("nope".utf8), Data()))) == "malformed approval payload")
    }

    @Test func refusesAPayloadThatDiffersFromTheIssuedNonce() throws {
        let f = try Fixture()
        let grant = f.book.issue(planHash: FarrierCrypto.sha256(f.data), now: f.now)
        let nonce = try #require(Data(hexString: grant.nonce))
        // The client stretches the expiry: the helper compares it with what it issued.
        let stretched = ApprovalPayload.build(planHash: FarrierCrypto.sha256(f.data), nonce: nonce, expiresAt: grant.expiresAt + 3600)
        #expect(refusal(f.verify((stretched, try f.key.signature(for: stretched).derRepresentation))) == "approval does not match the nonce the helper issued")
    }

    @Test func expiryIsEnforced() throws {
        let f = try Fixture()
        #expect(refusal(f.verify(try f.approve(), at: f.now + 300)) == "approval expired")
        // The approval is fresh but the plan itself has expired: a new book with a long TTL to separate the two.
        let longBook = ApprovalBook(ttl: 7200)
        let h = FarrierCrypto.sha256(f.data)
        let grant = longBook.issue(planHash: h, now: f.now)
        let payload = ApprovalPayload.build(planHash: h, nonce: try #require(Data(hexString: grant.nonce)), expiresAt: grant.expiresAt)
        let r = PlanApproval.verify(planData: f.data, payload: payload, signature: try f.key.signature(for: payload).derRepresentation,
                                    publicKeyDER: f.publicKey, book: longBook, host: host, now: f.plan.expiresAt)
        #expect(refusal(r) == "the plan expired; make a new one")
    }

    @Test func refusesUnknownActionsAndTierDowngrades() throws {
        let f = try Fixture()
        func plan(_ action: String, _ tier: Tier) throws -> Data {
            let item = PlanItem(ruleID: "r", action: action, tier: tier, summary: "s", fact: "firewall.globalState", observed: .string("off"))
            return try Plan(id: "id", createdAt: f.now, expiresAt: f.now + 900, host: host, items: [item]).canonicalData()
        }
        let unknown = try plan("shell.run", .t4)
        #expect(refusal(f.verify(try f.approve(hash: FarrierCrypto.sha256(unknown)), planData: unknown)) == "unknown action `shell.run`")
        let downgraded = try plan("firewall.enable", .t2)
        #expect(refusal(f.verify(try f.approve(hash: FarrierCrypto.sha256(downgraded)), planData: downgraded))?.contains("is T4, but the plan says T2") == true)
    }
}

@Suite("Journal")
struct JournalTests {
    func temp() -> Journal {
        Journal(url: FileManager.default.temporaryDirectory.appendingPathComponent("farrier-journal-\(UUID().uuidString)/journal.jsonl"))
    }

    func record(_ n: Int) -> JournalRecord {
        JournalRecord(time: Int64(1_800_000_000 + n), actor: "cli", planID: "p\(n)", planHash: "h", outcome: "applied", detail: "n=\(n)")
    }

    @Test func chainVerifiesAndDetectsTampering() throws {
        let j = temp()
        defer { try? FileManager.default.removeItem(at: j.url.deletingLastPathComponent()) }
        #expect(j.verify().isEmpty)  // missing = empty and intact
        for n in 1...3 { try j.append(record(n)) }
        let entries = try j.entries()
        #expect(entries.count == 3)
        #expect(entries[0].prevHash == Journal.genesis)
        #expect(entries[1].prevHash == entries[0].hash)
        #expect(j.verify().isEmpty)

        let original = try String(contentsOf: j.url, encoding: .utf8)
        // Edit an entry.
        try original.replacingOccurrences(of: "n=2", with: "n=9").write(to: j.url, atomically: true, encoding: .utf8)
        #expect(j.verify() == ["line 2: hash mismatch (entry edited?)"])
        // Remove an entry.
        var lines = original.split(separator: "\n").map(String.init)
        lines.remove(at: 1)
        try (lines.joined(separator: "\n") + "\n").write(to: j.url, atomically: true, encoding: .utf8)
        #expect(j.verify() == ["line 2: does not follow the previous line (entries removed or reordered?)"])
    }
}
