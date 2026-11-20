import Foundation

// se-spike: answers one question for Farrier.
//   Can a Developer ID–signed binary (no provisioning profile) create a Secure Enclave key
//   that needs Touch ID or a password for each use, and sign plan approvals that a root helper verifies?
//
// See CHECKLIST.md for the test procedure.

let usage = """
usage: se-spike <command> [options]

  info                                   environment, signing and biometry facts

  a-create  --key PATH [--policy P]      Approach A: CryptoKit key, blob stored in a file
  a-sign    --key PATH [sign options]

  b-create  --label L [--policy P] [--access-group TEAMID.dev.farrier.spike]
                                         Approach B: permanent key in the data-protection keychain
  b-sign    --label L [sign options]
  b-delete  --label L

  verify    --pub PATH --approval PATH [--tamper]
                                         the helper's check (run it with sudo too)

  sign options:
    --out PATH          approval record to write (default: ./approval.json)
    --plan-hash HEX     32-byte hex (default: random, simulating a plan)
    --nonce HEX         32-byte hex (default: random, simulating the helper's nonce)
    --ttl SECONDS       approval lifetime (default: 300)
    --reason TEXT       text shown in the Touch ID prompt

  policies: \(Policy.allCases.map(\.rawValue).joined(separator: " | "))  (default: userPresence)
"""

var args = Array(CommandLine.arguments.dropFirst())
guard let command = args.first else {
    print(usage)
    exit(2)
}
args.removeFirst()

func opt(_ name: String) -> String? {
    guard let i = args.firstIndex(of: "--\(name)"), i + 1 < args.count else { return nil }
    return args[i + 1]
}

func flag(_ name: String) -> Bool { args.contains("--\(name)") }

func required(_ name: String) throws -> String {
    guard let v = opt(name) else { throw SpikeError("missing --\(name)") }
    return v
}

func policy() throws -> Policy {
    let raw = opt("policy") ?? Policy.userPresence.rawValue
    guard let p = Policy(rawValue: raw) else { throw SpikeError("unknown policy \(raw)") }
    return p
}

func hex32(_ name: String) throws -> Data {
    guard let raw = opt(name) else { return Data.random(32) }
    guard let d = Data(hex: raw), d.count == 32 else { throw SpikeError("--\(name) must be 64 hex chars") }
    return d
}

/// Shared signing flow for both approaches: build the payload, sign it, write the record.
func runSign(approach: String, _ signer: (Data, String) throws -> (signature: Data, publicKey: Data, seconds: Double)) throws {
    let ttl = Int64(opt("ttl") ?? "300") ?? 300
    let payload = try ApprovalPayload(
        planHash: try hex32("plan-hash"),
        nonce: try hex32("nonce"),
        expiresAt: Int64(Date().timeIntervalSince1970) + ttl
    )
    let reason = opt("reason") ?? "approve a Farrier plan (spike test, 3 items, 1.2 GB)"
    let result = try signer(payload.bytes, reason)
    let record = ApprovalRecord(
        approach: approach,
        payloadHex: payload.bytes.hex,
        signatureHex: result.signature.hex,
        publicKeyFingerprint: sha256Hex(result.publicKey)
    )
    let outURL = URL(fileURLWithPath: opt("out") ?? "approval.json")
    let enc = JSONEncoder()
    enc.outputFormatting = [.prettyPrinted, .sortedKeys]
    try writeFile(try enc.encode(record), to: outURL, mode: 0o644)
    // The public key is written next to the record, so `verify` works the same way for both approaches.
    let pubURL = outURL.appendingPathExtension("pub")
    try writeFile(result.publicKey, to: pubURL, mode: 0o644)
    Out.emit("\(approach.lowercased())-sign", [
        "ok": true,
        "approval": outURL.path,
        "publicKey": pubURL.path,
        "planHash": payload.planHash.hex,
        "secondsInSign": (result.seconds * 100).rounded() / 100,  // ~0 means NO prompt was shown
        "publicKeyFingerprint": record.publicKeyFingerprint,
    ])
}

do {
    switch command {
    case "info":
        var d = Info.collect()
        d["ok"] = true
        Out.emit("info", d)

    case "a-create":
        Out.emit("a-create", try ApproachA.create(policy: try policy(), keyURL: URL(fileURLWithPath: try required("key"))))

    case "a-sign":
        let keyURL = URL(fileURLWithPath: try required("key"))
        try runSign(approach: "A") { payload, reason in try ApproachA.sign(keyURL: keyURL, payload: payload, reason: reason) }

    case "b-create":
        Out.emit("b-create", try ApproachB.create(policy: try policy(), label: try required("label"), accessGroup: opt("access-group")))

    case "b-sign":
        let label = try required("label")
        try runSign(approach: "B") { payload, reason in try ApproachB.sign(label: label, payload: payload, reason: reason) }

    case "b-delete":
        Out.emit("b-delete", try ApproachB.delete(label: try required("label")))

    case "verify":
        let pub = try Data(contentsOf: URL(fileURLWithPath: try required("pub")))
        let record = try JSONDecoder().decode(ApprovalRecord.self, from: Data(contentsOf: URL(fileURLWithPath: try required("approval"))))
        var d = try Verifier.verify(publicKeyDER: pub, record: record, tamper: flag("tamper"))
        d["euid"] = Int(geteuid())
        Out.emit("verify", d)
        if d["ok"] as? Bool != true { exit(1) }

    default:
        print(usage)
        exit(2)
    }
} catch {
    Out.emit(command, describe(error))
    exit(1)
}
