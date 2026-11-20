import CryptoKit
import Foundation
import Security

// MARK: - Output

/// Every result is printed as one JSON line, so test runs can be pasted straight into RESULTS.md.
enum Out {
    static func emit(_ step: String, _ fields: [String: Any]) {
        var obj = fields
        obj["step"] = step
        guard let data = try? JSONSerialization.data(withJSONObject: obj, options: [.sortedKeys]) else {
            print("{\"step\":\"\(step)\",\"error\":\"unserializable output\"}")
            return
        }
        print(String(decoding: data, as: UTF8.self))
    }
}

// MARK: - Errors

struct SpikeError: Error, CustomStringConvertible {
    let description: String
    init(_ description: String) { self.description = description }
}

struct OSStatusError: Error, CustomStringConvertible {
    let status: OSStatus
    let context: String
    var description: String {
        let msg = (SecCopyErrorMessageString(status, nil) as String?) ?? "unknown"
        return "\(context): OSStatus \(status) (\(msg))"
    }
}

func describe(_ error: Error) -> [String: Any] {
    var d: [String: Any] = ["ok": false, "error": String(describing: error)]
    if let os = error as? OSStatusError {
        d["osstatus"] = Int(os.status)
    } else if !(error is SpikeError) {
        let ns = error as NSError
        d["domain"] = ns.domain
        d["code"] = ns.code
    }
    return d
}

/// Unwraps a CFError from a Security API out-parameter.
func cfError(_ err: Unmanaged<CFError>?, _ context: String) -> Error {
    if let e = err?.takeRetainedValue() { return e as Error }
    return SpikeError("\(context): failed without an error")
}

// MARK: - Hex and hashing

extension Data {
    var hex: String { map { String(format: "%02x", $0) }.joined() }

    init?(hex: String) {
        let chars = Array(hex.utf8)
        guard chars.count % 2 == 0 else { return nil }
        var bytes = [UInt8]()
        bytes.reserveCapacity(chars.count / 2)
        var i = 0
        while i < chars.count {
            guard let b = UInt8(String(decoding: chars[i..<(i + 2)], as: UTF8.self), radix: 16) else { return nil }
            bytes.append(b)
            i += 2
        }
        self.init(bytes)
    }

    static func random(_ count: Int) -> Data {
        var bytes = [UInt8](repeating: 0, count: count)
        let st = SecRandomCopyBytes(kSecRandomDefault, count, &bytes)
        precondition(st == errSecSuccess, "SecRandomCopyBytes failed")
        return Data(bytes)
    }
}

func sha256Hex(_ data: Data) -> String {
    SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined()
}

// MARK: - Files

func writeFile(_ data: Data, to url: URL, mode: Int16) throws {
    try? FileManager.default.removeItem(at: url)
    guard FileManager.default.createFile(atPath: url.path, contents: data,
                                         attributes: [.posixPermissions: NSNumber(value: mode)]) else {
        throw SpikeError("could not write \(url.path)")
    }
}

// MARK: - Access control

/// Access-control policies to compare. `userPresence` is the candidate for Farrier:
/// Touch ID, with the login password as a fallback (needed on Macs without Touch ID).
enum Policy: String, CaseIterable {
    case userPresence, biometryAny, biometryCurrentSet, devicePasscode, none

    var flags: SecAccessControlCreateFlags {
        switch self {
        case .userPresence: return [.privateKeyUsage, .userPresence]
        case .biometryAny: return [.privateKeyUsage, .biometryAny]
        case .biometryCurrentSet: return [.privateKeyUsage, .biometryCurrentSet]
        case .devicePasscode: return [.privateKeyUsage, .devicePasscode]
        case .none: return [.privateKeyUsage]  // control case: no prompt expected
        }
    }

    func accessControl() throws -> SecAccessControl {
        var err: Unmanaged<CFError>?
        guard let ac = SecAccessControlCreateWithFlags(
            nil, kSecAttrAccessibleWhenUnlockedThisDeviceOnly, flags, &err
        ) else { throw cfError(err, "SecAccessControlCreateWithFlags") }
        return ac
    }
}
