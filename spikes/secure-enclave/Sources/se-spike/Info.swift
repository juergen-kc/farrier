import CryptoKit
import Foundation
import LocalAuthentication
import Security

/// Environment facts that decide whether the results transfer to the real product:
/// how this binary is signed, who runs it, and in what session.
enum Info {
    static func collect() -> [String: Any] {
        var d: [String: Any] = [:]
        d["os"] = ProcessInfo.processInfo.operatingSystemVersionString
        d["hwModel"] = sysctlString("hw.model") ?? "?"
        d["uid"] = Int(getuid())
        d["euid"] = Int(geteuid())
        d["pid"] = Int(getpid())
        d["parent"] = parentCommand() ?? "?"
        d["sshSession"] = ProcessInfo.processInfo.environment["SSH_CONNECTION"] != nil
        d["termProgram"] = ProcessInfo.processInfo.environment["TERM_PROGRAM"] ?? ""
        d["executable"] = Bundle.main.executablePath ?? CommandLine.arguments[0]
        d["bundleID"] = Bundle.main.bundleIdentifier ?? ""
        d["secureEnclaveAvailable"] = SecureEnclave.isAvailable

        let ctx = LAContext()
        var laErr: NSError?
        d["canBiometrics"] = ctx.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: &laErr)
        if let laErr { d["biometricsError"] = "\(laErr.domain) \(laErr.code): \(laErr.localizedDescription)" }
        var ownerErr: NSError?
        d["canDeviceOwnerAuth"] = ctx.canEvaluatePolicy(.deviceOwnerAuthentication, error: &ownerErr)
        switch ctx.biometryType {
        case .touchID: d["biometryType"] = "touchID"
        case .none: d["biometryType"] = "none"
        default: d["biometryType"] = "other(\(ctx.biometryType.rawValue))"
        }

        d.merge(signing(), uniquingKeysWith: { a, _ in a })
        return d
    }

    /// Signing information of the running binary (Team ID, flags, entitlements).
    static func signing() -> [String: Any] {
        var code: SecCode?
        guard SecCodeCopySelf([], &code) == errSecSuccess, let code else {
            return ["signing": "SecCodeCopySelf failed"]
        }
        var staticCode: SecStaticCode?
        guard SecCodeCopyStaticCode(code, [], &staticCode) == errSecSuccess, let staticCode else {
            return ["signing": "SecCodeCopyStaticCode failed"]
        }
        var cfInfo: CFDictionary?
        let st = SecCodeCopySigningInformation(staticCode, SecCSFlags(rawValue: kSecCSSigningInformation), &cfInfo)
        guard st == errSecSuccess, let info = cfInfo as? [String: Any] else {
            return ["signing": "SecCodeCopySigningInformation failed (\(st))"]
        }
        var d: [String: Any] = [:]
        d["signingIdentifier"] = info[kSecCodeInfoIdentifier as String] as? String ?? "(none)"
        d["teamID"] = info[kSecCodeInfoTeamIdentifier as String] as? String ?? "(none)"
        let flags = (info[kSecCodeInfoFlags as String] as? NSNumber)?.uint32Value ?? 0
        d["csFlags"] = String(format: "0x%08x", flags)
        d["adhoc"] = flags & 0x0002 != 0           // kSecCodeSignatureAdhoc
        d["hardenedRuntime"] = flags & 0x1_0000 != 0  // kSecCodeSignatureRuntime
        d["linkerSigned"] = flags & 0x2_0000 != 0     // linker-signed (ad hoc by ld)
        if let ents = info[kSecCodeInfoEntitlementsDict as String] as? [String: Any] {
            d["entitlements"] = ents.keys.sorted()
        } else {
            d["entitlements"] = [String]()
        }
        if let certs = info[kSecCodeInfoCertificates as String] as? [SecCertificate], let leaf = certs.first {
            d["leafCert"] = (SecCertificateCopySubjectSummary(leaf) as String?) ?? "?"
        }
        return d
    }

    private static func sysctlString(_ name: String) -> String? {
        var size = 0
        guard sysctlbyname(name, nil, &size, nil, 0) == 0, size > 0 else { return nil }
        var buf = [CChar](repeating: 0, count: size)
        guard sysctlbyname(name, &buf, &size, nil, 0) == 0 else { return nil }
        return String(cString: buf)
    }

    /// Name of the parent process. This matters because an MCP server's parent is the AI client.
    private static func parentCommand() -> String? {
        let p = Process()
        p.executableURL = URL(fileURLWithPath: "/bin/ps")
        p.arguments = ["-o", "comm=", "-p", String(getppid())]
        let pipe = Pipe()
        p.standardOutput = pipe
        p.standardError = FileHandle.nullDevice
        do { try p.run() } catch { return nil }
        p.waitUntilExit()
        let out = pipe.fileHandleForReading.readDataToEndOfFile()
        return String(decoding: out, as: UTF8.self).trimmingCharacters(in: .whitespacesAndNewlines)
    }
}
