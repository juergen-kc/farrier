import Foundation
import Security
import SystemConfiguration

/// Decides whether an XPC caller is in the session at the screen (finding F4 of the Secure Enclave spike).
///
/// Method under test: `SessionGetInfo` on the caller's audit session ID. Its attribute bits say whether the
/// session has graphics access and whether it is remote (SSH). Plus: the caller's euid must be the console user.
/// Whether `SessionGetInfo` works for another process's session, from root, is exactly what this spike checks.
enum SessionCheck {
    // Bit values from <Security/AuthSession.h>. Compared numerically, so it works however Swift imports the type.
    private static let isRoot: UInt32 = 0x0001
    private static let hasGraphicAccess: UInt32 = 0x0010
    private static let hasTTY: UInt32 = 0x0020
    private static let isRemote: UInt32 = 0x1000

    static func evaluate(asid: au_asid_t, euid: uid_t) -> [String: Any] {
        var sessionID = SecuritySessionId(0)
        var attrs = SessionAttributeBits()
        let st = SessionGetInfo(SecuritySessionId(bitPattern: asid), &sessionID, &attrs)
        let bits: UInt32 = withUnsafeBytes(of: attrs) { $0.load(as: UInt32.self) }

        var consoleUID: uid_t = 0
        let consoleUser = SCDynamicStoreCopyConsoleUser(nil, &consoleUID, nil) as String?

        let graphic = bits & hasGraphicAccess != 0
        let remote = bits & isRemote != 0
        let isConsoleUser = consoleUser != nil && consoleUser != "loginwindow" && euid == consoleUID
        let ok = st == errSecSuccess && graphic && !remote && isConsoleUser

        var reasons: [String] = []
        if st != errSecSuccess { reasons.append("SessionGetInfo failed (\(st))") }
        if !graphic { reasons.append("session has no graphics access") }
        if remote { reasons.append("session is remote") }
        if !isConsoleUser { reasons.append("caller euid \(euid) is not the console user (\(consoleUser ?? "none"), uid \(consoleUID))") }

        return [
            "callerAsid": Int(asid),
            "callerEuid": Int(euid),
            "sessionGetInfoStatus": Int(st),
            "sessionBits": String(format: "0x%04x", bits),
            "sessionHasGraphicAccess": graphic,
            "sessionIsRemote": remote,
            "sessionHasTTY": bits & hasTTY != 0,
            "sessionIsRoot": bits & isRoot != 0,
            "consoleUser": consoleUser ?? "(none)",
            "consoleUID": Int(consoleUID),
            "sessionOK": ok,
            "sessionReasons": reasons,
        ]
    }
}
