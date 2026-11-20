#if os(macOS)
import FarrierHelperKit
import Foundation
import Security
import SystemConfiguration

/// Is the XPC caller the user at the screen? Verified in the SMAppService/XPC spike (X11–X13):
/// the console session has graphics access and isn't remote (0x6030); SSH is 0x5020 and refused; `sudo` stays in
/// the console's audit session, so the console-UID check is what refuses it.
enum SessionCheck {
    private static let hasGraphicAccess: UInt32 = 0x0010
    private static let isRemote: UInt32 = 0x1000

    static func evaluate(asid: au_asid_t, euid: uid_t) -> SessionDecision {
        var sessionID = SecuritySessionId(0)
        var attrs = SessionAttributeBits()
        let st = SessionGetInfo(SecuritySessionId(bitPattern: asid), &sessionID, &attrs)
        let bits: UInt32 = withUnsafeBytes(of: attrs) { $0.load(as: UInt32.self) }

        var consoleUID: uid_t = 0
        let consoleUser = SCDynamicStoreCopyConsoleUser(nil, &consoleUID, nil) as String?

        var reasons: [String] = []
        if st != errSecSuccess { reasons.append("SessionGetInfo failed (\(st))") }
        if bits & hasGraphicAccess == 0 { reasons.append("session has no graphics access") }
        if bits & isRemote != 0 { reasons.append("session is remote") }
        if consoleUser == nil || consoleUser == "loginwindow" || euid != consoleUID {
            reasons.append("caller uid \(euid) is not the console user (\(consoleUser ?? "none"))")
        }
        return SessionDecision(accepted: reasons.isEmpty, reasons: reasons, callerEUID: Int(euid),
                               consoleUser: consoleUser ?? "(none)", sessionBits: String(format: "0x%04x", bits))
    }
}
#endif
