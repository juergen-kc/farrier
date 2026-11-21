#if os(macOS)
import FarrierHelperKit
import Foundation
import Security

/// Admin authorization for enrolling or revoking the approval key (verified in the SMAppService/XPC spike, X16–X19).
///
/// The helper defines its own right with the rule `authenticate-admin`. The client sends an
/// AuthorizationExternalForm, and the helper asks for the right with interaction allowed: the admin dialog appears
/// in the client's session, credited to Farrier.app, every time.
enum Authz {
    /// Creates the right if it doesn't exist yet. Returns a line for the log.
    static func ensureRight() -> String {
        let right = HelperConstants.enrollRight
        if AuthorizationRightGet(right, nil) == errAuthorizationSuccess { return "\(right) exists" }
        var ref: AuthorizationRef?
        guard AuthorizationCreate(nil, nil, [], &ref) == errAuthorizationSuccess, let ref else { return "AuthorizationCreate failed" }
        defer { AuthorizationFree(ref, []) }
        let st = AuthorizationRightSet(ref, right, "authenticate-admin" as CFString,
                                       "enroll a Farrier approval key" as CFString, nil, nil)
        return st == errAuthorizationSuccess ? "\(right) created (authenticate-admin)" : "AuthorizationRightSet failed (\(st))"
    }

    /// Checks the client's authorization for the right. Shows the admin dialog. `errAuthorizationSuccess` or why not.
    static func check(_ external: Data) -> OSStatus {
        guard external.count == MemoryLayout<AuthorizationExternalForm>.size else { return errAuthorizationInvalidRef }
        var form = AuthorizationExternalForm()
        _ = withUnsafeMutableBytes(of: &form) { external.copyBytes(to: $0) }
        var ref: AuthorizationRef?
        let st = AuthorizationCreateFromExternalForm(&form, &ref)
        guard st == errAuthorizationSuccess, let ref else { return st }
        defer { AuthorizationFree(ref, []) }
        return HelperConstants.enrollRight.withCString { name in
            var item = AuthorizationItem(name: name, valueLength: 0, value: nil, flags: 0)
            return withUnsafeMutablePointer(to: &item) { itemPtr in
                var rights = AuthorizationRights(count: 1, items: itemPtr)
                return AuthorizationCopyRights(ref, &rights, nil, [.extendRights, .interactionAllowed], nil)
            }
        }
    }

    static func describe(_ status: OSStatus) -> String {
        switch status {
        case errAuthorizationCanceled: return "admin authorization was cancelled"
        case errAuthorizationDenied: return "admin authorization was denied"
        default: return "admin authorization failed (\(status))"
        }
    }
}
#endif
