import Foundation
import Security
import SpikeShared

/// Admin authorization for enrolling (and resetting) the approval key.
///
/// The helper defines its own right with the rule "authenticate-admin" in the authorization database (root can
/// do that). The client sends an AuthorizationExternalForm, and the helper asks for the right with interaction
/// allowed. The admin dialog should appear in the CLIENT's session (that's one of the things to verify).
enum Authz {
    /// Creates the right if it doesn't exist. Returns a short status for the log.
    static func ensureRight() -> String {
        if AuthorizationRightGet(Spike.enrollRight, nil) == errAuthorizationSuccess { return "\(Spike.enrollRight) exists" }
        var ref: AuthorizationRef?
        guard AuthorizationCreate(nil, nil, [], &ref) == errAuthorizationSuccess, let ref else { return "AuthorizationCreate failed" }
        defer { AuthorizationFree(ref, []) }
        let st = AuthorizationRightSet(ref, Spike.enrollRight, "authenticate-admin" as CFString,
                                       "enroll a Farrier approval key" as CFString, nil, nil)
        return st == errAuthorizationSuccess ? "\(Spike.enrollRight) created (authenticate-admin)" : "AuthorizationRightSet failed (\(st))"
    }

    /// Checks the client's authorization for the enroll right. May show the admin dialog.
    static func check(_ external: Data) -> OSStatus {
        guard external.count == MemoryLayout<AuthorizationExternalForm>.size else { return errAuthorizationInvalidRef }
        var form = AuthorizationExternalForm()
        _ = withUnsafeMutableBytes(of: &form) { external.copyBytes(to: $0) }
        var ref: AuthorizationRef?
        let st = AuthorizationCreateFromExternalForm(&form, &ref)
        guard st == errAuthorizationSuccess, let ref else { return st }
        defer { AuthorizationFree(ref, []) }
        return copyRight(ref, Spike.enrollRight, [.extendRights, .interactionAllowed])
    }
}
