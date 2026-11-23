import Foundation

/// Privacy (TCC) grants with the most reach, from the system `TCC.db`, which only a process with Full Disk Access
/// can read. The helper reads the rows (`service`, `client`, `client_type`, `auth_value`); this turns them into the
/// `tcc.grants` fact, so the mapping is tested on every platform.
public enum PrivacyGrants {
    /// The services reported, by their TCC name, with the name the fact uses. Grants for other services (camera,
    /// microphone, contacts, …) live in each user's own TCC.db and aren't part of this fact.
    public static let services: [String: String] = [
        "kTCCServiceSystemPolicyAllFiles": "fullDiskAccess",
        "kTCCServiceAccessibility": "accessibility",
        "kTCCServiceScreenCapture": "screenRecording",
        "kTCCServiceListenEvent": "inputMonitoring",
        "kTCCServicePostEvent": "postEvents",
        "kTCCServiceEndpointSecurityClient": "endpointSecurity",
        "kTCCServiceDeveloperTool": "developerTools",
    ]

    public struct Row: Sendable, Equatable {
        public let service: String
        public let client: String
        public let clientType: Int
        public let authValue: Int

        public init(service: String, client: String, clientType: Int, authValue: Int) {
            self.service = service
            self.client = client
            self.clientType = clientType
            self.authValue = authValue
        }
    }

    /// `auth_value` 2 means allowed (0 denied, 1 unknown, 3 limited). Only allowed grants are listed, sorted by
    /// service and then client. `client_type` 0 is a bundle identifier, 1 an absolute path.
    public static func fact(_ rows: [Row]) -> FactValue {
        let items = rows
            .filter { $0.authValue == 2 && services[$0.service] != nil }
            .map { row -> (String, String, FactValue) in
                let service = services[row.service]!
                let kind = row.clientType == 1 ? "path" : "bundle"
                return (service, row.client, .object(["service": .string(service), "client": .string(row.client),
                                                      "clientType": .string(kind)]))
            }
            .sorted { ($0.0, $0.1) < ($1.0, $1.1) }
        var seen = Set<String>()
        return .array(items.filter { seen.insert("\($0.0)\u{0}\($0.1)").inserted }.map(\.2))
    }
}

/// Full Disk Access for Farrier.app, as the helper sees it: it opens a file only Full Disk Access allows (without
/// reading it). Granted to the app, the access covers the helper only, never the terminal or AI client that runs
/// `farrier` (docs/ARCHITECTURE.md).
public enum FullDiskAccess {
    /// Files macOS protects with Full Disk Access even from root, tried in order; a missing one is skipped.
    public static let probePaths = [
        "/Library/Application Support/com.apple.TCC/TCC.db",
        "/Library/Preferences/com.apple.TimeMachine.plist",
    ]

    public enum ProbeResult: Equatable, Sendable {
        case granted
        case denied
        case undetermined(String)
    }

    /// `open` is the probe: it returns 0 (a descriptor) or an errno. EPERM/EACCES means TCC refused.
    public static func probe(open: (String) -> Int32) -> ProbeResult {
        var missing: [String] = []
        for path in probePaths {
            let result = open(path)
            if result == 0 { return .granted }
            switch result {
            case EPERM, EACCES: return .denied
            case ENOENT, ENOTDIR: missing.append(path)
            default: return .undetermined("opening \(path) failed with errno \(result)")
            }
        }
        return .undetermined("none of the probe files exist: \(missing.joined(separator: ", "))")
    }

    /// Shown wherever a fact is missing for lack of the grant.
    public static let missingHint = "Farrier.app doesn't have Full Disk Access; run `farrier helper full-disk-access`"

    /// System Settings → Privacy & Security → Full Disk Access.
    public static let settingsURL = "x-apple.systempreferences:com.apple.preference.security?Privacy_AllFiles"
}
