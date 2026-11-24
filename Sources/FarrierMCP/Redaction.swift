import FarrierCore
import FarrierHelperKit
import Foundation

/// The redactor for this Mac, shared by the CLI's `--redact` and `farrier mcp --redact`: names, hosts and home
/// folders (`Redactor.live`), plus the hardware UUID and, when the helper can tell, the MDM server.
public enum RedactionSetup {
    public static func forThisMac() -> Redactor {
        var extra: [Redactor.Secret] = []
        if let uuid = HostIdentity.hardwareUUID() { extra.append(.init(uuid, "<host-id>")) }
        #if os(macOS)
        if let reply = try? HelperClient.readPrivileged(.mdmProfiles), let profiles = reply.value?.array {
            for server in profiles.compactMap({ $0.object?["mdmServer"]?.string }) { extra.append(.init(server, "<mdm-server>")) }
        }
        #endif
        return Redactor.live(extra: extra)
    }
}
