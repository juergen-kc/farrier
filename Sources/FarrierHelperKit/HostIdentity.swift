import Foundation
#if os(macOS)
import IOKit
#endif

/// The Mac's hardware UUID (`IOPlatformUUID`). Plans record it, and the helper refuses plans made elsewhere.
public enum HostIdentity {
    public static func hardwareUUID() -> String? {
        #if os(macOS)
        let service = IOServiceGetMatchingService(kIOMainPortDefault, IOServiceMatching("IOPlatformExpertDevice"))
        guard service != 0 else { return nil }
        defer { IOObjectRelease(service) }
        let value = IORegistryEntryCreateCFProperty(service, kIOPlatformUUIDKey as CFString, kCFAllocatorDefault, 0)
        return (value?.takeRetainedValue() as? String)?.uppercased()
        #else
        return nil
        #endif
    }
}
