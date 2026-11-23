import Foundation
import Testing
@testable import FarrierCore

@Suite("Full Disk Access and privacy grants")
struct FullDiskAccessTests {
    @Test func probeReadsTheErrno() {
        #expect(FullDiskAccess.probe { _ in 0 } == .granted)
        #expect(FullDiskAccess.probe { _ in EPERM } == .denied)
        #expect(FullDiskAccess.probe { _ in EACCES } == .denied)
        // A missing probe file moves on to the next one...
        #expect(FullDiskAccess.probe { $0 == FullDiskAccess.probePaths[0] ? ENOENT : 0 } == .granted)
        #expect(FullDiskAccess.probe { $0 == FullDiskAccess.probePaths[0] ? ENOENT : EPERM } == .denied)
        // ...and with none there, or another error, the answer is "can't tell", never "denied" or "granted".
        guard case .undetermined = FullDiskAccess.probe(open: { _ in ENOENT }) else { Issue.record("expected undetermined"); return }
        guard case .undetermined = FullDiskAccess.probe(open: { _ in EIO }) else { Issue.record("expected undetermined"); return }
    }

    @Test func grantsListOnlyAllowedRowsOfKnownServices() {
        let rows: [PrivacyGrants.Row] = [
            .init(service: "kTCCServiceSystemPolicyAllFiles", client: "com.example.backup", clientType: 0, authValue: 2),
            .init(service: "kTCCServiceSystemPolicyAllFiles", client: "/usr/local/bin/agent", clientType: 1, authValue: 2),
            .init(service: "kTCCServiceAccessibility", client: "com.example.denied", clientType: 0, authValue: 0),
            .init(service: "kTCCServiceAccessibility", client: "com.example.limited", clientType: 0, authValue: 3),
            .init(service: "kTCCServiceScreenCapture", client: "com.example.zoom", clientType: 0, authValue: 2),
            .init(service: "kTCCServiceScreenCapture", client: "com.example.zoom", clientType: 0, authValue: 2),  // duplicate
            .init(service: "kTCCServiceCamera", client: "com.example.cam", clientType: 0, authValue: 2),          // not reported
        ]
        func grant(_ service: String, _ client: String, _ type: String) -> FactValue {
            .object(["service": .string(service), "client": .string(client), "clientType": .string(type)])
        }
        #expect(PrivacyGrants.fact(rows) == .array([
            grant("fullDiskAccess", "/usr/local/bin/agent", "path"),
            grant("fullDiskAccess", "com.example.backup", "bundle"),
            grant("screenRecording", "com.example.zoom", "bundle"),
        ]))
        #expect(PrivacyGrants.fact([]) == .array([]))
    }
}
