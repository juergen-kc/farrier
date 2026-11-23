import Foundation
import Testing
@testable import FarrierCore
@testable import FarrierHelperKit

@Suite("Helper kit")
struct HelperKitTests {
    @Test func codeRequirementPinsIdentifierAndTeam() {
        let r = codeRequirement(identifier: HelperConstants.helperIdentifier, teamID: "E89Q3796E9")
        #expect(r == #"anchor apple generic and identifier "dev.farrier.helper" and certificate leaf[subject.OU] = "E89Q3796E9""#)
    }

    @Test func machServiceMatchesTheLaunchDaemonPlist() throws {
        // The helper listens on this name and the client connects to it; the plist must declare the same.
        let plist = try String(contentsOf: repoRoot.appendingPathComponent("Packaging/dev.farrier.helper.plist"), encoding: .utf8)
        #expect(plist.contains("<string>\(HelperConstants.machService)</string>"))
        #expect(plist.contains("<key>\(HelperConstants.machService)</key>"))
        #expect(plist.contains("<string>\(HelperConstants.appIdentifier)</string>"))
        #expect(plist.contains("Contents/MacOS/farrier-helper"))
    }

    @Test func handshakeCoversTheProtocol() {
        // A protocol change must restart a running helper even when the version string doesn't change.
        #expect(HelperConstants.handshakeVersion == "\(FarrierVersion.string)+p\(HelperConstants.protocolVersion)")
        #expect(HelperConstants.handshakeVersion != FarrierVersion.string)
    }

    @Test func privilegedFactsAreAnAllowlist() {
        #expect(PrivilegedFact(rawValue: "mdm.payloadTypes") == .mdmPayloadTypes)
        #expect(PrivilegedFact(rawValue: "network.listeningTCP") == .listeningTCP)
        #expect(PrivilegedFact(rawValue: "helper.fullDiskAccess") == .fullDiskAccess)
        #expect(PrivilegedFact(rawValue: "mdm.profiles") == .mdmProfiles)
        #expect(PrivilegedFact(rawValue: "tcc.grants") == .tccGrants)
        #expect(PrivilegedFact(rawValue: "/etc/master.passwd") == nil)
        #expect(PrivilegedFact(rawValue: "../mdm.payloadTypes") == nil)
    }

    @Test func wireRoundTrip() throws {
        let reply = PrivilegedReply(fact: "mdm.payloadTypes", value: .array([.string("com.apple.security.firewall")]), error: nil)
        let back = try #require(HelperWire.decode(PrivilegedReply.self, HelperWire.encode(reply)))
        #expect(back.fact == reply.fact)
        #expect(back.value == reply.value)
        #expect(HelperWire.decode(HelperInfo.self, Data("not json".utf8)) == nil)
    }

    @Test func onlyPrivacyDataNeedsFullDiskAccess() {
        #expect(PrivilegedFact.allCases.filter(\.needsFullDiskAccess) == [.tccGrants])
    }

    @Test func olderRepliesWithoutTheFullDiskAccessFieldStillDecode() throws {
        let old = Data(#"{"fact":"tcc.grants","error":"boom"}"#.utf8)
        let reply = try #require(HelperWire.decode(PrivilegedReply.self, old))
        #expect(reply.needsFullDiskAccess == nil)
        let missing = PrivilegedReply(fact: "tcc.grants", value: nil, error: FullDiskAccess.missingHint, needsFullDiskAccess: true)
        #expect(HelperWire.decode(PrivilegedReply.self, HelperWire.encode(missing))?.needsFullDiskAccess == true)
    }
}
