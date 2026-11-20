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

    @Test func privilegedFactsAreAnAllowlist() {
        #expect(PrivilegedFact(rawValue: "mdm.payloadTypes") == .mdmPayloadTypes)
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
}
