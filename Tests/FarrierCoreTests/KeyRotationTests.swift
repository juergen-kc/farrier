import Foundation
import Testing
@testable import FarrierHelperKit

@Suite("Approval key rotation")
struct KeyRotationTests {
    let day: Int64 = 86_400
    let enrolled: Int64 = 1_800_000_000

    @Test func ageBands() {
        func age(_ days: Double) -> ApprovalKeyPolicy.Age {
            ApprovalKeyPolicy.age(enrolledAt: enrolled, now: enrolled + Int64(days * Double(day)))
        }
        #expect(age(0) == .fresh(days: 0))
        #expect(age(24.9) == .fresh(days: 24))
        #expect(age(25) == .dueSoon(daysLeft: 5) || age(25) == .fresh(days: 25))   // the edge of the warning window
        #expect(age(26) == .dueSoon(daysLeft: 4))
        #expect(age(29.5) == .dueSoon(daysLeft: 0))
        #expect(age(30) == .expired(days: 30))
        #expect(age(45) == .expired(days: 45))
        // A clock set back before enrollment never makes a key look older.
        #expect(ApprovalKeyPolicy.age(enrolledAt: enrolled, now: enrolled - 10 * day) == .fresh(days: 0))
    }

    @Test func noticesSayWhatToDo() throws {
        #expect(ApprovalKeyPolicy.notice(enrolledAt: enrolled, now: enrolled + 3 * day) == nil)
        #expect(ApprovalKeyPolicy.notice(enrolledAt: nil, now: enrolled) == nil)
        let soon = try #require(ApprovalKeyPolicy.notice(enrolledAt: enrolled, now: enrolled + 27 * day))
        #expect(soon.contains("within 3 day(s)") && soon.contains("farrier setup"))
        let expired = try #require(ApprovalKeyPolicy.notice(enrolledAt: enrolled, now: enrolled + 31 * day))
        #expect(expired.contains("31 days ago") && expired.contains("farrier setup"))
        #expect(expired == ApprovalKeyPolicy.expiredMessage(days: 31))
    }

    @Test func statusCarriesTheEnrollmentTimeAndOlderRepliesStillDecode() throws {
        let s = ApprovalKeyStatus(enrolled: true, fingerprint: "ab", error: nil, enrolledAt: enrolled)
        #expect(HelperWire.decode(ApprovalKeyStatus.self, HelperWire.encode(s))?.enrolledAt == enrolled)
        let old = Data(#"{"enrolled":true,"fingerprint":"ab"}"#.utf8)
        #expect(try #require(HelperWire.decode(ApprovalKeyStatus.self, old)).enrolledAt == nil)
    }
}
