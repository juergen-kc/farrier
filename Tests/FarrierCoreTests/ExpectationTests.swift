import Foundation
import Testing
@testable import FarrierCore

@Suite("Expectation")
struct ExpectationTests {
    // Qualified: Swift Testing also has a type named `Expectation`.
    func expect(_ yaml: String) throws -> FarrierCore.Expectation {
        try FarrierCore.Expectation.parse(FactValue.parseYAML(yaml))
    }

    @Test func equalsTreatsIntAndDoubleAlike() throws {
        let e = try expect("{ equals: 1 }")
        #expect(e.evaluate(.int(1)) == .pass)
        #expect(e.evaluate(.double(1.0)) == .pass)
        if case .fail = e.evaluate(.int(2)) {} else { Issue.record("2 should fail") }
    }

    @Test func quotedStringsStayStrings() throws {
        // YAML 1.1: unquoted On would be a boolean. Quoted, it must stay a string.
        let e = try expect(#"{ equals: "On" }"#)
        #expect(e.evaluate(.string("On")) == .pass)
        if case .fail = e.evaluate(.bool(true)) {} else { Issue.record("true must not equal \"On\"") }
    }

    @Test func oneOf() throws {
        let e = try expect(#"{ in: ["on", blockAll] }"#)
        #expect(e.evaluate(.string("blockAll")) == .pass)
        if case .fail = e.evaluate(.string("off")) {} else { Issue.record("off should fail") }
    }

    @Test func matchesIsAWholeStringMatch() throws {
        let e = try expect(#"{ matches: "1[45]\\..*" }"#)
        #expect(e.evaluate(.string("15.2")) == .pass)
        if case .fail = e.evaluate(.string("115.2")) {} else { Issue.record("must match the whole string") }
    }

    @Test func numbers() throws {
        #expect(try expect("{ lt: 10 }").evaluate(.int(3)) == .pass)
        #expect(try expect("{ gt: 2.5 }").evaluate(.double(3)) == .pass)
        if case .fail = try expect("{ lt: 10 }").evaluate(.string("3")) {} else { Issue.record("a string is not a number") }
    }

    @Test func existsHandlesMissingAndNull() throws {
        #expect(try expect("{ exists: true }").evaluate(.string("x")) == .pass)
        #expect(try expect("{ exists: false }").evaluate(nil) == .pass)
        #expect(try expect("{ exists: false }").evaluate(.null) == .pass)
        if case .fail = try expect("{ exists: true }").evaluate(nil) {} else { Issue.record("missing should fail") }
    }

    @Test func pathAndAll() throws {
        let e = try expect("""
            all:
              - { path: CriticalUpdateInstall, equals: true }
              - { path: ConfigDataInstall, equals: true }
            """)
        let good = FactValue.object(["CriticalUpdateInstall": .bool(true), "ConfigDataInstall": .bool(true)])
        let bad = FactValue.object(["CriticalUpdateInstall": .bool(true)])
        #expect(e.evaluate(good) == .pass)
        guard case .fail(let reason) = e.evaluate(bad) else { Issue.record("missing key should fail"); return }
        #expect(reason.contains("ConfigDataInstall"))
    }

    @Test func eachChecksEveryItemAndPassesOnEmpty() throws {
        let e = try expect("{ each: { path: signature.valid, equals: true } }")
        let item = { (valid: Bool) in FactValue.object(["signature": .object(["valid": .bool(valid)])]) }
        #expect(e.evaluate(.array([item(true), item(true)])) == .pass)
        #expect(e.evaluate(.array([])) == .pass)
        guard case .fail(let reason) = e.evaluate(.array([item(true), item(false)])) else {
            Issue.record("one invalid item should fail"); return
        }
        #expect(reason.contains("item 1"))
    }

    @Test func anyNeedsOne() throws {
        let e = try expect("any: [ { equals: a }, { equals: b } ]")
        #expect(e.evaluate(.string("b")) == .pass)
        if case .fail = e.evaluate(.string("c")) {} else { Issue.record("c should fail") }
    }

    @Test func rejectsBadExpectations() {
        for bad in ["{ equals: 1, gt: 0 }", "{ bogus: 1 }", "{ in: notalist }", "{ matches: \"(\" }", "{ exists: maybe }", "{ all: [] }", "[1, 2]"] {
            #expect(throws: RuleError.self) { _ = try expect(bad) }
        }
    }
}

