import Foundation
import Testing
@testable import FarrierCore

private func packs() throws -> [RulePack] {
    let (packs, issues) = RuleLinter.loadPacks(at: [repoRoot.appendingPathComponent("rules/posture").path], source: .bundled)
    try #require(issues.filter { $0.level == .error }.isEmpty, "\(issues)")
    return packs
}

private func finding(_ id: String, _ facts: [String: FactValue]) throws -> Finding {
    let report = PostureEngine.evaluate(try packs(), facts: StaticFactStore(facts))
    return try #require(report.findings.first { $0.ruleID == id })
}

/// Golden output from `netstat -anp tcp` (macOS): SSH and Screen Sharing listening, CUPS only on loopback.
private let netstat = """
Active Internet connections (including servers)
Proto Recv-Q Send-Q  Local Address          Foreign Address        (state)
tcp4       0      0  10.211.55.49.22        10.211.55.2.61234      ESTABLISHED
tcp6       0      0  *.5900                 *.*                    LISTEN
tcp4       0      0  *.5900                 *.*                    LISTEN
tcp6       0      0  *.22                   *.*                    LISTEN
tcp4       0      0  *.22                   *.*                    LISTEN
tcp4       0      0  127.0.0.1.631          *.*                    LISTEN
tcp6       0      0  ::1.631                *.*                    LISTEN
tcp6       0      0  fe80::1%lo0.631        *.*                    LISTEN
"""

@Suite("Posture rules: firewall, sharing, scripted jobs")
struct PostureRulesTests {
    @Test func stealthModeParser() {
        #expect(Parsers.firewallStealthMode("Firewall stealth mode is on \n") == .string("on"))
        #expect(Parsers.firewallStealthMode("Firewall stealth mode is off") == .string("off"))
        #expect(Parsers.firewallStealthMode("Stealth mode enabled") == .string("on"))
        #expect(Parsers.firewallStealthMode("Stealth mode disabled") == .string("off"))
        #expect(Parsers.firewallStealthMode("Stealth mode is onward") == nil)
        #expect(Parsers.firewallStealthMode("something else") == nil)
    }

    @Test func listeningPortsParser() {
        // Only listening sockets on reachable addresses; loopback (127.x, ::1, %lo0) and connections don't count.
        #expect(Parsers.listeningTCPPorts(netstat) == .array([.int(22), .int(5900)]))
        #expect(Parsers.listeningTCPPorts("Active Internet connections (including servers)\nProto Recv-Q\n") == .array([]))
        #expect(Parsers.listeningTCPPorts("netstat: illegal option") == nil)
    }

    @Test func invalidUTF8DoesNotEmptyTheOutput() throws {
        // A stray byte (0xFF) in a command's output used to make the whole output read as empty.
        let r = try #require(ProcessRunner().run("/usr/bin/printf", ["\\377ok tcp4 *.22 LISTEN\\n"]))
        #expect(r.stdout.contains("ok tcp4 *.22 LISTEN"))
    }

    @Test func runnerDrainsLargeOutputWithoutStalling() throws {
        // ~1 MB on stdout and some stderr: more than a pipe buffer holds, so it only works if both are drained.
        let r = try #require(ProcessRunner().run("/bin/sh", ["-c", "head -c 1000000 /dev/zero | tr '\\0' x; echo oops >&2"], timeout: 20))
        #expect(r.stdout.count == 1_000_000)
        #expect(r.stderr == "oops\n")
        #expect(!r.timedOut)
    }

    @Test func runnerTimesOut() throws {
        let r = try #require(ProcessRunner().run("/bin/sleep", ["30"], timeout: 1))
        #expect(r.timedOut)
    }

    @Test func emptyNetstatIsUnavailableNotUnparsed() {
        // macOS 27 hides other processes' sockets from unprivileged third-party tools: netstat prints nothing.
        let runner = RecordedRunner(["/usr/sbin/netstat -anp tcp": CommandResult(status: 0, stdout: "")])
        let result = SystemCollectors(runner: runner, readFile: { _ in nil }, fileExists: { _ in false }).collect()
        let note = result.notes.first { $0.fact == "network.listeningTCP" }
        #expect(note?.status == .unavailable)
        #expect(note?.detail?.contains("helper") == true)
        #expect(result.facts["network.listeningTCP"] == nil)
    }

    @Test func mergingKeepsTheNoteOfWhoeverCollected() {
        let fact = "network.listeningTCP"
        let t0Empty = CollectionResult(facts: [:], notes: [CollectionNote(fact: fact, status: .unavailable, source: "netstat", detail: "x")])
        let t0Got = CollectionResult(facts: [fact: .array([.int(22)])], notes: [CollectionNote(fact: fact, status: .collected, source: "netstat", detail: nil)])
        let helperGot = CollectionResult(facts: [fact: .array([.int(22), .int(5900)])], notes: [CollectionNote(fact: fact, status: .collected, source: "helper", detail: nil)])
        let helperMissing = CollectionResult(facts: [:], notes: [CollectionNote(fact: fact, status: .unavailable, source: "helper", detail: "y")])

        let a = t0Empty.merging(helperGot)       // macOS 27 with the helper
        #expect(a.facts[fact] == .array([.int(22), .int(5900)]))
        #expect(a.notes.map(\.source) == ["helper"])
        let b = t0Got.merging(helperMissing)     // CI runner: no helper, but the unprivileged read worked
        #expect(b.facts[fact] == .array([.int(22)]))
        #expect(b.notes.map(\.status) == [.collected])
        let c = t0Empty.merging(helperMissing)   // neither: both reasons stay
        #expect(c.notes.count == 2)
    }

    @Test func sharingRulesReadTheListeningPorts() throws {
        let ports = try #require(Parsers.listeningTCPPorts(netstat))
        let facts: [String: FactValue] = ["network.listeningTCP": ports]
        #expect(try finding("posture.core.remote-login-off", facts).status == .fail)
        #expect(try finding("posture.core.remote-login-off", facts).reason == "contains 22")
        #expect(try finding("posture.core.screen-sharing-off", facts).status == .fail)
        #expect(try finding("posture.core.remote-management-off", facts).status == .pass)
        // None of them is ever fixed automatically: turning a remote-access service off can lock someone out.
        #expect(try finding("posture.core.remote-login-off", facts).fixable == false)
        #expect(try finding("posture.core.screen-sharing-off", facts).guidance?.isEmpty == false)
        #expect(try finding("posture.core.remote-management-off", ["network.listeningTCP": .array([.int(3283)])]).status == .fail)
        #expect(try finding("posture.core.remote-login-off", [:]).status == .unknown)
    }

    @Test func stealthModeIsFixableUnlessManaged() throws {
        var facts: [String: FactValue] = ["firewall.stealthMode": .string("off"), "mdm.payloadTypes": .array([])]
        let off = try finding("posture.core.firewall-stealth", facts)
        #expect(off.status == .fail)
        #expect(off.fixable)
        facts["mdm.payloadTypes"] = .array([.string("com.apple.security.firewall")])
        #expect(try finding("posture.core.firewall-stealth", facts).fixable == false)
        #expect(try finding("posture.core.firewall-stealth", ["firewall.stealthMode": .string("on")]).status == .pass)
    }

    @Test func stealthModeIsPlannedThroughTheCatalog() throws {
        let facts = StaticFactStore(["firewall.stealthMode": .string("off"), "mdm.payloadTypes": .array([]),
                                     "mdm.declarationTypes": .array([])])
        let packs = try packs()
        let report = PostureEngine.evaluate(packs, facts: facts)
        let (plan, _) = Planner.plan(report: report, packs: packs, facts: facts, ruleIDs: ["posture.core.firewall-stealth"],
                                     host: "H")
        let item = try #require(plan?.items.first)
        #expect(item.action == "firewall.stealthEnable")
        #expect(item.tier == .t4)
        #expect(try Plan.decodeCanonical(try #require(plan).canonicalData()) == plan)
    }

    @Test func scriptedJobsAreFlaggedByLabel() throws {
        func item(_ label: String, _ extra: [String: FactValue] = [:]) -> FactValue {
            .object(["label": .string(label), "inspected": .bool(true)].merging(extra) { $1 })
        }
        let clean = try finding("posture.core.scripted-launch-items", ["launchd.items": .array([item("a"), item("b")])])
        #expect(clean.status == .pass)
        let scripted = try finding("posture.core.scripted-launch-items", ["launchd.items": .array([
            item("a"), item("com.example.runner", ["script": .string("/opt/run.sh")]),
            item("com.example.inline", ["inlineCommand": .bool(true)]),
        ])])
        #expect(scripted.status == .fail)
        #expect(scripted.reason?.contains("com.example.runner") == true)
        #expect(scripted.reason?.contains("com.example.inline") == true)
        // A job the collector couldn't inspect (only an error) makes the rule unknown, never a pass...
        let uninspected: FactValue = .object(["plist": .string("/Library/LaunchDaemons/x.plist"), "error": .string("cannot read the plist")])
        #expect(try finding("posture.core.scripted-launch-items", ["launchd.items": .array([item("a"), uninspected])]).status == .unknown)
        // ...while a confirmed script still fails.
        #expect(try finding("posture.core.scripted-launch-items",
                            ["launchd.items": .array([uninspected, item("s", ["script": .string("/opt/x.sh")])])]).status == .fail)
    }
}
