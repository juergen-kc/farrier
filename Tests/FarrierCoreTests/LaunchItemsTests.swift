import Foundation
import Testing
@testable import FarrierCore

/// A signature checker with fixed answers, counting how often each path is checked.
final class FakeSignatures: CodeSignatureChecking, @unchecked Sendable {
    let answers: [String: CodeSignatureInfo]
    private let lock = NSLock()
    private(set) var checks: [String: Int] = [:]

    init(_ answers: [String: CodeSignatureInfo]) { self.answers = answers }

    func check(path: String) -> CodeSignatureInfo? {
        lock.lock(); checks[path, default: 0] += 1; lock.unlock()
        return answers[path]
    }
}

private func plist(_ dict: [String: Any]) -> Data {
    try! PropertyListSerialization.data(fromPropertyList: dict, format: .xml, options: 0)  // swiftlint:disable:this force_try
}

private let home = "/Users/tester"
private let signed = CodeSignatureInfo(valid: true, notarized: true, teamID: "ABCDE12345", identifier: "com.example.agent")
private let apple = CodeSignatureInfo(valid: true, notarized: true, appleSigned: true, identifier: "com.apple.sh")
private let unsigned = CodeSignatureInfo(valid: false, notarized: false, error: "unsigned")

private func collector(files: [String: Data], dirs: [String: [String]], programs: Set<String>,
                       signatures: FakeSignatures, scripts: Set<String> = []) -> LaunchItemsCollector {
    LaunchItemsCollector(
        home: home,
        fileExists: { dirs[$0] != nil || files[$0] != nil || programs.contains($0) || scripts.contains($0) },
        readFile: { files[$0] },
        listDirectory: { dirs[$0] },
        signatures: signatures,
        readHead: { scripts.contains($0) ? Data("#!".utf8) : Data([0xCF, 0xFA]) },
        symlinkDestination: { _ in nil })  // the real /bin is a symlink on Linux; these tests use a fake filesystem
}

private func items(_ value: FactValue?) throws -> [String: [String: FactValue]] {
    let list = try #require(value?.array)
    var byPlist: [String: [String: FactValue]] = [:]
    for item in list {
        let o = try #require(item.object)
        byPlist[try #require(o["plist"]?.string)] = o
    }
    return byPlist
}

@Suite("launchd.items")
struct LaunchItemsTests {
    @Test func unavailableWithoutLaunchdFolders() {
        let (value, note) = collector(files: [:], dirs: [:], programs: [], signatures: FakeSignatures([:])).collect()
        #expect(value == nil)
        #expect(note.status == .unavailable)
    }

    @Test func readsEachKindOfJob() throws {
        let d = "/Library/LaunchDaemons", a = "/Library/LaunchAgents", u = home + "/Library/LaunchAgents"
        let files: [String: Data] = [
            d + "/com.example.daemon.plist": plist(["Label": "com.example.daemon", "Program": "/opt/example/daemon",
                                                     "RunAtLoad": true, "KeepAlive": ["SuccessfulExit": false]]),
            d + "/com.example.script.plist": plist(["Label": "com.example.script",
                                                     "ProgramArguments": ["sh", "/opt/example/run.sh"]]),
            d + "/com.example.inline.plist": plist(["Label": "com.example.inline",
                                                     "ProgramArguments": ["/bin/zsh", "-c", "curl … | sh"]]),
            d + "/com.example.gone.plist": plist(["Label": "com.example.gone", "Program": "/Applications/Gone.app/Contents/MacOS/gone"]),
            d + "/com.example.bundle.plist": plist(["Label": "com.example.bundle", "BundleProgram": "Contents/MacOS/helper"]),
            d + "/broken.plist": Data("not a plist".utf8),
            a + "/com.example.unsigned.plist": plist(["Label": "com.example.unsigned", "ProgramArguments": ["/usr/local/bin/tool"],
                                                       "Disabled": true]),
            u + "/com.example.docs.plist": plist(["Label": "com.example.docs", "Program": home + "/Documents/thing"]),
            // Not jobs: an empty placeholder (as GoogleUpdater leaves for Keystone) and a label without a program.
            u + "/com.google.keystone.agent.plist": plist([:]),
            u + "/labelonly.plist": plist(["Label": "labelonly"]),
        ]
        let dirs: [String: [String]] = [
            d: ["com.example.daemon.plist", "com.example.script.plist", "com.example.inline.plist", "com.example.gone.plist",
                "com.example.bundle.plist", "broken.plist", "unreadable.plist", ".hidden.plist", "README.txt"],
            a: ["com.example.unsigned.plist"],
            u: ["com.example.docs.plist", "com.google.keystone.agent.plist", "labelonly.plist"],
        ]
        let sigs = FakeSignatures(["/opt/example/daemon": signed, "/bin/sh": apple, "/bin/zsh": apple, "/usr/local/bin/tool": unsigned])
        let (value, note) = collector(files: files, dirs: dirs,
                                      programs: ["/opt/example/daemon", "/bin/sh", "/bin/zsh", "/usr/local/bin/tool", home + "/Documents/thing"],
                                      signatures: sigs).collect()
        #expect(note.status == .collected)
        let all = try items(value)
        #expect(all.count == 9)  // .hidden.plist and README.txt are skipped; unreadable.plist is listed with its error

        let daemon = try #require(all[d + "/com.example.daemon.plist"])
        #expect(daemon["scope"] == .string("system-daemon"))
        #expect(daemon["runAtLoad"] == .bool(true))
        #expect(daemon["keepAlive"] == .bool(true))
        #expect(daemon["signature"]?.object?["notarized"] == .bool(true))
        #expect(daemon["signature"]?.object?["teamID"] == .string("ABCDE12345"))

        // `sh` is found on the default PATH; the script it runs is recorded.
        let script = try #require(all[d + "/com.example.script.plist"])
        #expect(script["program"] == .string("/bin/sh"))
        #expect(script["script"] == .string("/opt/example/run.sh"))
        #expect(try #require(all[d + "/com.example.inline.plist"])["inlineCommand"] == .bool(true))

        // A missing program is a leftover: flagged as not valid.
        let gone = try #require(all[d + "/com.example.gone.plist"])
        #expect(gone["programExists"] == .bool(false))
        #expect(gone["signature"]?.object?["valid"] == .bool(false))
        #expect(gone["signature"]?.object?["source"] == .string("Missing program"))

        // Not checkable: app-embedded programs, broken or unreadable plists, privacy-protected folders.
        #expect(all[d + "/com.example.bundle.plist"]?["signature"] == nil)
        #expect(daemon["inspected"] == .bool(true))
        #expect(all[d + "/com.example.bundle.plist"]?["inspected"] == nil)
        #expect(all[d + "/broken.plist"]?["inspected"] == nil)
        #expect(all[d + "/broken.plist"]?["error"] == .string("cannot parse the plist"))
        #expect(all[d + "/unreadable.plist"]?["error"] == .string("cannot read the plist"))
        let docs = try #require(all[u + "/com.example.docs.plist"])
        #expect(docs["signature"] == nil)
        #expect(docs["scope"] == .string("user-agent"))
        #expect(sigs.checks[home + "/Documents/thing"] == nil)  // never opened

        #expect(try #require(all[a + "/com.example.unsigned.plist"])["disabled"] == .bool(true))
        // Each program is checked once, however many jobs use it.
        #expect(sigs.checks.values.allSatisfy { $0 == 1 })
        #expect(note.detail?.contains("not fully checked") == true)
        #expect(note.detail?.contains("2 plist(s) without a program ignored") == true)
        #expect(all[u + "/labelonly.plist"] == nil)
        #expect(daemon["signature"]?.object?["source"] == .string("Notarized Developer ID"))
    }

    @Test func aScriptRunDirectlyIsFlaggedAsAScript() throws {
        let d = "/Library/LaunchDaemons"
        let sigs = FakeSignatures([:])
        let (value, _) = collector(files: [d + "/x.plist": plist(["Label": "x", "Program": "/usr/local/libexec/x.sh"])],
                                   dirs: [d: ["x.plist"]], programs: [], signatures: sigs,
                                   scripts: ["/usr/local/libexec/x.sh"]).collect()
        let x = try #require(try items(value)[d + "/x.plist"])
        #expect(x["script"] == .string("/usr/local/libexec/x.sh"))
        #expect(x["signature"]?.object?["valid"] == .bool(false))
        #expect(x["signature"]?.object?["error"]?.string?.contains("a script") == true)
        #expect(x["signature"]?.object?["source"] == .string("Script"))
        #expect(sigs.checks.isEmpty)
    }

    @Test func sourceUsesGatekeepersWords() {
        #expect(CodeSignatureInfo(valid: true, notarized: false, teamID: "4C6364ACXT").source == "Unnotarized Developer ID")
        #expect(signed.source == "Notarized Developer ID")
        #expect(apple.source == "Apple")
        #expect(unsigned.source == "Unsigned")
        #expect(CodeSignatureInfo(valid: true, notarized: false, adhoc: true).source == "Ad hoc")
    }

    @Test func interpreterOptionsAreParsedPerInterpreter() {
        func op(_ program: String, _ args: [String]) -> String {
            guard let r = LaunchItemsCollector.interpreterOperand(program: program, arguments: args) else { return "not an interpreter" }
            return r.inline ? "inline" : (r.script ?? "none")
        }
        #expect(op("/bin/sh", ["-e", "/opt/job.sh"]) == "/opt/job.sh")        // -e: exit on error, not code
        #expect(op("/bin/sh", ["-lc", "echo hi"]) == "inline")                 // combined flags
        #expect(op("/bin/sh", ["/opt/x.sh", "-c", "arg"]) == "/opt/x.sh")       // the script's own arguments don't count
        #expect(op("/bin/bash", ["-o", "pipefail", "/opt/x.sh"]) == "/opt/x.sh") // -o takes an argument
        #expect(op("/bin/zsh", ["--", "/opt/x.sh"]) == "/opt/x.sh")
        #expect(op("/usr/bin/python3", ["-W", "ignore", "/opt/x.py"]) == "/opt/x.py")
        #expect(op("/usr/bin/python3", ["-m", "http.server"]) == "inline")
        #expect(op("/usr/bin/perl", ["-e", "print 1"]) == "inline")
        #expect(op("/usr/bin/osascript", ["-e", "beep"]) == "inline")
        #expect(op("/usr/local/bin/node", ["--eval=1"]) == "inline")
        #expect(op("/usr/bin/ruby", ["/opt/x.rb"]) == "/opt/x.rb")
        #expect(op("/opt/example/daemon", ["-c", "x"]) == "not an interpreter")
    }

    @Test func bundleProgramAndEnvAreResolved() throws {
        let d = "/Library/LaunchDaemons"
        let files: [String: Data] = [
            // ProgramArguments alongside BundleProgram: launchd runs the bundle's program, so argv[0] isn't checked.
            d + "/bundle.plist": plist(["Label": "bundle", "BundleProgram": "Contents/MacOS/helper", "ProgramArguments": ["/bin/sh"]]),
            d + "/env.plist": plist(["Label": "env", "ProgramArguments": ["/usr/bin/env", "FOO=1", "python3", "-u", "/opt/x.py"]]),
        ]
        let sigs = FakeSignatures(["/bin/sh": apple, "/usr/bin/python3": apple])
        let (value, _) = collector(files: files, dirs: [d: ["bundle.plist", "env.plist"]],
                                   programs: ["/bin/sh", "/usr/bin/env", "/usr/bin/python3"], signatures: sigs).collect()
        let all = try items(value)
        #expect(all[d + "/bundle.plist"]?["signature"] == nil)
        #expect(all[d + "/bundle.plist"]?["error"]?.string?.contains("BundleProgram") == true)
        #expect(sigs.checks["/bin/sh"] == nil)
        let env = try #require(all[d + "/env.plist"])
        #expect(env["program"] == .string("/usr/bin/python3"))
        #expect(env["script"] == .string("/opt/x.py"))
    }

    @Test func protectedFoldersAreNeverTouched() {
        final class Calls: @unchecked Sendable { var paths: [String] = [] }
        let calls = Calls()
        let links: [String: String] = [
            "/usr/local/bin/tool": home + "/Documents/tool",   // symlink into Documents
            "/opt/a/link": "../b/real",                        // relative symlink
            "/opt/loop": "/opt/loop",
        ]
        let c = LaunchItemsCollector(home: home, signatures: FakeSignatures([:]),
                                     symlinkDestination: { calls.paths.append($0); return links[$0] })
        #expect(c.resolvedOutsideProtectedFolders(home + "/.local/../Documents/tool") == nil)
        #expect(c.resolvedOutsideProtectedFolders("/usr/local/bin/tool") == nil)
        #expect(c.resolvedOutsideProtectedFolders("/opt/a/link") == "/opt/b/real")
        #expect(c.resolvedOutsideProtectedFolders("/opt/loop") == nil)
        #expect(c.resolvedOutsideProtectedFolders("/Volumes/USB/agent") == nil)
        #expect(c.resolvedOutsideProtectedFolders("/opt/example/daemon") == "/opt/example/daemon")
        // Nothing inside a protected folder (or the folder itself) was ever looked at.
        #expect(!calls.paths.contains { c.isPrivacyProtected($0) })
    }

    @Test func aProtectedProgramIsUncheckedNotMissing() throws {
        let u = home + "/Library/LaunchAgents"
        let (value, _) = collector(files: [u + "/x.plist": plist(["Label": "x", "Program": home + "/Documents/gone"])],
                                   dirs: [u: ["x.plist"]], programs: [], signatures: FakeSignatures([:])).collect()
        let x = try #require(try items(value)[u + "/x.plist"])
        #expect(x["programExists"] == nil)
        #expect(x["signature"] == nil)
        #expect(x["error"]?.string?.contains("privacy-protected") == true)
    }

    @Test func anUnlistableFolderMakesTheFactUnknown() {
        let (value, note) = LaunchItemsCollector(
            home: home, fileExists: { $0 == "/Library/LaunchDaemons" }, readFile: { _ in nil },
            listDirectory: { _ in nil }, signatures: FakeSignatures([:])).collect()
        #expect(value == nil)
        #expect(note.status == .failed)
    }

    @Test func postureRuleNamesTheItemThatFails() throws {
        let (packs, _) = RuleLinter.loadPacks(at: [repoRoot.appendingPathComponent("rules/posture").path], source: .bundled)
        func evaluate(_ items: [FactValue]) throws -> Finding {
            let report = PostureEngine.evaluate(packs, facts: StaticFactStore(["launchd.items": .array(items)]))
            return try #require(report.findings.first { $0.ruleID == "posture.core.unsigned-launch-items" })
        }
        func item(_ label: String, _ sig: CodeSignatureInfo?) -> FactValue {
            var o: [String: FactValue] = ["label": .string(label)]
            if let sig { o["signature"] = sig.factValue }
            return .object(o)
        }
        #expect(try evaluate([]).status == .pass)
        #expect(try evaluate([item("a", signed), item("b", apple)]).status == .pass)
        let failing = try evaluate([item("a", signed), item("com.example.unsigned", unsigned)])
        #expect(failing.status == .fail)
        #expect(failing.reason?.contains("\"com.example.unsigned\"") == true)
        // One item that couldn't be checked, the rest fine: unknown, never a pass.
        #expect(try evaluate([item("a", signed), item("b", nil)]).status == .unknown)
        // A failure wins over an unknown.
        #expect(try evaluate([item("a", unsigned), item("b", nil)]).status == .fail)
    }
}
