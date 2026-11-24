import Foundation
import MCP
import Testing
@testable import FarrierCore
@testable import FarrierMCP

/// A temporary home folder with real files, so the scanner runs its real code paths.
private final class FakeHome {
    let root: String
    let now = Date(timeIntervalSince1970: 1_800_000_000)
    init() {
        root = FileManager.default.temporaryDirectory.appendingPathComponent("farrier-home-\(UUID().uuidString)").path
        try! FileManager.default.createDirectory(atPath: root, withIntermediateDirectories: true)
    }
    deinit { try? FileManager.default.removeItem(atPath: root) }

    /// Creates a file of `bytes` with its modification and access time `daysAgo` days before `now`.
    func file(_ rel: String, bytes: Int = 10_000, daysAgo: Double) {
        let path = "\(root)/\(rel)"
        try! FileManager.default.createDirectory(atPath: (path as NSString).deletingLastPathComponent, withIntermediateDirectories: true)
        FileManager.default.createFile(atPath: path, contents: Data(repeating: 7, count: bytes))
        touch(rel, daysAgo: daysAgo)
    }

    func dir(_ rel: String, daysAgo: Double) {
        try! FileManager.default.createDirectory(atPath: "\(root)/\(rel)", withIntermediateDirectories: true)
        touch(rel, daysAgo: daysAgo)
    }

    func touch(_ rel: String, daysAgo: Double) {
        let t = time_t(now.timeIntervalSince1970 - daysAgo * 86_400)
        var times = [timeval(tv_sec: t, tv_usec: 0), timeval(tv_sec: t, tv_usec: 0)]
        utimes("\(root)/\(rel)", &times)
    }

    func scanner(running: Set<String> = [], apps: Set<String> = []) -> CleanupScanner {
        CleanupScanner(home: root, now: now, runningProcesses: { running }, appInstalled: { apps.contains($0) })
    }
}

private func pack(_ yaml: String) throws -> RulePack {
    let url = FileManager.default.temporaryDirectory.appendingPathComponent("pack-\(UUID().uuidString).yaml")
    try yaml.write(to: url, atomically: true, encoding: .utf8)
    defer { try? FileManager.default.removeItem(at: url) }
    let r = RulePackParser.parse(file: url, source: .bundled)
    #expect(r.issues.filter { $0.level == .error }.isEmpty, "\(r.issues)")
    return try #require(r.pack)
}

private func rule(_ id: String, _ body: String) -> String {
    """
      - id: t.\(id)
        title: \(id)
        kind: cleanup
        tier: T2
        regenerable: true
        evidence: Test data that the test recreates whenever it needs it.
    \(body.split(separator: "\n").map { "    " + $0 }.joined(separator: "\n"))

    """
}

private func packYAML(_ rules: String...) -> String {
    "pack:\n  id: t\n  title: T\n  version: 1\nrules:\n" + rules.joined()
}

@Suite("Cleanup scanner")
struct CleanupScannerTests {
    @Test func globsAgeAndSize() throws {
        let home = FakeHome()
        home.file("Library/Caches/old.app/blob", bytes: 50_000, daysAgo: 40)
        home.dir("Library/Caches/old.app", daysAgo: 40)
        home.file("Library/Caches/fresh.app/blob", daysAgo: 2)       // written recently: not old enough
        home.file("Library/Caches/mixed.app/a", daysAgo: 90)
        home.file("Library/Caches/mixed.app/sub/b", daysAgo: 3)      // something inside is in use
        home.file("Library/Caches/.hidden/x", daysAgo: 90)           // `*` doesn't match dot files
        home.file("Library/Caches/tiny.app/x", bytes: 10, daysAgo: 90)
        let p = try pack(packYAML(rule("caches", """
            targets:
              - path: ~/Library/Caches/*
            minAge: 30d
            minSize: 20KB
            """)))
        let report = home.scanner().scan([p])
        let r = try #require(report.rules.first)
        #expect(r.skipped == nil)
        #expect(r.candidates.map { ($0.path as NSString).lastPathComponent } == ["old.app"])
        let c = try #require(r.candidates.first)
        #expect(c.bytes >= 50_000)
        #expect(c.ageDays == 40)
        #expect(report.bytes == c.bytes && report.candidates == 1)
        // A run-time minimum age raises the rule's own, never lowers it.
        #expect(home.scanner().scan([p], minAge: RuleDuration("60d")).candidates == 0)
        #expect(home.scanner().scan([p], minAge: RuleDuration("1d")).candidates == 1)
    }

    @Test func protectedPathsAreNeverMatched() throws {
        let home = FakeHome()
        home.file("Documents/report.pdf", daysAgo: 400)
        home.file("Library/Mobile Documents/x", daysAgo: 400)
        home.file("Library/Logs/old.log", daysAgo: 400)
        // A pack can't name a protected path (the linter refuses it), but the scanner refuses it on its own too.
        let unsafe = CleanupRule(id: "t.unsafe", title: "unsafe", tier: .t2,
                                 targets: [CleanupTarget(path: "~/*", fact: nil, type: .any, contains: []),
                                           CleanupTarget(path: "~/Documents/*", fact: nil, type: .any, contains: []),
                                           CleanupTarget(path: "~/Library/**", fact: nil, type: .file, contains: [])],
                                 regenerable: true, minAge: nil, minSize: nil,
                                 when: CleanupConditions(processNotRunning: [], appInstalled: [], appNotInstalled: []),
                                 privileged: false, evidence: "x", references: [])
        let p = RulePack(id: "t", title: "T", version: 1, rules: [.cleanup(unsafe)], source: .bundled, file: "t.yaml")
        let paths = home.scanner().scan([p]).rules.flatMap(\.candidates).map(\.path)
        #expect(!paths.contains { $0.contains("/Documents") })
        #expect(paths.contains("\(home.root)/Library/Logs/old.log"))
        #expect(!paths.contains("\(home.root)/Library"))   // it holds Mail, Messages, keychains, …
        #expect(home.scanner().isProtected("\(home.root)/documents/x"))   // case-insensitive, like APFS
    }

    @Test func symlinksAreNotFollowed() throws {
        let home = FakeHome()
        home.file("Documents/secret/big", bytes: 500_000, daysAgo: 400)
        home.dir("Library/Caches", daysAgo: 400)
        try FileManager.default.createSymbolicLink(atPath: "\(home.root)/Library/Caches/link", withDestinationPath: "\(home.root)/Documents/secret")
        home.file("Library/Caches/real/x", daysAgo: 400)
        try FileManager.default.createSymbolicLink(atPath: "\(home.root)/Library/Caches/real/inner", withDestinationPath: "\(home.root)/Documents/secret")
        let p = try pack(packYAML(rule("caches", "targets:\n  - path: ~/Library/Caches/*\n"), rule("deep", "targets:\n  - path: ~/Library/Caches/link/*\n")))
        let report = home.scanner().scan([p])
        let paths = report.rules.flatMap(\.candidates).map(\.path)
        #expect(!paths.contains { $0.hasSuffix("/big") })   // not descended through the link
        let real = try #require(report.rules[0].candidates.first { $0.path.hasSuffix("/real") })
        #expect(real.bytes < 500_000)                       // the link inside isn't measured through
        let link = try #require(report.rules[0].candidates.first { $0.path.hasSuffix("/link") })
        #expect(link.bytes < 500_000)                       // the link itself, not its target
    }

    @Test func typeMarkersAndExcludes() throws {
        let home = FakeHome()
        home.file("Library/Caches/proj/node_modules/x", daysAgo: 90)
        home.file("Library/Caches/proj/package.json", daysAgo: 90)
        home.file("Library/Caches/orphan/node_modules/x", daysAgo: 90)
        home.file("Library/Caches/file.bin", daysAgo: 90)
        home.file("Library/Caches/com.apple.Safari/x", daysAgo: 90)
        let p = try pack(packYAML(
            rule("modules", "targets:\n  - path: ~/Library/Caches/*/node_modules\n    contains: [package.json]\n"),
            rule("dirs", "targets:\n  - path: ~/Library/Caches/*\n    type: directory\n    exclude: [\"com.apple.*\", proj]\n")))
        let report = home.scanner().scan([p])
        #expect(report.rules[0].candidates.map(\.path) == ["\(home.root)/Library/Caches/proj/node_modules"])
        #expect(Set(report.rules[1].candidates.map { ($0.path as NSString).lastPathComponent }) == ["orphan"])
    }

    @Test func conditionsSkipRules() throws {
        let home = FakeHome()
        home.file("Library/Developer/Xcode/DerivedData/App-abc/x", daysAgo: 90)
        let p = try pack(packYAML(
            rule("dd", "targets:\n  - path: ~/Library/Developer/Xcode/DerivedData/*\nwhen:\n  processNotRunning: [Xcode]\n"),
            rule("needs", "targets:\n  - path: ~/Library/Developer/Xcode/DerivedData/*\nwhen:\n  appInstalled: [Xcode]\n"),
            rule("orphan", "targets:\n  - path: ~/Library/Developer/Xcode/DerivedData/*\nwhen:\n  appNotInstalled: [Xcode]\n"),
            rule("fact", "targets:\n  - fact: simctl.devices.unavailable\n")))
        let running = home.scanner(running: ["Xcode"], apps: ["Xcode"]).scan([p])
        #expect(running.rules[0].skipped == "Xcode is running")
        #expect(running.rules[2].skipped == "Xcode is installed")
        #expect(running.rules[3].skipped?.contains("collector") == true)
        let idle = home.scanner(running: [], apps: []).scan([p])
        #expect(idle.rules[0].skipped == nil && idle.rules[1].skipped == "Xcode isn't installed")
        // Same path, same specificity: the first rule keeps it, so nothing is counted twice.
        #expect(idle.rules[0].candidates.count == 1 && idle.rules[2].candidates.isEmpty && idle.candidates == 1)
    }

    @Test func mostSpecificRuleClaimsAPath() throws {
        let home = FakeHome()
        home.file("Library/Caches/Homebrew/downloads/bottle.tar.gz", daysAgo: 90)
        home.file("Library/Caches/other/x", daysAgo: 90)
        let p = try pack(packYAML(
            rule("all", "targets:\n  - path: ~/Library/Caches/**\n    type: file\n"),
            rule("brew", "targets:\n  - path: ~/Library/Caches/Homebrew/downloads/*\n")))
        let report = home.scanner().scan([p])
        #expect(report.rules[1].candidates.map(\.path) == ["\(home.root)/Library/Caches/Homebrew/downloads/bottle.tar.gz"])
        #expect(report.rules[0].candidates.map(\.path) == ["\(home.root)/Library/Caches/other/x"])
    }

    @Test func nestedMatchesCountOnce() throws {
        let home = FakeHome()
        home.file("Library/Caches/app/a", bytes: 30_000, daysAgo: 90)
        home.file("Library/Caches/app/sub/b", bytes: 30_000, daysAgo: 90)
        let p = try pack(packYAML(rule("tree", "targets:\n  - path: ~/Library/Caches/**\n")))
        let report = home.scanner().scan([p])
        // `**` matches Caches itself, app, sub and the files; only the outermost is a candidate.
        #expect(report.rules[0].candidates.map(\.path) == ["\(home.root)/Library/Caches"])
        #expect(report.candidates == 1)
    }

    @Test func sizeIsALowerBoundPastTheEntryLimit() throws {
        let home = FakeHome()
        for i in 0..<20 { home.file("Library/Caches/many/f\(i)", bytes: 100, daysAgo: 90) }
        let p = try pack(packYAML(rule("c", "targets:\n  - path: ~/Library/Caches/*\n")))
        let s = CleanupScanner(home: home.root, now: home.now, runningProcesses: { [] }, appInstalled: { _ in false }, entryLimit: 5)
        #expect(s.scan([p]).rules[0].candidates.first?.sizeIsLowerBound == true)
        #expect(home.scanner().scan([p]).rules[0].candidates.first?.sizeIsLowerBound == nil)
    }

    @Test func bundledPacksLintAndUseKnownRoots() throws {
        let (packs, issues) = RuleLinter.loadPacks(at: [repoRoot.appendingPathComponent("rules/cleanup").path], source: .bundled)
        #expect((issues + RuleLinter.lint(packs)).filter { $0.level == .error }.isEmpty)
        let ids = Set(packs.flatMap { $0.rules.map(\.id) })
        #expect(ids.isSuperset(of: ["user.library.caches", "user.library.logs", "user.library.homebrew-downloads", "dev.packages.npm"]))
    }

    @Test func byteCountFormat() {
        #expect(ByteCount.format(512) == "512 bytes")
        #expect(ByteCount.format(1_500_000) == "1.5 MB")
        #expect(ByteCount.format(42_000_000_000) == "42 GB")
    }

    @Test func mcpToolScansAndValidates() throws {
        let home = FakeHome()
        home.file("Library/Logs/old/app.log", daysAgo: 100)
        let dir = FileManager.default.temporaryDirectory.appendingPathComponent("farrier-ctx-\(UUID().uuidString)")
        defer { try? FileManager.default.removeItem(at: dir) }
        var ctx = FarrierContext(
            collectFacts: { CollectionResult(facts: [:], notes: []) },
            rulePaths: [repoRoot.appendingPathComponent("rules").path],
            plans: PlanStore(directory: dir.appendingPathComponent("plans")),
            journal: Journal(url: dir.appendingPathComponent("j.jsonl")),
            host: { "H" }, applyThroughHelper: { _ in throw OperationError("none") }, actor: "mcp:test")
        ctx.cleanupScanner = { home.scanner() }
        let r = try ToolCatalog.call("cleanup_scan", arguments: ["ruleIDs": .array([.string("user.library.logs")])], context: ctx)
        #expect(r.isError != true)
        let rules = try #require(r.structuredContent?.objectValue?["rules"]?.arrayValue)
        #expect(rules.count == 1)
        #expect(rules[0].objectValue?["candidates"]?.arrayValue?.count == 1)
        #expect(try ToolCatalog.call("cleanup_scan", arguments: ["ruleIDs": .array([.string("nope")])], context: ctx).isError == true)
        #expect(try ToolCatalog.call("cleanup_scan", arguments: ["minAge": .string("soon")], context: ctx).isError == true)
        let tool = try #require(ToolCatalog.tools.first { $0.name == "cleanup_scan" })
        #expect(tool.annotations.readOnlyHint == true)
    }
}
