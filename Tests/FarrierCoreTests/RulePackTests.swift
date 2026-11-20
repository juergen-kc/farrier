import Foundation
import Testing
@testable import FarrierCore

/// The repository root, found from this file's location (Tests/FarrierCoreTests/RulePackTests.swift).
let repoRoot = URL(fileURLWithPath: #filePath).deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()

@Suite("Rule packs")
struct RulePackTests {
    func parse(_ yaml: String, source: RulePack.Source = .bundled) -> RulePackParser.Result {
        RulePackParser.parse(yaml: yaml, file: "test.yaml", source: source)
    }

    func errors(_ issues: [LintIssue]) -> [String] { issues.filter { $0.level == .error }.map(\.message) }

    // MARK: The packs shipped in rules/

    @Test func bundledPacksLoadAndLintClean() {
        let (packs, issues) = RuleLinter.loadPacks(at: [repoRoot.appendingPathComponent("rules").path], source: .bundled)
        let all = issues + RuleLinter.lint(packs)
        #expect(errors(all).isEmpty, "\(all)")
        #expect(packs.count >= 2)
        let ids = packs.flatMap { $0.rules.map(\.id) }
        #expect(ids.contains("posture.core.filevault"))
        #expect(ids.contains("dev.xcode.derived-data"))
    }

    // MARK: Parser

    let validCheck = """
        pack: { id: p, title: P, version: 1 }
        rules:
          - id: p.fv
            title: FileVault
            kind: check
            severity: high
            collect: { fact: filevault.status }
            expect: { equals: "On" }
            remediation: { automatic: false, guidance: Turn it on. }
            mappings: { cis: "2.6.6" }
        """

    @Test func parsesAValidCheck() throws {
        let r = parse(validCheck)
        #expect(errors(r.issues).isEmpty, "\(r.issues)")
        let pack = try #require(r.pack)
        guard case .check(let c) = try #require(pack.rules.first) else { Issue.record("expected a check"); return }
        #expect(c.severity == .high)
        #expect(c.fact == "filevault.status")
        #expect(c.mappings["cis"] == "2.6.6")
    }

    @Test func unknownKeysAreErrors() {
        let r = parse(validCheck.replacingOccurrences(of: "severity: high", with: "severity: high\n    sevrity: low"))
        #expect(errors(r.issues).contains { $0.contains("unknown key `sevrity`") })
        #expect(r.pack?.rules.isEmpty == true)  // the broken rule is skipped, never half-loaded
    }

    @Test func unquotedBenchmarkIDIsCaught() {
        let r = parse(validCheck.replacingOccurrences(of: #"cis: "2.6.6""#, with: "cis: 2.6"))
        #expect(errors(r.issues).contains { $0.contains("mappings.cis") })
    }

    @Test func automaticRemediationNeedsAnAction() {
        let r = parse(validCheck.replacingOccurrences(of: "{ automatic: false, guidance: Turn it on. }", with: "{ automatic: true }"))
        #expect(errors(r.issues).contains { $0.contains("remediation.action") })
    }

    let validCleanup = """
        pack: { id: dev }
        rules:
          - id: dev.cache
            title: A cache
            kind: cleanup
            tier: T2
            targets: [ { path: "~/Library/Caches/com.example/*", type: directory } ]
            regenerable: true
            minAge: 14d
            minSize: 50MB
            evidence: Regenerated automatically by the app on next launch.
        """

    @Test func parsesAValidCleanup() throws {
        let r = parse(validCleanup)
        #expect(errors(r.issues).isEmpty, "\(r.issues)")
        guard case .cleanup(let c) = try #require(r.pack?.rules.first) else { Issue.record("expected a cleanup"); return }
        // Unwrap first: comparing the optional chain with a computed literal reported equal values as unequal.
        let minAge = try #require(c.minAge)
        let fourteenDays: Int64 = 14 * 86_400
        #expect(minAge.seconds == fourteenDays)
        #expect(c.minSize == 50_000_000)
        #expect(c.targets.first?.type == .directory)
    }

    @Test func cleanupTierMustBeT2OrT3() {
        let r = parse(validCleanup.replacingOccurrences(of: "tier: T2", with: "tier: T4"))
        #expect(errors(r.issues).contains { $0.contains("T2") })
    }

    @Test func badDurationIsCaught() {
        let r = parse(validCleanup.replacingOccurrences(of: "minAge: 14d", with: "minAge: fortnight"))
        #expect(errors(r.issues).contains { $0.contains("minAge") })
    }

    // MARK: Linter: protected paths and user packs

    func lintCleanup(path: String, source: RulePack.Source = .bundled, tier: String = "T2") -> [String] {
        let yaml = validCleanup
            .replacingOccurrences(of: "~/Library/Caches/com.example/*", with: path)
            .replacingOccurrences(of: "tier: T2", with: "tier: \(tier)")
        let r = parse(yaml, source: source)
        return errors(r.issues + RuleLinter.lint(r.pack.map { [$0] } ?? []))
    }

    @Test func protectedPathsAreRejected() {
        #expect(lintCleanup(path: "~/Documents/*").contains { $0.contains("protected path `~/Documents`") })
        #expect(lintCleanup(path: "~/Library/Mail/V10/**").contains { $0.contains("~/Library/Mail") })
        // A broad glob reaches protected paths underneath it.
        #expect(lintCleanup(path: "~/**/*.log").contains { $0.contains("protected path") })
        #expect(lintCleanup(path: "~/Library/*/Caches").contains { $0.contains("protected path") })
        #expect(lintCleanup(path: "/System/Library/Caches/*").contains { $0.contains("/System") })
    }

    @Test func safePathsPass() {
        #expect(lintCleanup(path: "~/Library/Caches/com.example/*").isEmpty)
        #expect(lintCleanup(path: "~/Library/Developer/Xcode/DerivedData/*").isEmpty)
        #expect(lintCleanup(path: "~/Library/Logs/DiagnosticReports/*.ips").isEmpty)
        // "~/Documents-old" is not inside "~/Documents".
        #expect(lintCleanup(path: "~/Documents-old/*").isEmpty)
    }

    @Test func protectedPathAliasesAreRejected() {
        // PR #2 review: equivalent spellings and case must not get around the protected-path list.
        for alias in ["~/./Documents/*", "~//Documents/*", "/./System/*", "~/documents/*", "~/Library/MAIL/*"] {
            #expect(lintCleanup(path: alias).contains { $0.contains("protected path") }, "\(alias)")
        }
        // Non-canonical spellings are also rejected in their own right.
        #expect(lintCleanup(path: "~/Library/Caches//x/*").contains { $0.contains("canonical") })
        #expect(lintCleanup(path: "~/Library/Caches/./x/*").contains { $0.contains("canonical") })
        // A root-wide glob reaches everything.
        #expect(lintCleanup(path: "/*").contains { $0.contains("protected path") })
    }

    @Test func userPacksOnlyGetExplicitDeveloperArtifacts() {
        // PR #2 review: not all of ~/Library/Developer. Xcode/UserData holds user-authored settings.
        #expect(lintCleanup(path: "~/Library/Developer/Xcode/UserData/*", source: .user).contains { $0.contains("user pack target must be inside") })
        #expect(lintCleanup(path: "~/Library/Developer/Xcode/Archives/*", source: .user).contains { $0.contains("user pack target must be inside") })
        #expect(lintCleanup(path: "~/Library/Developer/Xcode/DerivedData/*", source: .user).isEmpty)
    }

    @Test func overflowingDurationsAndSizesAreErrorsNotCrashes() {
        // PR #2 review: these used to trap on multiplication overflow.
        #expect(RuleDuration("9223372036854775807w") == nil)
        #expect(RuleSize.parse(.string("10000000000GB")) == nil)
        #expect(RuleSize.parse(.string("-1")) == nil)
        #expect(RuleSize.parse(.string("1024")) == Optional(Int64(1024)))
        let r = parse(validCleanup.replacingOccurrences(of: "minAge: 14d", with: "minAge: 9223372036854775807w"))
        #expect(errors(r.issues).contains { $0.contains("minAge") })
    }

    @Test func missingInputPathsAreErrors() {
        // PR #2 review: a requested path that doesn't exist must not be dropped silently.
        let rules = repoRoot.appendingPathComponent("rules").path
        let (packs, issues) = RuleLinter.loadPacks(at: [rules, "/nonexistent/farrier-rules"], source: .bundled)
        #expect(!packs.isEmpty)
        #expect(errors(issues).contains { $0.contains("no such file") })
    }

    @Test func pathTraversalIsRejected() {
        #expect(lintCleanup(path: "~/Library/Caches/../Mail/*").contains { $0.contains("..") })
    }

    @Test func userPacksAreRestricted() {
        #expect(lintCleanup(path: "~/Library/Caches/x/*", source: .user).isEmpty)
        #expect(lintCleanup(path: "~/Library/Caches/x/*", source: .user, tier: "T3").contains { $0.contains("only declare T2") })
        #expect(lintCleanup(path: "/Library/Caches/x/*", source: .user).contains { $0.contains("user pack target must be inside") })
    }

    @Test func ruleIDsMustBeUniqueAndPrefixed() {
        let yaml = validCleanup + """

              - id: other.cache
                title: Wrong prefix
                kind: cleanup
                tier: T2
                targets: [ { path: "~/Library/Caches/other/*" } ]
                regenerable: true
                evidence: Regenerated automatically by the app on next launch.
              - id: dev.cache
                title: Duplicate
                kind: cleanup
                tier: T2
                targets: [ { path: "~/Library/Caches/dup/*" } ]
                regenerable: true
                evidence: Regenerated automatically by the app on next launch.
            """
        let r = parse(yaml)
        let errs = errors(r.issues + RuleLinter.lint(r.pack.map { [$0] } ?? []))
        #expect(errs.contains { $0.contains("must start with the pack id") })
        #expect(errs.contains { $0.contains("duplicate rule id") })
    }

    @Test func literalPrefix() {
        #expect(ProtectedPaths.literalPrefix(of: "~/Library/Caches/*/x") == "~/Library/Caches")
        #expect(ProtectedPaths.literalPrefix(of: "/tmp/a") == "/tmp/a")
        #expect(ProtectedPaths.literalPrefix(of: "/*") == "/")
    }
}
