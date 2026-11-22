import Foundation

/// `launchd.items`: the launch daemons and agents outside /System, each with the program it runs and that
/// program's signature. Tier T0: these folders and their plists are world-readable by convention, and code-signature
/// checks need no privileges. Apps' embedded launchd jobs (SMAppService, `BundleProgram`) aren't in these folders
/// and need the Background Task Management database (T1, later).
public struct LaunchItemsCollector: Sendable {
    public struct Location: Sendable, Equatable {
        public let path: String
        public let scope: String
    }

    public static let fact = "launchd.items"

    public let locations: [Location]
    public let fileExists: @Sendable (String) -> Bool
    public let readFile: @Sendable (String) -> Data?
    /// File names in a directory; nil if it can't be listed.
    public let listDirectory: @Sendable (String) -> [String]?
    public let signatures: CodeSignatureChecking
    /// The first bytes of a file (to recognise a script by its `#!`), without reading all of a large binary.
    public let readHead: @Sendable (String) -> Data?
    /// The target of a symbolic link (as stored), or nil if the path isn't one. Only called on paths outside
    /// privacy-protected folders.
    public let symlinkDestination: @Sendable (String) -> String?
    public let home: String

    public init(home: String = FileManager.default.homeDirectoryForCurrentUser.path,
                locations: [Location]? = nil,
                fileExists: @escaping @Sendable (String) -> Bool = { FileManager.default.fileExists(atPath: $0) },
                readFile: @escaping @Sendable (String) -> Data? = { FileManager.default.contents(atPath: $0) },
                listDirectory: @escaping @Sendable (String) -> [String]? = { try? FileManager.default.contentsOfDirectory(atPath: $0) },
                signatures: CodeSignatureChecking = SecurityFrameworkSignatures(),
                readHead: (@Sendable (String) -> Data?)? = nil,
                symlinkDestination: @escaping @Sendable (String) -> String? = { try? FileManager.default.destinationOfSymbolicLink(atPath: $0) }) {
        self.home = home
        self.symlinkDestination = symlinkDestination
        self.readHead = readHead ?? { path in
            guard let handle = FileHandle(forReadingAtPath: path) else { return nil }
            defer { try? handle.close() }
            return try? handle.read(upToCount: 2)
        }
        self.locations = locations ?? [
            Location(path: "/Library/LaunchDaemons", scope: "system-daemon"),
            Location(path: "/Library/LaunchAgents", scope: "system-agent"),
            Location(path: home + "/Library/LaunchAgents", scope: "user-agent"),
        ]
        self.fileExists = fileExists
        self.readFile = readFile
        self.listDirectory = listDirectory
        self.signatures = signatures
    }

    static let searchPath = ["/usr/bin", "/bin", "/usr/sbin", "/sbin", "/usr/libexec"]

    public func collect() -> (value: FactValue?, note: CollectionNote) {
        let source = locations.map(\.path).joined(separator: ", ")
        let present = locations.filter { fileExists($0.path) }
        guard !present.isEmpty else {
            return (nil, CollectionNote(fact: Self.fact, status: .unavailable, source: source, detail: "no launchd folders"))
        }
        var items: [FactValue] = []
        var cache: [String: CodeSignatureInfo?] = [:]
        var ignored = 0
        for location in present {
            // An unlistable folder would make the inventory incomplete, so the whole fact is unknown.
            guard let names = listDirectory(location.path) else {
                return (nil, CollectionNote(fact: Self.fact, status: .failed, source: source, detail: "cannot list \(location.path)"))
            }
            for name in names.sorted() where name.hasSuffix(".plist") && !name.hasPrefix(".") {
                let path = location.path + "/" + name
                if let item = item(plist: path, scope: location.scope, cache: &cache) { items.append(item) } else { ignored += 1 }
            }
        }
        let unchecked = items.filter { $0.object?["signature"]?.object?["notarized"] == nil }.count
        let detail = "\(items.count) item(s)" + (unchecked > 0 ? ", \(unchecked) not fully checked" : "")
            + (ignored > 0 ? ", \(ignored) plist(s) without a program ignored (launchd can't run them)" : "")
        return (.array(items), CollectionNote(fact: Self.fact, status: .collected, source: source, detail: detail))
    }

    /// One job, or nil for a plist launchd can't run (no Program, ProgramArguments or BundleProgram: for example
    /// the empty placeholders an updater leaves behind). Those aren't jobs, so they don't affect the rule.
    func item(plist path: String, scope: String, cache: inout [String: CodeSignatureInfo?]) -> FactValue? {
        var o: [String: FactValue] = ["plist": .string(path), "scope": .string(scope)]
        guard let data = readFile(path) else {
            o["error"] = .string("cannot read the plist")
            return .object(o)
        }
        guard let plist = Parsers.propertyList(data)?.object else {
            o["error"] = .string("cannot parse the plist")
            return .object(o)
        }
        let runnable = plist["Program"] != nil || plist["ProgramArguments"] != nil || plist["BundleProgram"] != nil
        guard runnable else { return nil }
        if let label = plist["Label"]?.string { o["label"] = .string(label) }
        if case .bool(let b)? = plist["Disabled"] { o["disabled"] = .bool(b) }
        if case .bool(let b)? = plist["RunAtLoad"] { o["runAtLoad"] = .bool(b) }
        if let keepAlive = plist["KeepAlive"] {
            // KeepAlive is a bool or a dictionary of conditions (which also means "keep it running").
            if case .bool(let b) = keepAlive { o["keepAlive"] = .bool(b) } else if keepAlive.object != nil { o["keepAlive"] = .bool(true) }
        }

        let (program, arguments, problem) = Self.program(from: plist, fileExists: fileExists)
        if let problem {
            o["error"] = .string(problem)
            return .object(o)
        }
        guard let program else { return .object(o) }
        o["program"] = .string(program)
        if let operand = Self.interpreterOperand(program: program, arguments: Array(arguments.dropFirst())) {
            if operand.inline { o["inlineCommand"] = .bool(true) } else if let script = operand.script { o["script"] = .string(script) }
        }
        // The program and its arguments were read, so "no script" is a finding, not a gap. Jobs that end earlier
        // (unreadable plist, BundleProgram, unresolved program) lack this, and rules about scripts treat them as unknown.
        o["inspected"] = .bool(true)
        // Where the path really leads, without ever looking inside a privacy-protected folder (even a stat there
        // can prompt). `..` and symlinks into such a folder leave the program unchecked, never "missing".
        guard let resolved = resolvedOutsideProtectedFolders(program) else {
            o["error"] = .string("the program is in a privacy-protected folder (or reached through one); its signature wasn't checked")
            return .object(o)
        }
        if resolved != program { o["resolvedProgram"] = .string(resolved) }
        guard fileExists(resolved) else {
            o["programExists"] = .bool(false)
            // A job whose program is gone is a leftover; it's flagged so it gets reviewed and removed.
            o["signature"] = CodeSignatureInfo(valid: false, notarized: false, error: "program not found").factValue
            return .object(o)
        }
        o["programExists"] = .bool(true)
        if readHead(resolved) == Data("#!".utf8) {
            // launchd runs the script itself (through its #! line). Scripts can't be signed, so it's flagged for review.
            o["script"] = .string(program)
            o["signature"] = CodeSignatureInfo(valid: false, notarized: false,
                                               error: "a script (scripts can't be signed); review what it does").factValue
            return .object(o)
        }
        if cache[resolved] == nil { cache[resolved] = .some(signatures.check(path: resolved)) }
        if let info = cache[resolved] ?? nil { o["signature"] = info.factValue }
        return .object(o)
    }

    /// The program launchd runs: `Program`, else `ProgramArguments[0]` (found on the default PATH if relative).
    static func program(from plist: [String: FactValue], fileExists: (String) -> Bool)
        -> (program: String?, arguments: [String], problem: String?) {
        var arguments = plist["ProgramArguments"]?.array?.compactMap(\.string) ?? []
        // With BundleProgram, launchd runs that (inside the app) whatever ProgramArguments says; checking argv[0]
        // instead would check the wrong file.
        if plist["BundleProgram"] != nil {
            return (nil, arguments, "the program is inside an app (BundleProgram); not checked yet")
        }
        guard var first = plist["Program"]?.string ?? arguments.first, !first.isEmpty else {
            return (nil, arguments, "no Program or ProgramArguments")
        }
        func resolve(_ name: String) -> String? {
            name.hasPrefix("/") ? name : searchPath.map({ $0 + "/" + name }).first(where: fileExists)
        }
        guard var path = resolve(first) else {
            return (nil, arguments, "program `\(first)` is not an absolute path and wasn't found")
        }
        // `env [VAR=value…] command …`: the command is what runs.
        if (path as NSString).lastPathComponent == "env" {
            let rest = Array(arguments.dropFirst())
            guard let index = rest.firstIndex(where: { !$0.hasPrefix("-") && !$0.contains("=") }) else {
                return (nil, arguments, "`env` without a command")
            }
            first = rest[index]
            guard let command = resolve(first) else {
                return (nil, arguments, "program `\(first)` (run by env) is not an absolute path and wasn't found")
            }
            path = command
            arguments = Array(rest[index...])
        }
        return (path, arguments, nil)
    }

    /// For an interpreter, what it runs: a script operand, or an inline command (`sh -c`, `python3 -c`,
    /// `osascript -e`, …). Nil if the program isn't an interpreter. Options are parsed per interpreter, combined
    /// short flags included (`-lc`), and parsing stops at the first operand: the script's own arguments don't count.
    static func interpreterOperand(program: String, arguments: [String]) -> (script: String?, inline: Bool)? {
        let name = (program as NSString).lastPathComponent
        let shells: Set<String> = ["sh", "bash", "zsh", "dash", "ksh", "csh", "tcsh"]
        // Short options that run code given as an argument, and short options that take a separate argument.
        let inlineFlags: [String: Set<Character>] = [
            "python": ["c", "m"], "python3": ["c", "m"], "perl": ["e", "E"], "ruby": ["e"], "osascript": ["e"],
            "node": ["e", "p"], "php": ["r"],
        ]
        let takesArgument: [String: Set<Character>] = [
            "python": ["W", "X"], "python3": ["W", "X"], "perl": ["I", "M"], "ruby": ["I", "r"],
            "osascript": ["l"], "node": ["r"], "php": ["c", "d"],
        ]
        let isShell = shells.contains(name)
        guard isShell || inlineFlags[name] != nil else { return nil }
        let inline: Set<Character> = isShell ? ["c"] : inlineFlags[name] ?? []
        let withArgument: Set<Character> = isShell ? ["o", "O"] : takesArgument[name] ?? []

        var i = 0
        while i < arguments.count {
            let a = arguments[i]
            if a == "--" { return (i + 1 < arguments.count ? arguments[i + 1] : nil, false) }
            if a == "-" { return (nil, false) }  // reads the program from stdin
            if a.hasPrefix("--") {
                if ["--eval", "--print", "--command"].contains(where: { a == $0 || a.hasPrefix($0 + "=") }) { return (nil, true) }
                i += 1
                continue
            }
            if (a.hasPrefix("-") || (isShell && a.hasPrefix("+"))) && a.count > 1 {
                let flags = a.dropFirst()
                if flags.contains(where: inline.contains) { return (nil, true) }
                if let last = flags.last, withArgument.contains(last) { i += 1 }  // its argument follows
                i += 1
                continue
            }
            return (a, false)  // the first operand is the script
        }
        return (nil, false)
    }

    /// Folders macOS guards with privacy prompts (Files and Folders, removable and network volumes).
    func isPrivacyProtected(_ path: String) -> Bool {
        let folders = ["Desktop", "Documents", "Downloads", "Library/Mobile Documents", "Pictures", "Movies", "Music"]
            .map { home + "/" + $0 } + ["/Volumes"]
        return folders.contains { path == $0 || path.hasPrefix($0 + "/") }
    }

    /// The path with `.`/`..` and symlinks resolved one component at a time, checking each step BEFORE touching it.
    /// Nil if it leads into a privacy-protected folder, or loops.
    func resolvedOutsideProtectedFolders(_ path: String) -> String? {
        var pending = Self.components(path)
        var resolved: [String] = []
        var hops = 0
        while !pending.isEmpty {
            let c = pending.removeFirst()
            if c == "." { continue }
            if c == ".." { _ = resolved.popLast(); continue }
            let candidate = "/" + (resolved + [c]).joined(separator: "/")
            if isPrivacyProtected(candidate) { return nil }
            if let target = symlinkDestination(candidate) {
                hops += 1
                if hops > 32 { return nil }
                // A relative link is relative to the directory that holds it.
                if target.hasPrefix("/") { resolved = [] }
                pending = Self.components(target) + pending
                continue
            }
            resolved.append(c)
        }
        let result = "/" + resolved.joined(separator: "/")
        return isPrivacyProtected(result) ? nil : result
    }

    static func components(_ path: String) -> [String] {
        path.split(separator: "/", omittingEmptySubsequences: true).map(String.init)
    }
}
