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
    public let home: String

    public init(home: String = FileManager.default.homeDirectoryForCurrentUser.path,
                locations: [Location]? = nil,
                fileExists: @escaping @Sendable (String) -> Bool = { FileManager.default.fileExists(atPath: $0) },
                readFile: @escaping @Sendable (String) -> Data? = { FileManager.default.contents(atPath: $0) },
                listDirectory: @escaping @Sendable (String) -> [String]? = { try? FileManager.default.contentsOfDirectory(atPath: $0) },
                signatures: CodeSignatureChecking = SecurityFrameworkSignatures(),
                readHead: (@Sendable (String) -> Data?)? = nil) {
        self.home = home
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

    /// Interpreters: when one is the program, the script it runs is what matters, and scripts can't be signed.
    static let interpreters: Set<String> = ["sh", "bash", "zsh", "dash", "ksh", "csh", "tcsh", "python", "python3",
                                            "perl", "ruby", "osascript", "node", "php", "env"]
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
        if Self.interpreters.contains((program as NSString).lastPathComponent) {
            let operands = arguments.dropFirst().filter { !$0.hasPrefix("-") }
            if arguments.contains("-c") || arguments.contains("-e") {
                o["inlineCommand"] = .bool(true)
            } else if let script = operands.first {
                o["script"] = .string(script)
            }
        }
        guard fileExists(program) else {
            o["programExists"] = .bool(false)
            // A job whose program is gone is a leftover; it's flagged so it gets reviewed and removed.
            o["signature"] = CodeSignatureInfo(valid: false, notarized: false, error: "program not found").factValue
            return .object(o)
        }
        o["programExists"] = .bool(true)
        if isPrivacyProtected(program) {
            // Reading it could trigger a privacy prompt for the terminal; the signature stays unknown.
            o["error"] = .string("the program is in a privacy-protected folder; its signature wasn't checked")
            return .object(o)
        }
        if readHead(program) == Data("#!".utf8) {
            // launchd runs the script itself (through its #! line). Scripts can't be signed, so it's flagged for review.
            o["script"] = .string(program)
            o["signature"] = CodeSignatureInfo(valid: false, notarized: false,
                                               error: "a script (scripts can't be signed); review what it does").factValue
            return .object(o)
        }
        if cache[program] == nil { cache[program] = .some(signatures.check(path: program)) }
        if let info = cache[program] ?? nil { o["signature"] = info.factValue }
        return .object(o)
    }

    /// The program launchd runs: `Program`, else `ProgramArguments[0]` (found on the default PATH if relative).
    static func program(from plist: [String: FactValue], fileExists: (String) -> Bool)
        -> (program: String?, arguments: [String], problem: String?) {
        let arguments = plist["ProgramArguments"]?.array?.compactMap(\.string) ?? []
        if plist["BundleProgram"] != nil && plist["Program"] == nil && arguments.isEmpty {
            return (nil, [], "the program is inside an app (BundleProgram); not checked yet")
        }
        guard let first = plist["Program"]?.string ?? arguments.first, !first.isEmpty else {
            return (nil, arguments, "no Program or ProgramArguments")
        }
        if first.hasPrefix("/") { return (first, arguments, nil) }
        if let found = searchPath.map({ $0 + "/" + first }).first(where: fileExists) { return (found, arguments, nil) }
        return (nil, arguments, "program `\(first)` is not an absolute path and wasn't found")
    }

    func isPrivacyProtected(_ path: String) -> Bool {
        ["Desktop", "Documents", "Downloads", "Library/Mobile Documents", "Pictures", "Movies", "Music"]
            .contains { path.hasPrefix(home + "/" + $0 + "/") }
    }
}
