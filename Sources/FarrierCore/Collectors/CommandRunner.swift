import Foundation

/// The output of an external command.
public struct CommandResult: Sendable, Hashable {
    public let status: Int32
    public let stdout: String
    public let stderr: String
    public let timedOut: Bool

    public init(status: Int32, stdout: String, stderr: String = "", timedOut: Bool = false) {
        self.status = status
        self.stdout = stdout
        self.stderr = stderr
        self.timedOut = timedOut
    }

    /// stdout and stderr together. Some Apple tools print their answer on stderr (`spctl --status` on some versions).
    public var combined: String { stdout + (stderr.isEmpty ? "" : "\n" + stderr) }
}

/// Runs external commands. A protocol so collectors can be tested with recorded outputs.
public protocol CommandRunning: Sendable {
    /// Returns nil if the executable doesn't exist (for example on Linux, or a tool missing on this macOS version).
    func run(_ executable: String, _ arguments: [String], timeout: TimeInterval) -> CommandResult?
}

/// Runs commands directly, never through a shell: absolute path, fixed arguments, a minimal environment with
/// `LANG=C` (so output is in English and parsers can rely on it), no stdin, and a timeout.
///
/// Output goes to temporary files rather than pipes. That way a chatty command can't fill a pipe buffer and
/// deadlock, and no closure has to cross threads (which keeps this simple under Swift 6 strict concurrency).
public struct ProcessRunner: CommandRunning {
    public init() {}

    public func run(_ executable: String, _ arguments: [String], timeout: TimeInterval = 10) -> CommandResult? {
        guard executable.hasPrefix("/"), FileManager.default.isExecutableFile(atPath: executable) else { return nil }

        let tmp = FileManager.default.temporaryDirectory
        let id = UUID().uuidString
        let outURL = tmp.appendingPathComponent("farrier-\(id).out")
        let errURL = tmp.appendingPathComponent("farrier-\(id).err")
        _ = FileManager.default.createFile(atPath: outURL.path, contents: nil)
        _ = FileManager.default.createFile(atPath: errURL.path, contents: nil)
        defer {
            try? FileManager.default.removeItem(at: outURL)
            try? FileManager.default.removeItem(at: errURL)
        }

        let process = Process()
        process.executableURL = URL(fileURLWithPath: executable)
        process.arguments = arguments
        process.environment = ["PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "LANG": "C", "LC_ALL": "C"]
        process.standardInput = FileHandle.nullDevice
        guard let out = try? FileHandle(forWritingTo: outURL), let err = try? FileHandle(forWritingTo: errURL) else { return nil }
        process.standardOutput = out
        process.standardError = err

        do { try process.run() } catch { return nil }
        let deadline = Date().addingTimeInterval(timeout)
        var timedOut = false
        while process.isRunning {
            if Date() > deadline {
                timedOut = true
                process.terminate()  // SIGTERM, which a process can ignore…
                break
            }
            usleep(10_000)
        }
        if timedOut {
            // …so give it a short grace period, then SIGKILL. The wait stays bounded either way.
            let killAt = Date().addingTimeInterval(2)
            while process.isRunning && Date() < killAt { usleep(10_000) }
            if process.isRunning { kill(process.processIdentifier, SIGKILL) }
            let giveUpAt = Date().addingTimeInterval(2)
            while process.isRunning && Date() < giveUpAt { usleep(10_000) }
            if process.isRunning {
                return CommandResult(status: -1, stdout: "", stderr: "did not exit after SIGKILL", timedOut: true)
            }
        }
        process.waitUntilExit()
        try? out.close()
        try? err.close()

        let stdout = (try? String(contentsOf: outURL, encoding: .utf8)) ?? ""
        let stderr = (try? String(contentsOf: errURL, encoding: .utf8)) ?? ""
        return CommandResult(status: process.terminationStatus, stdout: stdout, stderr: stderr, timedOut: timedOut)
    }
}

/// Plays back recorded outputs, keyed by "executable arg1 arg2". For tests and for `--replay`.
public struct RecordedRunner: CommandRunning {
    public let outputs: [String: CommandResult]

    public init(_ outputs: [String: CommandResult]) { self.outputs = outputs }

    public func run(_ executable: String, _ arguments: [String], timeout: TimeInterval) -> CommandResult? {
        outputs[([executable] + arguments).joined(separator: " ")]
    }
}
