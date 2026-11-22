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
/// Output is read through pipes, each drained on its own thread while the command runs, so a chatty command
/// can't fill a pipe buffer and stall. (Temporary files were used before; on macOS 27, `netstat` wrote nothing to
/// a file handle opened that way, while the same call through a pipe worked.)
public struct ProcessRunner: CommandRunning {
    public init() {}

    /// Collects one pipe's bytes on a background thread.
    private final class Drain: @unchecked Sendable {
        private let lock = NSLock()
        private var data = Data()
        private let done = DispatchSemaphore(value: 0)

        init(_ handle: FileHandle) {
            DispatchQueue.global(qos: .userInitiated).async { [self] in
                let bytes = handle.readDataToEndOfFile()
                lock.lock(); data = bytes; lock.unlock()
                done.signal()
            }
        }

        /// The bytes read, waiting at most `timeout` for end-of-file (a background grandchild may keep the pipe open).
        func result(timeout: TimeInterval) -> Data {
            _ = done.wait(timeout: .now() + timeout)
            lock.lock(); defer { lock.unlock() }
            return data
        }
    }

    public func run(_ executable: String, _ arguments: [String], timeout: TimeInterval = 10) -> CommandResult? {
        guard executable.hasPrefix("/"), FileManager.default.isExecutableFile(atPath: executable) else { return nil }

        let process = Process()
        process.executableURL = URL(fileURLWithPath: executable)
        process.arguments = arguments
        process.environment = ["PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "LANG": "C", "LC_ALL": "C"]
        process.standardInput = FileHandle.nullDevice
        let outPipe = Pipe(), errPipe = Pipe()
        process.standardOutput = outPipe
        process.standardError = errPipe

        do { try process.run() } catch { return nil }
        // Our copies of the write ends must close, or end-of-file never comes.
        try? outPipe.fileHandleForWriting.close()
        try? errPipe.fileHandleForWriting.close()
        let out = Drain(outPipe.fileHandleForReading)
        let err = Drain(errPipe.fileHandleForReading)

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

        // Lenient decoding: one byte that isn't valid UTF-8 must not throw away the whole output. Invalid bytes
        // become U+FFFD, which no parser matches by accident.
        let outData = out.result(timeout: 2), errData = err.result(timeout: 2)
        let stdout = String(decoding: outData, as: UTF8.self)
        let stderr = String(decoding: errData, as: UTF8.self)
        if ProcessInfo.processInfo.environment["FARRIER_DEBUG_COMMANDS"] == "1" {
            // Diagnostics only (stderr, opt-in): what ran and what came back.
            let elapsed = String(format: "%.2f", Date().timeIntervalSince(deadline.addingTimeInterval(-timeout)))
            let head = stdout.prefix(120).replacingOccurrences(of: "\n", with: "⏎")
            FileHandle.standardError.write(Data(("[farrier run] \(([executable] + arguments).joined(separator: " ")) → exit \(process.terminationStatus)"
                + " reason \(process.terminationReason.rawValue) \(elapsed)s out \(outData.count)B err \(errData.count)B"
                + (timedOut ? " TIMED OUT" : "") + " | \(head)\n").utf8))
        }
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
