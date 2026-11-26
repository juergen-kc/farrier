import Foundation

/// What's using the Mac right now, from two `top` samples (the second one's figures are for the interval, unlike
/// `ps`'s long-run averages). Command names only, never arguments: those can hold tokens or file names.
public struct ProcessUsage: Codable, Sendable, Equatable {
    public let pid: Int
    public let command: String
    public let cpu: Double
    /// Resident memory, bytes.
    public let memory: Int64
    /// top's energy impact (POWER).
    public let energy: Double?
}

public struct ProcessSnapshot: Codable, Sendable {
    public let sampleSeconds: Int
    public let cpuUser: Double?
    public let cpuSystem: Double?
    public let cpuIdle: Double?
    public let load: [Double]
    public let memoryUsed: Int64?
    public let memoryWired: Int64?
    public let memoryCompressed: Int64?
    public let memoryUnused: Int64?
    public let swapUsed: Int64?
    public let swapTotal: Int64?
    public let processCount: Int?
    public let byCPU: [ProcessUsage]
    public let byMemory: [ProcessUsage]
    public let byEnergy: [ProcessUsage]
}

public enum ProcessSampler {
    /// `123M`, `1024K`, `2G`, `12M+`, `512B` → bytes.
    static func bytes(_ s: String) -> Int64? {
        var t = s.trimmingCharacters(in: CharacterSet(charactersIn: "+- "))
        guard let unit = t.last else { return nil }
        let factors: [Character: Double] = ["B": 1, "K": 1_024, "M": 1_048_576, "G": 1_073_741_824, "T": 1_099_511_627_776]
        var factor = 1.0
        if let f = factors[unit] { factor = f; t.removeLast() }
        guard let n = Double(t) else { return nil }
        return Int64(n * factor)
    }

    /// `top -l 2 -s N -n 40 -o cpu -stats pid,cpu,mem,power,command`: summary lines, then a table after a
    /// `PID %CPU MEM POWER COMMAND` header. Only the last sample is read; command (last column) may hold spaces.
    public static func parse(top: String, swap: String, sampleSeconds: Int, count: Int = 10) -> ProcessSnapshot {
        let lines = top.components(separatedBy: "\n")
        guard let lastHeader = lines.lastIndex(where: { $0.trimmingCharacters(in: .whitespaces).hasPrefix("PID") }) else {
            return empty(sampleSeconds, swap)
        }
        // The summary of the same sample: the lines between the previous sample's table and this header.
        let sampleStart = lines[..<lastHeader].lastIndex { $0.hasPrefix("Processes:") } ?? 0
        let summary = lines[sampleStart..<lastHeader]
        func line(_ prefix: String) -> String? { summary.first { $0.hasPrefix(prefix) } }

        var user: Double?, sys: Double?, idle: Double?
        if let c = line("CPU usage:") {
            func pct(_ word: String) -> Double? {
                guard let r = c.range(of: "% \(word)") else { return nil }
                let before = c[..<r.lowerBound]
                return Double(before.split(separator: " ").last ?? "")
            }
            user = pct("user"); sys = pct("sys"); idle = pct("idle")
        }
        var load: [Double] = []
        if let l = line("Load Avg:") {
            load = l.dropFirst("Load Avg:".count).split(separator: ",").compactMap { Double($0.trimmingCharacters(in: .whitespaces)) }
        }
        var used: Int64?, wired: Int64?, compressed: Int64?, unused: Int64?
        if let m = line("PhysMem:") {
            func value(before word: String) -> Int64? {
                guard let r = m.range(of: " \(word)") else { return nil }
                let token = m[..<r.lowerBound].split(whereSeparator: { $0 == " " || $0 == "(" || $0 == "," }).last
                return token.flatMap { bytes(String($0)) }
            }
            used = value(before: "used"); wired = value(before: "wired"); compressed = value(before: "compressor")
            unused = value(before: "unused")
        }
        let processes = line("Processes:").flatMap { Int($0.dropFirst("Processes:".count).split(separator: " ").first ?? "") }

        var rows: [ProcessUsage] = []
        for row in lines[(lastHeader + 1)...] {
            let parts = row.split(separator: " ", maxSplits: 4, omittingEmptySubsequences: true).map(String.init)
            guard parts.count == 5, let pid = Int(parts[0]), let cpu = Double(parts[1]), let mem = bytes(parts[2]) else { continue }
            rows.append(ProcessUsage(pid: pid, command: String(parts[4].trimmingCharacters(in: .whitespaces).prefix(100)),
                                     cpu: cpu, memory: mem, energy: Double(parts[3])))
        }
        let (swapUsed, swapTotal) = parseSwap(swap)
        return ProcessSnapshot(
            sampleSeconds: sampleSeconds, cpuUser: user, cpuSystem: sys, cpuIdle: idle, load: load,
            memoryUsed: used, memoryWired: wired, memoryCompressed: compressed, memoryUnused: unused,
            swapUsed: swapUsed, swapTotal: swapTotal, processCount: processes,
            byCPU: Array(rows.sorted { $0.cpu > $1.cpu }.prefix(count)),
            byMemory: Array(rows.sorted { $0.memory > $1.memory }.prefix(count)),
            byEnergy: Array(rows.filter { ($0.energy ?? 0) > 0 }.sorted { ($0.energy ?? 0) > ($1.energy ?? 0) }.prefix(count)))
    }

    static func empty(_ seconds: Int, _ swap: String) -> ProcessSnapshot {
        let (u, t) = parseSwap(swap)
        return ProcessSnapshot(sampleSeconds: seconds, cpuUser: nil, cpuSystem: nil, cpuIdle: nil, load: [], memoryUsed: nil,
                               memoryWired: nil, memoryCompressed: nil, memoryUnused: nil, swapUsed: u, swapTotal: t,
                               processCount: nil, byCPU: [], byMemory: [], byEnergy: [])
    }

    /// `vm.swapusage: total = 2048.00M  used = 1024.50M  free = 1023.50M  (encrypted)`.
    static func parseSwap(_ s: String) -> (used: Int64?, total: Int64?) {
        func field(_ name: String) -> Int64? {
            guard let r = s.range(of: "\(name) = ") else { return nil }
            return bytes(String(s[r.upperBound...].split(separator: " ").first ?? ""))
        }
        return (field("used"), field("total"))
    }

    public static func run(seconds: Int, count: Int, runner: CommandRunning = ProcessRunner()) throws -> ProcessSnapshot {
        guard seconds >= 1, seconds <= 10 else { throw PlanError("`seconds` must be between 1 and 10") }
        guard count >= 1, count <= 50 else { throw PlanError("`count` must be between 1 and 50") }
        let args = ["-l", "2", "-s", "\(seconds)", "-n", "400", "-o", "cpu", "-stats", "pid,cpu,mem,power,command"]
        guard let top = runner.run("/usr/bin/top", args, timeout: TimeInterval(seconds * 2 + 20)) else {
            throw PlanError("top isn't available here")
        }
        guard !top.timedOut, top.status == 0 else { throw PlanError("top failed (exit \(top.status))") }
        let swap = runner.run("/usr/sbin/sysctl", ["vm.swapusage"], timeout: 5)?.stdout ?? ""
        return parse(top: top.stdout, swap: swap, sampleSeconds: seconds, count: count)
    }
}
