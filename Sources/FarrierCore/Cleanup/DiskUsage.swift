import Foundation

/// The volume the home folder is on.
public struct VolumeUsage: Sendable, Codable, Equatable {
    public let totalBytes: Int64
    /// Free now.
    public let availableBytes: Int64
    /// Free once macOS removes purgeable data (caches it manages, iCloud copies it can download again, local
    /// snapshots): what macOS shows as available. macOS only.
    public let availableWithPurgeableBytes: Int64?
    public var purgeableBytes: Int64? { availableWithPurgeableBytes.map { max(0, $0 - availableBytes) } }

    public init(totalBytes: Int64, availableBytes: Int64, availableWithPurgeableBytes: Int64?) {
        self.totalBytes = totalBytes
        self.availableBytes = availableBytes
        self.availableWithPurgeableBytes = availableWithPurgeableBytes
    }

    enum CodingKeys: String, CodingKey { case totalBytes, availableBytes, availableWithPurgeableBytes, purgeableBytes }

    public func encode(to encoder: Encoder) throws {
        var c = encoder.container(keyedBy: CodingKeys.self)
        try c.encode(totalBytes, forKey: .totalBytes)
        try c.encode(availableBytes, forKey: .availableBytes)
        try c.encodeIfPresent(availableWithPurgeableBytes, forKey: .availableWithPurgeableBytes)
        try c.encodeIfPresent(purgeableBytes, forKey: .purgeableBytes)
    }

    public init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        totalBytes = try c.decode(Int64.self, forKey: .totalBytes)
        availableBytes = try c.decode(Int64.self, forKey: .availableBytes)
        availableWithPurgeableBytes = try c.decodeIfPresent(Int64.self, forKey: .availableWithPurgeableBytes)
    }

    /// The live values for the volume holding `path`.
    public static func live(_ path: String) -> VolumeUsage? {
        let url = URL(fileURLWithPath: path)
        #if os(macOS)
        let keys: Set<URLResourceKey> = [.volumeTotalCapacityKey, .volumeAvailableCapacityKey,
                                         .volumeAvailableCapacityForImportantUsageKey]
        guard let v = try? url.resourceValues(forKeys: keys), let total = v.volumeTotalCapacity,
              let available = v.volumeAvailableCapacity else { return nil }
        return VolumeUsage(totalBytes: Int64(total), availableBytes: Int64(available),
                           availableWithPurgeableBytes: v.volumeAvailableCapacityForImportantUsage)
        #else
        guard let a = try? FileManager.default.attributesOfFileSystem(forPath: path),
              let total = (a[.systemSize] as? NSNumber)?.int64Value,
              let free = (a[.systemFreeSize] as? NSNumber)?.int64Value else { return nil }
        return VolumeUsage(totalBytes: total, availableBytes: free, availableWithPurgeableBytes: nil)
        #endif
    }
}

/// One measured place.
public struct UsageCategory: Sendable, Codable, Equatable {
    public let id: String
    public let title: String
    public let paths: [String]
    public let bytes: Int64
    /// Part of it couldn't be read (no permission, or too many entries to count): `bytes` is a lower bound.
    public let incomplete: Bool?
    public let note: String?
}

/// Space Farrier can free, and when (docs/ARCHITECTURE.md, Quarantine: nothing is freed until the quarantine is
/// emptied, so the numbers say when, not just how much).
public struct Reclaimable: Sendable, Codable, Equatable {
    /// Quarantined items past their 7 days: freed by an expiry plan now.
    public let nowBytes: Int64
    /// Quarantined items still in their 7 days: freed when they expire (or by an early expiry plan).
    public let afterExpiryBytes: Int64
    /// What the cleanup rules match now: freed after a cleanup plan moves it into the quarantine and it expires.
    public let cleanupCandidatesBytes: Int64
    public let cleanupCandidates: Int
}

public struct DiskUsageReport: Sendable, Codable {
    public let volume: VolumeUsage?
    public let categories: [UsageCategory]
    public let reclaimable: Reclaimable
    /// APFS local snapshots on the volume (macOS doesn't report their size; macOS removes them when space runs low).
    public let localSnapshots: Int?
    public let notes: [String]
}

public enum DiskUsage {
    /// What's measured, relative to the home folder unless absolute. Personal folders (Documents, Desktop,
    /// Downloads, …) aren't: macOS asks the user before an app reads them.
    public static let categories: [(id: String, title: String, paths: [String], note: String?)] = [
        ("caches", "Caches", ["~/Library/Caches"], nil),
        ("logs", "Logs", ["~/Library/Logs"], nil),
        ("xcode", "Xcode (DerivedData, archives, device support)", ["~/Library/Developer/Xcode"], nil),
        ("simulators", "Simulators", ["~/Library/Developer/CoreSimulator"], nil),
        ("packageManagers", "Package manager caches", ["~/.npm", "~/.cargo", "~/.gradle", "~/.m2", "~/go/pkg/mod", "~/Library/pnpm"], nil),
        ("trash", "Trash", ["~/.Trash"], "emptied in the Finder"),
        ("apps", "Applications", ["/Applications", "~/Applications"], nil),
        ("quarantine", "Farrier's quarantine", ["~/Library/Application Support/Farrier/Quarantine"], nil),
    ]

    public static let personalFoldersNote = "Documents, Desktop, Downloads, Pictures, Movies and Music aren't measured: "
        + "macOS asks before an app reads them"

    /// `localSnapshots`: the count, or nil where it can't be read. `entryLimit` bounds each category's count.
    public static func report(home: String, scan: CleanupReport, quarantine: [QuarantineManifest], volume: VolumeUsage?,
                              localSnapshots: Int?, now: Date = Date(), entryLimit: Int = 1_000_000) -> DiskUsageReport {
        let scanner = CleanupScanner(home: home, runningProcesses: { [] }, appInstalled: { _ in false }, entryLimit: entryLimit)
        var measured: [UsageCategory] = []
        for c in resolvedCategories(home: scanner.home) {
            var bytes: Int64 = 0, incomplete = false, found: [String] = []
            for path in c.paths {
                guard let entry = FileStat.lstat(path) else { continue }
                found.append(path)
                let m = scanner.measure(path, entry)
                bytes += m.bytes
                incomplete = incomplete || m.truncated
            }
            guard !found.isEmpty else { continue }
            var note = c.note
            if incomplete && c.id == "trash" {
                note = "macOS lets only apps with Full Disk Access read the Trash; at least this much"
            }
            measured.append(UsageCategory(id: c.id, title: c.title, paths: found, bytes: bytes,
                                            incomplete: incomplete ? true : nil, note: note))
        }
        let t = Int64(now.timeIntervalSince1970)
        let due = quarantine.filter { t >= $0.expiresAt }.reduce(0) { $0 + $1.quarantinedBytes }
        let held = quarantine.reduce(0) { $0 + $1.quarantinedBytes }
        let reclaimable = Reclaimable(nowBytes: due, afterExpiryBytes: held - due,
                                      cleanupCandidatesBytes: scan.bytes, cleanupCandidates: scan.candidates)
        var notes = [personalFoldersNote,
                     "moving items into the quarantine frees nothing: the space comes back when the quarantine is emptied"]
        if localSnapshots == nil { notes.append("local snapshots couldn't be listed") }
        return DiskUsageReport(volume: volume, categories: measured, reclaimable: reclaimable,
                               localSnapshots: localSnapshots, notes: notes)
    }

    static func resolvedCategories(home: String) -> [(id: String, title: String, paths: [String], note: String?)] {
        categories.map { c in (c.id, c.title, c.paths.map { $0.hasPrefix("~/") ? home + $0.dropFirst(1) : $0 }, c.note) }
    }

    /// `tmutil listlocalsnapshots /`: one `com.apple.TimeMachine.<date>.local` line per snapshot.
    public static func parseLocalSnapshots(_ output: String) -> Int {
        output.split(separator: "\n").filter { $0.contains("com.apple.") }.count
    }

    public static func liveLocalSnapshots(runner: CommandRunning = ProcessRunner()) -> Int? {
        #if os(macOS)
        guard let r = runner.run("/usr/bin/tmutil", ["listlocalsnapshots", "/"], timeout: 15), r.status == 0 else { return nil }
        return parseLocalSnapshots(r.stdout)
        #else
        return nil
        #endif
    }
}
