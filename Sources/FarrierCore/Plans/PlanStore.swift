import Foundation

/// Plans on disk: `~/.farrier/plans/<id>.json`, canonical bytes, directory 0700 and files 0600.
/// A plan file is only a convenience: whatever it says, the helper re-checks the hash, signature and Mac.
public struct PlanStore: Sendable {
    public let directory: URL

    public init(directory: URL) { self.directory = directory }

    public static var `default`: PlanStore {
        PlanStore(directory: FileManager.default.homeDirectoryForCurrentUser.appendingPathComponent(".farrier/plans"))
    }

    public func save(_ plan: Plan) throws -> URL {
        let fm = FileManager.default
        try fm.createDirectory(at: directory, withIntermediateDirectories: true,
                               attributes: [.posixPermissions: NSNumber(value: 0o700)])
        let url = directory.appendingPathComponent("\(plan.id).json")
        guard fm.createFile(atPath: url.path, contents: try plan.canonicalData(),
                            attributes: [.posixPermissions: NSNumber(value: 0o600)]) else {
            throw PlanError("could not write \(url.path)")
        }
        return url
    }

    /// Loads by full id or a unique prefix (at least 4 characters).
    public func load(_ idOrPrefix: String) throws -> Plan {
        let wanted = idOrPrefix.lowercased()
        guard wanted.count >= 4, wanted.allSatisfy({ $0.isHexDigit || $0 == "-" }) else {
            throw PlanError("`\(idOrPrefix)` is not a plan id")
        }
        let matches = ids().filter { $0.hasPrefix(wanted) }
        guard let id = matches.first else { throw PlanError("no plan `\(idOrPrefix)` in \(directory.path)") }
        guard matches.count == 1 else { throw PlanError("`\(idOrPrefix)` matches \(matches.count) plans; give more of the id") }
        return try Plan.decodeCanonical(Data(contentsOf: directory.appendingPathComponent("\(id).json")))
    }

    public func ids() -> [String] {
        let names = (try? FileManager.default.contentsOfDirectory(atPath: directory.path)) ?? []
        return names.filter { $0.hasSuffix(".json") }.map { String($0.dropLast(5)) }.sorted()
    }
}
