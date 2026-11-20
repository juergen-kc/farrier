import Foundation

/// Tries to read locations protected by TCC (Transparency, Consent and Control) and reports, per location,
/// whether this process could. The point: macOS attributes TCC checks to the "responsible process". For a
/// tool started from Terminal or by an AI client, that may be Terminal or the client, not Farrier, so
/// Farrier's own Full Disk Access grant may not apply. The helper, started by launchd, is its own responsible process.
public enum TCCProbe {
    public static func run(home: String, includeUserFolders: Bool) -> [[String: Any]] {
        var targets: [(category: String, path: String, kind: String)] = [
            ("fullDiskAccess", "/Library/Application Support/com.apple.TCC/TCC.db", "file"),
            ("fullDiskAccess", home + "/Library/Safari", "dir"),
            ("fullDiskAccess", home + "/Library/Mail", "dir"),
            ("fullDiskAccess", home + "/Library/Messages", "dir"),
            ("unprotected", home + "/Library/Caches", "dir"),  // control: should always work
        ]
        if includeUserFolders {
            // These can trigger a consent dialog. The app name in that dialog shows who TCC thinks is asking.
            targets += [
                ("userFolder", home + "/Desktop", "dir"),
                ("userFolder", home + "/Documents", "dir"),
                ("userFolder", home + "/Downloads", "dir"),
            ]
        }
        return targets.map { t in
            var r: [String: Any] = ["category": t.category, "path": t.path]
            do {
                if t.kind == "dir" {
                    r["entries"] = try FileManager.default.contentsOfDirectory(atPath: t.path).count
                } else {
                    let h = try FileHandle(forReadingFrom: URL(fileURLWithPath: t.path))
                    r["bytesRead"] = (try h.read(upToCount: 16) ?? Data()).count
                    try? h.close()
                }
                r["readable"] = true
            } catch {
                let ns = error as NSError
                r["readable"] = false
                r["error"] = "\(ns.domain) \(ns.code)"
                if let underlying = ns.userInfo[NSUnderlyingErrorKey] as? NSError {
                    r["posix"] = "\(underlying.domain) \(underlying.code)"  // EPERM (1) = TCC denial, ENOENT (2) = missing
                }
            }
            return r
        }
    }
}
