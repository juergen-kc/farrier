import Foundation

/// The network as this Mac sees it: the default route, the primary interface, DNS resolvers and proxies, plus timed
/// checks (DNS lookup, HTTPS connect) and, on request, `networkQuality`. Read-only; the checks reach the network.
public struct NetworkReport: Codable, Sendable {
    public struct Route: Codable, Sendable, Equatable { public let gateway: String?; public let interface: String? }
    public struct Interface: Codable, Sendable, Equatable {
        public let name: String
        public let status: String?
        public let ipv4: [String]
        public let ipv6: [String]
    }
    public struct Resolver: Codable, Sendable, Equatable {
        public let nameservers: [String]
        public let domain: String?
        public let searchDomains: [String]
    }
    public struct Proxies: Codable, Sendable, Equatable {
        public let http: String?
        public let https: String?
        public let socks: String?
        public let autoConfigURL: String?
        public let autoDiscovery: Bool
        public let exceptions: [String]
    }
    public struct Check: Codable, Sendable, Equatable {
        public let name: String
        public let ok: Bool
        public let milliseconds: Int?
        public let detail: String
    }
    public struct Quality: Codable, Sendable, Equatable {
        public let downloadMbps: Double?
        public let uploadMbps: Double?
        /// Round trips per minute under load (higher is better).
        public let responsivenessRPM: Double?
        public let baseRTTms: Double?
    }

    public let route: Route?
    public let interface: Interface?
    public let resolvers: [Resolver]
    public let proxies: Proxies?
    public let checks: [Check]
    public let quality: Quality?
    public let notes: [String]
}

public enum NetworkParsers {
    /// `route -n get default`: `gateway: 192.168.1.1` and `interface: en0` lines.
    public static func route(_ s: String) -> NetworkReport.Route? {
        func v(_ k: String) -> String? {
            s.split(separator: "\n").first { $0.trimmingCharacters(in: .whitespaces).hasPrefix("\(k):") }
                .map { $0.split(separator: ":", maxSplits: 1)[1].trimmingCharacters(in: .whitespaces) }
        }
        let gw = v("gateway"), iface = v("interface")
        return gw == nil && iface == nil ? nil : .init(gateway: gw, interface: iface)
    }

    /// `ifconfig en0`: `inet 192.168.1.20 netmask …`, `inet6 fe80::1%en0 prefixlen …`, `status: active`.
    public static func interface(_ name: String, _ s: String) -> NetworkReport.Interface {
        var v4: [String] = [], v6: [String] = [], status: String?
        for raw in s.split(separator: "\n") {
            let words = raw.trimmingCharacters(in: .whitespaces).split(separator: " ").map(String.init)
            guard let first = words.first else { continue }
            if first == "inet", words.count > 1 { v4.append(words[1]) }
            if first == "inet6", words.count > 1 { v6.append(words[1]) }
            if first == "status:", words.count > 1 { status = words[1] }
        }
        return .init(name: name, status: status, ipv4: v4, ipv6: v6)
    }

    /// `scutil --dns`, the first section (before "DNS configuration (for scoped queries)"): resolver blocks with
    /// `nameserver[0] : 1.1.1.1`, `domain : local`, `search domain[0] : example.com`.
    public static func resolvers(_ s: String) -> [NetworkReport.Resolver] {
        let main = s.components(separatedBy: "DNS configuration (for scoped queries)").first ?? s
        var out: [NetworkReport.Resolver] = []
        for block in main.components(separatedBy: "resolver #").dropFirst() {
            var ns: [String] = [], search: [String] = [], domain: String?
            for raw in block.split(separator: "\n") {
                let parts = raw.split(separator: ":", maxSplits: 1).map { $0.trimmingCharacters(in: .whitespaces) }
                guard parts.count == 2 else { continue }
                if parts[0].hasPrefix("nameserver[") { ns.append(parts[1]) }
                if parts[0].hasPrefix("search domain[") { search.append(parts[1]) }
                if parts[0] == "domain" { domain = parts[1] }
            }
            if !ns.isEmpty { out.append(.init(nameservers: ns, domain: domain, searchDomains: search)) }
        }
        return out
    }

    /// `scutil --proxy`: a `<dictionary> { HTTPEnable : 1  HTTPProxy : … }` listing.
    public static func proxies(_ s: String) -> NetworkReport.Proxies {
        var kv: [String: String] = [:], exceptions: [String] = []
        var inExceptions = false
        for raw in s.split(separator: "\n") {
            let line = raw.trimmingCharacters(in: .whitespaces)
            if line.hasPrefix("ExceptionsList") { inExceptions = true; continue }
            if inExceptions {
                if line == "}" { inExceptions = false; continue }
                if let r = line.range(of: " : ") { exceptions.append(String(line[r.upperBound...])) }
                continue
            }
            if let r = line.range(of: " : ") { kv[String(line[..<r.lowerBound])] = String(line[r.upperBound...]) }
        }
        func proxy(_ p: String) -> String? {
            guard kv["\(p)Enable"] == "1", let host = kv["\(p)Proxy"] else { return nil }
            return kv["\(p)Port"].map { "\(host):\($0)" } ?? host
        }
        let pac = kv["ProxyAutoConfigEnable"] == "1" ? kv["ProxyAutoConfigURLString"] : nil
        return .init(http: proxy("HTTP"), https: proxy("HTTPS"), socks: proxy("SOCKS"), autoConfigURL: pac,
                     autoDiscovery: kv["ProxyAutoDiscoveryEnable"] == "1", exceptions: exceptions)
    }

    /// `networkQuality -c`: JSON with `dl_throughput`/`ul_throughput` (bits/s), `responsiveness` (RPM), `base_rtt` (ms).
    public static func quality(_ s: String) -> NetworkReport.Quality? {
        guard let o = try? JSONSerialization.jsonObject(with: Data(s.utf8)) as? [String: Any] else { return nil }
        func d(_ k: String) -> Double? { (o[k] as? NSNumber)?.doubleValue }
        return .init(downloadMbps: d("dl_throughput").map { $0 / 1_000_000 }, uploadMbps: d("ul_throughput").map { $0 / 1_000_000 },
                     responsivenessRPM: d("responsiveness") ?? d("dl_responsiveness"), baseRTTms: d("base_rtt"))
    }

    /// A hostname: letters, digits, hyphens and dots, 1–253 characters. Anything else (spaces, flags, URLs) is refused.
    public static func isHostname(_ h: String) -> Bool {
        guard !h.isEmpty, h.count <= 253, !h.hasPrefix("-"), !h.hasPrefix("."), !h.contains("..") else { return false }
        return h.allSatisfy { $0.isASCII && ($0.isLetter || $0.isNumber || $0 == "-" || $0 == ".") }
    }
}

public enum NetworkDiagnose {
    public static func run(host: String = "apple.com", quality: Bool = false, runner: CommandRunning = ProcessRunner()) throws -> NetworkReport {
        guard NetworkParsers.isHostname(host) else { throw PlanError("`host` must be a hostname, e.g. apple.com") }
        var notes: [String] = []
        let route = runner.run("/sbin/route", ["-n", "get", "default"], timeout: 5).flatMap { NetworkParsers.route($0.stdout) }
        if route == nil { notes.append("no default route: this Mac isn't connected to a network") }
        var iface: NetworkReport.Interface?
        if let name = route?.interface, NetworkParsers.isHostname(name), let r = runner.run("/sbin/ifconfig", [name], timeout: 5) {
            iface = NetworkParsers.interface(name, r.stdout)
        }
        let resolvers = runner.run("/usr/sbin/scutil", ["--dns"], timeout: 5).map { NetworkParsers.resolvers($0.stdout) } ?? []
        if resolvers.isEmpty { notes.append("no DNS resolvers configured") }
        let proxies = runner.run("/usr/sbin/scutil", ["--proxy"], timeout: 5).map { NetworkParsers.proxies($0.stdout) }

        var checks: [NetworkReport.Check] = []
        // DNS: dscacheutil asks the system resolver, as apps do.
        let t0 = Date()
        let dns = runner.run("/usr/bin/dscacheutil", ["-q", "host", "-a", "name", host], timeout: 10)
        let dnsMs = Int(Date().timeIntervalSince(t0) * 1_000)
        let addresses = (dns?.stdout ?? "").split(separator: "\n").filter { $0.hasPrefix("ip_address:") || $0.hasPrefix("ipv6_address:") }
            .map { $0.split(separator: ":", maxSplits: 1)[1].trimmingCharacters(in: .whitespaces) }
        checks.append(.init(name: "dns", ok: !addresses.isEmpty, milliseconds: dns == nil ? nil : dnsMs,
                            detail: addresses.isEmpty ? "\(host) didn't resolve" : "\(host) → \(addresses.prefix(3).joined(separator: ", "))"))
        // HTTPS: a TCP connect to port 443 (nc -z, 5 s timeout); no data is sent.
        let t1 = Date()
        let tcp = runner.run("/usr/bin/nc", ["-z", "-G", "5", host, "443"], timeout: 10)
        let tcpMs = Int(Date().timeIntervalSince(t1) * 1_000)
        let connected = tcp?.status == 0
        checks.append(.init(name: "https", ok: connected, milliseconds: tcp == nil ? nil : tcpMs,
                            detail: connected ? "connected to \(host):443" : "couldn't connect to \(host):443\(proxies?.https != nil || proxies?.autoConfigURL != nil ? " (a proxy is set; direct connections may be blocked)" : "")"))

        var q: NetworkReport.Quality?
        if quality {
            if let r = runner.run("/usr/bin/networkQuality", ["-c"], timeout: 60), r.status == 0 {
                q = NetworkParsers.quality(r.stdout)
            } else {
                notes.append("networkQuality didn't finish")
            }
        }
        return NetworkReport(route: route, interface: iface, resolvers: resolvers, proxies: proxies, checks: checks, quality: q, notes: notes)
    }
}
