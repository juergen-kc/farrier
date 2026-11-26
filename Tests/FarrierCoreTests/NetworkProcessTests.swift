import Foundation
import MCP
import Testing
@testable import FarrierCore
@testable import FarrierMCP

private let top = """
Processes: 500 total, 2 running, 498 sleeping, 2500 threads
2026/11/26 07:00:00
Load Avg: 9.00, 9.00, 9.00
CPU usage: 50.00% user, 50.00% sys, 0.00% idle
PhysMem: 1G used (1M wired, 1M compressor), 1M unused.

PID    %CPU MEM    POWER COMMAND
1      99.0 1M     99.0  first sample
Processes: 512 total, 3 running, 509 sleeping, 2600 threads
2026/11/26 07:00:02
Load Avg: 1.52, 1.61, 1.70
CPU usage: 5.12% user, 8.20% sys, 86.67% idle
SharedLibs: 500M resident, 80M data, 40M linkedit.
PhysMem: 7642M used (1234M wired, 456M compressor), 381M unused.
VM: 200T vsize, 4G framework vsize.

PID    %CPU MEM    POWER COMMAND
375    12.5 220M+  14.2  Google Chrome Helper (Renderer)
88     40.1 1024K  2.0   WindowServer
501    0.0  2G     0.0   Xcode
42     3.0  12M-   0.0   mds_stores
"""

@Suite("Network and process tools")
struct NetworkProcessTests {
    @Test func topIsParsedFromTheSecondSample() {
        let p = ProcessSampler.parse(top: top, swap: "vm.swapusage: total = 2048.00M  used = 1024.50M  free = 1023.50M  (encrypted)",
                                     sampleSeconds: 2, count: 2)
        #expect(p.cpuUser == 5.12 && p.cpuSystem == 8.2 && p.cpuIdle == 86.67)
        #expect(p.load == [1.52, 1.61, 1.70])
        #expect(p.memoryUsed == 7642 * 1_048_576 && p.memoryWired == 1234 * 1_048_576 && p.memoryCompressed == 456 * 1_048_576)
        #expect(p.memoryUnused == 381 * 1_048_576 && p.processCount == 512)
        #expect(p.swapUsed == Int64(1024.5 * 1_048_576) && p.swapTotal == 2048 * 1_048_576)
        #expect(p.byCPU.map(\.command) == ["WindowServer", "Google Chrome Helper (Renderer)"])   // commands with spaces kept
        #expect(p.byMemory.map(\.command) == ["Xcode", "Google Chrome Helper (Renderer)"])
        #expect(p.byEnergy.map(\.pid) == [375, 88])                                                 // zero-energy left out
        #expect(!p.byCPU.contains { $0.command == "first sample" })
        #expect(ProcessSampler.bytes("12M+") == 12 * 1_048_576 && ProcessSampler.bytes("512B") == 512 && ProcessSampler.bytes("x") == nil)
    }

    @Test func networkOutputsAreParsed() {
        #expect(NetworkParsers.route("   route to: default\ndestination: default\n    gateway: 10.211.55.1\n  interface: en0\n")
                == .init(gateway: "10.211.55.1", interface: "en0"))
        #expect(NetworkParsers.route("route: writing to routing socket: not in table") == nil)
        let i = NetworkParsers.interface("en0", """
        en0: flags=8863<UP,BROADCAST,SMART,RUNNING,SIMPLEX,MULTICAST> mtu 1500
        \tinet6 fe80::1c2b:3a4d%en0 prefixlen 64 secured scopeid 0x4
        \tinet 10.211.55.5 netmask 0xffffff00 broadcast 10.211.55.255
        \tstatus: active
        """)
        #expect(i.ipv4 == ["10.211.55.5"] && i.ipv6 == ["fe80::1c2b:3a4d%en0"] && i.status == "active")
        let dns = NetworkParsers.resolvers("""
        DNS configuration

        resolver #1
          search domain[0] : corp.example.com
          nameserver[0] : 10.211.55.1
          nameserver[1] : 1.1.1.1
          flags    : Request A records
        resolver #2
          domain   : local
          options  : mdns

        DNS configuration (for scoped queries)

        resolver #1
          nameserver[0] : 9.9.9.9
        """)
        #expect(dns == [.init(nameservers: ["10.211.55.1", "1.1.1.1"], domain: nil, searchDomains: ["corp.example.com"])])
        let p = NetworkParsers.proxies("""
        <dictionary> {
          ExceptionsList : <array> {
            0 : *.local
            1 : 169.254/16
          }
          HTTPEnable : 1
          HTTPPort : 3128
          HTTPProxy : proxy.corp.example.com
          HTTPSEnable : 0
          ProxyAutoConfigEnable : 1
          ProxyAutoConfigURLString : http://wpad/proxy.pac
        }
        """)
        #expect(p.http == "proxy.corp.example.com:3128" && p.https == nil && p.autoConfigURL == "http://wpad/proxy.pac")
        #expect(p.exceptions == ["*.local", "169.254/16"] && !p.autoDiscovery)
        let q = NetworkParsers.quality(#"{"dl_throughput":250000000,"ul_throughput":40000000,"responsiveness":1200,"base_rtt":18.5}"#)
        #expect(q?.downloadMbps == 250 && q?.uploadMbps == 40 && q?.responsivenessRPM == 1200 && q?.baseRTTms == 18.5)
    }

    @Test func onlyHostnamesAreChecked() {
        for good in ["apple.com", "a-b.example.org", "localhost"] { #expect(NetworkParsers.isHostname(good)) }
        for bad in ["", "-oProxyCommand=x", "https://apple.com", "a b", "a..b", ".apple.com", "ä.com", "apple.com;ls"] {
            #expect(!NetworkParsers.isHostname(bad), "\(bad)")
        }
    }

    @Test func networkDiagnoseRunsFixedCommands() throws {
        let runner = RecordedRunner([
            "/sbin/route -n get default": CommandResult(status: 0, stdout: "gateway: 10.0.0.1\ninterface: en0\n"),
            "/sbin/ifconfig en0": CommandResult(status: 0, stdout: "\tinet 10.0.0.5 netmask 0xffffff00\n\tstatus: active\n"),
            "/usr/sbin/scutil --dns": CommandResult(status: 0, stdout: "resolver #1\n  nameserver[0] : 10.0.0.1\n"),
            "/usr/sbin/scutil --proxy": CommandResult(status: 0, stdout: "<dictionary> {\n  HTTPEnable : 0\n}\n"),
            "/usr/bin/dscacheutil -q host -a name example.com": CommandResult(status: 0, stdout: "name: example.com\nip_address: 93.184.216.34\n"),
            "/usr/bin/nc -z -G 5 example.com 443": CommandResult(status: 1, stdout: ""),
        ])
        let r = try NetworkDiagnose.run(host: "example.com", runner: runner)
        #expect(r.route?.gateway == "10.0.0.1" && r.interface?.ipv4 == ["10.0.0.5"] && r.resolvers.count == 1)
        #expect(r.checks.map(\.ok) == [true, false])
        #expect(r.checks[0].detail.contains("93.184.216.34") && r.checks[1].detail.contains("couldn't connect"))
        #expect(r.quality == nil)
        #expect(throws: PlanError.self) { try NetworkDiagnose.run(host: "-G 0 evil", runner: runner) }
    }

    @Test func mcpTools() throws {
        let dir = FileManager.default.temporaryDirectory.appendingPathComponent("farrier-ctx-\(UUID().uuidString)")
        defer { try? FileManager.default.removeItem(at: dir) }
        var ctx = FarrierContext(
            collectFacts: { CollectionResult(facts: [:], notes: []) }, rulePaths: [],
            plans: PlanStore(directory: dir.appendingPathComponent("plans")),
            journal: Journal(url: dir.appendingPathComponent("j.jsonl")),
            host: { "H" }, applyThroughHelper: { _ in throw OperationError("none") }, actor: "mcp:test")
        ctx.debugRunner = RecordedRunner([
            "/usr/bin/top -l 2 -s 3 -n 400 -o cpu -stats pid,cpu,mem,power,command": CommandResult(status: 0, stdout: top),
            "/usr/sbin/sysctl vm.swapusage": CommandResult(status: 0, stdout: "vm.swapusage: total = 0.00M  used = 0.00M  free = 0.00M"),
        ])
        let p = try ToolCatalog.call("process_snapshot", arguments: ["seconds": .int(3), "count": .int(3)], context: ctx)
        #expect(p.isError != true)
        #expect(p.structuredContent?.objectValue?["byCPU"]?.arrayValue?.count == 3)
        #expect(try ToolCatalog.call("process_snapshot", arguments: ["seconds": .int(60)], context: ctx).isError == true)
        #expect(try ToolCatalog.call("network_diagnose", arguments: ["host": .string("https://x")], context: ctx).isError == true)
        let net = try #require(ToolCatalog.tools.first { $0.name == "network_diagnose" })
        #expect(net.annotations.readOnlyHint == true && net.annotations.openWorldHint == true)
    }
}
