import Foundation
import Testing
@testable import FarrierCore
@testable import FarrierMCP
import MCP

@Suite("Redaction")
struct RedactionTests {
    let r = Redactor(secrets: [
        .init("juergen", "<user>"), .init("Jürgen Klaaßen", "<user name>"), .init("kiosk", "<account-1>"),
        .init("macos-dev", "<host>"), .init("8E5C0F3A-1111-4000-8000-0000000000AA", "<host-id>"),
        .init("mdm.example.com", "<mdm-server>"), .init("ab", "<x>"), .init("root", "<root>"),
    ])

    @Test func replacesNamesHostsAndIDs() {
        #expect(r.redact("console user juergen on macos-dev") == "console user <user> on <host>")
        #expect(r.redact("Jürgen Klaaßen's Mac") == "<user name>'s Mac")
        #expect(r.redact(#"{"host":"8E5C0F3A-1111-4000-8000-0000000000AA","server":"mdm.example.com"}"#)
                == #"{"host":"<host-id>","server":"<mdm-server>"}"#)
        #expect(r.redact("admins: kiosk, root") == "admins: <account-1>, root")   // system accounts stay
    }

    @Test func homeFoldersOfAnyone() {
        #expect(r.redact("/Users/juergen/Library/LaunchAgents/x.plist") == "/Users/<user>/Library/LaunchAgents/x.plist")
        #expect(r.redact("/Users/someone-else/Applications/A.app") == "/Users/<user>/Applications/A.app")
        #expect(r.redact("/Users/Shared/thing") == "/Users/Shared/thing")
    }

    @Test func emailAddresses() {
        #expect(r.redact("managed by it-team@example.co.uk, see notes") == "managed by <email>, see notes")
    }

    @Test func onlyWholeWords() {
        // Not inside longer names or identifiers, and short values are never replaced.
        #expect(r.redact("juergenx dev.juergen-app kiosks") == "juergenx dev.juergen-app kiosks")
        #expect(r.redact("about tab") == "about tab")
    }

    @Test func jsonStaysValid() throws {
        let original = #"{"path":"/Users/juergen/x","name":"juergen","list":["kiosk","root"]}"#
        let redacted = r.redactJSON(Data(original.utf8))
        let parsed = try JSONSerialization.jsonObject(with: redacted) as? [String: Any]
        #expect(parsed?["name"] as? String == "<user>")
        #expect(parsed?["path"] as? String == "/Users/<user>/x")
        #expect(parsed?["list"] as? [String] == ["<account-1>", "root"])
    }
}

@Suite("Redaction in MCP results")
struct MCPRedactionTests {
    @Test func toolResultsAndResourcesAreRedacted() throws {
        let r = Redactor(secrets: [.init("juergen", "<user>"), .init("8E5C0F3A-1111-4000-8000-0000000000AA", "<host-id>")])
        let tool = try ToolCatalog.result(["host": "8E5C0F3A-1111-4000-8000-0000000000AA", "path": "/Users/juergen/x"])
        let redacted = FarrierMCPServer.redacted(tool, r)
        let structured = try #require(redacted.structuredContent?.objectValue)
        #expect(structured["host"]?.stringValue == "<host-id>")
        #expect(structured["path"]?.stringValue == "/Users/<user>/x")
        let json = String(decoding: try JSONEncoder().encode(redacted), as: UTF8.self)
        #expect(!json.contains("juergen") && !json.contains("8E5C0F3A"))   // the text copy too
        let resource = ReadResource.Result(contents: [.text("{\"actor\":\"juergen\"}", uri: "farrier://journal/recent")])
        #expect(FarrierMCPServer.redacted(resource, r).contents.first?.text == "{\"actor\":\"<user>\"}")
    }
}
