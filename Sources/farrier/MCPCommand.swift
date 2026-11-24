import ArgumentParser
import FarrierMCP

// MARK: - farrier mcp

struct MCPCommand: AsyncParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "mcp",
        abstract: "Run the MCP server on stdin/stdout (for Claude Code and other MCP clients).",
        discussion: """
        Register it with Claude Code (user scope, so it's available in every folder):
          claude mcp add --scope user farrier -- /Applications/Farrier.app/Contents/MacOS/farrier mcp
        Names, hosts, the hardware UUID, the MDM server and home folders are redacted from everything the client \
        receives (it may send them to a hosted model); --no-redact turns that off. \
        Tools: farrier_status, facts_collect, posture_check, posture_explain, posture_plan_remediation, plan_show, \
        plan_undo, apply_plan, inventory, journal_recent, exceptions_list, posture_plan_exception. Applying a plan that changes system settings asks for Touch ID or your password \
        on the Mac; the agent can't approve it. Set FARRIER_MCP_WIRE_LOG=1 to log every message to \
        ~/Library/Logs/Farrier/mcp-wire.log.
        """
    )

    @Flag(inversion: .prefixedNo,
          help: "Replace user and account names, computer and host names, the hardware UUID, the MDM server, home folders and email addresses in everything sent to the client (on by default).")
    var redact = true

    func run() async throws {
        try await FarrierMCPServer.run(redact: redact)
    }
}
