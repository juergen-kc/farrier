import ArgumentParser
import FarrierCore
import FarrierMCP
import Foundation

/// Set by `--redact`: everything the CLI prints (text and JSON, stdout and notes) goes through it.
nonisolated(unsafe) var activeRedactor: Redactor?

/// Shadows Swift's `print` in this module, so `--redact` covers every line without touching each command.
func print(_ items: Any..., separator: String = " ", terminator: String = "\n") {
    let text = items.map { "\($0)" }.joined(separator: separator)
    Swift.print(activeRedactor?.redact(text) ?? text, terminator: terminator)
}

/// `--redact` for the commands whose output shows this Mac's details.
struct RedactOption: ParsableArguments {
    @Flag(help: "Replace user and account names, computer and host names, the hardware UUID, the MDM server and home folders (for output you share).")
    var redact = false

    func apply() {
        if redact || ProcessInfo.processInfo.environment["FARRIER_REDACT"] == "1" { activeRedactor = RedactionSetup.forThisMac() }
    }
}
