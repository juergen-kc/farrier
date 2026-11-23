import Foundation
#if canImport(Security)
import Security
#endif

/// What Farrier knows about a program's code signature.
public struct CodeSignatureInfo: Sendable, Equatable {
    /// The signature is intact (strict validation). False for unsigned code too.
    public var valid: Bool
    /// Notarized by Apple, or Apple's own code (which isn't notarized but is trusted the same way). Nil if it
    /// couldn't be determined.
    public var notarized: Bool?
    public var appleSigned: Bool
    public var adhoc: Bool
    public var teamID: String?
    public var identifier: String?
    /// Why the signature is invalid, or why it couldn't be checked.
    public var error: String?
    /// Gatekeeper's own verdict (`spctl --assess`), asked only when the offline checks say "not notarized" or
    /// "invalid": it also looks up notarization tickets online, which the static checks can't. Nil if not asked.
    public var gatekeeperAccepted: Bool?
    /// Gatekeeper's source, e.g. "Notarized Developer ID", "no usable signature".
    public var gatekeeperSource: String?

    public init(valid: Bool, notarized: Bool?, appleSigned: Bool = false, adhoc: Bool = false, teamID: String? = nil,
                identifier: String? = nil, error: String? = nil, gatekeeperAccepted: Bool? = nil, gatekeeperSource: String? = nil) {
        self.valid = valid
        self.notarized = notarized
        self.appleSigned = appleSigned
        self.adhoc = adhoc
        self.teamID = teamID
        self.identifier = identifier
        self.error = error
        self.gatekeeperAccepted = gatekeeperAccepted
        self.gatekeeperSource = gatekeeperSource
    }

    public var factValue: FactValue {
        var o: [String: FactValue] = ["valid": .bool(valid), "appleSigned": .bool(appleSigned), "adhoc": .bool(adhoc)]
        if let notarized { o["notarized"] = .bool(notarized) }
        if let teamID { o["teamID"] = .string(teamID) }
        if let identifier { o["identifier"] = .string(identifier) }
        if let error { o["error"] = .string(error) }
        if let gatekeeperAccepted { o["gatekeeperAccepted"] = .bool(gatekeeperAccepted) }
        if let gatekeeperSource { o["gatekeeperSource"] = .string(gatekeeperSource) }
        o["source"] = .string(source)
        return .object(o)
    }

    /// In Gatekeeper's words where it has them ("Notarized Developer ID", "Unnotarized Developer ID").
    public var source: String {
        // When Gatekeeper was asked and accepted the code, its words are the ones that count.
        if gatekeeperAccepted == true, let gatekeeperSource { return gatekeeperSource }
        if !valid {
            if error?.hasPrefix("a script") == true { return "Script" }
            if error == "program not found" { return "Missing program" }
            return error == "unsigned" ? "Unsigned" : "Invalid signature"
        }
        if appleSigned { return "Apple" }
        if adhoc { return "Ad hoc" }
        if teamID == nil { return "Unknown signer" }
        switch notarized {
        case true?: return "Notarized Developer ID"
        case false?: return "Unnotarized Developer ID"
        case nil: return "Developer ID (notarization unknown)"
        }
    }
}

/// Checks code signatures. Injectable, so collectors can be tested without real binaries.
public protocol CodeSignatureChecking: Sendable {
    /// Nil when signatures can't be checked on this platform.
    func check(path: String) -> CodeSignatureInfo?
}

/// The Security framework's static code checks, in-process (no `codesign` or `spctl` processes):
/// strict validation, Apple's anchor, and the `notarized` requirement.
public struct SecurityFrameworkSignatures: CodeSignatureChecking {
    public init() {}

    public func check(path: String) -> CodeSignatureInfo? {
        #if canImport(Security) && os(macOS)
        var code: SecStaticCode?
        let created = SecStaticCodeCreateWithPath(URL(fileURLWithPath: path) as CFURL, [], &code)
        guard created == errSecSuccess, let code else {
            return CodeSignatureInfo(valid: false, notarized: false, error: "cannot open the code (\(created))")
        }
        var cfError: Unmanaged<CFError>?
        // The executable and its signature, strictly; not every resource of a large app bundle (that takes seconds).
        let strict = SecCSFlags(rawValue: kSecCSStrictValidate | kSecCSCheckAllArchitectures | kSecCSDoNotValidateResources)
        let status = SecStaticCodeCheckValidityWithErrors(code, strict, nil, &cfError)
        guard status == errSecSuccess else {
            let reason = status == errSecCSUnsigned ? "unsigned"
                : (cfError?.takeRetainedValue()).map { CFErrorCopyDescription($0) as String } ?? "invalid (\(status))"
            var invalid = CodeSignatureInfo(valid: false, notarized: false, error: reason)
            // A second opinion: Gatekeeper's own assessment (it reads some signatures the strict static check rejects).
            if let (accepted, source) = assess(path) {
                invalid.gatekeeperAccepted = accepted
                invalid.gatekeeperSource = source
                if accepted && source == "Notarized Developer ID" { invalid.notarized = true }
            }
            return invalid
        }

        var info: CFDictionary?
        _ = SecCodeCopySigningInformation(code, SecCSFlags(rawValue: kSecCSSigningInformation), &info)
        let dict = (info as? [String: Any]) ?? [:]
        let flags = (dict[kSecCodeInfoFlags as String] as? NSNumber)?.uint32Value ?? 0
        let adhoc = flags & 0x0002 != 0  // kSecCodeSignatureAdhoc

        let apple = satisfies(code, "anchor apple")
        var notarized = apple || satisfies(code, "notarized")
        var info2 = CodeSignatureInfo(valid: true, notarized: notarized, appleSigned: apple, adhoc: adhoc,
                                      teamID: dict[kSecCodeInfoTeamIdentifier as String] as? String,
                                      identifier: dict[kSecCodeInfoIdentifier as String] as? String)
        // The "notarized" requirement only sees stapled or cached tickets; Gatekeeper also asks Apple.
        if !notarized && !adhoc, let (accepted, source) = assess(path) {
            info2.gatekeeperAccepted = accepted
            info2.gatekeeperSource = source
            if accepted && source == "Notarized Developer ID" { notarized = true; info2.notarized = true }
        }
        return info2
        #else
        return nil
        #endif
    }

    #if canImport(Security) && os(macOS)
    /// Gatekeeper's verdict for running the code (what `spctl --assess --type execute` reports), and its source.
    private func assess(_ path: String) -> (accepted: Bool, source: String?)? {
        let context = [kSecAssessmentContextKeyOperation: kSecAssessmentOperationTypeExecute] as CFDictionary
        var error: Unmanaged<CFError>?
        guard let assessment = SecAssessmentCreate(URL(fileURLWithPath: path) as CFURL, SecAssessmentFlags(0), context, &error) else {
            // A rejection can come back as an error carrying the same result dictionary.
            guard let e = error?.takeRetainedValue(), let info = CFErrorCopyUserInfo(e) as? [String: Any] else { return nil }
            return verdict(info)
        }
        guard let result = SecAssessmentCopyResult(assessment, SecAssessmentFlags(0))?.takeRetainedValue() as? [String: Any] else { return nil }
        return verdict(result)
    }

    private func verdict(_ result: [String: Any]) -> (accepted: Bool, source: String?)? {
        guard let accepted = result[kSecAssessmentAssessmentVerdict as String] as? Bool else { return nil }
        let authority = result[kSecAssessmentAssessmentAuthority as String] as? [String: Any]
        return (accepted, authority?[kSecAssessmentAssessmentSource as String] as? String)
    }

    private func satisfies(_ code: SecStaticCode, _ requirement: String) -> Bool {
        var req: SecRequirement?
        guard SecRequirementCreateWithString(requirement as CFString, [], &req) == errSecSuccess, let req else { return false }
        // The same executable-only validation as above: a resource problem elsewhere in a large bundle must not
        // read as "not notarized" or "not Apple".
        return SecStaticCodeCheckValidity(code, SecCSFlags(rawValue: kSecCSDoNotValidateResources), req) == errSecSuccess
    }
    #endif
}
