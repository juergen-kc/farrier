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

    public init(valid: Bool, notarized: Bool?, appleSigned: Bool = false, adhoc: Bool = false, teamID: String? = nil,
                identifier: String? = nil, error: String? = nil) {
        self.valid = valid
        self.notarized = notarized
        self.appleSigned = appleSigned
        self.adhoc = adhoc
        self.teamID = teamID
        self.identifier = identifier
        self.error = error
    }

    public var factValue: FactValue {
        var o: [String: FactValue] = ["valid": .bool(valid), "appleSigned": .bool(appleSigned), "adhoc": .bool(adhoc)]
        if let notarized { o["notarized"] = .bool(notarized) }
        if let teamID { o["teamID"] = .string(teamID) }
        if let identifier { o["identifier"] = .string(identifier) }
        if let error { o["error"] = .string(error) }
        return .object(o)
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
            return CodeSignatureInfo(valid: false, notarized: false, error: reason)
        }

        var info: CFDictionary?
        _ = SecCodeCopySigningInformation(code, SecCSFlags(rawValue: kSecCSSigningInformation), &info)
        let dict = (info as? [String: Any]) ?? [:]
        let flags = (dict[kSecCodeInfoFlags as String] as? NSNumber)?.uint32Value ?? 0
        let adhoc = flags & 0x0002 != 0  // kSecCodeSignatureAdhoc

        let apple = satisfies(code, "anchor apple")
        let notarized = apple || satisfies(code, "notarized")
        return CodeSignatureInfo(valid: true, notarized: notarized, appleSigned: apple, adhoc: adhoc,
                                 teamID: dict[kSecCodeInfoTeamIdentifier as String] as? String,
                                 identifier: dict[kSecCodeInfoIdentifier as String] as? String)
        #else
        return nil
        #endif
    }

    #if canImport(Security) && os(macOS)
    private func satisfies(_ code: SecStaticCode, _ requirement: String) -> Bool {
        var req: SecRequirement?
        guard SecRequirementCreateWithString(requirement as CFString, [], &req) == errSecSuccess, let req else { return false }
        return SecStaticCodeCheckValidity(code, [], req) == errSecSuccess
    }
    #endif
}
