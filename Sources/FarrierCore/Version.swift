/// One version for the CLI and the helper. The helper compares the client's version on every call and exits
/// after replying when they differ, so an updated app never talks to a stale helper (SMAppService/XPC spike, X29).
public enum FarrierVersion {
    public static let string = "0.1.0-dev"
}
