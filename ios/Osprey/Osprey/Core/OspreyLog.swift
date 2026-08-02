import Foundation
import OSLog

/// Subsystem loggers.
///
/// Nothing here ever takes key material, a pairing secret or a decrypted
/// payload: the unified log is readable by anyone with the device, and a
/// pairing secret that reaches it stops being a secret.
public enum OspreyLog {
    private static let subsystem = "com.ospreyremote.app"

    public static let identity = Logger(subsystem: subsystem, category: "identity")
    public static let pairing = Logger(subsystem: subsystem, category: "pairing")
    public static let network = Logger(subsystem: subsystem, category: "network")
    public static let session = Logger(subsystem: subsystem, category: "session")
    public static let scanner = Logger(subsystem: subsystem, category: "scanner")
}
