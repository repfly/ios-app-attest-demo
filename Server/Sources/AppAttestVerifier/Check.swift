import Crypto
import Foundation

/// One row of a verification checklist.
public struct Check: Codable, Equatable, Sendable {
    public enum Status: String, Codable, Sendable {
        case passed
        case failed
        case skipped
    }

    public var name: String
    public var status: Status
    public var detail: String

    public init(name: String, status: Status, detail: String) {
        self.name = name
        self.status = status
        self.detail = detail
    }

    public static func passed(_ name: String, _ detail: String) -> Check { .init(name: name, status: .passed, detail: detail) }
    public static func failed(_ name: String, _ detail: String) -> Check { .init(name: name, status: .failed, detail: detail) }
    public static func skipped(_ name: String, _ detail: String = "Skipped because an earlier step failed") -> Check {
        .init(name: name, status: .skipped, detail: detail)
    }

    /// Builds a passed/failed check from a condition.
    public static func expect(_ name: String, _ ok: Bool, pass: String, fail: String) -> Check {
        ok ? .passed(name, pass) : .failed(name, fail)
    }
}

extension Array where Element == Check {
    /// True when there is at least one check and none failed or were skipped.
    public var allPassed: Bool { !isEmpty && allSatisfy { $0.status == .passed } }
}

/// The App Attest environment encoded in the attestation's AAGUID.
public enum AppAttestEnvironment: String, Codable, Sendable, CaseIterable {
    case development
    case production

    /// "appattestdevelop" (16 bytes) or "appattest" followed by seven zero bytes.
    public var aaguid: [UInt8] {
        switch self {
        case .development: return Array("appattestdevelop".utf8)
        case .production: return Array("appattest".utf8) + [UInt8](repeating: 0, count: 7)
        }
    }

    public init?(aaguid: [UInt8]) {
        guard let env = Self.allCases.first(where: { $0.aaguid == aaguid }) else { return nil }
        self = env
    }
}

enum Util {
    static func sha256(_ bytes: [UInt8]) -> [UInt8] { Array(SHA256.hash(data: bytes)) }

    static func hex(_ bytes: [UInt8], max: Int = 8) -> String {
        let s = bytes.prefix(max).map { String(format: "%02x", $0) }.joined()
        return bytes.count > max ? s + "…" : s
    }
}
