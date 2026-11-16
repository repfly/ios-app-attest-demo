import Foundation

/// WebAuthn-style authenticator data as produced by App Attest.
///
/// Layout: rpIdHash[0..<32], flags[32], signCount (big-endian UInt32)[33..<37], then, when attested
/// credential data is present: aaguid[37..<53], credentialIdLength (big-endian UInt16)[53..<55],
/// credentialId[55..<55+len]. Anything after the credential ID (e.g. a COSE key) is ignored.
public struct AuthenticatorData: Equatable, Sendable {
    public let rpIdHash: [UInt8]
    public let flags: UInt8
    public let counter: UInt32
    public let aaguid: [UInt8]?
    public let credentialId: [UInt8]?

    public enum ParseError: Error, CustomStringConvertible {
        case tooShort(Int)
        case truncatedAttestedCredentialData
        case truncatedCredentialId(declared: Int, available: Int)

        public var description: String {
            switch self {
            case let .tooShort(n): return "authenticator data is \(n) bytes; at least 37 required"
            case .truncatedAttestedCredentialData: return "attested credential data is truncated (need 55 bytes for aaguid + length)"
            case let .truncatedCredentialId(d, a): return "credential ID declares \(d) bytes but only \(a) remain"
            }
        }
    }

    public init(_ data: [UInt8]) throws {
        guard data.count >= 37 else { throw ParseError.tooShort(data.count) }
        rpIdHash = Array(data[0..<32])
        flags = data[32]
        counter = data[33..<37].reduce(0) { ($0 << 8) | UInt32($1) }

        if data.count > 37 {
            guard data.count >= 55 else { throw ParseError.truncatedAttestedCredentialData }
            aaguid = Array(data[37..<53])
            let len = Int(data[53]) << 8 | Int(data[54])
            guard data.count >= 55 + len else {
                throw ParseError.truncatedCredentialId(declared: len, available: data.count - 55)
            }
            credentialId = Array(data[55..<(55 + len)])
        } else {
            aaguid = nil
            credentialId = nil
        }
    }
}
