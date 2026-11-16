import Crypto
import Foundation
import SwiftASN1
import X509

/// A throwaway CA that plays "fake Apple" for simulated attestation (`ALLOW_SIMULATED=1`).
///
/// It does what Apple's servers do inside `DCAppAttestService.attestKey`: it certifies the app's
/// public key and embeds the nonce in extension 1.2.840.113635.100.8.2. The root and intermediate
/// are generated in memory on each start; nothing is written to disk and the private keys never
/// leave this process. Certificates issued here only validate against `root`, never against
/// Apple's App Attest root.
public struct SimulatedAppAttestCA: Sendable {
    public static let rootName = "Simulated App Attest Test Root CA (not Apple)"
    public static let intermediateName = "Simulated App Attest CA 1 (not Apple)"
    /// How long an issued leaf is valid, like Apple's short-lived attestation certificates.
    public static let leafLifetime: TimeInterval = 3 * 86400

    public enum IssueError: Error, CustomStringConvertible {
        case invalidPublicKey
        case invalidNonce(Int)

        public var description: String {
            switch self {
            case .invalidPublicKey: return "publicKey is not a P-256 key in X9.63 form (65 bytes, 0x04 ‖ X ‖ Y)"
            case let .invalidNonce(n): return "nonce is \(n) bytes; expected 32 (SHA-256(authData ‖ clientDataHash))"
            }
        }
    }

    public let root: Certificate
    public let intermediate: Certificate
    private let intermediateKey: P256.Signing.PrivateKey

    public init(now: Date = Date()) throws {
        let rootKey = P256.Signing.PrivateKey()
        let intermediateKey = P256.Signing.PrivateKey()
        let rootDN = try DistinguishedName { CommonName(Self.rootName) }
        let interDN = try DistinguishedName { CommonName(Self.intermediateName) }
        let notBefore = now.addingTimeInterval(-3600) // tolerate small clock differences
        root = try Certificate(
            version: .v3, serialNumber: .init(), publicKey: .init(rootKey.publicKey),
            notValidBefore: notBefore, notValidAfter: now.addingTimeInterval(86400 * 365),
            issuer: rootDN, subject: rootDN, signatureAlgorithm: .ecdsaWithSHA256,
            extensions: try Certificate.Extensions {
                Critical(BasicConstraints.isCertificateAuthority(maxPathLength: nil))
                Critical(KeyUsage(keyCertSign: true, cRLSign: true))
            },
            issuerPrivateKey: .init(rootKey)
        )
        intermediate = try Certificate(
            version: .v3, serialNumber: .init(), publicKey: .init(intermediateKey.publicKey),
            notValidBefore: notBefore, notValidAfter: now.addingTimeInterval(86400 * 365),
            issuer: rootDN, subject: interDN, signatureAlgorithm: .ecdsaWithSHA256,
            extensions: try Certificate.Extensions {
                Critical(BasicConstraints.isCertificateAuthority(maxPathLength: 0))
                Critical(KeyUsage(keyCertSign: true, cRLSign: true))
            },
            issuerPrivateKey: .init(rootKey)
        )
        self.intermediateKey = intermediateKey
    }

    /// Issues a leaf for `publicKeyX963` carrying `nonce`, and returns `[leaf, intermediate]` as DER,
    /// in the order of an attestation object's `x5c`.
    public func issue(publicKeyX963: [UInt8], nonce: [UInt8], now: Date = Date()) throws -> [[UInt8]] {
        guard let key = try? P256.Signing.PublicKey(x963Representation: publicKeyX963) else {
            throw IssueError.invalidPublicKey
        }
        guard nonce.count == 32 else { throw IssueError.invalidNonce(nonce.count) }
        let keyID = Util.sha256(Array(key.x963Representation))
        // SEQUENCE { [1] EXPLICIT OCTET STRING(32) }, the shape AttestationVerifier.parseNonceExtension reads.
        let nonceExtension: [UInt8] = [0x30, 0x24, 0xA1, 0x22, 0x04, 0x20] + nonce
        let leaf = try Certificate(
            version: .v3, serialNumber: .init(), publicKey: .init(key),
            notValidBefore: now.addingTimeInterval(-300), notValidAfter: now.addingTimeInterval(Self.leafLifetime),
            issuer: intermediate.subject,
            subject: try DistinguishedName { CommonName(keyID.map { String(format: "%02x", $0) }.joined()) },
            signatureAlgorithm: .ecdsaWithSHA256,
            extensions: try Certificate.Extensions {
                Critical(KeyUsage(digitalSignature: true))
                Certificate.Extension(oid: AttestationVerifier.nonceExtensionOID, critical: false, value: nonceExtension[...])
            },
            issuerPrivateKey: .init(intermediateKey)
        )
        return [try Self.der(leaf), try Self.der(intermediate)]
    }

    static func der(_ cert: Certificate) throws -> [UInt8] {
        var s = DER.Serializer()
        try s.serialize(cert)
        return s.serializedBytes
    }
}
