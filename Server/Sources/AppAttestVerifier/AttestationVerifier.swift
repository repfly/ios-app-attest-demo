import Crypto
import Foundation
import SwiftASN1
import X509

/// What the server stores after a successful attestation.
public struct VerifiedAttestation: Sendable, Equatable {
    /// The attested P-256 public key in X9.63 uncompressed form (0x04 ‖ X ‖ Y).
    public let publicKey: [UInt8]
    public let counter: UInt32
    /// Apple's receipt, which can later be exchanged for a fraud metric. Not used by this demo.
    public let receipt: [UInt8]
    public let environment: AppAttestEnvironment
    /// Which trust anchor the certificate chain ended at.
    public let anchor: TrustAnchor
}

/// The root a validated certificate chain ended at.
public enum TrustAnchor: String, Codable, Sendable {
    /// One of `AttestationVerifier.rootCertificates` (Apple's App Attest root in production).
    case apple
    /// One of `AttestationVerifier.testRootCertificates`: the simulated-mode test root, not Apple.
    case testRoot

    public var isSimulated: Bool { self == .testRoot }
}

public struct AttestationVerificationResult: Sendable {
    public var checks: [Check]
    /// Non-nil only when every check passed.
    public var verified: VerifiedAttestation?
    /// The root the certificate chain validated to, or nil if it did not validate.
    /// Set even when a later check failed, so a rejected simulated attestation is still labelled.
    public var anchor: TrustAnchor?
    public var passed: Bool { verified != nil }
}

/// Verifies an App Attest attestation object per Apple's
/// "Validating apps that connect to your server" steps.
public struct AttestationVerifier: Sendable {
    public enum CheckName {
        public static let decode = "Decode attestation object"
        public static let chain = "Certificate chain to Apple App Attest root"
        public static let nonce = "Nonce (authData ‖ clientDataHash) matches certificate"
        public static let keyId = "Key ID is SHA-256 of certificate public key"
        public static let rpId = "App ID matches (rpIdHash)"
        public static let counter = "Counter is 0"
        public static let aaguid = "AAGUID / environment"
        public static let credentialId = "Credential ID equals key ID"
    }

    /// Apple's App Attest nonce extension.
    public static let nonceExtensionOID: ASN1ObjectIdentifier = [1, 2, 840, 113635, 100, 8, 2]

    /// Apple's App Attest root CA.
    public var rootCertificates: [Certificate]
    /// Extra roots accepted only in simulated mode (`ALLOW_SIMULATED=1`). Empty by default, so a
    /// chain issued by the simulated CA fails unless the server explicitly opts in. Chains are tried
    /// against `rootCertificates` first; a chain that validates there is always reported as `.apple`.
    public var testRootCertificates: [Certificate]
    public var appID: String
    public var allowedEnvironments: Set<AppAttestEnvironment>

    public init(
        rootCertificates: [Certificate],
        testRootCertificates: [Certificate] = [],
        appID: String,
        allowedEnvironments: Set<AppAttestEnvironment> = Set(AppAttestEnvironment.allCases)
    ) {
        self.rootCertificates = rootCertificates
        self.testRootCertificates = testRootCertificates
        self.appID = appID
        self.allowedEnvironments = allowedEnvironments
    }

    private struct Decoded {
        let leaf: Certificate
        let intermediates: [Certificate]
        let authDataBytes: [UInt8]
        let authData: AuthenticatorData
        let receipt: [UInt8]
    }

    private enum DecodeError: Error, CustomStringConvertible {
        case message(String)
        var description: String { if case let .message(m) = self { return m }; return "" }
    }

    private static func decode(_ attestation: [UInt8]) throws -> Decoded {
        let root: CBORValue
        do { root = try CBORDecoder.decode(attestation) } catch {
            throw DecodeError.message("Not valid CBOR: \(error)")
        }
        guard case .map = root else { throw DecodeError.message("Top-level CBOR item is not a map") }
        guard let fmt = root["fmt"]?.textValue else { throw DecodeError.message("Missing text field 'fmt'") }
        guard fmt == "apple-appattest" else { throw DecodeError.message("fmt is \"\(fmt)\", expected \"apple-appattest\"") }
        guard let attStmt = root["attStmt"], case .map = attStmt else { throw DecodeError.message("Missing map field 'attStmt'") }
        guard let x5c = attStmt["x5c"]?.arrayValue else { throw DecodeError.message("Missing array 'attStmt.x5c'") }
        guard x5c.count >= 2 else { throw DecodeError.message("x5c has \(x5c.count) certificate(s); expected leaf + intermediate") }
        var certs: [Certificate] = []
        for (i, item) in x5c.enumerated() {
            guard let der = item.bytesValue else { throw DecodeError.message("x5c[\(i)] is not a byte string") }
            do { certs.append(try Certificate(derEncoded: der)) } catch {
                throw DecodeError.message("x5c[\(i)] is not a valid DER certificate: \(error)")
            }
        }
        guard let authDataBytes = root["authData"]?.bytesValue else { throw DecodeError.message("Missing byte string 'authData'") }
        let authData: AuthenticatorData
        do { authData = try AuthenticatorData(authDataBytes) } catch {
            throw DecodeError.message("authData: \(error)")
        }
        let receipt = attStmt["receipt"]?.bytesValue ?? []
        return Decoded(leaf: certs[0], intermediates: Array(certs.dropFirst()), authDataBytes: authDataBytes, authData: authData, receipt: receipt)
    }

    /// Runs every attestation check.
    ///
    /// - Parameters:
    ///   - attestation: The raw attestation object returned by `DCAppAttestService.attestKey`.
    ///   - keyID: The raw key identifier bytes (base64-decoded `keyId` string).
    ///   - clientDataHash: The hash the app passed to `attestKey` (here: SHA-256 of the challenge).
    ///   - validationTime: Time used for certificate validity checks.
    public func verify(
        attestation: [UInt8],
        keyID: [UInt8],
        clientDataHash: [UInt8],
        validationTime: Date = Date()
    ) async -> AttestationVerificationResult {
        let decoded: Decoded
        do {
            decoded = try Self.decode(attestation)
        } catch {
            let rest = [CheckName.chain, CheckName.nonce, CheckName.keyId, CheckName.rpId, CheckName.counter, CheckName.aaguid, CheckName.credentialId]
            return .init(checks: [.failed(CheckName.decode, "\(error)")] + rest.map { .skipped($0) }, verified: nil)
        }

        var checks: [Check] = [
            .passed(CheckName.decode, "fmt=apple-appattest, \(decoded.intermediates.count + 1) certificates, \(decoded.authDataBytes.count)-byte authData"),
        ]

        // 2. Certificate chain.
        let (chain, anchor) = await chainCheck(decoded, validationTime: validationTime)
        checks.append(chain)

        // 3. Nonce.
        let expectedNonce = Util.sha256(decoded.authDataBytes + clientDataHash)
        if let ext = decoded.leaf.extensions[oid: Self.nonceExtensionOID] {
            if let certNonce = Self.parseNonceExtension(Array(ext.value)) {
                checks.append(.expect(CheckName.nonce, certNonce == expectedNonce,
                                      pass: "nonce \(Util.hex(expectedNonce))",
                                      fail: "certificate nonce \(Util.hex(certNonce)) ≠ computed \(Util.hex(expectedNonce)) (wrong or reused challenge?)"))
            } else {
                checks.append(.failed(CheckName.nonce, "Nonce extension is not SEQUENCE { [1] OCTET STRING(32) }"))
            }
        } else {
            checks.append(.failed(CheckName.nonce, "Leaf certificate has no 1.2.840.113635.100.8.2 extension"))
        }

        // 4. Key ID = SHA256(public key).
        let publicKey = P256.Signing.PublicKey(decoded.leaf.publicKey)?.x963Representation.map { $0 }
        if let publicKey {
            let digest = Util.sha256(publicKey)
            checks.append(.expect(CheckName.keyId, digest == keyID,
                                  pass: "SHA-256(pubkey) = \(Util.hex(digest))",
                                  fail: "SHA-256(pubkey) = \(Util.hex(digest)) but keyId = \(Util.hex(keyID))"))
        } else {
            checks.append(.failed(CheckName.keyId, "Leaf public key is not P-256"))
        }

        // 5. rpIdHash.
        let appIDHash = Util.sha256(Array(appID.utf8))
        checks.append(.expect(CheckName.rpId, decoded.authData.rpIdHash == appIDHash,
                              pass: "SHA-256(\"\(appID)\")",
                              fail: "rpIdHash \(Util.hex(decoded.authData.rpIdHash)) ≠ SHA-256(\"\(appID)\") \(Util.hex(appIDHash)). Is APP_ID TEAMID.bundleID of this build?"))

        // 6. Counter.
        checks.append(.expect(CheckName.counter, decoded.authData.counter == 0,
                              pass: "counter = 0", fail: "counter = \(decoded.authData.counter), expected 0"))

        // 7. AAGUID.
        var environment: AppAttestEnvironment?
        if let aaguid = decoded.authData.aaguid {
            if let env = AppAttestEnvironment(aaguid: aaguid) {
                if allowedEnvironments.contains(env) {
                    environment = env
                    checks.append(.passed(CheckName.aaguid, "\(env.rawValue) (\"\(String(decoding: aaguid.prefix { $0 != 0 }, as: UTF8.self))\")"))
                } else {
                    checks.append(.failed(CheckName.aaguid, "\(env.rawValue) environment is not allowed by this server"))
                }
            } else {
                checks.append(.failed(CheckName.aaguid, "Unknown AAGUID \(Util.hex(aaguid, max: 16))"))
            }
        } else {
            checks.append(.failed(CheckName.aaguid, "authData has no attested credential data"))
        }

        // 8. Credential ID.
        if let credentialId = decoded.authData.credentialId {
            checks.append(.expect(CheckName.credentialId, credentialId == keyID,
                                  pass: "credentialId = keyId",
                                  fail: "credentialId \(Util.hex(credentialId)) ≠ keyId \(Util.hex(keyID))"))
        } else {
            checks.append(.failed(CheckName.credentialId, "authData has no credential ID"))
        }

        guard checks.allPassed, let publicKey, let environment, let anchor else {
            return .init(checks: checks, verified: nil, anchor: anchor)
        }
        return .init(
            checks: checks,
            verified: VerifiedAttestation(publicKey: publicKey, counter: decoded.authData.counter, receipt: decoded.receipt,
                                          environment: environment, anchor: anchor),
            anchor: anchor
        )
    }

    /// Validates against Apple's root first, then (simulated mode only) the test root.
    private func chainCheck(_ decoded: Decoded, validationTime: Date) async -> (Check, TrustAnchor?) {
        guard !rootCertificates.isEmpty || !testRootCertificates.isEmpty else {
            return (.failed(CheckName.chain, "No trusted root certificate configured"), nil)
        }
        var failures: [String] = []
        if !rootCertificates.isEmpty {
            switch await Self.validate(decoded, roots: rootCertificates, validationTime: validationTime) {
            case let .success(names):
                return (.passed(CheckName.chain, "Anchored to Apple's App Attest root. Valid chain of \(names.count): " + names.joined(separator: " → ")), .apple)
            case let .failure(reason):
                failures.append("Apple's root " + reason.description)
            }
        } else {
            failures.append("Apple's root is not loaded")
        }
        if !testRootCertificates.isEmpty {
            switch await Self.validate(decoded, roots: testRootCertificates, validationTime: validationTime) {
            case let .success(names):
                return (.passed(CheckName.chain, "Anchored to test root (simulated), NOT Apple. Valid chain of \(names.count): " + names.joined(separator: " → ")), .testRoot)
            case let .failure(reason):
                failures.append("test root (simulated) " + reason.description)
            }
        }
        return (.failed(CheckName.chain, "Chain does not validate to the trusted root. " + failures.joined(separator: " — ")), nil)
    }

    private struct ChainFailureReason: Error, CustomStringConvertible {
        let description: String
        init(_ d: String) { description = d }
    }

    private static func validate(_ decoded: Decoded, roots: [Certificate], validationTime: Date) async -> Result<[String], ChainFailureReason> {
        final class DiagnosticsBox: @unchecked Sendable { var lines: [String] = [] }
        let box = DiagnosticsBox()
        var verifier = Verifier(rootCertificates: CertificateStore(roots)) {
            RFC5280Policy(validationTime: validationTime)
        }
        let result = await verifier.validate(
            leaf: decoded.leaf,
            intermediates: CertificateStore(decoded.intermediates),
            diagnosticCallback: { box.lines.append($0.description) }
        )
        switch result {
        case let .validCertificate(chain):
            return .success(chain.map { $0.subject.description })
        case let .couldNotValidate(failures):
            var detail = "does not validate."
            if !failures.isEmpty {
                detail += " Policy failures: " + failures.map { "\($0.policyFailureReason)" }.joined(separator: "; ")
            }
            let diag = box.lines.suffix(4)
            if !diag.isEmpty { detail += " Diagnostics: " + diag.joined(separator: " | ") }
            return .failure(ChainFailureReason(detail))
        }
    }

    /// Parses `SEQUENCE { [1] EXPLICIT OCTET STRING(32) }` and returns the 32 bytes.
    static func parseNonceExtension(_ der: [UInt8]) -> [UInt8]? {
        guard let seq = DERReader.readTLV(der[...], expectedTag: 0x30), seq.rest.isEmpty,
              let tagged = DERReader.readTLV(seq.content, expectedTag: 0xA1),
              let octets = DERReader.readTLV(tagged.content, expectedTag: 0x04),
              octets.content.count == 32
        else { return nil }
        return Array(octets.content)
    }
}

/// Just enough DER to read nested TLVs.
enum DERReader {
    static func readTLV(_ input: ArraySlice<UInt8>, expectedTag: UInt8) -> (content: ArraySlice<UInt8>, rest: ArraySlice<UInt8>)? {
        var i = input.startIndex
        guard i < input.endIndex, input[i] == expectedTag else { return nil }
        i += 1
        guard i < input.endIndex else { return nil }
        var length = Int(input[i])
        i += 1
        if length & 0x80 != 0 {
            let n = length & 0x7F
            guard n >= 1, n <= 4, input.endIndex - i >= n else { return nil }
            length = 0
            for _ in 0..<n { length = (length << 8) | Int(input[i]); i += 1 }
        }
        guard input.endIndex - i >= length else { return nil }
        return (input[i..<(i + length)], input[(i + length)...])
    }
}
