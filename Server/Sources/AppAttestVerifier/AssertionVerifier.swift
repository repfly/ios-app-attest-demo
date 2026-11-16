import Crypto
import Foundation

public struct AssertionVerificationResult: Sendable {
    public var checks: [Check]
    /// The counter to store; non-nil only when every check passed.
    public var newCounter: UInt32?
    public var passed: Bool { newCounter != nil }
}

/// Verifies an App Attest assertion against a previously attested key.
public struct AssertionVerifier: Sendable {
    public enum CheckName {
        public static let decode = "Decode assertion"
        public static let signature = "Signature valid for stored public key"
        public static let rpId = "App ID matches (rpIdHash)"
        public static let counter = "Counter increased"
    }

    public var appID: String

    public init(appID: String) {
        self.appID = appID
    }

    /// - Parameters:
    ///   - assertion: Raw bytes returned by `generateAssertion`.
    ///   - clientData: The exact bytes the app hashed and signed.
    ///   - publicKey: Stored X9.63 public key from attestation.
    ///   - storedCounter: Last accepted counter for this key.
    public func verify(assertion: [UInt8], clientData: [UInt8], publicKey: [UInt8], storedCounter: UInt32) -> AssertionVerificationResult {
        let signature: [UInt8]
        let authDataBytes: [UInt8]
        let authData: AuthenticatorData
        do {
            let root = try CBORDecoder.decode(assertion)
            guard case .map = root else { throw Msg("Top-level CBOR item is not a map") }
            guard let sig = root["signature"]?.bytesValue else { throw Msg("Missing byte string 'signature'") }
            guard let ad = root["authenticatorData"]?.bytesValue else { throw Msg("Missing byte string 'authenticatorData'") }
            signature = sig
            authDataBytes = ad
            authData = try AuthenticatorData(ad)
        } catch {
            return .init(
                checks: [.failed(CheckName.decode, "\(error)"), .skipped(CheckName.signature), .skipped(CheckName.rpId), .skipped(CheckName.counter)],
                newCounter: nil
            )
        }

        var checks: [Check] = [.passed(CheckName.decode, "\(signature.count)-byte signature, counter \(authData.counter)")]

        // nonce = SHA256(authenticatorData ‖ SHA256(clientData)); the signature is ECDSA-SHA256 over the nonce.
        let nonce = Util.sha256(authDataBytes + Util.sha256(clientData))
        do {
            let key = try P256.Signing.PublicKey(x963Representation: publicKey)
            let sig = try P256.Signing.ECDSASignature(derRepresentation: signature)
            checks.append(.expect(CheckName.signature, key.isValidSignature(sig, for: Data(nonce)),
                                  pass: "ECDSA P-256 over nonce \(Util.hex(nonce))",
                                  fail: "Signature does not match nonce \(Util.hex(nonce)) — clientData or authenticatorData was altered, or a different key signed it"))
        } catch {
            checks.append(.failed(CheckName.signature, "Could not parse key or signature: \(error)"))
        }

        let appIDHash = Util.sha256(Array(appID.utf8))
        checks.append(.expect(CheckName.rpId, authData.rpIdHash == appIDHash,
                              pass: "SHA-256(\"\(appID)\")",
                              fail: "rpIdHash \(Util.hex(authData.rpIdHash)) ≠ SHA-256(\"\(appID)\")"))

        checks.append(.expect(CheckName.counter, authData.counter > storedCounter,
                              pass: "\(storedCounter) → \(authData.counter)",
                              fail: "counter \(authData.counter) is not greater than stored \(storedCounter) (replayed assertion?)"))

        return .init(checks: checks, newCounter: checks.allPassed ? authData.counter : nil)
    }

    private struct Msg: Error, CustomStringConvertible {
        let description: String
        init(_ d: String) { description = d }
    }
}
