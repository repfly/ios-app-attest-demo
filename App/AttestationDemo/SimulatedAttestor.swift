#if targetEnvironment(simulator)
import CryptoKit
import Foundation

/// Simulator-only stand-in for `DCAppAttestService`, which is unavailable in the Simulator.
///
/// It uses a CryptoKit P-256 software key (not the Secure Enclave), builds the authenticator data
/// itself, and asks the server's test CA (`POST /simulator/attest-key`, only when the server runs
/// with `ALLOW_SIMULATED=1`) for the certificate Apple would issue. The server verifies the result
/// with its normal checks but marks it SIMULATED. This is not real App Attest.
@MainActor
final class SimulatedAttestor: Attestor {
    private let keychain = KeychainStore(service: "com.example.AttestationDemo.simulated")
    private let privateKeyAccount = "privateKey"
    private let defaults = UserDefaults.standard
    private enum Key {
        static let counter = "simulated.counter"
        static let appID = "simulated.appID"
        static let attested = "simulated.attestedKeyId"
    }

    let isSupported = true
    let isSimulated = true
    let keyKind = "software P-256 key (simulated)"

    private var privateKey: P256.Signing.PrivateKey? {
        guard let b64 = keychain.string(for: privateKeyAccount), let raw = Data(base64Encoded: b64) else { return nil }
        return try? P256.Signing.PrivateKey(rawRepresentation: raw)
    }

    private static func keyId(for key: P256.Signing.PrivateKey) -> String {
        Data(SHA256.hash(data: key.publicKey.x963Representation)).base64EncodedString()
    }

    var keyId: String? { privateKey.map(Self.keyId) }

    var isAttested: Bool {
        guard let keyId else { return false }
        return defaults.string(forKey: Key.attested) == keyId
    }

    func markAttested() { defaults.set(keyId, forKey: Key.attested) }

    func ensureKey() async throws -> (keyId: String, isNew: Bool) {
        if let keyId { return (keyId, false) }
        let key = P256.Signing.PrivateKey()
        keychain.set(key.rawRepresentation.base64EncodedString(), for: privateKeyAccount)
        guard self.keyId != nil else { throw SimulatedError.keychainUnavailable }
        defaults.removeObject(forKey: Key.attested)
        defaults.set(0, forKey: Key.counter)
        return (Self.keyId(for: key), true)
    }

    func attest(keyId: String, challenge: Data, server: APIClient) async throws -> Data {
        guard let key = privateKey, Self.keyId(for: key) == keyId else { throw SimulatedError.noKey }
        // rpIdHash must be SHA-256("TEAMID.bundleID"); take the App ID the server runs with.
        let state = try await server.state()
        guard state.simulatedModeEnabled == true else { throw APIError.simulatedModeOff }
        defaults.set(state.appID, forKey: Key.appID)

        let publicKey = key.publicKey.x963Representation
        let credentialId = Data(SHA256.hash(data: publicKey))
        var authData = Self.authData(appID: state.appID, flags: 0x40, counter: 0)
        authData += Data("appattestdevelop".utf8) // AAGUID, development environment
        authData += [UInt8(credentialId.count >> 8), UInt8(credentialId.count & 0xFF)]
        authData += credentialId

        let clientDataHash = Data(SHA256.hash(data: challenge))
        let nonce = Data(SHA256.hash(data: authData + clientDataHash))
        let x5c = try await server.simulatorAttestKey(publicKey: publicKey, nonce: nonce)

        return MiniCBOR.encode(.map([
            (.text("fmt"), .text("apple-appattest")),
            (.text("attStmt"), .map([
                (.text("x5c"), .array(x5c.map { .bytes($0) })),
                (.text("receipt"), .bytes(Data())),
            ])),
            (.text("authData"), .bytes(authData)),
        ]))
    }

    func assertion(keyId: String, clientData: Data) async throws -> Data {
        guard let key = privateKey, Self.keyId(for: key) == keyId else { throw SimulatedError.noKey }
        guard let appID = defaults.string(forKey: Key.appID) else { throw SimulatedError.notAttested }
        // Like the Secure Enclave, the counter goes up on every assertion, accepted or not.
        let counter = UInt32(defaults.integer(forKey: Key.counter)) + 1
        defaults.set(Int(counter), forKey: Key.counter)

        let authData = Self.authData(appID: appID, flags: 0x00, counter: counter)
        let nonce = Data(SHA256.hash(data: authData + Data(SHA256.hash(data: clientData))))
        let signature = try key.signature(for: nonce) // ECDSA-SHA256 over the nonce
        return MiniCBOR.encode(.map([
            (.text("signature"), .bytes(signature.derRepresentation)),
            (.text("authenticatorData"), .bytes(authData)),
        ]))
    }

    func resetKey() {
        keychain.delete(privateKeyAccount)
        for k in [Key.counter, Key.appID, Key.attested] { defaults.removeObject(forKey: k) }
    }

    /// rpIdHash (32) ‖ flags (1) ‖ counter (4, big-endian).
    private static func authData(appID: String, flags: UInt8, counter: UInt32) -> Data {
        var d = Data(SHA256.hash(data: Data(appID.utf8)))
        d.append(flags)
        d += withUnsafeBytes(of: counter.bigEndian) { Data($0) }
        return d
    }

    enum SimulatedError: LocalizedError {
        case noKey, notAttested, keychainUnavailable
        var errorDescription: String? {
            switch self {
            case .noKey: return "No simulated key. Tap Register first."
            case .notAttested: return "The simulated key has not been attested yet. Tap Register first."
            case .keychainUnavailable: return "Could not store the simulated key in the Keychain."
            }
        }
    }
}

/// Just enough CBOR (definite lengths, shortest-form heads) for attestation and assertion objects.
enum MiniCBOR {
    indirect enum Value {
        case bytes(Data)
        case text(String)
        case array([Value])
        case map([(Value, Value)])
    }

    static func encode(_ value: Value) -> Data {
        switch value {
        case let .bytes(b): return head(2, b.count) + b
        case let .text(s): return head(3, s.utf8.count) + Data(s.utf8)
        case let .array(a): return a.reduce(head(4, a.count)) { $0 + encode($1) }
        case let .map(m): return m.reduce(head(5, m.count)) { $0 + encode($1.0) + encode($1.1) }
        }
    }

    private static func head(_ major: UInt8, _ count: Int) -> Data {
        let m = major << 5
        let n = UInt64(count)
        switch n {
        case 0..<24: return Data([m | UInt8(n)])
        case 24..<0x100: return Data([m | 24, UInt8(n)])
        case 0x100..<0x10000: return Data([m | 25, UInt8(n >> 8), UInt8(n & 0xFF)])
        default: return Data([m | 26] + (0..<4).reversed().map { UInt8(truncatingIfNeeded: n >> (UInt64($0) * 8)) })
        }
    }
}
#endif
