import Foundation

/// The client side of App Attest: a key that can be attested once and then sign assertions.
///
/// `AttestationService` uses `DCAppAttestService` (real devices). The Simulator build uses
/// `SimulatedAttestor` instead, because App Attest is unavailable there.
@MainActor
protocol Attestor {
    var isSupported: Bool { get }
    /// True when this is not real App Attest.
    var isSimulated: Bool { get }
    /// How the key is described in the log, e.g. "Secure Enclave key".
    var keyKind: String { get }
    /// Base64 key identifier (SHA-256 of the public key).
    var keyId: String? { get }
    var isAttested: Bool { get }
    func markAttested()
    func ensureKey() async throws -> (keyId: String, isNew: Bool)
    /// Returns the attestation object for the key; `clientDataHash` = SHA-256(challenge).
    /// `server` is only used by the simulated attestor.
    func attest(keyId: String, challenge: Data, server: APIClient) async throws -> Data
    /// Signs SHA-256(clientData) with the attested key.
    func assertion(keyId: String, clientData: Data) async throws -> Data
    func resetKey()
}
