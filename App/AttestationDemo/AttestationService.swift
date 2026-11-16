import CryptoKit
import DeviceCheck
import Foundation

/// Thin wrapper around `DCAppAttestService` that also remembers the key identifier.
@MainActor
final class AttestationService: Attestor {
    private let service = DCAppAttestService.shared
    private let keychain = KeychainStore(service: "com.example.AttestationDemo.appattest")
    private let keyIdAccount = "keyId"
    private let attestedDefaultsKey = "attestedKeyId"

    /// False on the Simulator and on devices without a Secure Enclave.
    var isSupported: Bool { service.isSupported }
    let isSimulated = false
    let keyKind = "Secure Enclave key"

    /// The key identifier (base64 string, as returned by `generateKey`).
    var keyId: String? { keychain.string(for: keyIdAccount) }

    /// Whether the server accepted an attestation for the current key.
    var isAttested: Bool {
        guard let keyId else { return false }
        return UserDefaults.standard.string(forKey: attestedDefaultsKey) == keyId
    }

    func markAttested() {
        UserDefaults.standard.set(keyId, forKey: attestedDefaultsKey)
    }

    /// Returns the stored key, generating a new Secure Enclave key if there is none.
    func ensureKey() async throws -> (keyId: String, isNew: Bool) {
        if let keyId { return (keyId, false) }
        let newKey = try await service.generateKey()
        keychain.set(newKey, for: keyIdAccount)
        UserDefaults.standard.removeObject(forKey: attestedDefaultsKey)
        return (newKey, true)
    }

    /// Asks Apple to attest the key. `clientDataHash` = SHA-256(server challenge).
    func attest(keyId: String, challenge: Data, server _: APIClient) async throws -> Data {
        try await service.attestKey(keyId, clientDataHash: Data(SHA256.hash(data: challenge)))
    }

    /// Signs SHA-256(clientData) with the attested key.
    func assertion(keyId: String, clientData: Data) async throws -> Data {
        try await service.generateAssertion(keyId, clientDataHash: Data(SHA256.hash(data: clientData)))
    }

    /// Forgets the key locally. The Secure Enclave key cannot be deleted, it simply goes unused.
    func resetKey() {
        keychain.delete(keyIdAccount)
        UserDefaults.standard.removeObject(forKey: attestedDefaultsKey)
    }
}
