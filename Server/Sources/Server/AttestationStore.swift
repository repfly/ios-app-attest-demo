import AppAttestVerifier
import Crypto
import Foundation

/// In-memory state. Everything is lost when the server stops.
actor AttestationStore {
    static let challengeLifetime: TimeInterval = 5 * 60
    static let maxEvents = 100

    enum CheckName {
        static let challengeFresh = "Challenge is fresh (issued by server, single-use, < 5 min)"
        static let keyRegistered = "Key ID is registered"
        static let clientData = "clientData is a transfer request"
    }

    struct RegisteredKey: Sendable {
        let keyId: Data
        let publicKey: [UInt8]
        var counter: UInt32
        let environment: AppAttestEnvironment
        let registeredAt: Date
        /// Anchored to the simulated-mode test root, not Apple's.
        let simulated: Bool
    }

    struct Event: Sendable {
        let kind: String
        let keyId: Data?
        let timestamp: Date
        let passed: Bool
        let message: String
        let checks: [Check]
        var simulated = false
    }

    private var challenges: [Data: Date] = [:]
    private(set) var keys: [Data: RegisteredKey] = [:]
    private(set) var events: [Event] = []

    // MARK: Challenges

    func issueChallenge() -> Data {
        purgeExpired()
        var bytes = [UInt8](repeating: 0, count: 32)
        var rng = SystemRandomNumberGenerator()
        for i in bytes.indices { bytes[i] = rng.next() }
        let challenge = Data(bytes)
        challenges[challenge] = Date().addingTimeInterval(Self.challengeLifetime)
        return challenge
    }

    /// Removes the challenge if present (single use) and reports whether it was fresh.
    func consumeChallenge(_ challenge: Data) -> Check {
        purgeExpired()
        guard let expiry = challenges.removeValue(forKey: challenge) else {
            return .failed(CheckName.challengeFresh, "Unknown, already used, or expired challenge — the server never issued it or it was replayed")
        }
        let remaining = Int(expiry.timeIntervalSinceNow)
        return .passed(CheckName.challengeFresh, "Issued by this server, consumed now (\(remaining)s before expiry)")
    }

    private func purgeExpired() {
        let now = Date()
        challenges = challenges.filter { $0.value > now }
    }

    // MARK: Keys

    func register(keyId: Data, attestation: VerifiedAttestation) {
        keys[keyId] = RegisteredKey(keyId: keyId, publicKey: attestation.publicKey, counter: attestation.counter,
                                    environment: attestation.environment, registeredAt: Date(),
                                    simulated: attestation.anchor.isSimulated)
    }

    struct TransferOutcome: Sendable {
        let passed: Bool
        let message: String
        let checks: [Check]
        var simulated = false
    }

    /// Verifies a protected transfer and updates the counter, atomically (no suspension points).
    func processTransfer(keyId: Data, assertion: Data, clientData: Data, verifier: AssertionVerifier) -> TransferOutcome {
        let assertionNames = [AssertionVerifier.CheckName.decode, AssertionVerifier.CheckName.signature,
                              AssertionVerifier.CheckName.rpId, AssertionVerifier.CheckName.counter]
        guard let key = keys[keyId] else {
            let checks: [Check] = [.failed(CheckName.keyRegistered, "No attested key with this ID — this device never registered (or the server was reset)"),
                                   .skipped(CheckName.challengeFresh), .skipped(CheckName.clientData)]
                + assertionNames.map { .skipped($0) }
            return TransferOutcome(passed: false, message: "Rejected: unknown key", checks: checks)
        }
        let kind = key.simulated ? "simulated \(key.environment.rawValue)" : key.environment.rawValue
        var checks: [Check] = [.passed(CheckName.keyRegistered, "Registered \(kind) key, stored counter \(key.counter)")]

        // The signed clientData carries the challenge; parse it to check freshness.
        let request = TransferRequest.parse(clientData)
        if let challenge = request?.challenge {
            checks.append(consumeChallenge(challenge))
        } else {
            checks.append(.failed(CheckName.challengeFresh, "clientData has no base64 'challenge' field"))
        }
        if let r = request, r.action == "transfer", let amount = r.amount, let to = r.to {
            checks.append(.passed(CheckName.clientData, "transfer \(amount) to \(to)"))
        } else {
            checks.append(.failed(CheckName.clientData, "Expected {\"challenge\",\"action\":\"transfer\",\"amount\",\"to\"}"))
        }

        let result = verifier.verify(assertion: [UInt8](assertion), clientData: [UInt8](clientData),
                                     publicKey: key.publicKey, storedCounter: key.counter)
        checks += result.checks

        if checks.allPassed, let newCounter = result.newCounter, let r = request, let amount = r.amount, let to = r.to {
            keys[keyId]?.counter = newCounter
            return TransferOutcome(passed: true, message: "Transferred \(amount) to \(to). Counter is now \(newCounter).", checks: checks,
                                   simulated: key.simulated)
        }
        let failed = checks.filter { $0.status == .failed }.map(\.name)
        return TransferOutcome(passed: false, message: "Rejected: " + failed.joined(separator: "; "), checks: checks,
                               simulated: key.simulated)
    }

    // MARK: Events

    func log(_ event: Event) {
        events.append(event)
        if events.count > Self.maxEvents { events.removeFirst(events.count - Self.maxEvents) }
    }

    func reset() {
        challenges.removeAll()
        keys.removeAll()
        events.removeAll()
    }

    func snapshot() -> (keys: [RegisteredKey], events: [Event]) {
        (keys.values.sorted { $0.registeredAt < $1.registeredAt }, events.reversed())
    }
}

/// The JSON the app signs: {"challenge":<base64>,"action":"transfer","amount":<int>,"to":<string>}.
struct TransferRequest {
    let challenge: Data?
    let action: String?
    let amount: Int?
    let to: String?

    static func parse(_ data: Data) -> TransferRequest? {
        guard let obj = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else { return nil }
        return TransferRequest(
            challenge: (obj["challenge"] as? String).flatMap { Data(base64Encoded: $0) },
            action: obj["action"] as? String,
            amount: (obj["amount"] as? NSNumber)?.intValue,
            to: obj["to"] as? String
        )
    }
}
