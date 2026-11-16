import DeviceCheck
import Foundation
import Observation

/// One action in the on-screen log: the client-side steps plus the server's checklist.
struct LogEntry: Identifiable {
    let id = UUID()
    let date = Date()
    let title: String
    /// What this attack is expected to produce, so the presenter can compare.
    let expectation: String?
    var steps: [String] = []
    var httpStatus: Int?
    var ok: Bool?
    var message: String?
    var checks: [ServerCheck] = []
    var error: String?
}

@Observable
@MainActor
final class DemoViewModel {
    private static let serverURLKey = "serverURL"

    var serverURL: String {
        didSet { UserDefaults.standard.set(serverURL, forKey: Self.serverURLKey) }
    }

    private(set) var keyId: String?
    private(set) var isAttested = false
    private(set) var isBusy = false
    private(set) var log: [LogEntry] = []
    /// Exact bytes of the last /transfer request, for the replay attack.
    private(set) var lastTransferBody: Data?

    let isSupported: Bool
    /// True in the Simulator build, which uses a software key instead of App Attest.
    let isSimulated: Bool
    /// Simulator only: set when the server answered but has simulated mode off.
    private(set) var simulatedModeOffMessage: String?
    private let attestation: any Attestor

    #if targetEnvironment(simulator)
    private static let defaultServerURL = "http://localhost:8080"
    #else
    private static let defaultServerURL = ""
    #endif

    init() {
        #if targetEnvironment(simulator)
        attestation = SimulatedAttestor()
        #else
        attestation = AttestationService()
        #endif
        serverURL = UserDefaults.standard.string(forKey: Self.serverURLKey) ?? Self.defaultServerURL
        isSupported = attestation.isSupported
        isSimulated = attestation.isSimulated
        refreshKeyState()
    }

    /// Simulator only: asks the server whether simulated mode is on, so the banner can say so up front.
    func checkSimulatedServer() async {
        guard isSimulated, let api = try? api(), let state = try? await api.state() else {
            simulatedModeOffMessage = nil
            return
        }
        simulatedModeOffMessage = state.simulatedModeEnabled == true ? nil : APIError.simulatedModeOff.errorDescription
    }

    var canAttest: Bool { isSupported && !isBusy }
    var canTransfer: Bool { isSupported && isAttested && !isBusy }

    private func refreshKeyState() {
        keyId = attestation.keyId
        isAttested = attestation.isAttested
    }

    // MARK: - Running an action

    private final class Steps {
        var lines: [String] = []
        func add(_ s: String) { lines.append(s) }
    }

    /// Runs `work`, records its steps and the server's reply as a log entry.
    private func perform(_ title: String, expect: String? = nil,
                         _ work: (Steps) async throws -> (status: Int, reply: ServerReply)) async {
        isBusy = true
        defer { isBusy = false; refreshKeyState() }
        let steps = Steps()
        var entry = LogEntry(title: title, expectation: expect)
        do {
            let (status, reply) = try await work(steps)
            steps.add("Server answered HTTP \(status): \(reply.message)")
            entry.httpStatus = status
            entry.ok = reply.ok
            entry.message = reply.message
            entry.checks = reply.checks
        } catch {
            entry.error = describe(error)
            steps.add("Stopped: \(entry.error ?? "")")
        }
        entry.steps = steps.lines
        log.insert(entry, at: 0)
    }

    private func describe(_ error: Error) -> String {
        if let dc = error as? DCError {
            switch dc.code {
            case .featureUnsupported: return "App Attest is not supported on this device"
            case .invalidKey: return "The key is invalid (already attested or unknown). Tap Reset key and register again."
            case .invalidInput: return "DeviceCheck rejected the input"
            case .serverUnavailable: return "Apple's App Attest service is unavailable; try again"
            default: return "DeviceCheck error \(dc.code.rawValue): \(dc.localizedDescription)"
            }
        }
        return error.localizedDescription
    }

    private func api() throws -> APIClient { try APIClient(urlString: serverURL) }

    private static func short(_ data: Data) -> String { String(data.base64EncodedString().prefix(12)) + "…" }
    private static func short(_ s: String) -> String { String(s.prefix(12)) + "…" }

    /// The exact JSON the app signs. The server parses these same bytes.
    private static func clientData(challenge: Data, amount: Int, to: String) -> Data {
        let json = "{\"challenge\":\(APIClient.jsonString(challenge.base64EncodedString())),"
            + "\"action\":\"transfer\",\"amount\":\(amount),\"to\":\(APIClient.jsonString(to))}"
        return Data(json.utf8)
    }

    private static func transferBody(keyId: String, assertion: Data, clientData: Data) -> Data {
        APIClient.jsonBody(["keyId": keyId,
                            "assertion": assertion.base64EncodedString(),
                            "clientData": clientData.base64EncodedString()])
    }

    // MARK: - Actions

    func register() async {
        defer { Task { await checkSimulatedServer() } }
        await perform("Register device (attest)", expect: "All checks green; key appears on dashboard with counter 0") { s in
            let api = try api()
            let (keyId, isNew) = try await attestation.ensureKey()
            s.add(isNew ? "Generated new \(attestation.keyKind) \(Self.short(keyId))" : "Using existing key \(Self.short(keyId))")
            let challenge = try await api.challenge()
            s.add("Received one-time challenge \(Self.short(challenge))")
            let object = try await attestation.attest(keyId: keyId, challenge: challenge, server: api)
            if attestation.isSimulated {
                s.add("Server's test CA (not Apple) certified the key: \(object.count)-byte attestation object")
            } else {
                s.add("Apple attested the key: \(object.count)-byte attestation object (clientDataHash = SHA-256(challenge))")
            }
            let body = APIClient.jsonBody(["keyId": keyId,
                                           "challenge": challenge.base64EncodedString(),
                                           "attestation": object.base64EncodedString()])
            s.add("Sent keyId + challenge + attestation to /attest")
            let result = try await api.post("attest", body: body)
            if result.reply.ok { attestation.markAttested() }
            return result
        }
    }

    func transfer(amount: Int = 10, to: String = "bob") async {
        await perform("Protected transfer (\(amount) → \(to))", expect: "Accepted; counter increases by 1") { s in
            guard let keyId = attestation.keyId else { throw DCError(.invalidKey) }
            let api = try api()
            let challenge = try await api.challenge()
            s.add("Received one-time challenge \(Self.short(challenge))")
            let clientData = Self.clientData(challenge: challenge, amount: amount, to: to)
            s.add("clientData = \(String(decoding: clientData, as: UTF8.self))")
            let assertion = try await attestation.assertion(keyId: keyId, clientData: clientData)
            s.add("\(attestation.isSimulated ? "Software key" : "Secure Enclave") signed SHA-256(clientData): \(assertion.count)-byte assertion")
            let body = Self.transferBody(keyId: keyId, assertion: assertion, clientData: clientData)
            lastTransferBody = body
            s.add("Sent to /transfer (request saved for the replay attack)")
            return try await api.post("transfer", body: body)
        }
    }

    // MARK: - Attacks

    func replay() async {
        await perform("Attack: replay previous transfer", expect: "Rejected: challenge already used, counter not increased") { s in
            guard let body = lastTransferBody else { throw AttackError.nothingToReplay }
            s.add("Resending the previous /transfer request byte-for-byte (\(body.count) bytes)")
            return try await api().post("transfer", body: body)
        }
    }

    func tamper() async {
        await perform("Attack: tamper amount after signing", expect: "Rejected: signature invalid") { s in
            guard let keyId = attestation.keyId else { throw DCError(.invalidKey) }
            let api = try api()
            let challenge = try await api.challenge()
            s.add("Received challenge \(Self.short(challenge))")
            let signed = Self.clientData(challenge: challenge, amount: 10, to: "bob")
            let assertion = try await attestation.assertion(keyId: keyId, clientData: signed)
            s.add("Signed clientData with amount 10")
            let tampered = Self.clientData(challenge: challenge, amount: 10_000, to: "bob")
            s.add("Man-in-the-middle swaps clientData for amount 10000 before sending")
            return try await api.post("transfer", body: Self.transferBody(keyId: keyId, assertion: assertion, clientData: tampered))
        }
    }

    func staleChallenge() async {
        await perform("Attack: made-up challenge", expect: "Rejected: challenge not issued by server (signature itself is valid)") { s in
            guard let keyId = attestation.keyId else { throw DCError(.invalidKey) }
            var bytes = [UInt8](repeating: 0, count: 32)
            _ = SecRandomCopyBytes(kSecRandomDefault, bytes.count, &bytes)
            let fake = Data(bytes)
            s.add("Invented challenge \(Self.short(fake)) without asking the server")
            let clientData = Self.clientData(challenge: fake, amount: 10, to: "bob")
            let assertion = try await attestation.assertion(keyId: keyId, clientData: clientData)
            s.add("Signed it with the genuine attested key")
            return try await api().post("transfer", body: Self.transferBody(keyId: keyId, assertion: assertion, clientData: clientData))
        }
    }

    func unknownKey() async {
        await perform("Attack: unknown key ID", expect: "Rejected: key not registered (fatal, nothing else checked)") { s in
            guard let keyId = attestation.keyId else { throw DCError(.invalidKey) }
            let api = try api()
            let challenge = try await api.challenge()
            let clientData = Self.clientData(challenge: challenge, amount: 10, to: "bob")
            let assertion = try await attestation.assertion(keyId: keyId, clientData: clientData)
            s.add("Made a valid assertion with the real key")
            var bytes = [UInt8](repeating: 0, count: 32)
            _ = SecRandomCopyBytes(kSecRandomDefault, bytes.count, &bytes)
            let randomKeyId = Data(bytes).base64EncodedString()
            s.add("…but claims to be key \(Self.short(randomKeyId)), which never attested")
            return try await api.post("transfer", body: Self.transferBody(keyId: randomKeyId, assertion: assertion, clientData: clientData))
        }
    }

    func resetKey() {
        attestation.resetKey()
        lastTransferBody = nil
        refreshKeyState()
        var entry = LogEntry(title: "Reset key", expectation: nil)
        entry.steps = ["Forgot the local key ID. The next registration generates and attests a fresh key."]
        log.insert(entry, at: 0)
    }

    func clearLog() { log.removeAll() }

    enum AttackError: LocalizedError {
        case nothingToReplay
        var errorDescription: String? { "Send a protected transfer first; there is nothing to replay yet." }
    }
}
