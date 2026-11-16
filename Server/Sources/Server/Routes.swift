import AppAttestVerifier
import Crypto
import Foundation
import Vapor

struct ChallengeResponse: Content {
    let challenge: String
}

struct AttestRequest: Content {
    let keyId: String?
    let challenge: String?
    let attestation: String?
}

struct TransferBody: Content {
    let keyId: String?
    let assertion: String?
    let clientData: String?
}

/// Simulated mode only: the app's software key and the nonce it wants certified.
struct SimulatedAttestKeyRequest: Content {
    let publicKey: String?
    let nonce: String?
}

/// `[leaf, intermediate]`, DER, base64: the `x5c` of an attestation object.
struct SimulatedAttestKeyResponse: Content {
    let x5c: [String]
}

struct VerificationResponse: Content {
    let ok: Bool
    let message: String
    let checks: [Check]
}

struct StateResponse: Content {
    struct Key: Content {
        let keyId: String
        let shortKeyId: String
        let counter: UInt32
        let environment: String
        let registeredAt: Int64
        let simulated: Bool
    }

    struct Event: Content {
        let kind: String
        let keyId: String?
        let timestamp: Int64
        let passed: Bool
        let message: String
        let checks: [Check]
        let simulated: Bool
    }

    let appID: String
    let appIDIsPlaceholder: Bool
    let rootCALoaded: Bool
    let rootCAPath: String
    let warnings: [String]
    /// True when the server runs with ALLOW_SIMULATED=1.
    let simulatedModeEnabled: Bool
    let testRootSubject: String?
    let keys: [Key]
    let events: [Event]
}

private func shortID(_ data: Data?) -> String? {
    guard let data else { return nil }
    return String(data.base64EncodedString().prefix(10)) + "…"
}

private func epochMillis(_ date: Date) -> Int64 { Int64((date.timeIntervalSince1970 * 1000).rounded()) }

private func respond(_ req: Request, ok: Bool, message: String, checks: [Check]) async throws -> Response {
    try await VerificationResponse(ok: ok, message: message, checks: checks)
        .encodeResponse(status: ok ? .ok : .forbidden, for: req)
}

private func decodeFields(_ fields: [(name: String, value: String?)]) -> (values: [Data], check: Check) {
    var values: [Data] = []
    var bad: [String] = []
    for f in fields {
        if let s = f.value, let d = Data(base64Encoded: s), !d.isEmpty { values.append(d) } else { bad.append(f.name) }
    }
    if bad.isEmpty {
        return (values, .passed("Request is well-formed", "All fields present and base64"))
    }
    return (values, .failed("Request is well-formed", "Missing or non-base64 field(s): " + bad.joined(separator: ", ")))
}

func routes(_ app: Application, config: ServerConfig, store: AttestationStore) throws {
    let attestationVerifier = AttestationVerifier(rootCertificates: config.rootCertificates,
                                                  testRootCertificates: config.simulatedCA.map { [$0.root] } ?? [],
                                                  appID: config.appID)
    let assertionVerifier = AssertionVerifier(appID: config.appID)

    let dashboardHTML: String = {
        guard let url = Bundle.module.url(forResource: "dashboard", withExtension: "html", subdirectory: "Resources"),
              let html = try? String(contentsOf: url, encoding: .utf8)
        else { return "<!doctype html><title>Dashboard missing</title><p>dashboard.html not found in bundle.</p>" }
        return html
    }()

    app.get { _ -> Response in
        var headers = HTTPHeaders()
        headers.contentType = .html
        headers.replaceOrAdd(name: .cacheControl, value: "no-store")
        return Response(status: .ok, headers: headers, body: .init(string: dashboardHTML))
    }

    app.post("challenge") { _ async -> ChallengeResponse in
        ChallengeResponse(challenge: await store.issueChallenge().base64EncodedString())
    }

    app.post("attest") { req async throws -> Response in
        let body = try req.content.decode(AttestRequest.self)
        let (values, wellFormed) = decodeFields([("keyId", body.keyId), ("challenge", body.challenge), ("attestation", body.attestation)])
        guard wellFormed.status == .passed else {
            let checks = [wellFormed]
            await store.log(.init(kind: "attest", keyId: nil, timestamp: Date(), passed: false, message: "Malformed request", checks: checks))
            return try await respond(req, ok: false, message: "Malformed request", checks: checks)
        }
        let (keyId, challenge, attestation) = (values[0], values[1], values[2])

        let fresh = await store.consumeChallenge(challenge)
        let clientDataHash = Array(SHA256.hash(data: challenge))
        var result = await attestationVerifier.verify(attestation: [UInt8](attestation), keyID: [UInt8](keyId),
                                                      clientDataHash: clientDataHash)
        if !config.rootCALoaded,
           let i = result.checks.firstIndex(where: { $0.name == AttestationVerifier.CheckName.chain && $0.status == .failed }) {
            result.checks[i].detail = config.missingRootHelp
        }
        let checks = [fresh] + result.checks

        let passed = checks.allPassed && result.verified != nil
        let simulated = result.anchor?.isSimulated ?? false
        let message: String
        if passed, let verified = result.verified {
            await store.register(keyId: keyId, attestation: verified)
            message = "Device registered (\(verified.environment.rawValue) environment" + (simulated ? ", SIMULATED: test root, not Apple)" : ")")
        } else {
            message = "Attestation rejected: " + checks.filter { $0.status == .failed }.map(\.name).joined(separator: "; ")
        }
        await store.log(.init(kind: "attest", keyId: keyId, timestamp: Date(), passed: passed, message: message, checks: checks,
                              simulated: simulated))
        return try await respond(req, ok: passed, message: message, checks: checks)
    }

    app.post("transfer") { req async throws -> Response in
        let body = try req.content.decode(TransferBody.self)
        let (values, wellFormed) = decodeFields([("keyId", body.keyId), ("assertion", body.assertion), ("clientData", body.clientData)])
        guard wellFormed.status == .passed else {
            let checks = [wellFormed]
            await store.log(.init(kind: "transfer", keyId: nil, timestamp: Date(), passed: false, message: "Malformed request", checks: checks))
            return try await respond(req, ok: false, message: "Malformed request", checks: checks)
        }
        let (keyId, assertion, clientData) = (values[0], values[1], values[2])
        let outcome = await store.processTransfer(keyId: keyId, assertion: assertion, clientData: clientData, verifier: assertionVerifier)
        await store.log(.init(kind: "transfer", keyId: keyId, timestamp: Date(), passed: outcome.passed, message: outcome.message,
                              checks: outcome.checks, simulated: outcome.simulated))
        return try await respond(req, ok: outcome.passed, message: outcome.message, checks: outcome.checks)
    }

    app.get("state") { _ async -> StateResponse in
        let snap = await store.snapshot()
        return StateResponse(
            appID: config.appID,
            appIDIsPlaceholder: config.appIDIsPlaceholder,
            rootCALoaded: config.rootCALoaded,
            rootCAPath: config.rootCAPath,
            warnings: config.warnings,
            simulatedModeEnabled: config.simulatedModeEnabled,
            testRootSubject: config.simulatedCA?.root.subject.description,
            keys: snap.keys.map {
                .init(keyId: $0.keyId.base64EncodedString(), shortKeyId: shortID($0.keyId) ?? "",
                      counter: $0.counter, environment: $0.environment.rawValue, registeredAt: epochMillis($0.registeredAt),
                      simulated: $0.simulated)
            },
            events: snap.events.map {
                .init(kind: $0.kind, keyId: shortID($0.keyId), timestamp: epochMillis($0.timestamp),
                      passed: $0.passed, message: $0.message, checks: $0.checks, simulated: $0.simulated)
            }
        )
    }

    // Simulated mode: plays the part of Apple's servers inside attestKey. The app sends its software
    // public key and nonce = SHA-256(authData ‖ clientDataHash); the test CA returns a certificate for
    // it. /attest then verifies the result like any other attestation. 404 unless ALLOW_SIMULATED=1.
    app.post("simulator", "attest-key") { req async throws -> SimulatedAttestKeyResponse in
        guard let ca = config.simulatedCA else {
            throw Abort(.notFound, reason: "Simulated attestation is off on this server. Restart it with ALLOW_SIMULATED=1.")
        }
        let body = try req.content.decode(SimulatedAttestKeyRequest.self)
        guard let publicKey = body.publicKey.flatMap({ Data(base64Encoded: $0) }),
              let nonce = body.nonce.flatMap({ Data(base64Encoded: $0) })
        else { throw Abort(.badRequest, reason: "Expected base64 fields 'publicKey' (X9.63) and 'nonce'") }
        do {
            let x5c = try ca.issue(publicKeyX963: [UInt8](publicKey), nonce: [UInt8](nonce))
            return SimulatedAttestKeyResponse(x5c: x5c.map { Data($0).base64EncodedString() })
        } catch {
            throw Abort(.badRequest, reason: "\(error)")
        }
    }

    app.post("reset") { _ async -> VerificationResponse in
        await store.reset()
        return VerificationResponse(ok: true, message: "Server state cleared", checks: [])
    }
}
