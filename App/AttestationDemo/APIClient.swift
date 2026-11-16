import Foundation

/// One row of the server's verification checklist.
struct ServerCheck: Decodable, Hashable, Identifiable {
    let name: String
    let status: String // "passed" | "failed" | "skipped"
    let detail: String
    var id: String { name }
}

/// `{ok, message, checks}` as returned by /attest and /transfer.
struct ServerReply: Decodable {
    let ok: Bool
    let message: String
    let checks: [ServerCheck]
}

/// The part of `GET /state` the app reads.
struct ServerState: Decodable {
    let appID: String
    /// Missing on servers that predate simulated mode.
    let simulatedModeEnabled: Bool?
}

enum APIError: LocalizedError {
    case invalidURL(String)
    case unexpectedStatus(Int, String)
    case badChallenge
    case simulatedModeOff
    case badSimulatedCertificates

    var errorDescription: String? {
        switch self {
        case let .invalidURL(s): return "Invalid server URL: \(s)"
        case let .unexpectedStatus(code, body): return "Server returned HTTP \(code): \(body.prefix(200))"
        case .badChallenge: return "Server sent a challenge that is not valid base64"
        case .simulatedModeOff:
            return "The server has simulated attestation turned off. Restart it with ALLOW_SIMULATED=1, e.g. ALLOW_SIMULATED=1 APP_ID=<TEAMID>.<bundle id> swift run Server"
        case .badSimulatedCertificates: return "Server's /simulator/attest-key reply has no usable x5c"
        }
    }
}

struct APIClient {
    let baseURL: URL

    init(urlString: String) throws {
        let trimmed = urlString.trimmingCharacters(in: .whitespacesAndNewlines)
        guard let url = URL(string: trimmed), let scheme = url.scheme, ["http", "https"].contains(scheme), url.host != nil else {
            throw APIError.invalidURL(trimmed)
        }
        baseURL = url
    }

    private func request(_ path: String, body: Data?, method: String = "POST") -> URLRequest {
        var req = URLRequest(url: baseURL.appendingPathComponent(path))
        req.httpMethod = method
        req.timeoutInterval = 10
        if let body {
            req.httpBody = body
            req.setValue("application/json", forHTTPHeaderField: "Content-Type")
        }
        return req
    }

    /// POST /challenge → raw challenge bytes.
    func challenge() async throws -> Data {
        let (data, response) = try await URLSession.shared.data(for: request("challenge", body: nil))
        let status = (response as? HTTPURLResponse)?.statusCode ?? 0
        guard status == 200 else { throw APIError.unexpectedStatus(status, String(decoding: data, as: UTF8.self)) }
        struct Body: Decodable { let challenge: String }
        guard let challenge = Data(base64Encoded: try JSONDecoder().decode(Body.self, from: data).challenge) else {
            throw APIError.badChallenge
        }
        return challenge
    }

    /// GET /state → the server's App ID and whether simulated mode is on.
    func state() async throws -> ServerState {
        let (data, response) = try await URLSession.shared.data(for: request("state", body: nil, method: "GET"))
        let status = (response as? HTTPURLResponse)?.statusCode ?? 0
        guard status == 200 else { throw APIError.unexpectedStatus(status, String(decoding: data, as: UTF8.self)) }
        return try JSONDecoder().decode(ServerState.self, from: data)
    }

    /// Simulated mode: POST /simulator/attest-key → `[leaf, intermediate]` DER certificates.
    func simulatorAttestKey(publicKey: Data, nonce: Data) async throws -> [Data] {
        let body = Self.jsonBody(["publicKey": publicKey.base64EncodedString(), "nonce": nonce.base64EncodedString()])
        let (data, response) = try await URLSession.shared.data(for: request("simulator/attest-key", body: body))
        let status = (response as? HTTPURLResponse)?.statusCode ?? 0
        if status == 404 { throw APIError.simulatedModeOff }
        guard status == 200 else { throw APIError.unexpectedStatus(status, String(decoding: data, as: UTF8.self)) }
        struct Body: Decodable { let x5c: [String] }
        let certs = try JSONDecoder().decode(Body.self, from: data).x5c.compactMap { Data(base64Encoded: $0) }
        guard certs.count >= 2 else { throw APIError.badSimulatedCertificates }
        return certs
    }

    /// POSTs an already-encoded JSON body; 200 and 403 both carry a checklist.
    func post(_ path: String, body: Data) async throws -> (status: Int, reply: ServerReply) {
        let (data, response) = try await URLSession.shared.data(for: request(path, body: body))
        let status = (response as? HTTPURLResponse)?.statusCode ?? 0
        guard status == 200 || status == 403 else {
            throw APIError.unexpectedStatus(status, String(decoding: data, as: UTF8.self))
        }
        return (status, try JSONDecoder().decode(ServerReply.self, from: data))
    }

    /// Encodes a flat string dictionary as JSON with stable key order.
    static func jsonBody(_ fields: KeyValuePairs<String, String>) -> Data {
        var parts: [String] = []
        for (k, v) in fields { parts.append("\(jsonString(k)):\(jsonString(v))") }
        return Data(("{" + parts.joined(separator: ",") + "}").utf8)
    }

    static func jsonString(_ s: String) -> String {
        let encoder = JSONEncoder()
        encoder.outputFormatting = .withoutEscapingSlashes
        return String(decoding: (try? encoder.encode(s)) ?? Data("\"\"".utf8), as: UTF8.self)
    }
}
