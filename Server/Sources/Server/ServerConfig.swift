import AppAttestVerifier
import Foundation
import Vapor
import X509

struct ServerConfig: Sendable {
    static let placeholderAppID = "TEAMID.com.example.AttestationDemo"
    static let rootCAFileName = "Apple_App_Attestation_Root_CA.pem"
    static let rootCAURL = "https://www.apple.com/certificateauthority/Apple_App_Attestation_Root_CA.pem"

    let appID: String
    let appIDIsPlaceholder: Bool
    let rootCertificates: [Certificate]
    let rootCAPath: String
    /// Human-readable configuration problems, shown on the dashboard.
    let warnings: [String]
    /// `ALLOW_SIMULATED=1`: an in-memory test CA, used by the Simulator build, is accepted as a second root.
    let simulatedCA: SimulatedAppAttestCA?

    var simulatedModeEnabled: Bool { simulatedCA != nil }

    var rootCALoaded: Bool { !rootCertificates.isEmpty }

    var missingRootHelp: String {
        "Apple App Attest root CA is not loaded (looked for \(rootCAPath)). "
            + "Fetch it with: curl -o \"\(rootCAPath)\" \(Self.rootCAURL)  — then restart the server "
            + "(or set APPLE_ROOT_CA_PATH)."
    }

    static func load(logger: Logger) -> ServerConfig {
        var warnings: [String] = []

        let envAppID = Environment.get("APP_ID")?.trimmingCharacters(in: .whitespaces)
        let appID = (envAppID?.isEmpty == false ? envAppID! : placeholderAppID)
        let isPlaceholder = appID == placeholderAppID
        if isPlaceholder {
            let w = "APP_ID is not set; using placeholder \"\(placeholderAppID)\". Attestations from a real build will fail the App ID check. Run with APP_ID=<TEAMID>.<bundle id>."
            logger.warning("\(w)")
            warnings.append(w)
        }

        // Explicit path wins. Otherwise accept the file whether the server is started from the
        // repository root (Server/<file>) or from inside Server/ (<file>).
        let candidates: [String]
        if let p = Environment.get("APPLE_ROOT_CA_PATH"), !p.isEmpty {
            candidates = [p]
        } else {
            candidates = ["Server/\(rootCAFileName)", rootCAFileName]
        }
        let fm = FileManager.default
        // If nothing exists yet, report the candidate whose directory exists, so the hint is a usable path.
        let path = candidates.first(where: { fm.fileExists(atPath: $0) })
            ?? candidates.first(where: { fm.fileExists(atPath: URL(fileURLWithPath: $0).deletingLastPathComponent().path) })
            ?? candidates[0]
        let absolute = URL(fileURLWithPath: path).standardizedFileURL.path

        var roots: [Certificate] = []
        if fm.fileExists(atPath: path) {
            do {
                let pem = try String(contentsOfFile: path, encoding: .utf8)
                roots = [try Certificate(pemEncoded: pem)]
                logger.notice("Loaded App Attest root CA from \(absolute): \(roots[0].subject)")
            } catch {
                let w = "Could not parse root CA at \(absolute): \(error). Attestation will fail at the chain check."
                logger.error("\(w)")
                warnings.append(w)
            }
        } else {
            let w = "Apple App Attest root CA not found at \(absolute). The server runs, but every attestation will fail the chain check. Fetch it with: curl -o \"\(absolute)\" \(rootCAURL)"
            logger.warning("\(w)")
            warnings.append(w)
        }

        // Simulated attestation is off unless explicitly enabled.
        var simulatedCA: SimulatedAppAttestCA?
        let flag = (Environment.get("ALLOW_SIMULATED") ?? "").lowercased()
        if ["1", "true", "yes"].contains(flag) {
            do {
                simulatedCA = try SimulatedAppAttestCA()
                logger.warning("ALLOW_SIMULATED is on: attestations chaining to an in-memory test root are accepted and labelled SIMULATED. This is not real App Attest.")
            } catch {
                let w = "ALLOW_SIMULATED is set but the test CA could not be created: \(error). Simulated mode is off."
                logger.error("\(w)")
                warnings.append(w)
            }
        }

        return ServerConfig(appID: appID, appIDIsPlaceholder: isPlaceholder, rootCertificates: roots,
                            rootCAPath: absolute, warnings: warnings, simulatedCA: simulatedCA)
    }
}
