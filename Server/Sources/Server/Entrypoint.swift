import Vapor

@main
enum Entrypoint {
    static func main() async throws {
        var env = try Environment.detect()
        try LoggingSystem.bootstrap(from: &env)
        let app = try await Application.make(env)
        do {
            try await configure(app)
            try await app.execute()
        } catch {
            app.logger.report(error: error)
            try? await app.asyncShutdown()
            throw error
        }
        try await app.asyncShutdown()
    }
}

func configure(_ app: Application) async throws {
    let config = ServerConfig.load(logger: app.logger)

    app.http.server.configuration.hostname = "0.0.0.0"
    app.http.server.configuration.port = Int(Environment.get("PORT") ?? "") ?? 8080
    app.routes.defaultMaxBodySize = "1mb"

    let store = AttestationStore()
    try routes(app, config: config, store: store)

    let port = app.http.server.configuration.port
    let urls = NetworkInfo.lanIPv4Addresses().map { "http://\($0.address):\(port)  (\($0.interface))" }
    app.logger.notice("App ID: \(config.appID)")
    if config.simulatedModeEnabled {
        app.logger.notice("Simulated attestation: ON (POST /simulator/attest-key, test root accepted)")
    }
    if urls.isEmpty {
        app.logger.warning("No non-loopback IPv4 address found. Is the Mac on Wi-Fi?")
    } else {
        app.logger.notice("Point the iPhone app at one of these URLs (same Wi-Fi):")
        for url in urls { app.logger.notice("  \(url)") }
    }
    app.logger.notice("Dashboard: http://localhost:\(port)/")
}
