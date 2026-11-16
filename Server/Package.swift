// swift-tools-version:6.0
import PackageDescription

let package = Package(
    name: "AttestationServer",
    platforms: [.macOS(.v14)],
    products: [
        .library(name: "AppAttestVerifier", targets: ["AppAttestVerifier"]),
        .executable(name: "Server", targets: ["Server"]),
    ],
    dependencies: [
        .package(url: "https://github.com/vapor/vapor.git", from: "4.100.0"),
        .package(url: "https://github.com/apple/swift-certificates.git", from: "1.5.0"),
        .package(url: "https://github.com/apple/swift-crypto.git", "3.0.0"..<"5.0.0"),
        // Already a transitive dependency of swift-certificates; declared directly because
        // DER/PEM parsing initialisers on `Certificate` come from SwiftASN1 protocols.
        .package(url: "https://github.com/apple/swift-asn1.git", from: "1.1.0"),
    ],
    targets: [
        // Pure verification logic: no networking, no storage.
        .target(
            name: "AppAttestVerifier",
            dependencies: [
                .product(name: "X509", package: "swift-certificates"),
                .product(name: "Crypto", package: "swift-crypto"),
                .product(name: "SwiftASN1", package: "swift-asn1"),
            ]
        ),
        .executableTarget(
            name: "Server",
            dependencies: [
                "AppAttestVerifier",
                .product(name: "Vapor", package: "vapor"),
            ],
            resources: [.copy("Resources")]
        ),
    ],
    swiftLanguageModes: [.v5]
)
