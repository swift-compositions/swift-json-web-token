// swift-tools-version: 6.4

import PackageDescription

extension String {
    static let jwt: Self = "JWT"
}

extension Target.Dependency {
    static var jwt: Self { .target(name: .jwt) }
}

extension Target.Dependency {
    static var crypto: Self { .product(name: "Crypto", package: "swift-crypto") }
    static var rfc7519: Self { .product(name: "RFC 7519", package: "swift-rfc-7519") }
}

let package = Package(
    // Must match the repository/directory name: SwiftPM matches workspace override
    // candidates by declared name and then rejects the override when the directory
    // disagrees, which aborts resolution for every package in the workspace.
    name: "swift-json-web-token",
    platforms: [
        .macOS(.v27),
        .iOS(.v27),
        .tvOS(.v27),
        .watchOS(.v27),
        .visionOS(.v27),
    ],
    products: [
        .library(name: .jwt, targets: [.jwt])
    ],
    dependencies: [
        .package(url: "https://github.com/apple/swift-crypto.git", "3.0.0"..<"5.0.0"),
        .package(url: "https://github.com/swift-ietf/swift-rfc-7519.git", branch: "main"),
    ],
    targets: [
        .target(
            name: .jwt,
            dependencies: [
                .rfc7519,
                .crypto,
            ]
        ),
        .testTarget(
            name: .jwt.tests,
            dependencies: [
                .jwt
            ]
        ),
    ],
    swiftLanguageModes: [.v6]
)

extension String { var tests: Self { self + " Tests" } }
