// swift-tools-version: 6.4

import PackageDescription

let package = Package(

    name: "swift-json-web-token",
    platforms: [
        .macOS(.v27),
        .iOS(.v27),
        .tvOS(.v27),
        .watchOS(.v27),
        .visionOS(.v27),
    ],
    products: [
        .library(name: "JWT", targets: ["JWT"])
    ],
    dependencies: [
        .package(url: "https://github.com/apple/swift-crypto.git", "3.0.0"..<"5.0.0"),
        .package(url: "https://github.com/swift-ietf/swift-rfc-7519.git", branch: "main"),
    ],
    targets: [
        .target(
            name: "JWT",
            dependencies: [
                .product(name: "RFC 7519", package: "swift-rfc-7519"),
                .product(name: "Crypto", package: "swift-crypto"),
            ]
        ),
        .testTarget(
            name: "JWT Tests",
            dependencies: [
                .target(name: "JWT")
            ]
        ),
    ],
    swiftLanguageModes: [.v6]
)

