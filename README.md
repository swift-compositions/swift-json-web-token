# swift-jwt

[![CI](https://github.com/swift-foundations/swift-json-web-token/workflows/CI/badge.svg)](https://github.com/swift-foundations/swift-json-web-token/actions/workflows/ci.yml)
![Development Status](https://img.shields.io/badge/status-active--development-blue.svg)

Creates, signs, and verifies JSON Web Tokens (JWTs) over Apple's Crypto framework, with RFC 7519 claims and timing validation.

## Features

- HMAC-SHA256/384/512 and ECDSA-SHA256 signing algorithms
- RFC 7519 compliant JWT implementation via `swift-rfc-7519`
- Apple Crypto framework integration via `swift-crypto`
- Static methods for HMAC and ECDSA JWT creation
- JWT header, claims, and timing configuration
- Type-safe JWT handling via Swift's type system
- Signature verification with timing validation (exp, nbf, iat)

## Requirements

- **Platforms**: macOS 13.0+, iOS 16.0+
- **Swift**: 5.9+ (Swift 6.0 supported)

## Installation

Add this package to your `Package.swift`:

```swift
dependencies: [
    .package(url: "https://github.com/swift-foundations/swift-json-web-token.git", from: "0.0.2")
]
```

Add the product to your target:

```swift
.target(
    name: "YourTarget",
    dependencies: [
        .product(name: "JWT", package: "swift-json-web-token")
    ]
)
```

## Quick Start

### Creating JWTs

#### HMAC-SHA256 (Recommended for shared secrets)

```swift
import JWT

// Create a JWT with HMAC-SHA256
let jwt = try JWT.hmacSHA256(
    issuer: "example.com",
    subject: "user123",
    audience: "api.example.com",
    expiresIn: 3600, // 1 hour
    claims: ["role": "admin", "permissions": ["read", "write"]],
    secretKey: "your-secret-key"
)

// Get the token string
let tokenString = try jwt.compactSerialization()
```

#### ECDSA-SHA256 (Recommended for public/private key pairs)

```swift
import JWT
import Crypto

// Generate or load your ECDSA private key
let privateKey = P256.Signing.PrivateKey()

let jwt = try JWT.ecdsaSHA256(
    issuer: "secure-service",
    subject: "user456",
    audience: "mobile-app",
    expiresIn: 7200, // 2 hours
    claims: ["scope": "user:read"],
    privateKey: privateKey
)
```

### Verifying JWTs

#### HMAC Verification

```swift
import JWT

// Parse JWT from token string
let jwt = try JWT.parse(from: tokenString)

// Create verification key
let verificationKey = VerificationKey.symmetric(string: "your-secret-key")

// Verify signature only
let isValidSignature = try jwt.verify(with: verificationKey)

// Verify signature and validate timing (exp, nbf, iat)
let isFullyValid = try jwt.verifyAndValidate(with: verificationKey)
```

#### ECDSA Verification

```swift
import JWT
import Crypto

// Create verification key from signing key
let privateKey = P256.Signing.PrivateKey()
let verificationKey = VerificationKey.ecdsa(from: .ecdsa(privateKey))!

// Verify the JWT
let isValid = try jwt.verifyAndValidate(with: verificationKey)
```

Alternative - using raw public key data:

```swift
import JWT
import Crypto

let privateKey = P256.Signing.PrivateKey()
let publicKeyData = privateKey.publicKey.rawRepresentation
let verificationKey = try VerificationKey.ecdsa(rawRepresentation: publicKeyData)

let isValid = try jwt.verifyAndValidate(with: verificationKey)
```

## Advanced Usage

### Custom JWT Configuration

```swift
import JWT

let jwt = try JWT.signed(
    algorithm: .hmacSHA384,
    key: .symmetric(string: "custom-key"),
    issuer: "custom-issuer",
    subject: "user789",
    audiences: ["api1.example.com", "api2.example.com"], // Multiple audiences
    expiresAt: Date(timeIntervalSinceNow: 86400), // Custom expiration
    notBefore: Date(timeIntervalSinceNow: 300), // Valid in 5 minutes
    jti: UUID().uuidString, // JWT ID
    claims: [
        "role": "moderator",
        "permissions": ["read", "moderate"],
        "active": true
    ],
    headerParameters: [
        "kid": "key-identifier",
        "custom": "header-value"
    ]
)
```

### Working with Claims

```swift
// Access standard claims
print("Issuer: \(jwt.payload.iss ?? "Unknown")")
print("Subject: \(jwt.payload.sub ?? "Unknown")")
print("Expires: \(jwt.payload.exp?.description ?? "Never")")

// Access custom claims
let role = jwt.payload.additionalClaim("role", as: String.self)
let permissions = jwt.payload.additionalClaim("permissions", as: [String].self)
let isActive = jwt.payload.additionalClaim("active", as: Bool.self)
```

### Timing Validation

```swift
// Validate with custom timing parameters
let isValid = try jwt.verifyAndValidate(
    with: verificationKey,
    currentTime: Date(), // Custom current time
    clockSkew: 120 // Allow 2 minutes clock skew
)
```

### Key Management

```swift
// Symmetric keys
let stringKey = SigningKey.symmetric(string: "secret")
let dataKey = SigningKey.symmetric(data: keyData)

// ECDSA keys
let generatedKey = SigningKey.generateECDSA()
let existingKey = try SigningKey.ecdsa(rawRepresentation: privateKeyData)

// Verification keys
let symmetricVerify = VerificationKey.symmetric(string: "secret")
let ecdsaVerify = VerificationKey.ecdsa(from: signingKey)
let publicKeyVerify = try VerificationKey.ecdsa(rawRepresentation: publicKeyData)
```

## Supported Algorithms

| Algorithm | Description | Use Case |
|-----------|-------------|----------|
| `HS256` | HMAC-SHA256 | Shared secret scenarios |
| `HS384` | HMAC-SHA384 | Enhanced security with shared secrets |
| `HS512` | HMAC-SHA512 | Maximum security with shared secrets |
| `ES256` | ECDSA-SHA256 | Public/private key scenarios |
| `none` | No signature | Testing only (not recommended for production) |

## Error Handling

The package throws RFC 7519 compliant errors:

```swift
do {
    let jwt = try JWT.hmacSHA256(/*...*/)
    let isValid = try jwt.verifyAndValidate(with: key)
} catch RFC_7519.Error.invalidSignature(let message) {
    print("Invalid signature: \(message)")
} catch RFC_7519.Error.tokenExpired {
    print("Token has expired")
} catch RFC_7519.Error.tokenNotYetValid {
    print("Token not yet valid")
} catch {
    print("Other error: \(error)")
}
```

## Dependencies

This package is built on top of:

- [swift-rfc-7519](https://github.com/swift-web-standards/swift-rfc-7519) - RFC 7519 compliant JWT implementation
- [swift-crypto](https://github.com/apple/swift-crypto) - Apple's cryptographic framework

## Security Considerations

- **Key Management**: Store secret keys securely and rotate them regularly
- **Algorithm Choice**: Use ECDSA for distributed systems, HMAC for simple scenarios
- **Token Expiration**: Always set appropriate expiration times
- **Timing Validation**: Enable timing validation in production
- **HTTPS Only**: Always transmit JWTs over HTTPS
- **Never Log Tokens**: Avoid logging JWTs in production systems

## Testing

Run the test suite:

```bash
swift test
```

The package includes comprehensive tests covering:
- JWT creation with all supported algorithms
- Signature verification
- Timing validation
- Edge cases and error conditions
- Key management operations

## Related Packages

### Used By

- [swift-identities-types](https://github.com/coenttb/swift-identities-types): A Swift package with foundational types for authentication.
- [swift-server-foundation](https://github.com/coenttb/swift-server-foundation): A Swift package with tools to simplify server development.
- [swift-web-foundation](https://github.com/coenttb/swift-web-foundation): A Swift package with tools to simplify web development.

### Third-Party Dependencies

- [apple/swift-crypto](https://github.com/apple/swift-crypto): Open-source implementation of a substantial portion of the API of Apple CryptoKit.

## Contributing

Contributions are welcome. Please open an issue or submit a pull request.

## License

This project is licensed under the **Apache 2.0 License**. See the [LICENSE](LICENSE).
