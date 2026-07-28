//
//  JWT Crypto Tests.swift
//  RFC_7519JWTCrypto Tests
//
//  Created by Generated on 2025-07-28.
//

import Crypto
import Foundation
import Testing

@testable import JWT

// QUICK START GUIDE:
//
// 1. Create a JWT (simplest way):
//    let jwt = try JWT.hmacSHA256(
//        issuer: "myapp",
//        subject: "user123",
//        secretKey: "my-secret-key"
//    )
//    let token = try jwt.compactSerialization()
//
// 2. Verify a JWT:
//    let receivedJWT = try JWT.parse(from: tokenString)
//    let isValid = try receivedJWT.verify(with: .symmetric(string: "my-secret-key"), algorithm: .hmacSHA256)
//
// 3. Create with expiration and claims:
//    let jwt = try JWT.hmacSHA256(
//        issuer: "myapp",
//        subject: "user@example.com",
//        expiresIn: 3600, // 1 hour
//        claims: ["role": "admin"],
//        secretKey: "secret"
//    )
//
// 4. Verify with expiration check:
//    let isValidAndNotExpired = try jwt.verifyAndValidate(
//        with: .symmetric(string: "secret"),
//        algorithm: .hmacSHA256
//    )

@Suite("JWT Crypto Tests")
struct JWT_Crypto_Tests {

  // MARK: - Simple JWT Creation Examples

  @Test("Simplest JWT creation - just a secret key")
  func testSimplestJWTCreation() throws {
    // The absolute simplest way - just provide a secret key
    let jwt = try JWT.hmacSHA256(
      issuer: "myapp",
      subject: "user123",
      secretKey: "my-secret-key"
    )

    #expect(jwt.header.alg == "HS256")
    #expect(jwt.payload.iss == "myapp")
    #expect(jwt.payload.sub == "user123")

    // Get the JWT string to send to clients
    let tokenString = try jwt.compactSerialization()
    #expect(tokenString.contains("."))  // JWT format: header.payload.signature
  }

  @Test("Common use case - API authentication token")
  func testAPIAuthToken() throws {
    // Typical API auth token with user info and expiration
    let jwt = try JWT.hmacSHA256(
      issuer: "api.myapp.com",
      subject: "user@example.com",
      audience: "mobile-app",
      expiresIn: 3600,  // 1 hour
      claims: [
        "userId": "12345",
        "role": "user",
        "scope": "read write",
      ],
      secretKey: "your-256-bit-secret"
    )

    // The token is ready to send in Authorization header
    let token = try jwt.compactSerialization()
    // Usage: Authorization: Bearer \(token)

    #expect(jwt.payload.iss == "api.myapp.com")
    #expect(jwt.payload.additionalClaim("role", as: String.self) == "user")
  }

  @Test("Real-world example - User session token")
  func testUserSessionToken() throws {
    // Create a session token after user login

    let secretKey = "your-super-secret-key"
    let sessionToken = try JWT.hmacSHA256(
      issuer: "auth.example.com",
      subject: "john.doe@example.com",
      expiresIn: 24 * 60 * 60,  // 24 hours
      claims: [
        "name": "John Doe",
        "email": "john.doe@example.com",
        "premium": true,
        "loginTime": ISO8601DateFormatter().string(from: Date()),
      ],
      secretKey: secretKey
    )

    // Verify it worked
    let tokenString = try sessionToken.compactSerialization()
    #expect(!tokenString.isEmpty)

    // Later, verify the token
    let verified = try JWT.parse(from: tokenString)
    let isValid = try verified.verify(with: .symmetric(string: secretKey), algorithm: .hmacSHA256)
    #expect(isValid)
  }

  @Test("Microservice communication token")
  func testMicroserviceToken() throws {
    // Service-to-service authentication
    let serviceToken = try JWT.hmacSHA384(
      issuer: "payment-service",
      subject: "order-service",
      audience: "inventory-service",
      expiresIn: 300,  // 5 minutes for service calls
      claims: [
        "requestId": UUID().uuidString,
        "action": "check-inventory",
        "items": ["SKU-123", "SKU-456"],
      ],
      secretKey: "shared-service-secret"
    )

    #expect(serviceToken.header.alg == "HS384")
    #expect(serviceToken.payload.exp != nil)
  }

  @Test("Refresh token pattern")
  func testRefreshTokenPattern() throws {
    // Short-lived access token
    let accessToken = try JWT.hmacSHA256(
      issuer: "auth.app.com",
      subject: "user123",
      expiresIn: 15 * 60,  // 15 minutes
      claims: ["type": "access"],
      secretKey: "access-token-secret"
    )

    // Long-lived refresh token
    let refreshToken = try JWT.hmacSHA512(
      issuer: "auth.app.com",
      subject: "user123",
      expiresIn: 30 * 24 * 60 * 60,  // 30 days
      claims: [
        "type": "refresh",
        "tokenFamily": UUID().uuidString,
      ],
      secretKey: "refresh-token-secret"
    )

    #expect(accessToken.header.alg == "HS256")
    #expect(refreshToken.header.alg == "HS512")
  }

  @Test("Email verification token")
  func testEmailVerificationToken() throws {
    // Create a token for email verification links
    let verificationToken = try JWT.hmacSHA256(
      issuer: "signup.example.com",
      subject: "new.user@example.com",
      expiresIn: 24 * 60 * 60,  // 24 hours to verify
      claims: [
        "action": "verify-email",
        "email": "new.user@example.com",
      ],
      secretKey: "email-verification-secret"
    )

    let tokenString = try verificationToken.compactSerialization()
    // Use in URL: https://example.com/verify?token=\(tokenString)

    #expect(verificationToken.payload.additionalClaim("action", as: String.self) == "verify-email")
  }

  @Test("Password reset token")
  func testPasswordResetToken() throws {
    // Secure password reset token
    let resetToken = try JWT.hmacSHA256(
      issuer: "auth.example.com",
      subject: "user@example.com",
      expiresIn: 60 * 60,  // 1 hour to reset
      claims: [
        "action": "password-reset",
        "resetId": UUID().uuidString,
      ],
      secretKey: "password-reset-secret"
    )

    #expect(resetToken.payload.exp != nil)
    #expect(resetToken.payload.additionalClaim("action", as: String.self) == "password-reset")
  }

  @Test("API key with scopes")
  func testAPIKeyWithScopes() throws {
    // API key for third-party integrations - no expiration
    let apiKey = try JWT.signed(
      algorithm: .hmacSHA256,
      key: .symmetric(string: "api-key-secret"),
      issuer: "api.platform.com",
      subject: "client-app-123",
      audience: "api.platform.com",
      expiresIn: nil,  // No expiration for API keys
      claims: [
        "scopes": ["users:read", "orders:read", "products:write"],
        "rateLimit": 1000,
        "tier": "premium",
      ]
    )

    // No expiration for API keys
    #expect(apiKey.payload.exp == nil)
    #expect(apiKey.payload.additionalClaim("tier", as: String.self) == "premium")
  }

  // MARK: - JWT Verification Patterns

  @Test("Simple JWT verification")
  func testSimpleJWTVerification() throws {
    let secret = "my-secret-key"

    // Create a token
    let jwt = try JWT.hmacSHA256(
      issuer: "myapp",
      subject: "user123",
      expiresIn: 3600,
      secretKey: secret
    )

    let tokenString = try jwt.compactSerialization()

    // Later, verify the token
    let receivedToken = try JWT.parse(from: tokenString)
    let isValid = try receivedToken.verify(with: .symmetric(string: secret), algorithm: .hmacSHA256)

    #expect(isValid)
  }

  @Test("JWT verification with expiration check")
  func testJWTVerificationWithExpiration() throws {
    let secret = "my-secret-key"

    // Create a token that expires in 1 hour
    let jwt = try JWT.hmacSHA256(
      issuer: "myapp",
      subject: "user123",
      expiresIn: 3600,
      secretKey: secret
    )

    let tokenString = try jwt.compactSerialization()
    let receivedToken = try JWT.parse(from: tokenString)

    // This checks both signature AND expiration/timing
    let isValidAndNotExpired = try receivedToken.verifyAndValidate(
      with: .symmetric(string: secret),
      algorithm: .hmacSHA256
    )

    #expect(isValidAndNotExpired)
  }

  @Test("Extract claims after verification")
  func testExtractClaimsAfterVerification() throws {
    let secret = "api-secret"

    // Create token with custom claims
    let jwt = try JWT.hmacSHA256(
      issuer: "api",
      subject: "user@example.com",
      claims: [
        "userId": "12345",
        "role": "admin",
        "permissions": ["read", "write", "delete"],
      ],
      secretKey: secret
    )

    let tokenString = try jwt.compactSerialization()

    // Verify and extract claims
    let receivedToken = try JWT.parse(from: tokenString)
    let isValid = try receivedToken.verify(with: .symmetric(string: secret), algorithm: .hmacSHA256)

    if isValid {
      // Safe to extract claims
      let userId = receivedToken.payload.additionalClaim("userId", as: String.self)
      let role = receivedToken.payload.additionalClaim("role", as: String.self)
      let permissions = receivedToken.payload.additionalClaim("permissions", as: [String].self)

      #expect(userId == "12345")
      #expect(role == "admin")
      #expect(permissions == ["read", "write", "delete"])
    }
  }

  // MARK: - JWT Creation with swift-crypto Tests

  @Test("JWT creation with HMAC-SHA256")
  func testJWTHMACSHA256() throws {
    let jwt = try JWT.hmacSHA256(
      issuer: "example.com",
      subject: "user123",
      audience: "api.example.com",
      expiresIn: 3600,
      claims: ["role": "admin", "permissions": ["read", "write"]],
      secretKey: "my-secret-key"
    )

    #expect(jwt.header.alg == "HS256")
    #expect(jwt.header.typ == "JWT")
    #expect(jwt.payload.iss == "example.com")
    #expect(jwt.payload.sub == "user123")
    #expect(jwt.payload.aud?.values == ["api.example.com"])
    #expect(jwt.payload.exp != nil)
    #expect(jwt.payload.iat != nil)
    #expect(jwt.payload.additionalClaim("role", as: String.self) == "admin")

    // Verify the token can be parsed back
    let tokenString = try jwt.compactSerialization()
    let parsedJWT = try JWT.parse(from: tokenString)

    #expect(parsedJWT.payload.iss == jwt.payload.iss)
    #expect(parsedJWT.payload.sub == jwt.payload.sub)
  }

  @Test("JWT creation with ECDSA-SHA256")
  func testJWTECDSASHA256() throws {
    let privateKey = P256.Signing.PrivateKey()
    let verificationKey = VerificationKey.ecdsa(from: .ecdsa(privateKey))!

    let jwt = try JWT.ecdsaSHA256(
      issuer: "ecdsa-issuer",
      subject: "ecdsa-user",
      audience: "ecdsa-api",
      expiresIn: 7200,
      claims: ["custom": "value"],
      privateKey: privateKey
    )

    #expect(jwt.header.alg == "ES256")
    #expect(jwt.payload.iss == "ecdsa-issuer")

    // Verify signature
    let isValid = try jwt.verify(with: verificationKey, algorithm: .ecdsaSHA256)
    #expect(isValid)
  }

  @Test("JWT creation with multiple audiences using swift-crypto")
  func testJWTMultipleAudiences() throws {
    let jwt = try JWT.signed(
      algorithm: .hmacSHA256,
      key: .symmetric(string: "test-key"),
      issuer: "multi-aud-issuer",
      subject: "user",
      audiences: ["api1.example.com", "api2.example.com", "api3.example.com"],
      expiresIn: 3600
    )

    #expect(
      jwt.payload.aud?.values == ["api1.example.com", "api2.example.com", "api3.example.com"]
    )
  }

  @Test("JWT creation with timing controls using swift-crypto")
  func testJWTTimingControls() throws {
    let customIat = Date(timeIntervalSinceNow: -60)  // 1 minute ago
    let customExp = Date(timeIntervalSinceNow: 7200)  // 2 hours from now
    let customNbf = Date(timeIntervalSinceNow: 300)  // 5 minutes from now

    let jwt = try JWT.signed(
      algorithm: .hmacSHA256,
      key: .symmetric(string: "timing-key"),
      issuer: "timing-issuer",
      subject: "timing-user",
      expiresAt: customExp,
      notBefore: customNbf,
      issuedAt: customIat
    )

    #expect(abs(jwt.payload.iat!.timeIntervalSince1970 - customIat.timeIntervalSince1970) < 1.0)
    #expect(abs(jwt.payload.exp!.timeIntervalSince1970 - customExp.timeIntervalSince1970) < 1.0)
    #expect(abs(jwt.payload.nbf!.timeIntervalSince1970 - customNbf.timeIntervalSince1970) < 1.0)
  }

  @Test("JWT creation with custom header parameters using swift-crypto")
  func testJWTCustomHeaders() throws {
    let jwt = try JWT.signed(
      algorithm: .hmacSHA256,
      key: .symmetric(string: "header-key"),
      issuer: "header-issuer",
      subject: "user",
      expiresIn: 3600,
      headerParameters: ["custom": "header-value", "version": 2]
    )

    #expect(jwt.header.additionalParameter("custom", as: String.self) == "header-value")
    #expect(jwt.header.additionalParameter("version", as: Int.self) == 2)
  }

  // MARK: - Convenience Method Tests

  @Test("JWT HMAC-SHA256 convenience method")
  func testJWTHMACConvenience() throws {
    let jwt = try JWT.hmacSHA256(
      issuer: "convenience-issuer",
      subject: "convenience-user",
      audience: "convenience-api",
      expiresIn: 1800,
      claims: ["role": "user", "active": true],
      secretKey: "convenience-key"
    )

    #expect(jwt.header.alg == "HS256")
    #expect(jwt.payload.iss == "convenience-issuer")
    #expect(jwt.payload.sub == "convenience-user")
    #expect(jwt.payload.aud?.values == ["convenience-api"])
    #expect(jwt.payload.additionalClaim("role", as: String.self) == "user")
    #expect(jwt.payload.additionalClaim("active", as: Bool.self) == true)

    // Verify the token
    let verificationKey = VerificationKey.symmetric(string: "convenience-key")
    let isValid = try jwt.verify(with: verificationKey, algorithm: .hmacSHA256)
    #expect(isValid)
  }

  @Test("JWT HMAC-SHA384 convenience method")
  func testJWTHMAC384Convenience() throws {
    let jwt = try JWT.hmacSHA384(
      issuer: "no-aud-issuer",
      subject: "no-aud-user",
      secretKey: "no-aud-key"
    )

    #expect(jwt.header.alg == "HS384")
    #expect(jwt.payload.aud == nil)
    #expect(jwt.payload.iss == "no-aud-issuer")
    #expect(jwt.payload.sub == "no-aud-user")
  }

  // MARK: - Signature Verification Tests

  @Test("JWT signature verification with HMAC")
  func testJWTVerificationHMAC() throws {
    let verificationKey = VerificationKey.symmetric(string: "verification-key")
    let wrongKey = VerificationKey.symmetric(string: "wrong-key")

    let jwt = try JWT.hmacSHA256(
      issuer: "verify-issuer",
      subject: "verify-user",
      expiresIn: 3600,
      secretKey: "verification-key"
    )

    // Correct key should verify
    let isValidCorrect = try jwt.verify(with: verificationKey, algorithm: .hmacSHA256)
    #expect(isValidCorrect)

    // Wrong key should fail
    let isValidWrong = try jwt.verify(with: wrongKey, algorithm: .hmacSHA256)
    #expect(!isValidWrong)
  }

  @Test("JWT verification with timing validation")
  func testJWTVerificationWithTiming() throws {
    let verificationKey = VerificationKey.symmetric(string: "timing-verify-key")

    // Create expired token
    let expiredJWT = try JWT.hmacSHA256(
      issuer: "expired-issuer",
      subject: "expired-user",
      expiresIn: -3600,  // Expired 1 hour ago
      secretKey: "timing-verify-key"
    )

    // Signature should be valid but timing should fail
    let isSignatureValid = try expiredJWT.verify(with: verificationKey, algorithm: .hmacSHA256)
    #expect(isSignatureValid)

    #expect(throws: RFC_7519.Error.self) {
      try expiredJWT.verifyAndValidate(with: verificationKey, algorithm: .hmacSHA256)
    }

    // Create valid token
    let validJWT = try JWT.hmacSHA256(
      issuer: "valid-issuer",
      subject: "valid-user",
      expiresIn: 3600,
      secretKey: "timing-verify-key"
    )

    // Both signature and timing should be valid
    let isValid = try validJWT.verifyAndValidate(with: verificationKey, algorithm: .hmacSHA256)
    #expect(isValid)
  }

  @Test("JWT verification with not-yet-valid token")
  func testJWTVerificationNotYetValid() throws {
    let verificationKey = VerificationKey.symmetric(string: "nbf-key")

    let jwt = try JWT.signed(
      algorithm: .hmacSHA256,
      key: .symmetric(string: "nbf-key"),
      issuer: "nbf-issuer",
      subject: "nbf-user",
      expiresIn: 7200,  // Expires in 2 hours
      notBefore: Date(timeIntervalSinceNow: 3600)  // Valid in 1 hour
    )

    // Signature should be valid but timing should fail
    let isSignatureValid = try jwt.verify(with: verificationKey, algorithm: .hmacSHA256)
    #expect(isSignatureValid)

    #expect(throws: RFC_7519.Error.self) {
      try jwt.verifyAndValidate(with: verificationKey, algorithm: .hmacSHA256)
    }
  }

  // MARK: - Algorithm Tests

  @Test("Signing algorithm names")
  func testSigningAlgorithmNames() {
    #expect(SigningAlgorithm.hmacSHA256.algorithmName == "HS256")
    #expect(SigningAlgorithm.hmacSHA384.algorithmName == "HS384")
    #expect(SigningAlgorithm.hmacSHA512.algorithmName == "HS512")
    #expect(SigningAlgorithm.ecdsaSHA256.algorithmName == "ES256")
  }

  @Test("Algorithm from string")
  func testAlgorithmFromString() {
    #expect(SigningAlgorithm.from(algorithmName: "HS256")?.algorithmName == "HS256")
    #expect(SigningAlgorithm.from(algorithmName: "HS384")?.algorithmName == "HS384")
    #expect(SigningAlgorithm.from(algorithmName: "HS512")?.algorithmName == "HS512")
    #expect(SigningAlgorithm.from(algorithmName: "ES256")?.algorithmName == "ES256")
    #expect(SigningAlgorithm.from(algorithmName: "none") == nil)
    #expect(SigningAlgorithm.from(algorithmName: "") == nil)
    #expect(SigningAlgorithm.from(algorithmName: "UNKNOWN") == nil)
  }

  // MARK: - Key Creation Tests

  @Test("Symmetric key creation")
  func testSymmetricKeyCreation() throws {
    let stringKey = SigningKey.symmetric(string: "test-key")
    let dataKey = SigningKey.symmetric(data: Data("test-key".utf8))

    // Both should work for signing (can't directly compare the keys)
    let jwt1 = try JWT.signed(
      algorithm: .hmacSHA256,
      key: stringKey,
      issuer: "key-test",
      subject: "user",
      expiresIn: 3600
    )

    let jwt2 = try JWT.signed(
      algorithm: .hmacSHA256,
      key: dataKey,
      issuer: "key-test",
      subject: "user",
      expiresIn: 3600
    )

    // Verify with equivalent verification keys
    let verifyKey1 = VerificationKey.symmetric(string: "test-key")
    let verifyKey2 = VerificationKey.symmetric(data: Data("test-key".utf8))

    #expect((try? jwt1.verify(with: verifyKey1, algorithm: .hmacSHA256)) == true)
    #expect((try? jwt1.verify(with: verifyKey2, algorithm: .hmacSHA256)) == true)
    #expect((try? jwt2.verify(with: verifyKey1, algorithm: .hmacSHA256)) == true)
    #expect((try? jwt2.verify(with: verifyKey2, algorithm: .hmacSHA256)) == true)
  }

  @Test("ECDSA key generation")
  func testECDSAKeyGeneration() throws {
    let signingKey = SigningKey.generateECDSA()
    let verificationKey = VerificationKey.ecdsa(from: signingKey)!

    let jwt = try JWT.signed(
      algorithm: .ecdsaSHA256,
      key: signingKey,
      issuer: "ecdsa-gen-test",
      subject: "user",
      expiresIn: 3600
    )

    let isValid = try jwt.verify(with: verificationKey, algorithm: .ecdsaSHA256)
    #expect(isValid)
  }

  // MARK: - Edge Cases

  @Test("JWT static method with full configuration")
  func testJWTStaticMethodFullConfiguration() throws {
    let jwt = try JWT.signed(
      algorithm: .hmacSHA256,
      key: .symmetric(string: "chain-key"),
      issuer: "chain-issuer",
      subject: "chain-user",
      audience: "chain-api",
      expiresIn: 3600,
      notBefore: Date(timeIntervalSinceNow: -60),
      jti: UUID().uuidString,
      claims: ["role": "admin", "active": true, "score": 95],
      headerParameters: ["custom": "value", "kid": "chain-key-1", "cty": "application/json"]
    )

    #expect(jwt.payload.iss == "chain-issuer")
    #expect(jwt.payload.sub == "chain-user")
    #expect(jwt.payload.aud?.values == ["chain-api"])
    #expect(jwt.payload.jti != nil)
    #expect(jwt.header.cty == "application/json")
    #expect(jwt.header.kid == "chain-key-1")
    #expect(jwt.payload.additionalClaim("role", as: String.self) == "admin")
    #expect(jwt.payload.additionalClaim("active", as: Bool.self) == true)
    #expect(jwt.payload.additionalClaim("score", as: Int.self) == 95)
  }
}
