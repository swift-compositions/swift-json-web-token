//
//  JWT Convenience Tests.swift
//  swift-jwt
//
//  Tests for JWT convenience accessors
//

import Foundation
import Testing

@testable import JWT

@Suite("JWT Convenience Accessors")
struct JWT_Convenience_Tests {

  @Test("Verify computed properties match actual properties")
  func testComputedPropertiesMatchActualProperties() throws {
    // Create a JWT with all properties set
    let jwt = try JWT.signed(
      algorithm: .hmacSHA256,
      key: .symmetric(string: "test-secret"),
      issuer: "test-issuer",
      subject: "test-subject",
      audience: "test-audience",
      expiresIn: 3600,
      notBefore: Date(timeIntervalSinceNow: -60),
      issuedAt: Date(),
      jti: "test-jwt-id",
      claims: ["custom": "value"],
      headerParameters: ["kid": "test-key-id", "cty": "test-content-type"]
    )

    // Test Header computed properties match actual properties
    #expect(jwt.header.algorithm == jwt.header.alg)
    #expect(jwt.header.type == jwt.header.typ)
    #expect(jwt.header.contentType == jwt.header.cty)
    #expect(jwt.header.keyId == jwt.header.kid)

    // Test Payload computed properties match actual properties
    #expect(jwt.payload.issuer == jwt.payload.iss)
    #expect(jwt.payload.subject == jwt.payload.sub)
    #expect(jwt.payload.audience == jwt.payload.aud)
    #expect(jwt.payload.expirationTime == jwt.payload.exp)
    #expect(jwt.payload.notBeforeTime == jwt.payload.nbf)
    #expect(jwt.payload.issuedAtTime == jwt.payload.iat)
    #expect(jwt.payload.id == jwt.payload.jti)

    // Verify the actual values
    #expect(jwt.header.algorithm == "HS256")
    #expect(jwt.header.type == "JWT")
    #expect(jwt.header.contentType == "test-content-type")
    #expect(jwt.header.keyId == "test-key-id")

    #expect(jwt.payload.issuer == "test-issuer")
    #expect(jwt.payload.subject == "test-subject")
    #expect(jwt.payload.id == "test-jwt-id")

    // Test JWT token property
    let tokenString = try jwt.token
    let compactString = try jwt.compactSerialization()
    #expect(tokenString == compactString)
  }

  @Test("Header convenience accessors")
  func testHeaderConvenienceAccessors() throws {
    let jwt = try JWT.hmacSHA256(
      issuer: "test",
      subject: "user",
      secretKey: "secret"
    )

    // Test reading with convenience names
    #expect(jwt.header.algorithm == "HS256")
    #expect(jwt.header.algorithm == jwt.header.alg)

    #expect(jwt.header.type == "JWT")
    #expect(jwt.header.type == jwt.header.typ)

    #expect(jwt.header.contentType == nil)
    #expect(jwt.header.contentType == jwt.header.cty)

    #expect(jwt.header.keyId == nil)
    #expect(jwt.header.keyId == jwt.header.kid)
  }

  @Test("Payload convenience accessors")
  func testPayloadConvenienceAccessors() throws {
    let jwt = try JWT.hmacSHA256(
      issuer: "myapp.com",
      subject: "user123",
      audience: "api.myapp.com",
      expiresIn: 3600,
      claims: ["role": "admin"],
      secretKey: "secret"
    )

    // Test reading with convenience names
    #expect(jwt.payload.issuer == "myapp.com")
    #expect(jwt.payload.issuer == jwt.payload.iss)

    #expect(jwt.payload.subject == "user123")
    #expect(jwt.payload.subject == jwt.payload.sub)

    #expect(jwt.payload.audienceValues == ["api.myapp.com"])
    #expect(jwt.payload.singleAudience == "api.myapp.com")

    #expect(jwt.payload.expirationTime != nil)
    #expect(jwt.payload.expirationTime == jwt.payload.exp)

    #expect(jwt.payload.issuedAtTime != nil)
    #expect(jwt.payload.issuedAtTime == jwt.payload.iat)

    #expect(jwt.payload.notBeforeTime == nil)
    #expect(jwt.payload.notBeforeTime == jwt.payload.nbf)

    #expect(jwt.payload.id == nil)
    #expect(jwt.payload.id == jwt.payload.jti)
  }

  @Test("Payload validation helpers")
  func testPayloadValidationHelpers() throws {
    // Test expired token
    let expiredJWT = try JWT.hmacSHA256(
      issuer: "test",
      subject: "user",
      expiresIn: -3600,  // Expired 1 hour ago
      secretKey: "secret"
    )

    #expect(expiredJWT.payload.isExpired)
    #expect(!expiredJWT.payload.isCurrentlyValid)
    #expect(expiredJWT.payload.timeUntilExpiration ?? 0 < 0)

    // Test valid token
    let validJWT = try JWT.hmacSHA256(
      issuer: "test",
      subject: "user",
      expiresIn: 3600,  // Expires in 1 hour
      secretKey: "secret"
    )

    #expect(!validJWT.payload.isExpired)
    #expect(validJWT.payload.isCurrentlyValid)
    #expect(validJWT.payload.timeUntilExpiration ?? 0 > 0)

    // Test not-yet-valid token
    let futureJWT = try JWT.signed(
      algorithm: .hmacSHA256,
      key: .symmetric(string: "secret"),
      issuer: "test",
      subject: "user",
      notBefore: Date(timeIntervalSinceNow: 3600)  // Valid in 1 hour
    )

    #expect(futureJWT.payload.isNotYetValid)
    #expect(!futureJWT.payload.isCurrentlyValid)
  }

  @Test("Convenient claim access")
  func testConvenientClaimAccess() throws {
    let jwt = try JWT.hmacSHA256(
      issuer: "test",
      subject: "user",
      claims: [
        "role": "admin",
        "permissions": ["read", "write"],
        "userId": 12345,
      ],
      secretKey: "secret"
    )

    // Test claim() method
    #expect(jwt.payload.claim("role", as: String.self) == "admin")
    #expect(jwt.payload.claim("permissions", as: [String].self) == ["read", "write"])
    #expect(jwt.payload.claim("userId", as: Int.self) == 12345)

    // Test claim with default
    #expect(jwt.payload.claim("missing", default: "default") == "default")
    #expect(jwt.payload.claim("role", default: "user") == "admin")

    // Test hasClaim
    #expect(jwt.payload.hasClaim("role"))
    #expect(!jwt.payload.hasClaim("nonexistent"))

    // Test standard claim keys
    let keys = jwt.payload.standardClaimKeys
    #expect(keys.contains("iss"))
    #expect(keys.contains("sub"))
  }

  @Test("Audience convenience methods")
  func testAudienceConvenience() throws {
    // Single audience
    let singleAudJWT = try JWT.hmacSHA256(
      issuer: "test",
      subject: "user",
      audience: "api.example.com",
      secretKey: "secret"
    )

    #expect(singleAudJWT.payload.audience?.contains("api.example.com") == true)
    #expect(singleAudJWT.payload.audience?.contains("other.example.com") == false)
    #expect(singleAudJWT.payload.audienceValues == ["api.example.com"])

    // Multiple audiences
    let multiAudJWT = try JWT.signed(
      algorithm: .hmacSHA256,
      key: .symmetric(string: "secret"),
      issuer: "test",
      subject: "user",
      audiences: ["api.example.com", "web.example.com", "mobile.example.com"]
    )

    #expect(multiAudJWT.payload.audience?.contains("api.example.com") == true)
    #expect(multiAudJWT.payload.audience?.contains("web.example.com") == true)
    #expect(multiAudJWT.payload.audienceValues.count == 3)
  }

  @Test("JWT token convenience property")
  func testJWTTokenProperty() throws {
    let jwt = try JWT.hmacSHA256(
      issuer: "test",
      subject: "user",
      secretKey: "secret"
    )

    let token1 = try jwt.token
    let token2 = try jwt.compactSerialization()

    #expect(token1 == token2)
    #expect(token1.split(separator: ".").count == 3)  // header.payload.signature
  }

  @Test("Quick validation methods")
  func testQuickValidation() throws {
    let secret = "validation-secret"
    let jwt = try JWT.hmacSHA256(
      issuer: "test",
      subject: "user",
      expiresIn: 3600,
      secretKey: secret
    )

    // Test isValid
    #expect(jwt.isValid(with: .symmetric(string: secret), algorithm: .hmacSHA256))
    #expect(!jwt.isValid(with: .symmetric(string: "wrong-secret"), algorithm: .hmacSHA256))

    // Test validation errors
    let errors = jwt.validationErrors(with: .symmetric(string: "wrong-secret"), algorithm: .hmacSHA256)
    #expect(errors.contains { $0.contains("signature") || $0.contains("Signature") })

    // Test expired token
    let expiredJWT = try JWT.hmacSHA256(
      issuer: "test",
      subject: "user",
      expiresIn: -3600,
      secretKey: secret
    )

    let expiredErrors = expiredJWT.validationErrors(with: .symmetric(string: secret), algorithm: .hmacSHA256)
    #expect(expiredErrors.contains("Token is expired"))
  }
}
