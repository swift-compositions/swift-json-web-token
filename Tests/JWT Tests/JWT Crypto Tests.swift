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

@Suite
struct `JWT Crypto Tests` {

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

}
