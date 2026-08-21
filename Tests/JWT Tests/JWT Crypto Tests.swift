import Crypto
import Foundation
import Testing

@testable import JWT

@Suite
struct `JWT Crypto Tests` {

    @Test("Simplest JWT creation - just a secret key")
    func testSimplestJWTCreation() throws {

        let jwt = try JWT.hmacSHA256(
            issuer: "myapp",
            subject: "user123",
            secretKey: "my-secret-key"
        )

        #expect(jwt.header.alg == "HS256")
        #expect(jwt.payload.iss == "myapp")
        #expect(jwt.payload.sub == "user123")

        let tokenString = try jwt.compactSerialization()
        #expect(tokenString.contains("."))
    }

    @Test("Common use case - API authentication token")
    func testAPIAuthToken() throws {

        let jwt = try JWT.hmacSHA256(
            issuer: "api.myapp.com",
            subject: "user@example.com",
            audience: "mobile-app",
            expiresIn: 3600,
            claims: [
                "userId": "12345",
                "role": "user",
                "scope": "read write",
            ],
            secretKey: "your-256-bit-secret"
        )

        let token = try jwt.compactSerialization()

        #expect(jwt.payload.iss == "api.myapp.com")
        #expect(jwt.payload.additionalClaim("role", as: String.self) == "user")
    }

    @Test("Real-world example - User session token")
    func testUserSessionToken() throws {

        let secretKey = "your-super-secret-key"
        let sessionToken = try JWT.hmacSHA256(
            issuer: "auth.example.com",
            subject: "john.doe@example.com",
            expiresIn: 24 * 60 * 60,
            claims: [
                "name": "John Doe",
                "email": "john.doe@example.com",
                "premium": true,
                "loginTime": ISO8601DateFormatter().string(from: Date()),
            ],
            secretKey: secretKey
        )

        let tokenString = try sessionToken.compactSerialization()
        #expect(!tokenString.isEmpty)

        let verified = try JWT.parse(from: tokenString)
        let isValid = try verified.verify(
            with: .symmetric(string: secretKey),
            algorithm: .hmacSHA256
        )
        #expect(isValid)
    }

    @Test("Microservice communication token")
    func testMicroserviceToken() throws {

        let serviceToken = try JWT.hmacSHA384(
            issuer: "payment-service",
            subject: "order-service",
            audience: "inventory-service",
            expiresIn: 300,
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

        let accessToken = try JWT.hmacSHA256(
            issuer: "auth.app.com",
            subject: "user123",
            expiresIn: 15 * 60,
            claims: ["type": "access"],
            secretKey: "access-token-secret"
        )

        let refreshToken = try JWT.hmacSHA512(
            issuer: "auth.app.com",
            subject: "user123",
            expiresIn: 30 * 24 * 60 * 60,
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

        let verificationToken = try JWT.hmacSHA256(
            issuer: "signup.example.com",
            subject: "new.user@example.com",
            expiresIn: 24 * 60 * 60,
            claims: [
                "action": "verify-email",
                "email": "new.user@example.com",
            ],
            secretKey: "email-verification-secret"
        )

        let tokenString = try verificationToken.compactSerialization()

        #expect(
            verificationToken.payload.additionalClaim("action", as: String.self) == "verify-email"
        )
    }

    @Test("Password reset token")
    func testPasswordResetToken() throws {

        let resetToken = try JWT.hmacSHA256(
            issuer: "auth.example.com",
            subject: "user@example.com",
            expiresIn: 60 * 60,
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

        let apiKey = try JWT.signed(
            algorithm: .hmacSHA256,
            key: .symmetric(string: "api-key-secret"),
            issuer: "api.platform.com",
            subject: "client-app-123",
            audience: "api.platform.com",
            expiresIn: nil,
            claims: [
                "scopes": ["users:read", "orders:read", "products:write"],
                "rateLimit": 1000,
                "tier": "premium",
            ]
        )

        #expect(apiKey.payload.exp == nil)
        #expect(apiKey.payload.additionalClaim("tier", as: String.self) == "premium")
    }

    @Test("Simple JWT verification")
    func testSimpleJWTVerification() throws {
        let secret = "my-secret-key"

        let jwt = try JWT.hmacSHA256(
            issuer: "myapp",
            subject: "user123",
            expiresIn: 3600,
            secretKey: secret
        )

        let tokenString = try jwt.compactSerialization()

        let receivedToken = try JWT.parse(from: tokenString)
        let isValid = try receivedToken.verify(
            with: .symmetric(string: secret),
            algorithm: .hmacSHA256
        )

        #expect(isValid)
    }

    @Test("JWT verification with expiration check")
    func testJWTVerificationWithExpiration() throws {
        let secret = "my-secret-key"

        let jwt = try JWT.hmacSHA256(
            issuer: "myapp",
            subject: "user123",
            expiresIn: 3600,
            secretKey: secret
        )

        let tokenString = try jwt.compactSerialization()
        let receivedToken = try JWT.parse(from: tokenString)

        let isValidAndNotExpired = try receivedToken.verifyAndValidate(
            with: .symmetric(string: secret),
            algorithm: .hmacSHA256
        )

        #expect(isValidAndNotExpired)
    }

    @Test("Extract claims after verification")
    func testExtractClaimsAfterVerification() throws {
        let secret = "api-secret"

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

        let receivedToken = try JWT.parse(from: tokenString)
        let isValid = try receivedToken.verify(
            with: .symmetric(string: secret),
            algorithm: .hmacSHA256
        )

        if isValid {

            let userId = receivedToken.payload.additionalClaim("userId", as: String.self)
            let role = receivedToken.payload.additionalClaim("role", as: String.self)
            let permissions = receivedToken.payload.additionalClaim(
                "permissions",
                as: [String].self
            )

            #expect(userId == "12345")
            #expect(role == "admin")
            #expect(permissions == ["read", "write", "delete"])
        }
    }

}
