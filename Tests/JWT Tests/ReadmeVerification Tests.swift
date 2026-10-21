import Crypto
import Foundation
import Testing

@testable import JWT

@Suite("README Verification")
struct ReadmeVerificationTests {

    @Test("Example from README: Creating JWTs with HMAC-SHA256 (lines 35-50)")
    func exampleHMACSHA256Creation() throws {

        let jwt = try JWT.hmacSHA256(
            issuer: "example.com",
            subject: "user123",
            audience: "api.example.com",
            expiresIn: 3600,
            claims: ["role": "admin", "permissions": ["read", "write"]],
            secretKey: "your-secret-key"
        )

        let tokenString = try jwt.compactSerialization()

        #expect(!tokenString.isEmpty)
        #expect(jwt.payload.iss == "example.com")
        #expect(jwt.payload.sub == "user123")
    }

    @Test("Example from README: Creating JWTs with ECDSA-SHA256 (lines 52-69)")
    func exampleECDSASHA256Creation() throws {

        let privateKey = P256.Signing.PrivateKey()

        let jwt = try JWT.ecdsaSHA256(
            issuer: "secure-service",
            subject: "user456",
            audience: "mobile-app",
            expiresIn: 7200,
            claims: ["scope": "user:read"],
            privateKey: privateKey
        )

        #expect(jwt.header.alg == "ES256")
        #expect(jwt.payload.iss == "secure-service")
        #expect(jwt.payload.sub == "user456")
    }

    @Test("Example from README: HMAC Verification (lines 73-89)")
    func exampleHMACVerification() throws {

        let jwt = try JWT.hmacSHA256(
            issuer: "example.com",
            subject: "user123",
            secretKey: "your-secret-key"
        )
        let tokenString = try jwt.compactSerialization()

        let parsedJWT = try JWT.parse(from: tokenString)

        let verificationKey = VerificationKey.symmetric(string: "your-secret-key")

        let isValidSignature = try parsedJWT.verify(with: verificationKey, algorithm: .hmacSHA256)
        #expect(isValidSignature)

        let isFullyValid = try parsedJWT.verifyAndValidate(
            with: verificationKey,
            algorithm: .hmacSHA256
        )
        #expect(isFullyValid)
    }

    @Test("Example from README: ECDSA Verification (lines 97-107)")
    func exampleECDSAVerification() throws {

        let privateKey = P256.Signing.PrivateKey()
        let verificationKey = try #require(VerificationKey.ecdsa(from: .ecdsa(privateKey)))

        let jwt = try JWT.ecdsaSHA256(
            issuer: "test",
            subject: "user",
            privateKey: privateKey
        )

        let isValid = try jwt.verifyAndValidate(with: verificationKey, algorithm: .ecdsaSHA256)
        #expect(isValid)
    }

    @Test("Example from README: ECDSA Verification with raw key data (lines 111-120)")
    func exampleECDSAVerificationRawKey() throws {
        let privateKey = P256.Signing.PrivateKey()
        let publicKeyData = privateKey.publicKey.rawRepresentation
        let verificationKey = try VerificationKey.ecdsa(rawRepresentation: publicKeyData)

        let jwt = try JWT.ecdsaSHA256(
            issuer: "test",
            subject: "user",
            privateKey: privateKey
        )

        let isValid = try jwt.verifyAndValidate(with: verificationKey, algorithm: .ecdsaSHA256)
        #expect(isValid)
    }

    @Test("Example from README: Custom JWT Configuration (lines 124-140)")
    func exampleCustomConfiguration() throws {
        let jwt = try JWT.signed(
            algorithm: .hmacSHA384,
            key: .symmetric(string: "custom-key"),
            issuer: "custom-issuer",
            subject: "user789",
            audiences: ["api1.example.com", "api2.example.com"],
            expiresAt: Date(timeIntervalSinceNow: 86400),
            notBefore: Date(timeIntervalSinceNow: 300),
            jti: UUID().uuidString,
            claims: [
                "role": "moderator",
                "permissions": ["read", "moderate"],
                "active": true,
            ],
            headerParameters: [
                "kid": "key-identifier",
                "custom": "header-value",
            ]
        )

        #expect(jwt.header.alg == "HS384")
        #expect(jwt.payload.iss == "custom-issuer")
        #expect(jwt.payload.sub == "user789")
        #expect(jwt.payload.jti != nil)
    }

    @Test("Example from README: Working with Claims (lines 143-154)")
    func exampleWorkingWithClaims() throws {
        let jwt = try JWT.hmacSHA256(
            issuer: "test-issuer",
            subject: "test-subject",
            claims: [
                "role": "admin",
                "permissions": ["read", "write"],
                "active": true,
            ],
            secretKey: "test-key"
        )

        #expect(jwt.payload.iss == "test-issuer")
        #expect(jwt.payload.sub == "test-subject")
        #expect(jwt.payload.exp != nil)

        let role = jwt.payload.additionalClaim("role", as: String.self)
        let permissions = jwt.payload.additionalClaim("permissions", as: [String].self)
        let isActive = jwt.payload.additionalClaim("active", as: Bool.self)

        #expect(role == "admin")
        #expect(permissions == ["read", "write"])
        #expect(isActive == true)
    }

    @Test("Example from README: Timing Validation (lines 158-166)")
    func exampleTimingValidation() throws {
        let jwt = try JWT.hmacSHA256(
            issuer: "test",
            subject: "user",
            expiresIn: 3600,
            secretKey: "test-key"
        )

        let verificationKey = VerificationKey.symmetric(string: "test-key")

        let isValid = try jwt.verifyAndValidate(
            with: verificationKey,
            algorithm: .hmacSHA256,
            currentTime: Date(),
            clockSkew: 120
        )

        #expect(isValid)
    }

    @Test("Example from README: Key Management - Symmetric keys (lines 171-173)")
    func exampleSymmetricKeys() throws {
        let keyData = Data("secret".utf8)

        let stringKey = SigningKey.symmetric(string: "secret")
        let dataKey = SigningKey.symmetric(data: keyData)

        let jwt1 = try JWT.signed(
            algorithm: .hmacSHA256,
            key: stringKey,
            issuer: "test",
            subject: "user",
            expiresIn: 3600
        )

        let jwt2 = try JWT.signed(
            algorithm: .hmacSHA256,
            key: dataKey,
            issuer: "test",
            subject: "user",
            expiresIn: 3600
        )

        #expect(jwt1.header.alg == "HS256")
        #expect(jwt2.header.alg == "HS256")
    }

    @Test("Example from README: Key Management - ECDSA keys (lines 175-182)")
    func exampleECDSAKeys() throws {
        let privateKey = P256.Signing.PrivateKey()
        let privateKeyData = privateKey.rawRepresentation
        let publicKeyData = privateKey.publicKey.rawRepresentation

        let generatedKey = SigningKey.generateECDSA()
        let existingKey = try SigningKey.ecdsa(rawRepresentation: privateKeyData)

        let symmetricVerify = VerificationKey.symmetric(string: "secret")
        let ecdsaVerify = VerificationKey.ecdsa(from: generatedKey)
        let publicKeyVerify = try VerificationKey.ecdsa(rawRepresentation: publicKeyData)

        #expect(ecdsaVerify != nil)

        _ = symmetricVerify
        _ = existingKey
        _ = publicKeyVerify
    }

    @Test("Example from README: Error Handling (lines 199-211)")
    func exampleErrorHandling() throws {
        do {
            let jwt = try JWT.hmacSHA256(
                issuer: "test",
                subject: "user",
                expiresIn: -3600,
                secretKey: "test-key"
            )
            let key = VerificationKey.symmetric(string: "test-key")
            let isValid = try jwt.verifyAndValidate(with: key, algorithm: .hmacSHA256)
            #expect(!isValid)
        } catch RFC_7519.Error.tokenExpired {

            #expect(true)
        } catch {
            #expect(Bool(false), "Unexpected error: \(error)")
        }
    }
}
