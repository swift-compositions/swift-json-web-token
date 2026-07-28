//
//  JWT Signature Rejection Tests.swift
//  JWT Tests
//

import Crypto
import Foundation
import Testing

@testable import JWT

@Suite("JWT Signature Rejection Tests")
struct JWT_Signature_Rejection_Tests {

    private static let secret = "a-secret-long-enough-for-hmac-sha-256-use"

    private static func token(
        algorithm: SigningAlgorithm = .hmacSHA256,
        subject: String = "subject",
        claims: [String: Any] = ["role": "user"]
    ) throws -> JWT {
        try JWT.signed(
            algorithm: algorithm,
            key: .symmetric(string: secret),
            issuer: "issuer",
            subject: subject,
            expiresIn: 3600,
            claims: claims
        )
    }

    @Test("Accepts a signature produced by the same key")
    func acceptsMatchingSignature() throws {
        let jwt = try Self.token()
        let parsed = try JWT.parse(from: jwt.compactSerialization())

        #expect(
            try parsed.verify(
                with: .symmetric(string: Self.secret),
                algorithm: .hmacSHA256
            )
        )
    }

    @Test("Rejects a signature that does not match")
    func rejectsNonMatchingSignature() throws {
        let jwt = try Self.token()
        let parsed = try JWT.parse(from: jwt.compactSerialization())

        #expect(
            try parsed.verify(
                with: .symmetric(string: "a-different-secret-of-the-same-length--"),
                algorithm: .hmacSHA256
            ) == false
        )
    }

    @Test("Rejects a signature of the wrong length")
    func rejectsTruncatedSignature() throws {
        let jwt = try Self.token()
        let truncated = JWT(
            header: jwt.header,
            payload: jwt.payload,
            signature: jwt.signature.dropLast(1)
        )

        #expect(
            try truncated.verify(
                with: .symmetric(string: Self.secret),
                algorithm: .hmacSHA256
            ) == false
        )
    }

    @Test("Rejects an empty signature")
    func rejectsEmptySignature() throws {
        let jwt = try Self.token()
        let unsigned = JWT(header: jwt.header, payload: jwt.payload, signature: Data())

        #expect(
            try unsigned.verify(
                with: .symmetric(string: Self.secret),
                algorithm: .hmacSHA256
            ) == false
        )
    }

    @Test("Rejects a payload altered after signing")
    func rejectsAlteredPayload() throws {
        let jwt = try Self.token(subject: "subject", claims: ["role": "user"])

        let altered = JWT(
            header: jwt.header,
            payload: JWT.Payload(
                iss: jwt.payload.iss,
                sub: "another-subject",
                aud: jwt.payload.aud,
                exp: jwt.payload.exp,
                nbf: jwt.payload.nbf,
                iat: jwt.payload.iat,
                jti: jwt.payload.jti,
                additionalClaims: ["role": "admin"]
            ),
            signature: jwt.signature
        )

        #expect(
            try altered.verify(
                with: .symmetric(string: Self.secret),
                algorithm: .hmacSHA256
            ) == false
        )
    }

    @Test("Rejects an expiry extended after signing")
    func rejectsAlteredExpiry() throws {
        let jwt = try Self.token()

        let extended = JWT(
            header: jwt.header,
            payload: JWT.Payload(
                iss: jwt.payload.iss,
                sub: jwt.payload.sub,
                aud: jwt.payload.aud,
                exp: Date(timeIntervalSinceNow: 60 * 60 * 24 * 365),
                nbf: jwt.payload.nbf,
                iat: jwt.payload.iat,
                jti: jwt.payload.jti,
                additionalClaims: ["role": "user"]
            ),
            signature: jwt.signature
        )

        #expect(
            try extended.verify(
                with: .symmetric(string: Self.secret),
                algorithm: .hmacSHA256
            ) == false
        )
    }

    @Test("Rejects a token whose declared algorithm is not the expected one")
    func rejectsUnexpectedAlgorithm() throws {
        let jwt = try Self.token(algorithm: .hmacSHA512)

        #expect(throws: RFC_7519.Error.self) {
            try jwt.verify(
                with: .symmetric(string: Self.secret),
                algorithm: .hmacSHA256
            )
        }
    }

    @Test("Rejects a header algorithm the library does not implement")
    func rejectsUnimplementedAlgorithm() throws {
        let jwt = try Self.token()
        let relabelled = JWT(
            header: JWT.Header(
                alg: "none",
                typ: jwt.header.typ,
                cty: jwt.header.cty,
                kid: jwt.header.kid,
                additionalParameters: nil
            ),
            payload: jwt.payload,
            signature: Data()
        )

        #expect(throws: RFC_7519.Error.self) {
            try relabelled.verify(
                with: .symmetric(string: Self.secret),
                algorithm: .hmacSHA256
            )
        }
    }

    @Test("Resolves no algorithm for an unimplemented or absent name")
    func resolvesNoUnimplementedAlgorithm() {
        #expect(SigningAlgorithm.from(algorithmName: "none") == nil)
        #expect(SigningAlgorithm.from(algorithmName: "NONE") == nil)
        #expect(SigningAlgorithm.from(algorithmName: "") == nil)
    }

    @Test("Rejects an HMAC token presented against an asymmetric key")
    func rejectsMismatchedKeyKind() throws {
        let jwt = try Self.token()
        let ecdsaKey = VerificationKey.ecdsa(from: .generateECDSA())!

        #expect(throws: RFC_7519.Error.self) {
            try jwt.verify(with: ecdsaKey, algorithm: .hmacSHA256)
        }
    }

    @Test("Reports an unverified token as invalid through the convenience surface")
    func reportsInvalidThroughConvenience() throws {
        let jwt = try Self.token()

        #expect(
            jwt.isValid(
                with: .symmetric(string: "a-different-secret-of-the-same-length--"),
                algorithm: .hmacSHA256
            ) == false
        )
        #expect(jwt.isValid(with: .symmetric(string: Self.secret), algorithm: .hmacSHA256))
    }
}
