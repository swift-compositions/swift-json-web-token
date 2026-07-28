// ===----------------------------------------------------------------------===//
//
// This source file is part of the swift-json-web-token open source project
//
// Copyright (c) 2026 Coen ten Thije Boonkkamp
// Licensed under Apache License v2.0
//
// See LICENSE for license information
//
// SPDX-License-Identifier: Apache-2.0
//
// ===----------------------------------------------------------------------===//

@preconcurrency import Crypto
import Foundation

// MARK: - Signing

extension JWT {
    /// Creates and signs a JWT.
    ///
    /// - Parameters:
    ///   - algorithm: The signing algorithm.
    ///   - key: The signing key.
    ///   - issuer: The `iss` claim.
    ///   - subject: The `sub` claim.
    ///   - audience: A single `aud` value (mutually exclusive with `audiences`).
    ///   - audiences: Multiple `aud` values.
    ///   - expiresIn: Seconds from now until expiration (sets `exp`).
    ///   - expiresAt: An explicit expiration time (takes precedence over `expiresIn`).
    ///   - notBefore: The `nbf` claim.
    ///   - issuedAt: The `iat` claim (defaults to now).
    ///   - jti: The `jti` claim.
    ///   - claims: Additional custom claims.
    ///   - headerParameters: Additional header parameters (`typ`, `cty`, `kid`
    ///     are lifted into the registered header fields).
    /// - Returns: The signed JWT.
    /// - Throws: ``RFC_7519/Error``.
    public static func signed(
        algorithm: SigningAlgorithm,
        key: SigningKey,
        issuer: String? = nil,
        subject: String? = nil,
        audience: String? = nil,
        audiences: [String]? = nil,
        expiresIn: TimeInterval? = nil,
        expiresAt: Date? = nil,
        notBefore: Date? = nil,
        issuedAt: Date? = Date(),
        jti: String? = nil,
        claims: [String: Any] = [:],
        headerParameters: [String: Any] = [:]
    ) throws(RFC_7519.Error) -> JWT {
        let aud: Audience?
        if let audiences {
            aud = Audience(audiences)
        } else if let audience {
            aud = .single(audience)
        } else {
            aud = nil
        }

        let exp: Date?
        if let expiresAt {
            exp = expiresAt
        } else if let expiresIn {
            exp = Date(timeIntervalSinceNow: expiresIn)
        } else {
            exp = nil
        }

        // 'alg' is never taken from headerParameters: it must come from the
        // algorithm argument so it cannot be spoofed.
        var filteredHeaderParameters = headerParameters
        let typ = filteredHeaderParameters.removeValue(forKey: "typ") as? String ?? "JWT"
        let cty = filteredHeaderParameters.removeValue(forKey: "cty") as? String
        let kid = filteredHeaderParameters.removeValue(forKey: "kid") as? String

        let header = Header(
            alg: algorithm.algorithmName,
            typ: typ,
            cty: cty,
            kid: kid,
            additionalParameters: filteredHeaderParameters.isEmpty ? nil : filteredHeaderParameters
        )

        let payload = Payload(
            iss: issuer,
            sub: subject,
            aud: aud,
            exp: exp,
            nbf: notBefore,
            iat: issuedAt,
            jti: jti,
            additionalClaims: claims.isEmpty ? nil : claims
        )

        let unsignedJWT = JWT(header: header, payload: payload, signature: Data())
        let signingInput = try unsignedJWT.signingInput()
        let signature = try algorithm.sign(signingInput, key)
        return JWT(header: header, payload: payload, signature: signature)
    }

    /// Creates and signs a JWT using HMAC-SHA256 (`HS256`).
    public static func hmacSHA256(
        issuer: String,
        subject: String,
        audience: String? = nil,
        expiresIn: TimeInterval = 3600,
        claims: [String: Any] = [:],
        secretKey: String
    ) throws(RFC_7519.Error) -> JWT {
        try signed(
            algorithm: .hmacSHA256,
            key: .symmetric(string: secretKey),
            issuer: issuer,
            subject: subject,
            audience: audience,
            expiresIn: expiresIn,
            claims: claims
        )
    }

    /// Creates and signs a JWT using HMAC-SHA384 (`HS384`).
    public static func hmacSHA384(
        issuer: String,
        subject: String,
        audience: String? = nil,
        expiresIn: TimeInterval = 3600,
        claims: [String: Any] = [:],
        secretKey: String
    ) throws(RFC_7519.Error) -> JWT {
        try signed(
            algorithm: .hmacSHA384,
            key: .symmetric(string: secretKey),
            issuer: issuer,
            subject: subject,
            audience: audience,
            expiresIn: expiresIn,
            claims: claims
        )
    }

    /// Creates and signs a JWT using HMAC-SHA512 (`HS512`).
    public static func hmacSHA512(
        issuer: String,
        subject: String,
        audience: String? = nil,
        expiresIn: TimeInterval = 3600,
        claims: [String: Any] = [:],
        secretKey: String
    ) throws(RFC_7519.Error) -> JWT {
        try signed(
            algorithm: .hmacSHA512,
            key: .symmetric(string: secretKey),
            issuer: issuer,
            subject: subject,
            audience: audience,
            expiresIn: expiresIn,
            claims: claims
        )
    }

    /// Creates and signs a JWT using ECDSA-P256-SHA256 (`ES256`).
    public static func ecdsaSHA256(
        issuer: String,
        subject: String,
        audience: String? = nil,
        expiresIn: TimeInterval = 3600,
        claims: [String: Any] = [:],
        privateKey: P256.Signing.PrivateKey
    ) throws(RFC_7519.Error) -> JWT {
        try signed(
            algorithm: .ecdsaSHA256,
            key: .ecdsa(privateKey),
            issuer: issuer,
            subject: subject,
            audience: audience,
            expiresIn: expiresIn,
            claims: claims
        )
    }
}

// MARK: - Verification

extension JWT {
    /// Verifies the JWT signature (only) against a key, under the algorithm the
    /// caller declares.
    ///
    /// The algorithm is supplied by the caller and never derived from the token.
    /// The `alg` header is treated as an untrusted assertion: it must match
    /// `algorithm`, and it selects nothing.
    ///
    /// - Parameters:
    ///   - key: The verification key.
    ///   - algorithm: The algorithm the caller requires the token to carry.
    /// - Returns: `true` if the signature is valid.
    /// - Throws: ``RFC_7519/Error/unsupportedAlgorithm(_:)`` if the header `alg`
    ///   is not the declared algorithm.
    public func verify(
        with key: VerificationKey,
        algorithm: SigningAlgorithm
    ) throws(RFC_7519.Error) -> Bool {
        guard header.alg == algorithm.algorithmName else {
            throw .unsupportedAlgorithm(
                "Expected \(algorithm.algorithmName), token declares \(header.alg)"
            )
        }
        let input = try signingInput()
        return try algorithm.verify(signature, input, key)
    }

    /// Verifies the signature *and* validates the timing claims (`exp` / `nbf`).
    ///
    /// - Parameters:
    ///   - key: The verification key.
    ///   - algorithm: The algorithm the caller requires the token to carry.
    ///   - currentTime: The reference time (defaults to now).
    ///   - clockSkew: Allowed clock skew in seconds (defaults to 60).
    /// - Returns: `true` if the signature is valid and the timing checks pass.
    /// - Throws: ``RFC_7519/Error`` (including `tokenExpired` / `tokenNotYetValid`).
    public func verifyAndValidate(
        with key: VerificationKey,
        algorithm: SigningAlgorithm,
        currentTime: Date = Date(),
        clockSkew: TimeInterval = 60
    ) throws(RFC_7519.Error) -> Bool {
        guard try verify(with: key, algorithm: algorithm) else { return false }
        try payload.validateTiming(currentTime: currentTime, clockSkew: clockSkew)
        return true
    }
}
