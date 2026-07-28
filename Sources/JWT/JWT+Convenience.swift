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

import Foundation

// MARK: - Token

extension JWT {
    /// The full compact-serialized JWT string.
    public var token: String {
        get throws(RFC_7519.Error) {
            try compactSerialization()
        }
    }
}

// MARK: - Header conveniences

extension JWT.Header {
    /// The algorithm used to sign the JWT (same as `alg`).
    public var algorithm: String { alg }

    /// The token type (same as `typ`).
    public var type: String? { typ }

    /// The content type (same as `cty`).
    public var contentType: String? { cty }

    /// The key ID (same as `kid`).
    public var keyId: String? { kid }
}

// MARK: - Payload conveniences

extension JWT.Payload {
    /// The issuer of the JWT (same as `iss`).
    public var issuer: String? { iss }

    /// The subject of the JWT (same as `sub`).
    public var subject: String? { sub }

    /// The audience of the JWT (same as `aud`).
    public var audience: JWT.Audience? { aud }

    /// The expiration time (same as `exp`).
    public var expirationTime: Date? { exp }

    /// The not-before time (same as `nbf`).
    public var notBeforeTime: Date? { nbf }

    /// The issued-at time (same as `iat`).
    public var issuedAtTime: Date? { iat }

    /// The JWT ID (same as `jti`).
    public var id: String? { jti }

    /// Whether the token is expired (relative to now).
    public var isExpired: Bool {
        guard let exp else { return false }
        return exp < Date()
    }

    /// Whether the token is not yet valid (relative to now).
    public var isNotYetValid: Bool {
        guard let nbf else { return false }
        return nbf > Date()
    }

    /// Whether the token is currently within its validity window.
    public var isCurrentlyValid: Bool {
        !isExpired && !isNotYetValid
    }

    /// The remaining time until expiration in seconds, if `exp` is present.
    public var timeUntilExpiration: TimeInterval? {
        guard let exp else { return nil }
        return exp.timeIntervalSinceNow
    }

    /// A single audience value, when there is one (or the first of many).
    public var singleAudience: String? {
        switch aud {
        case .single(let value):
            return value
        case .multiple(let values):
            return values.first
        case .none:
            return nil
        }
    }

    /// All audience values as an array.
    public var audienceValues: [String] {
        aud?.values ?? []
    }

    /// Reads a claim by name and type (registered or additional).
    public func claim<T>(_ key: String, as type: T.Type = T.self) -> T? {
        additionalClaim(key, as: type)
    }

    /// Reads a claim by name, falling back to `defaultValue` when absent.
    public func claim<T>(_ key: String, default defaultValue: T) -> T {
        additionalClaim(key, as: T.self) ?? defaultValue
    }

    /// Whether a claim with the given name exists.
    public func hasClaim(_ key: String) -> Bool {
        switch key {
        case "iss": return iss != nil
        case "sub": return sub != nil
        case "aud": return aud != nil
        case "exp": return exp != nil
        case "nbf": return nbf != nil
        case "iat": return iat != nil
        case "jti": return jti != nil
        default:
            return additionalClaim(key, as: String.self) != nil
                || additionalClaim(key, as: Int.self) != nil
                || additionalClaim(key, as: Bool.self) != nil
                || additionalClaim(key, as: Double.self) != nil
                || additionalClaim(key, as: [String].self) != nil
                || additionalClaim(key, as: [String: Any].self) != nil
        }
    }

    /// The names of the registered claims that are present.
    public var standardClaimKeys: [String] {
        var keys: [String] = []
        if iss != nil { keys.append("iss") }
        if sub != nil { keys.append("sub") }
        if aud != nil { keys.append("aud") }
        if exp != nil { keys.append("exp") }
        if nbf != nil { keys.append("nbf") }
        if iat != nil { keys.append("iat") }
        if jti != nil { keys.append("jti") }
        return keys
    }
}

// MARK: - Quick validation

extension JWT {
    /// Whether the token verifies and passes timing validation with `key`, under
    /// the algorithm the caller declares.
    public func isValid(with key: VerificationKey, algorithm: SigningAlgorithm) -> Bool {
        do {
            return try verifyAndValidate(with: key, algorithm: algorithm)
        } catch {
            return false
        }
    }

    /// A list of human-readable validation problems for the token under `key`
    /// and the algorithm the caller declares.
    public func validationErrors(
        with key: VerificationKey,
        algorithm: SigningAlgorithm
    ) -> [String] {
        var errors: [String] = []

        do {
            let signatureValid = try verify(with: key, algorithm: algorithm)
            if !signatureValid {
                errors.append("Invalid signature")
            }
        } catch {
            errors.append("Signature verification failed: \(error)")
        }

        if payload.isExpired {
            errors.append("Token is expired")
        }
        if payload.isNotYetValid {
            errors.append("Token is not yet valid")
        }

        return errors
    }
}
