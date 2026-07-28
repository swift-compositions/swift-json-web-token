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

/// A JWS signing algorithm backed by swift-crypto.
public struct SigningAlgorithm: Sendable {
    /// The `alg` value as it appears in the JWT header (e.g. `"HS256"`).
    public let algorithmName: String

    /// Signs the signing input with the given key.
    let sign: @Sendable (Data, SigningKey) throws(RFC_7519.Error) -> Data

    /// Verifies a signature over the signing input with the given key.
    let verify: @Sendable (Data, Data, VerificationKey) throws(RFC_7519.Error) -> Bool

    /// Creates a custom signing algorithm.
    public init(
        algorithmName: String,
        sign: @escaping @Sendable (Data, SigningKey) throws(RFC_7519.Error) -> Data,
        verify: @escaping @Sendable (Data, Data, VerificationKey) throws(RFC_7519.Error) -> Bool
    ) {
        self.algorithmName = algorithmName
        self.sign = sign
        self.verify = verify
    }
}

extension SigningAlgorithm {
    /// HMAC using SHA-256 (`HS256`).
    public static let hmacSHA256 = SigningAlgorithm(
        algorithmName: "HS256",
        sign: { data, key throws(RFC_7519.Error) in
            guard let symmetricKey = key._symmetricKey else {
                throw .invalidSignature("HMAC requires a symmetric key")
            }
            return Data(HMAC<SHA256>.authenticationCode(for: data, using: symmetricKey))
        },
        verify: { signature, data, key throws(RFC_7519.Error) in
            guard let symmetricKey = key._symmetricKey else {
                throw .invalidSignature("HMAC requires a symmetric key")
            }
            return HMAC<SHA256>.isValidAuthenticationCode(
                signature,
                authenticating: data,
                using: symmetricKey
            )
        }
    )

    /// HMAC using SHA-384 (`HS384`).
    public static let hmacSHA384 = SigningAlgorithm(
        algorithmName: "HS384",
        sign: { data, key throws(RFC_7519.Error) in
            guard let symmetricKey = key._symmetricKey else {
                throw .invalidSignature("HMAC requires a symmetric key")
            }
            return Data(HMAC<SHA384>.authenticationCode(for: data, using: symmetricKey))
        },
        verify: { signature, data, key throws(RFC_7519.Error) in
            guard let symmetricKey = key._symmetricKey else {
                throw .invalidSignature("HMAC requires a symmetric key")
            }
            return HMAC<SHA384>.isValidAuthenticationCode(
                signature,
                authenticating: data,
                using: symmetricKey
            )
        }
    )

    /// HMAC using SHA-512 (`HS512`).
    public static let hmacSHA512 = SigningAlgorithm(
        algorithmName: "HS512",
        sign: { data, key throws(RFC_7519.Error) in
            guard let symmetricKey = key._symmetricKey else {
                throw .invalidSignature("HMAC requires a symmetric key")
            }
            return Data(HMAC<SHA512>.authenticationCode(for: data, using: symmetricKey))
        },
        verify: { signature, data, key throws(RFC_7519.Error) in
            guard let symmetricKey = key._symmetricKey else {
                throw .invalidSignature("HMAC requires a symmetric key")
            }
            return HMAC<SHA512>.isValidAuthenticationCode(
                signature,
                authenticating: data,
                using: symmetricKey
            )
        }
    )

    /// ECDSA using P-256 and SHA-256 (`ES256`).
    public static let ecdsaSHA256 = SigningAlgorithm(
        algorithmName: "ES256",
        sign: { data, key throws(RFC_7519.Error) in
            guard let privateKey = key._ecdsaPrivateKey else {
                throw .invalidSignature("ECDSA requires an ECDSA private key")
            }
            do {
                return try privateKey.signature(for: SHA256.hash(data: data)).rawRepresentation
            } catch {
                throw .invalidSignature("ECDSA signing failed: \(error)")
            }
        },
        verify: { signature, data, key throws(RFC_7519.Error) in
            guard let publicKey = key._ecdsaPublicKey else {
                throw .invalidSignature("ECDSA requires an ECDSA public key")
            }
            do {
                let ecdsaSignature = try P256.Signing.ECDSASignature(rawRepresentation: signature)
                return publicKey.isValidSignature(ecdsaSignature, for: SHA256.hash(data: data))
            } catch {
                throw .invalidSignature("ECDSA verification failed: \(error)")
            }
        }
    )

    /// Resolves a standard algorithm from its `alg` header value.
    ///
    /// Only the algorithms this library implements resolve; every other value —
    /// including an absent one — returns `nil` and is treated as unsupported by
    /// callers.
    ///
    /// - Parameter algorithmName: The `alg` value (e.g. `"HS256"`).
    /// - Returns: The matching algorithm, or `nil` if unsupported.
    public static func from(algorithmName: String) -> SigningAlgorithm? {
        switch algorithmName {
        case "HS256": return .hmacSHA256
        case "HS384": return .hmacSHA384
        case "HS512": return .hmacSHA512
        case "ES256": return .ecdsaSHA256
        default: return nil
        }
    }
}
