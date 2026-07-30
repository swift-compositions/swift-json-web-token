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

/// A key used to verify JWT signatures, backed by swift-crypto.
public struct VerificationKey: Sendable {
    private enum Storage: Sendable {
        case symmetric(SymmetricKey)
        case ecdsa(P256.Signing.PublicKey)
    }

    private let storage: Storage

    private init(storage: Storage) {
        self.storage = storage
    }

    /// Creates a symmetric (HMAC) verification key from raw data.
    public static func symmetric(data: Data) -> VerificationKey {
        VerificationKey(storage: .symmetric(SymmetricKey(data: data)))
    }

    /// Creates a symmetric (HMAC) verification key from a UTF-8 string.
    public static func symmetric(string: String) -> VerificationKey {
        VerificationKey(storage: .symmetric(SymmetricKey(data: Data(string.utf8))))
    }

    /// Wraps an existing ECDSA P-256 public key.
    public static func ecdsa(_ publicKey: P256.Signing.PublicKey) -> VerificationKey {
        VerificationKey(storage: .ecdsa(publicKey))
    }

    /// Derives a verification key from an ECDSA signing key.
    ///
    /// - Returns: The verification key, or `nil` if `signingKey` is not ECDSA.
    public static func ecdsa(from signingKey: SigningKey) -> VerificationKey? {
        guard let privateKey = signingKey._ecdsaPrivateKey else { return nil }
        return VerificationKey(storage: .ecdsa(privateKey.publicKey))
    }

    /// Creates an ECDSA P-256 public key from its raw representation.
    ///
    /// - Throws: ``RFC_7519/Error/invalidKey(_:)`` if the data is not a valid key.
    public static func ecdsa(rawRepresentation: Data) throws(RFC_7519.Error) -> VerificationKey {
        do {
            return VerificationKey(
                storage: .ecdsa(try P256.Signing.PublicKey(rawRepresentation: rawRepresentation))
            )
        } catch {
            throw .invalidKey("Invalid ECDSA public key: \(error)")
        }
    }

    var _symmetricKey: SymmetricKey? {
        guard case .symmetric(let key) = storage else { return nil }
        return key
    }

    var _ecdsaPublicKey: P256.Signing.PublicKey? {
        guard case .ecdsa(let key) = storage else { return nil }
        return key
    }
}
