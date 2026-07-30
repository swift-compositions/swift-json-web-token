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

/// A key used to sign JWTs, backed by swift-crypto.
public struct SigningKey: Sendable {
    private enum Storage: Sendable {
        case symmetric(SymmetricKey)
        case ecdsa(P256.Signing.PrivateKey)
    }

    private let storage: Storage

    private init(storage: Storage) {
        self.storage = storage
    }

    /// Creates a symmetric (HMAC) key from raw data.
    public static func symmetric(data: Data) -> SigningKey {
        SigningKey(storage: .symmetric(SymmetricKey(data: data)))
    }

    /// Creates a symmetric (HMAC) key from a UTF-8 string.
    ///
    /// - Important: RFC 7518 recommends a key at least as long as the hash
    ///   output — 32 bytes for HS256, 48 for HS384, 64 for HS512.
    public static func symmetric(string: String) -> SigningKey {
        SigningKey(storage: .symmetric(SymmetricKey(data: Data(string.utf8))))
    }

    /// Wraps an existing ECDSA P-256 private key.
    public static func ecdsa(_ privateKey: P256.Signing.PrivateKey) -> SigningKey {
        SigningKey(storage: .ecdsa(privateKey))
    }

    /// Generates a fresh ECDSA P-256 private key.
    public static func generateECDSA() -> SigningKey {
        SigningKey(storage: .ecdsa(P256.Signing.PrivateKey()))
    }

    /// Creates an ECDSA P-256 private key from its raw representation.
    ///
    /// - Throws: ``RFC_7519/Error/invalidKey(_:)`` if the data is not a valid key.
    public static func ecdsa(rawRepresentation: Data) throws(RFC_7519.Error) -> SigningKey {
        do {
            return SigningKey(
                storage: .ecdsa(try P256.Signing.PrivateKey(rawRepresentation: rawRepresentation))
            )
        } catch {
            throw .invalidKey("Invalid ECDSA private key: \(error)")
        }
    }

    var _symmetricKey: SymmetricKey? {
        guard case .symmetric(let key) = storage else { return nil }
        return key
    }

    var _ecdsaPrivateKey: P256.Signing.PrivateKey? {
        guard case .ecdsa(let key) = storage else { return nil }
        return key
    }
}
