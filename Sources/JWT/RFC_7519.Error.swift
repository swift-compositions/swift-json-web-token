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

import RFC_7519

extension RFC_7519 {
    /// Errors raised by the typed JWT claims layer.
    public enum Error: Swift.Error, Hashable, Sendable, CustomStringConvertible {
        /// The compact serialization was malformed.
        case invalidFormat(String)

        /// The token's `exp` claim is in the past.
        case tokenExpired(String)

        /// The token's `nbf` claim is in the future.
        case tokenNotYetValid(String)

        /// The signature did not verify, or a key was unsuitable for the algorithm.
        case invalidSignature(String)

        /// The `alg` header value is not supported.
        case unsupportedAlgorithm(String)

        /// The header or payload could not be encoded to JSON.
        case encodingFailed(String)

        /// A cryptographic key could not be constructed.
        case invalidKey(String)

        public var description: String {
            switch self {
            case .invalidFormat(let message):
                return "Invalid JWT format: \(message)"

            case .tokenExpired(let message):
                return "JWT token expired: \(message)"

            case .tokenNotYetValid(let message):
                return "JWT token not yet valid: \(message)"

            case .invalidSignature(let message):
                return "Invalid JWT signature: \(message)"

            case .unsupportedAlgorithm(let message):
                return "Unsupported algorithm: \(message)"

            case .encodingFailed(let message):
                return "JWT encoding failed: \(message)"

            case .invalidKey(let message):
                return "Invalid key: \(message)"
            }
        }
    }
}
