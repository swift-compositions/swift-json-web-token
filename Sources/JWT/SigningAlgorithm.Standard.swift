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

extension SigningAlgorithm {
    /// Type-safe selection of the standard, built-in signing algorithms.
    public enum Standard: Sendable, Hashable, CaseIterable {
        case hmacSHA256
        case hmacSHA384
        case hmacSHA512
        case ecdsaSHA256

        /// The corresponding ``SigningAlgorithm``.
        public var algorithm: SigningAlgorithm {
            switch self {
            case .hmacSHA256: return .hmacSHA256
            case .hmacSHA384: return .hmacSHA384
            case .hmacSHA512: return .hmacSHA512
            case .ecdsaSHA256: return .ecdsaSHA256
            }
        }
    }
}
