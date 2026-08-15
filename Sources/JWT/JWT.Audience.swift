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

extension JWT {
    /// The `aud` (audience) claim, which per RFC 7519 §4.1.3 is either a single
    /// string or an array of strings.
    public enum Audience: Hashable, Sendable {
        /// A single audience value.
        case single(String)

        /// Multiple audience values.
        case multiple([String])

        /// Creates an audience from a single string.
        public init(_ audience: String) {
            self = .single(audience)
        }

        /// Creates an audience from an array of strings, collapsing a
        /// single-element array to ``single(_:)``.
        public init(_ audiences: [String]) {
            self = audiences.count == 1 ? .single(audiences[0]) : .multiple(audiences)
        }

        /// All audience values as an array.
        public var values: [String] {
            switch self {
            case .single(let audience):
                return [audience]

            case .multiple(let audiences):
                return audiences
            }
        }

        /// Whether a specific audience value is present.
        public func contains(_ audience: String) -> Bool {
            values.contains(audience)
        }
    }
}

extension JWT.Audience: Codable {
    public init(from decoder: any Decoder) throws {
        let container = try decoder.singleValueContainer()
        do {
            self = .single(try container.decode(String.self))
            return
        } catch {}
        do {
            self = .multiple(try container.decode([String].self))
            return
        } catch {}
        throw DecodingError.typeMismatch(
            JWT.Audience.self,
            DecodingError.Context(
                codingPath: decoder.codingPath,
                debugDescription: "Audience must be a string or array of strings"
            )
        )
    }

    public func encode(to encoder: any Encoder) throws {
        var container = encoder.singleValueContainer()
        switch self {
        case .single(let audience):
            try container.encode(audience)

        case .multiple(let audiences):
            try container.encode(audiences)
        }
    }
}
