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

/// A type-erased, `Codable` JSON value used to carry additional (non-registered)
/// JWT header parameters and payload claims.
enum AnyCodable: Codable, Hashable, Sendable {
    case string(String)
    case integer(Int)
    case double(Double)
    case bool(Bool)
    case array([AnyCodable])
    case dictionary([String: AnyCodable])

    /// Wraps an arbitrary value, discriminating `Bool` before `Int` so that
    /// boolean claims round-trip as booleans rather than integers.
    init(_ value: Any) {
        switch value {
        case let bool as Bool:
            self = .bool(bool)

        case let int as Int:
            self = .integer(int)

        case let double as Double:
            self = .double(double)

        case let string as String:
            self = .string(string)

        case let array as [Any]:
            self = .array(array.map(AnyCodable.init))

        case let dictionary as [String: Any]:
            self = .dictionary(dictionary.mapValues(AnyCodable.init))

        default:
            self = .string(String(describing: value))
        }
    }

    /// The underlying value, unwrapped to its native Swift type.
    var value: Any {
        switch self {
        case .string(let string):
            return string

        case .integer(let int):
            return int

        case .double(let double):
            return double

        case .bool(let bool):
            return bool

        case .array(let array):
            return array.map(\.value)

        case .dictionary(let dictionary):
            return dictionary.mapValues(\.value)
        }
    }

    init(from decoder: any Decoder) throws {
        let container = try decoder.singleValueContainer()
        do {
            self = .bool(try container.decode(Bool.self))
            return
        } catch {}
        do {
            self = .integer(try container.decode(Int.self))
            return
        } catch {}
        do {
            self = .double(try container.decode(Double.self))
            return
        } catch {}
        do {
            self = .string(try container.decode(String.self))
            return
        } catch {}
        do {
            self = .array(try container.decode([AnyCodable].self))
            return
        } catch {}
        do {
            self = .dictionary(try container.decode([String: AnyCodable].self))
            return
        } catch {}
        throw DecodingError.typeMismatch(
            AnyCodable.self,
            DecodingError.Context(
                codingPath: decoder.codingPath,
                debugDescription: "Unsupported JSON value"
            )
        )
    }

    func encode(to encoder: any Encoder) throws {
        var container = encoder.singleValueContainer()
        switch self {
        case .string(let string):
            try container.encode(string)

        case .integer(let int):
            try container.encode(int)

        case .double(let double):
            try container.encode(double)

        case .bool(let bool):
            try container.encode(bool)

        case .array(let array):
            try container.encode(array)

        case .dictionary(let dictionary):
            try container.encode(dictionary)
        }
    }
}
