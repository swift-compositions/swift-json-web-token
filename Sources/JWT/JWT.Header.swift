import Foundation

extension JWT {

    public struct Header: Hashable, Sendable {

        public let typ: String?

        public let alg: String

        public let cty: String?

        public let kid: String?

        private let additionalParameters: [String: AnyCodable]?

        public init(
            alg: String,
            typ: String? = "JWT",
            cty: String? = nil,
            kid: String? = nil,
            additionalParameters: [String: Any]? = nil
        ) {
            self.alg = alg
            self.typ = typ
            self.cty = cty
            self.kid = kid
            self.additionalParameters = additionalParameters?.mapValues(AnyCodable.init)
        }

        public func additionalParameter<T>(_ key: String, as type: T.Type = T.self) -> T? {
            additionalParameters?[key]?.value as? T
        }
    }
}

extension JWT.Header: Codable {
    private enum CodingKeys: String, CodingKey, CaseIterable {
        case typ, alg, cty, kid
    }

    public init(from decoder: any Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        let dynamicContainer = try decoder.container(keyedBy: DynamicCodingKey.self)

        self.typ = try container.decodeIfPresent(String.self, forKey: .typ)
        self.alg = try container.decode(String.self, forKey: .alg)
        self.cty = try container.decodeIfPresent(String.self, forKey: .cty)
        self.kid = try container.decodeIfPresent(String.self, forKey: .kid)

        let known = Set(CodingKeys.allCases.map(\.stringValue))
        var additional: [String: AnyCodable] = [:]
        for key in dynamicContainer.allKeys where !known.contains(key.stringValue) {
            additional[key.stringValue] = try dynamicContainer.decode(AnyCodable.self, forKey: key)
        }
        self.additionalParameters = additional.isEmpty ? nil : additional
    }

    public func encode(to encoder: any Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encodeIfPresent(typ, forKey: .typ)
        try container.encode(alg, forKey: .alg)
        try container.encodeIfPresent(cty, forKey: .cty)
        try container.encodeIfPresent(kid, forKey: .kid)

        if let additionalParameters {
            var dynamicContainer = encoder.container(keyedBy: DynamicCodingKey.self)
            for (key, value) in additionalParameters {
                guard let codingKey = DynamicCodingKey(stringValue: key) else { continue }
                try dynamicContainer.encode(value, forKey: codingKey)
            }
        }
    }
}
