import Foundation

extension JWT {

    public struct Payload: Hashable, Sendable {

        public let iss: String?

        public let sub: String?

        public let aud: Audience?

        public let exp: Date?

        public let nbf: Date?

        public let iat: Date?

        public let jti: String?

        private let additionalClaims: [String: AnyCodable]?

        public init(
            iss: String? = nil,
            sub: String? = nil,
            aud: Audience? = nil,
            exp: Date? = nil,
            nbf: Date? = nil,
            iat: Date? = nil,
            jti: String? = nil,
            additionalClaims: [String: Any]? = nil
        ) {
            self.iss = iss
            self.sub = sub
            self.aud = aud
            self.exp = exp
            self.nbf = nbf
            self.iat = iat
            self.jti = jti
            self.additionalClaims = additionalClaims?.mapValues(AnyCodable.init)
        }

        public func additionalClaim<T>(_ key: String, as type: T.Type = T.self) -> T? {
            additionalClaims?[key]?.value as? T
        }

        public func validateTiming(
            currentTime: Date = Date(),
            clockSkew: TimeInterval = 60
        ) throws(RFC_7519.Error) {
            if let exp, currentTime.timeIntervalSince1970 > exp.timeIntervalSince1970 + clockSkew {
                throw .tokenExpired("Token expired at \(exp)")
            }
            if let nbf, currentTime.timeIntervalSince1970 < nbf.timeIntervalSince1970 - clockSkew {
                throw .tokenNotYetValid("Token not valid before \(nbf)")
            }
        }
    }
}

extension JWT.Payload: Codable {
    private enum CodingKeys: String, CodingKey, CaseIterable {
        case iss, sub, aud, exp, nbf, iat, jti
    }

    public init(from decoder: any Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        let dynamicContainer = try decoder.container(keyedBy: DynamicCodingKey.self)

        self.iss = try container.decodeIfPresent(String.self, forKey: .iss)
        self.sub = try container.decodeIfPresent(String.self, forKey: .sub)
        self.aud = try container.decodeIfPresent(JWT.Audience.self, forKey: .aud)

        if let expTimestamp = try container.decodeIfPresent(TimeInterval.self, forKey: .exp) {
            self.exp = Date(timeIntervalSince1970: expTimestamp)
        } else {
            self.exp = nil
        }
        if let nbfTimestamp = try container.decodeIfPresent(TimeInterval.self, forKey: .nbf) {
            self.nbf = Date(timeIntervalSince1970: nbfTimestamp)
        } else {
            self.nbf = nil
        }
        if let iatTimestamp = try container.decodeIfPresent(TimeInterval.self, forKey: .iat) {
            self.iat = Date(timeIntervalSince1970: iatTimestamp)
        } else {
            self.iat = nil
        }

        self.jti = try container.decodeIfPresent(String.self, forKey: .jti)

        let known = Set(CodingKeys.allCases.map(\.stringValue))
        var additional: [String: AnyCodable] = [:]
        for key in dynamicContainer.allKeys where !known.contains(key.stringValue) {
            additional[key.stringValue] = try dynamicContainer.decode(AnyCodable.self, forKey: key)
        }
        self.additionalClaims = additional.isEmpty ? nil : additional
    }

    public func encode(to encoder: any Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encodeIfPresent(iss, forKey: .iss)
        try container.encodeIfPresent(sub, forKey: .sub)
        try container.encodeIfPresent(aud, forKey: .aud)
        if let exp {
            try container.encode(exp.timeIntervalSince1970, forKey: .exp)
        }
        if let nbf {
            try container.encode(nbf.timeIntervalSince1970, forKey: .nbf)
        }
        if let iat {
            try container.encode(iat.timeIntervalSince1970, forKey: .iat)
        }
        try container.encodeIfPresent(jti, forKey: .jti)

        if let additionalClaims {
            var dynamicContainer = encoder.container(keyedBy: DynamicCodingKey.self)
            for (key, value) in additionalClaims {
                guard let codingKey = DynamicCodingKey(stringValue: key) else { continue }
                try dynamicContainer.encode(value, forKey: codingKey)
            }
        }
    }
}
