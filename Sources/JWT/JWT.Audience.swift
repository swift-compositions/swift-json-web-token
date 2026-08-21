extension JWT {

    public enum Audience: Hashable, Sendable {

        case single(String)

        case multiple([String])

        public init(_ audience: String) {
            self = .single(audience)
        }

        public init(_ audiences: [String]) {
            self = audiences.count == 1 ? .single(audiences[0]) : .multiple(audiences)
        }

        public var values: [String] {
            switch self {
            case .single(let audience):
                return [audience]

            case .multiple(let audiences):
                return audiences
            }
        }

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
