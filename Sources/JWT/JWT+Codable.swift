import Foundation

extension JWT: Codable {
    public init(from decoder: any Decoder) throws {
        let container = try decoder.singleValueContainer()
        let token = try container.decode(String.self)
        do {
            self = try JWT.parse(from: token)
        } catch {
            throw DecodingError.dataCorrupted(
                DecodingError.Context(
                    codingPath: decoder.codingPath,
                    debugDescription: "Invalid JWT compact serialization",
                    underlyingError: error
                )
            )
        }
    }

    public func encode(to encoder: any Encoder) throws {
        let serialized: String
        do {
            serialized = try compactSerialization()
        } catch {
            throw EncodingError.invalidValue(
                self,
                EncodingError.Context(
                    codingPath: encoder.codingPath,
                    debugDescription: "JWT could not be serialized to its compact form",
                    underlyingError: error
                )
            )
        }
        var container = encoder.singleValueContainer()
        try container.encode(serialized)
    }
}
