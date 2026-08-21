import RFC_7519

extension RFC_7519 {

    public enum Error: Swift.Error, Hashable, Sendable, CustomStringConvertible {

        case invalidFormat(String)

        case tokenExpired(String)

        case tokenNotYetValid(String)

        case invalidSignature(String)

        case unsupportedAlgorithm(String)

        case encodingFailed(String)

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
