extension SigningAlgorithm {

    public enum Standard: Sendable, Hashable, CaseIterable {
        case hmacSHA256
        case hmacSHA384
        case hmacSHA512
        case ecdsaSHA256

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
