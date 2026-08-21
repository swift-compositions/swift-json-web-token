@preconcurrency import Crypto
import Foundation

public struct SigningAlgorithm: Sendable {

    public let algorithmName: String

    let sign: @Sendable (Data, SigningKey) throws(RFC_7519.Error) -> Data

    let verify: @Sendable (Data, Data, VerificationKey) throws(RFC_7519.Error) -> Bool

    public init(
        algorithmName: String,
        sign: @escaping @Sendable (Data, SigningKey) throws(RFC_7519.Error) -> Data,
        verify: @escaping @Sendable (Data, Data, VerificationKey) throws(RFC_7519.Error) -> Bool
    ) {
        self.algorithmName = algorithmName
        self.sign = sign
        self.verify = verify
    }
}

extension SigningAlgorithm {

    public static let hmacSHA256 = SigningAlgorithm(
        algorithmName: "HS256",
        sign: { data, key throws(RFC_7519.Error) in
            guard let symmetricKey = key._symmetricKey else {
                throw .invalidSignature("HMAC requires a symmetric key")
            }
            return Data(HMAC<SHA256>.authenticationCode(for: data, using: symmetricKey))
        },
        verify: { signature, data, key throws(RFC_7519.Error) in
            guard let symmetricKey = key._symmetricKey else {
                throw .invalidSignature("HMAC requires a symmetric key")
            }
            return HMAC<SHA256>.isValidAuthenticationCode(
                signature,
                authenticating: data,
                using: symmetricKey
            )
        }
    )

    public static let hmacSHA384 = SigningAlgorithm(
        algorithmName: "HS384",
        sign: { data, key throws(RFC_7519.Error) in
            guard let symmetricKey = key._symmetricKey else {
                throw .invalidSignature("HMAC requires a symmetric key")
            }
            return Data(HMAC<SHA384>.authenticationCode(for: data, using: symmetricKey))
        },
        verify: { signature, data, key throws(RFC_7519.Error) in
            guard let symmetricKey = key._symmetricKey else {
                throw .invalidSignature("HMAC requires a symmetric key")
            }
            return HMAC<SHA384>.isValidAuthenticationCode(
                signature,
                authenticating: data,
                using: symmetricKey
            )
        }
    )

    public static let hmacSHA512 = SigningAlgorithm(
        algorithmName: "HS512",
        sign: { data, key throws(RFC_7519.Error) in
            guard let symmetricKey = key._symmetricKey else {
                throw .invalidSignature("HMAC requires a symmetric key")
            }
            return Data(HMAC<SHA512>.authenticationCode(for: data, using: symmetricKey))
        },
        verify: { signature, data, key throws(RFC_7519.Error) in
            guard let symmetricKey = key._symmetricKey else {
                throw .invalidSignature("HMAC requires a symmetric key")
            }
            return HMAC<SHA512>.isValidAuthenticationCode(
                signature,
                authenticating: data,
                using: symmetricKey
            )
        }
    )

    public static let ecdsaSHA256 = SigningAlgorithm(
        algorithmName: "ES256",
        sign: { data, key throws(RFC_7519.Error) in
            guard let privateKey = key._ecdsaPrivateKey else {
                throw .invalidSignature("ECDSA requires an ECDSA private key")
            }
            do {
                return try privateKey.signature(for: SHA256.hash(data: data)).rawRepresentation
            } catch {
                throw .invalidSignature("ECDSA signing failed: \(error)")
            }
        },
        verify: { signature, data, key throws(RFC_7519.Error) in
            guard let publicKey = key._ecdsaPublicKey else {
                throw .invalidSignature("ECDSA requires an ECDSA public key")
            }
            do {
                let ecdsaSignature = try P256.Signing.ECDSASignature(rawRepresentation: signature)
                return publicKey.isValidSignature(ecdsaSignature, for: SHA256.hash(data: data))
            } catch {
                throw .invalidSignature("ECDSA verification failed: \(error)")
            }
        }
    )

    public static func from(algorithmName: String) -> SigningAlgorithm? {
        switch algorithmName {
        case "HS256": return .hmacSHA256
        case "HS384": return .hmacSHA384
        case "HS512": return .hmacSHA512
        case "ES256": return .ecdsaSHA256
        default: return nil
        }
    }
}
