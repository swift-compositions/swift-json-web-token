@preconcurrency import Crypto
import Foundation

public struct VerificationKey: Sendable {
    private enum Storage: Sendable {
        case symmetric(SymmetricKey)
        case ecdsa(P256.Signing.PublicKey)
    }

    private let storage: Storage

    private init(storage: Storage) {
        self.storage = storage
    }

    public static func symmetric(data: Data) -> VerificationKey {
        VerificationKey(storage: .symmetric(SymmetricKey(data: data)))
    }

    public static func symmetric(string: String) -> VerificationKey {
        VerificationKey(storage: .symmetric(SymmetricKey(data: Data(string.utf8))))
    }

    public static func ecdsa(_ publicKey: P256.Signing.PublicKey) -> VerificationKey {
        VerificationKey(storage: .ecdsa(publicKey))
    }

    public static func ecdsa(from signingKey: SigningKey) -> VerificationKey? {
        guard let privateKey = signingKey._ecdsaPrivateKey else { return nil }
        return VerificationKey(storage: .ecdsa(privateKey.publicKey))
    }

    public static func ecdsa(rawRepresentation: Data) throws(RFC_7519.Error) -> VerificationKey {
        do {
            return VerificationKey(
                storage: .ecdsa(try P256.Signing.PublicKey(rawRepresentation: rawRepresentation))
            )
        } catch {
            throw .invalidKey("Invalid ECDSA public key: \(error)")
        }
    }

    var _symmetricKey: SymmetricKey? {
        guard case .symmetric(let key) = storage else { return nil }
        return key
    }

    var _ecdsaPublicKey: P256.Signing.PublicKey? {
        guard case .ecdsa(let key) = storage else { return nil }
        return key
    }
}
