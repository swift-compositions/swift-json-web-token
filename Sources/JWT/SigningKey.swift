@preconcurrency import Crypto
import Foundation

public struct SigningKey: Sendable {
    private enum Storage: Sendable {
        case symmetric(SymmetricKey)
        case ecdsa(P256.Signing.PrivateKey)
    }

    private let storage: Storage

    private init(storage: Storage) {
        self.storage = storage
    }

    public static func symmetric(data: Data) -> SigningKey {
        SigningKey(storage: .symmetric(SymmetricKey(data: data)))
    }

    public static func symmetric(string: String) -> SigningKey {
        SigningKey(storage: .symmetric(SymmetricKey(data: Data(string.utf8))))
    }

    public static func ecdsa(_ privateKey: P256.Signing.PrivateKey) -> SigningKey {
        SigningKey(storage: .ecdsa(privateKey))
    }

    public static func generateECDSA() -> SigningKey {
        SigningKey(storage: .ecdsa(P256.Signing.PrivateKey()))
    }

    public static func ecdsa(rawRepresentation: Data) throws(RFC_7519.Error) -> SigningKey {
        do {
            return SigningKey(
                storage: .ecdsa(try P256.Signing.PrivateKey(rawRepresentation: rawRepresentation))
            )
        } catch {
            throw .invalidKey("Invalid ECDSA private key: \(error)")
        }
    }

    var _symmetricKey: SymmetricKey? {
        guard case .symmetric(let key) = storage else { return nil }
        return key
    }

    var _ecdsaPrivateKey: P256.Signing.PrivateKey? {
        guard case .ecdsa(let key) = storage else { return nil }
        return key
    }
}
