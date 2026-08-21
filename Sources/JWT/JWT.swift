import Foundation

public struct JWT: Sendable {

    public let header: Header

    public let payload: Payload

    public let signature: Data

    let headerBase64URL: String?

    let payloadBase64URL: String?

    public init(header: Header, payload: Payload, signature: Data) {
        self.header = header
        self.payload = payload
        self.signature = signature
        self.headerBase64URL = nil
        self.payloadBase64URL = nil
    }

    init(
        header: Header,
        payload: Payload,
        signature: Data,
        headerBase64URL: String,
        payloadBase64URL: String
    ) {
        self.header = header
        self.payload = payload
        self.signature = signature
        self.headerBase64URL = headerBase64URL
        self.payloadBase64URL = payloadBase64URL
    }

    public static func parse(from token: String) throws(RFC_7519.Error) -> JWT {
        let components = token.components(separatedBy: ".")
        guard components.count == 3 else {
            throw .invalidFormat("JWT must have exactly 3 parts separated by dots")
        }

        guard let headerData = Data(base64URLEncoded: components[0]) else {
            throw .invalidFormat("Invalid base64url encoding in header")
        }
        let header: Header
        do {
            header = try JSONDecoder().decode(Header.self, from: headerData)
        } catch {
            throw .invalidFormat("Invalid JSON in header: \(error)")
        }

        guard let payloadData = Data(base64URLEncoded: components[1]) else {
            throw .invalidFormat("Invalid base64url encoding in payload")
        }
        let payload: Payload
        do {
            payload = try JSONDecoder().decode(Payload.self, from: payloadData)
        } catch {
            throw .invalidFormat("Invalid JSON in payload: \(error)")
        }

        guard let signature = Data(base64URLEncoded: components[2]) else {
            throw .invalidFormat("Invalid base64url encoding in signature")
        }

        return JWT(
            header: header,
            payload: payload,
            signature: signature,
            headerBase64URL: components[0],
            payloadBase64URL: components[1]
        )
    }

    public func compactSerialization() throws(RFC_7519.Error) -> String {
        let headerBase64: String
        let payloadBase64: String

        if let originalHeader = headerBase64URL, let originalPayload = payloadBase64URL {
            headerBase64 = originalHeader
            payloadBase64 = originalPayload
        } else {
            let encoder = JSONEncoder()
            encoder.outputFormatting = .sortedKeys
            do {
                headerBase64 = try encoder.encode(header).base64URLEncodedString()
                payloadBase64 = try encoder.encode(payload).base64URLEncodedString()
            } catch {
                throw .encodingFailed("Failed to encode JWT: \(error)")
            }
        }

        let signatureBase64 = signature.base64URLEncodedString()
        return "\(headerBase64).\(payloadBase64).\(signatureBase64)"
    }

    public func signingInput() throws(RFC_7519.Error) -> Data {
        if let originalHeader = headerBase64URL, let originalPayload = payloadBase64URL {
            return Data("\(originalHeader).\(originalPayload)".utf8)
        }

        let encoder = JSONEncoder()
        encoder.outputFormatting = .sortedKeys
        let headerBase64: String
        let payloadBase64: String
        do {
            headerBase64 = try encoder.encode(header).base64URLEncodedString()
            payloadBase64 = try encoder.encode(payload).base64URLEncodedString()
        } catch {
            throw .encodingFailed("Failed to encode JWT signing input: \(error)")
        }

        return Data("\(headerBase64).\(payloadBase64)".utf8)
    }
}

extension JWT: Equatable {}

extension JWT: Hashable {}
