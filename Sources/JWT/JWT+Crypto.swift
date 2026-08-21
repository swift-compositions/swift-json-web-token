@preconcurrency import Crypto
import Foundation

extension JWT {

    public static func signed(
        algorithm: SigningAlgorithm,
        key: SigningKey,
        issuer: String? = nil,
        subject: String? = nil,
        audience: String? = nil,
        audiences: [String]? = nil,
        expiresIn: TimeInterval? = nil,
        expiresAt: Date? = nil,
        notBefore: Date? = nil,
        issuedAt: Date? = Date(),
        jti: String? = nil,
        claims: [String: Any] = [:],
        headerParameters: [String: Any] = [:]
    ) throws(RFC_7519.Error) -> JWT {
        let aud: Audience?
        if let audiences {
            aud = Audience(audiences)
        } else if let audience {
            aud = .single(audience)
        } else {
            aud = nil
        }

        let exp: Date?
        if let expiresAt {
            exp = expiresAt
        } else if let expiresIn {
            exp = Date(timeIntervalSinceNow: expiresIn)
        } else {
            exp = nil
        }

        var filteredHeaderParameters = headerParameters
        let typ = filteredHeaderParameters.removeValue(forKey: "typ") as? String ?? "JWT"
        let cty = filteredHeaderParameters.removeValue(forKey: "cty") as? String
        let kid = filteredHeaderParameters.removeValue(forKey: "kid") as? String

        let header = Header(
            alg: algorithm.algorithmName,
            typ: typ,
            cty: cty,
            kid: kid,
            additionalParameters: filteredHeaderParameters.isEmpty ? nil : filteredHeaderParameters
        )

        let payload = Payload(
            iss: issuer,
            sub: subject,
            aud: aud,
            exp: exp,
            nbf: notBefore,
            iat: issuedAt,
            jti: jti,
            additionalClaims: claims.isEmpty ? nil : claims
        )

        let unsignedJWT = JWT(header: header, payload: payload, signature: Data())
        let signingInput = try unsignedJWT.signingInput()
        let signature = try algorithm.sign(signingInput, key)
        return JWT(header: header, payload: payload, signature: signature)
    }

    public static func hmacSHA256(
        issuer: String,
        subject: String,
        audience: String? = nil,
        expiresIn: TimeInterval = 3600,
        claims: [String: Any] = [:],
        secretKey: String
    ) throws(RFC_7519.Error) -> JWT {
        try signed(
            algorithm: .hmacSHA256,
            key: .symmetric(string: secretKey),
            issuer: issuer,
            subject: subject,
            audience: audience,
            expiresIn: expiresIn,
            claims: claims
        )
    }

    public static func hmacSHA384(
        issuer: String,
        subject: String,
        audience: String? = nil,
        expiresIn: TimeInterval = 3600,
        claims: [String: Any] = [:],
        secretKey: String
    ) throws(RFC_7519.Error) -> JWT {
        try signed(
            algorithm: .hmacSHA384,
            key: .symmetric(string: secretKey),
            issuer: issuer,
            subject: subject,
            audience: audience,
            expiresIn: expiresIn,
            claims: claims
        )
    }

    public static func hmacSHA512(
        issuer: String,
        subject: String,
        audience: String? = nil,
        expiresIn: TimeInterval = 3600,
        claims: [String: Any] = [:],
        secretKey: String
    ) throws(RFC_7519.Error) -> JWT {
        try signed(
            algorithm: .hmacSHA512,
            key: .symmetric(string: secretKey),
            issuer: issuer,
            subject: subject,
            audience: audience,
            expiresIn: expiresIn,
            claims: claims
        )
    }

    public static func ecdsaSHA256(
        issuer: String,
        subject: String,
        audience: String? = nil,
        expiresIn: TimeInterval = 3600,
        claims: [String: Any] = [:],
        privateKey: P256.Signing.PrivateKey
    ) throws(RFC_7519.Error) -> JWT {
        try signed(
            algorithm: .ecdsaSHA256,
            key: .ecdsa(privateKey),
            issuer: issuer,
            subject: subject,
            audience: audience,
            expiresIn: expiresIn,
            claims: claims
        )
    }
}

extension JWT {

    public func verify(
        with key: VerificationKey,
        algorithm: SigningAlgorithm
    ) throws(RFC_7519.Error) -> Bool {
        guard header.alg == algorithm.algorithmName else {
            throw .unsupportedAlgorithm(
                "Expected \(algorithm.algorithmName), token declares \(header.alg)"
            )
        }
        let input = try signingInput()
        return try algorithm.verify(signature, input, key)
    }

    public func verifyAndValidate(
        with key: VerificationKey,
        algorithm: SigningAlgorithm,
        currentTime: Date = Date(),
        clockSkew: TimeInterval = 60
    ) throws(RFC_7519.Error) -> Bool {
        guard try verify(with: key, algorithm: algorithm) else { return false }
        try payload.validateTiming(currentTime: currentTime, clockSkew: clockSkew)
        return true
    }
}
