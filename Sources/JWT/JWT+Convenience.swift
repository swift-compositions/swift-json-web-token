import Foundation

extension JWT {

    public var token: String {
        get throws(RFC_7519.Error) {
            try compactSerialization()
        }
    }
}

extension JWT.Header {

    public var algorithm: String { alg }

    public var type: String? { typ }

    public var contentType: String? { cty }

    public var keyId: String? { kid }
}

extension JWT.Payload {

    public var issuer: String? { iss }

    public var subject: String? { sub }

    public var audience: JWT.Audience? { aud }

    public var expirationTime: Date? { exp }

    public var notBeforeTime: Date? { nbf }

    public var issuedAtTime: Date? { iat }

    public var id: String? { jti }

    public var isExpired: Bool {
        guard let exp else { return false }
        return exp < Date()
    }

    public var isNotYetValid: Bool {
        guard let nbf else { return false }
        return nbf > Date()
    }

    public var isCurrentlyValid: Bool {
        !isExpired && !isNotYetValid
    }

    public var timeUntilExpiration: TimeInterval? {
        guard let exp else { return nil }
        return exp.timeIntervalSinceNow
    }

    public var singleAudience: String? {
        switch aud {
        case .single(let value):
            return value

        case .multiple(let values):
            return values.first

        case .none:
            return nil
        }
    }

    public var audienceValues: [String] {
        aud?.values ?? []
    }

    public func claim<T>(_ key: String, as type: T.Type = T.self) -> T? {
        additionalClaim(key, as: type)
    }

    public func claim<T>(_ key: String, default defaultValue: T) -> T {
        additionalClaim(key, as: T.self) ?? defaultValue
    }

    public func hasClaim(_ key: String) -> Bool {
        switch key {
        case "iss": return iss != nil
        case "sub": return sub != nil
        case "aud": return aud != nil
        case "exp": return exp != nil
        case "nbf": return nbf != nil
        case "iat": return iat != nil
        case "jti": return jti != nil

        default:
            return additionalClaim(key, as: String.self) != nil
                || additionalClaim(key, as: Int.self) != nil
                || additionalClaim(key, as: Bool.self) != nil
                || additionalClaim(key, as: Double.self) != nil
                || additionalClaim(key, as: [String].self) != nil
                || additionalClaim(key, as: [String: Any].self) != nil
        }
    }

    public var standardClaimKeys: [String] {
        var keys: [String] = []
        if iss != nil { keys.append("iss") }
        if sub != nil { keys.append("sub") }
        if aud != nil { keys.append("aud") }
        if exp != nil { keys.append("exp") }
        if nbf != nil { keys.append("nbf") }
        if iat != nil { keys.append("iat") }
        if jti != nil { keys.append("jti") }
        return keys
    }
}

extension JWT {

    public func isValid(with key: VerificationKey, algorithm: SigningAlgorithm) -> Bool {
        do {
            return try verifyAndValidate(with: key, algorithm: algorithm)
        } catch {
            return false
        }
    }

    public func validationErrors(
        with key: VerificationKey,
        algorithm: SigningAlgorithm
    ) -> [String] {
        var errors: [String] = []

        do {
            let signatureValid = try verify(with: key, algorithm: algorithm)
            if !signatureValid {
                errors.append("Invalid signature")
            }
        } catch {
            errors.append("Signature verification failed: \(error)")
        }

        if payload.isExpired {
            errors.append("Token is expired")
        }
        if payload.isNotYetValid {
            errors.append("Token is not yet valid")
        }

        return errors
    }
}
