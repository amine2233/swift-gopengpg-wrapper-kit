import Foundation

/// A secret passphrase. Its textual descriptions are redacted so it never leaks into logs.
public struct PGPPassphrase: Sendable, Equatable, CustomStringConvertible, CustomDebugStringConvertible {
    /// The raw passphrase bytes.
    public let data: Data

    /// Creates a passphrase from raw bytes.
    /// - Parameter data: The passphrase bytes.
    public init(_ data: Data) {
        self.data = data
    }

    /// Creates a passphrase from a string, encoded as UTF-8.
    /// - Parameter string: The passphrase text.
    public init(_ string: String) {
        self.data = Data(string.utf8)
    }

    /// A redacted description that never includes the passphrase.
    public var description: String {
        "PGPPassphrase(redacted)"
    }

    /// A redacted debug description that never includes the passphrase.
    public var debugDescription: String {
        description
    }
}

/// The name and email a key is bound to.
public struct PGPIdentity: Sendable, Hashable {
    /// The owner's display name.
    public let name: String
    /// The owner's email address.
    public let email: String

    /// Creates an identity.
    /// - Parameters:
    ///   - name: The owner's display name.
    ///   - email: The owner's email address.
    public init(name: String, email: String) {
        self.name = name
        self.email = email
    }
}

/// The algorithm used to generate a key.
public enum PGPKeyAlgorithm: Sendable, Hashable {
    /// Curve25519 elliptic-curve key.
    case curve25519
    /// RSA key of the given size. Sizes below 3072 bits are rejected at generation time.
    case rsa(bits: Int)
}

/// A public key that can encrypt data and verify signatures.
public struct PGPPublicKey: Sendable, Hashable {
    /// The binary key material.
    public let data: Data
    /// The key fingerprint, in hexadecimal.
    public let fingerprint: String

    /// Creates a public key.
    /// - Parameters:
    ///   - data: The binary key material.
    ///   - fingerprint: The key fingerprint, in hexadecimal.
    public init(data: Data, fingerprint: String) {
        self.data = data
        self.fingerprint = fingerprint
    }
}

/// A private key, normally locked by a passphrase. Its textual descriptions omit the key material.
public struct PGPPrivateKey: Sendable, Equatable, CustomStringConvertible, CustomDebugStringConvertible {
    /// The binary key material.
    public let data: Data
    /// The key fingerprint, in hexadecimal.
    public let fingerprint: String

    /// Creates a private key.
    /// - Parameters:
    ///   - data: The binary key material.
    ///   - fingerprint: The key fingerprint, in hexadecimal.
    public init(data: Data, fingerprint: String) {
        self.data = data
        self.fingerprint = fingerprint
    }

    /// A description showing only the fingerprint.
    public var description: String {
        "PGPPrivateKey(\(fingerprint))"
    }

    /// A debug description showing only the fingerprint.
    public var debugDescription: String {
        description
    }
}

/// A matching public and private key.
public struct PGPKeyPair: Sendable, Equatable {
    /// The public half.
    public let publicKey: PGPPublicKey
    /// The private half, locked by the passphrase used at generation.
    public let privateKey: PGPPrivateKey

    /// Creates a key pair.
    /// - Parameters:
    ///   - publicKey: The public half.
    ///   - privateKey: The private half.
    public init(publicKey: PGPPublicKey, privateKey: PGPPrivateKey) {
        self.publicKey = publicKey
        self.privateKey = privateKey
    }
}

/// The kind of data wrapped in an ASCII armor block.
public enum PGPArmorType: Sendable, Hashable {
    /// An encrypted message.
    case message
    /// A detached signature.
    case signature
    /// A public key block.
    case publicKey
    /// A private key block.
    case privateKey
}
