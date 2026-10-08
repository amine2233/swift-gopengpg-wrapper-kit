import Foundation

/// Entry point grouping every PGP capability behind its own protocol.
///
/// Consumers can depend on the whole facade or on a single capability such as ``PGPCipher``.
public struct PGP: Sendable {
    /// Generates, imports and re-protects keys.
    public let keys: any PGPKeyManager
    /// Encrypts and decrypts data.
    public let cipher: any PGPCipher
    /// Produces and verifies detached signatures.
    public let signer: any PGPSigner
    /// Converts between binary and ASCII-armored representations.
    public let armorer: any PGPArmorer

    /// Creates a facade from independent capability implementations.
    /// - Parameters:
    ///   - keys: The key management implementation.
    ///   - cipher: The encryption and decryption implementation.
    ///   - signer: The signing and verification implementation.
    ///   - armorer: The armoring implementation.
    public init(
        keys: any PGPKeyManager,
        cipher: any PGPCipher,
        signer: any PGPSigner,
        armorer: any PGPArmorer
    ) {
        self.keys = keys
        self.cipher = cipher
        self.signer = signer
        self.armorer = armorer
    }
}
