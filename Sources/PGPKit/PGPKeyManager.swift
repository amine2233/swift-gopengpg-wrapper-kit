import Foundation

/// Generates, imports and re-protects OpenPGP keys.
public protocol PGPKeyManager: Sendable {
    /// Generates a new key pair whose private key is protected by a passphrase.
    /// - Parameters:
    ///   - identity: The name and email bound to the key.
    ///   - algorithm: The key algorithm. RSA keys below 3072 bits are rejected.
    ///   - passphrase: The passphrase that locks the private key.
    /// - Returns: The generated key pair.
    /// - Throws: ``PGPError/invalidInput`` for an unsupported size, ``PGPError/keyGenerationFailed`` on engine failure.
    func generateKeyPair(
        for identity: PGPIdentity,
        algorithm: PGPKeyAlgorithm,
        passphrase: PGPPassphrase
    ) async throws -> PGPKeyPair

    /// Imports a public key from binary or ASCII-armored data.
    /// - Parameter data: The key material.
    /// - Returns: The public key.
    /// - Throws: ``PGPError/invalidKey`` when the data is not a valid key.
    func importPublicKey(from data: Data) async throws -> PGPPublicKey

    /// Imports a private key from binary or ASCII-armored data.
    /// - Parameter data: The key material.
    /// - Returns: The private key, still protected by its original passphrase.
    /// - Throws: ``PGPError/invalidKey`` when the data is not a valid private key.
    func importPrivateKey(from data: Data) async throws -> PGPPrivateKey

    /// Derives the public key from a private key.
    /// - Parameter privateKey: The private key.
    /// - Returns: The matching public key.
    /// - Throws: ``PGPError/invalidKey`` when the private key is unusable.
    func publicKey(from privateKey: PGPPrivateKey) async throws -> PGPPublicKey

    /// Re-protects a private key with a new passphrase.
    /// - Parameters:
    ///   - privateKey: The private key to re-protect.
    ///   - current: The passphrase currently protecting `privateKey`.
    ///   - new: The passphrase to protect it with from now on.
    /// - Returns: The private key locked with `new`.
    /// - Throws: ``PGPError/invalidPassphrase`` when `current` is wrong.
    func changePassphrase(
        of privateKey: PGPPrivateKey,
        from current: PGPPassphrase,
        to new: PGPPassphrase
    ) async throws -> PGPPrivateKey
}
