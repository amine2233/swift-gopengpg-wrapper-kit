import Foundation

/// Encrypts and decrypts data with OpenPGP keys.
public protocol PGPCipher: Sendable {
    /// Encrypts data so that any of the recipients can decrypt it.
    /// - Parameters:
    ///   - plaintext: The data to encrypt.
    ///   - recipients: The public keys allowed to decrypt. Must not be empty.
    /// - Returns: The binary encrypted message.
    /// - Throws: ``PGPError/invalidInput`` when `recipients` is empty, ``PGPError/invalidKey`` for an
    /// unusable key.
    func encrypt(_ plaintext: Data, to recipients: [PGPPublicKey]) async throws -> Data

    /// Decrypts a binary or ASCII-armored message.
    /// - Parameters:
    ///   - ciphertext: The encrypted message.
    ///   - privateKey: The recipient's private key.
    ///   - passphrase: The passphrase protecting `privateKey`.
    /// - Returns: The decrypted data.
    /// - Throws: ``PGPError/invalidPassphrase`` for a wrong passphrase,
    ///   ``PGPError/decryptionFailed`` when the key cannot decrypt the message.
    func decrypt(
        _ ciphertext: Data,
        using privateKey: PGPPrivateKey,
        passphrase: PGPPassphrase
    ) async throws -> Data
}
