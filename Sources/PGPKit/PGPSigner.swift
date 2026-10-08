import Foundation

/// Produces and verifies detached OpenPGP signatures.
public protocol PGPSigner: Sendable {
    /// Signs data with a private key.
    /// - Parameters:
    ///   - data: The data to sign.
    ///   - privateKey: The signing key.
    ///   - passphrase: The passphrase protecting `privateKey`.
    /// - Returns: The binary detached signature.
    /// - Throws: ``PGPError/invalidPassphrase`` for a wrong passphrase, ``PGPError/invalidKey`` for an unusable key.
    func sign(
        _ data: Data,
        using privateKey: PGPPrivateKey,
        passphrase: PGPPassphrase
    ) async throws -> Data

    /// Verifies a detached signature, binary or ASCII-armored.
    /// - Parameters:
    ///   - data: The data that was signed.
    ///   - signature: The detached signature.
    ///   - publicKey: The signer's public key.
    /// - Throws: ``PGPError/signatureInvalid`` when the signature does not match.
    func verify(_ data: Data, signature: Data, with publicKey: PGPPublicKey) async throws
}
