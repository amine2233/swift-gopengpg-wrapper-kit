import Foundation
import PGPKit

/// A ``PGPKeyManager`` whose every operation is a replaceable closure. Unset operations throw
/// ``PGPError/invalidInput``.
public struct PGPKeyManagerFake: PGPKeyManager {
    /// Behavior of ``generateKeyPair(for:algorithm:passphrase:)``.
    public var onGenerateKeyPair: @Sendable (PGPIdentity, PGPKeyAlgorithm, PGPPassphrase) async throws
        -> PGPKeyPair
    /// Behavior of ``importPublicKey(from:)``.
    public var onImportPublicKey: @Sendable (Data) async throws -> PGPPublicKey
    /// Behavior of ``importPrivateKey(from:)``.
    public var onImportPrivateKey: @Sendable (Data) async throws -> PGPPrivateKey
    /// Behavior of ``publicKey(from:)``.
    public var onPublicKey: @Sendable (PGPPrivateKey) async throws -> PGPPublicKey
    /// Behavior of ``changePassphrase(of:from:to:)``.
    public var onChangePassphrase: @Sendable (PGPPrivateKey, PGPPassphrase, PGPPassphrase) async throws
        -> PGPPrivateKey

    /// Creates a fake with the given behaviors.
    /// - Parameters:
    ///   - onGenerateKeyPair: Behavior of key generation.
    ///   - onImportPublicKey: Behavior of public key import.
    ///   - onImportPrivateKey: Behavior of private key import.
    ///   - onPublicKey: Behavior of public key derivation.
    ///   - onChangePassphrase: Behavior of passphrase change.
    public init(
        onGenerateKeyPair: @escaping @Sendable (PGPIdentity, PGPKeyAlgorithm, PGPPassphrase) async throws
            -> PGPKeyPair = { _, _, _ in throw PGPError.invalidInput },
        onImportPublicKey: @escaping @Sendable (Data) async throws -> PGPPublicKey = { _ in
            throw PGPError.invalidInput
        },
        onImportPrivateKey: @escaping @Sendable (Data) async throws -> PGPPrivateKey = { _ in
            throw PGPError.invalidInput
        },
        onPublicKey: @escaping @Sendable (PGPPrivateKey) async throws -> PGPPublicKey = { _ in
            throw PGPError.invalidInput
        },
        onChangePassphrase: @escaping @Sendable (PGPPrivateKey, PGPPassphrase, PGPPassphrase) async throws
            -> PGPPrivateKey = { _, _, _ in throw PGPError.invalidInput }
    ) {
        self.onGenerateKeyPair = onGenerateKeyPair
        self.onImportPublicKey = onImportPublicKey
        self.onImportPrivateKey = onImportPrivateKey
        self.onPublicKey = onPublicKey
        self.onChangePassphrase = onChangePassphrase
    }

    /// Forwards to ``onGenerateKeyPair``.
    public func generateKeyPair(
        for identity: PGPIdentity,
        algorithm: PGPKeyAlgorithm,
        passphrase: PGPPassphrase
    ) async throws -> PGPKeyPair {
        try await onGenerateKeyPair(identity, algorithm, passphrase)
    }

    /// Forwards to ``onImportPublicKey``.
    public func importPublicKey(from data: Data) async throws -> PGPPublicKey {
        try await onImportPublicKey(data)
    }

    /// Forwards to ``onImportPrivateKey``.
    public func importPrivateKey(from data: Data) async throws -> PGPPrivateKey {
        try await onImportPrivateKey(data)
    }

    /// Forwards to ``onPublicKey``.
    public func publicKey(from privateKey: PGPPrivateKey) async throws -> PGPPublicKey {
        try await onPublicKey(privateKey)
    }

    /// Forwards to ``onChangePassphrase``.
    public func changePassphrase(
        of privateKey: PGPPrivateKey,
        from current: PGPPassphrase,
        to new: PGPPassphrase
    ) async throws -> PGPPrivateKey {
        try await onChangePassphrase(privateKey, current, new)
    }
}

/// A ``PGPCipher`` whose every operation is a replaceable closure. Unset operations throw
/// ``PGPError/invalidInput``.
public struct PGPCipherFake: PGPCipher {
    /// Behavior of ``encrypt(_:to:)``.
    public var onEncrypt: @Sendable (Data, [PGPPublicKey]) async throws -> Data
    /// Behavior of ``decrypt(_:using:passphrase:)``.
    public var onDecrypt: @Sendable (Data, PGPPrivateKey, PGPPassphrase) async throws -> Data

    /// Creates a fake with the given behaviors.
    /// - Parameters:
    ///   - onEncrypt: Behavior of encryption.
    ///   - onDecrypt: Behavior of decryption.
    public init(
        onEncrypt: @escaping @Sendable (Data, [PGPPublicKey]) async throws -> Data = { _, _ in
            throw PGPError.invalidInput
        },
        onDecrypt: @escaping @Sendable (Data, PGPPrivateKey, PGPPassphrase) async throws
            -> Data = { _, _, _ in
                throw PGPError.invalidInput
            }
    ) {
        self.onEncrypt = onEncrypt
        self.onDecrypt = onDecrypt
    }

    /// Forwards to ``onEncrypt``.
    public func encrypt(_ plaintext: Data, to recipients: [PGPPublicKey]) async throws -> Data {
        try await onEncrypt(plaintext, recipients)
    }

    /// Forwards to ``onDecrypt``.
    public func decrypt(
        _ ciphertext: Data,
        using privateKey: PGPPrivateKey,
        passphrase: PGPPassphrase
    ) async throws -> Data {
        try await onDecrypt(ciphertext, privateKey, passphrase)
    }
}

/// A ``PGPSigner`` whose every operation is a replaceable closure.
///
/// Unset signing throws ``PGPError/invalidInput``; unset verification throws ``PGPError/signatureInvalid``.
public struct PGPSignerFake: PGPSigner {
    /// Behavior of ``sign(_:using:passphrase:)``.
    public var onSign: @Sendable (Data, PGPPrivateKey, PGPPassphrase) async throws -> Data
    /// Behavior of ``verify(_:signature:with:)``.
    public var onVerify: @Sendable (Data, Data, PGPPublicKey) async throws -> Void

    /// Creates a fake with the given behaviors.
    /// - Parameters:
    ///   - onSign: Behavior of signing.
    ///   - onVerify: Behavior of verification.
    public init(
        onSign: @escaping @Sendable (Data, PGPPrivateKey, PGPPassphrase) async throws -> Data = { _, _, _ in
            throw PGPError.invalidInput
        },
        onVerify: @escaping @Sendable (Data, Data, PGPPublicKey) async throws -> Void = { _, _, _ in
            throw PGPError.signatureInvalid
        }
    ) {
        self.onSign = onSign
        self.onVerify = onVerify
    }

    /// Forwards to ``onSign``.
    public func sign(
        _ data: Data,
        using privateKey: PGPPrivateKey,
        passphrase: PGPPassphrase
    ) async throws -> Data {
        try await onSign(data, privateKey, passphrase)
    }

    /// Forwards to ``onVerify``.
    public func verify(_ data: Data, signature: Data, with publicKey: PGPPublicKey) async throws {
        try await onVerify(data, signature, publicKey)
    }
}

/// A ``PGPArmorer`` whose every operation is a replaceable closure. Unset operations throw
/// ``PGPError/invalidInput``.
public struct PGPArmorerFake: PGPArmorer {
    /// Behavior of ``armor(_:as:)``.
    public var onArmor: @Sendable (Data, PGPArmorType) async throws -> String
    /// Behavior of ``dearmor(_:)``.
    public var onDearmor: @Sendable (String) async throws -> Data

    /// Creates a fake with the given behaviors.
    /// - Parameters:
    ///   - onArmor: Behavior of armoring.
    ///   - onDearmor: Behavior of dearmoring.
    public init(
        onArmor: @escaping @Sendable (Data, PGPArmorType) async throws -> String = { _, _ in
            throw PGPError.invalidInput
        },
        onDearmor: @escaping @Sendable (String) async throws -> Data = { _ in throw PGPError.invalidInput }
    ) {
        self.onArmor = onArmor
        self.onDearmor = onDearmor
    }

    /// Forwards to ``onArmor``.
    public func armor(_ data: Data, as type: PGPArmorType) async throws -> String {
        try await onArmor(data, type)
    }

    /// Forwards to ``onDearmor``.
    public func dearmor(_ armored: String) async throws -> Data {
        try await onDearmor(armored)
    }
}
