import Foundation
import PGPKit
import PGPKitGopenPGP
import PGPKitTesting
import Testing

struct RoundTripTests {
    private let pgp = PGP.gopenPGP()
    private let identity = PGPIdentity(name: "Test", email: "test@example.com")
    private let passphrase = PGPPassphrase("correct horse")

    private func makeKeyPair() async throws -> PGPKeyPair {
        try await pgp.keys.generateKeyPair(for: identity, algorithm: .curve25519, passphrase: passphrase)
    }

    @Test
    func encryptThenDecryptReturnsOriginalPlaintext() async throws {
        let pair = try await makeKeyPair()
        let plaintext = Data("secret message".utf8)

        let ciphertext = try await pgp.cipher.encrypt(plaintext, to: [pair.publicKey])
        let decrypted = try await pgp.cipher.decrypt(
            ciphertext,
            using: pair.privateKey,
            passphrase: passphrase
        )

        #expect(ciphertext != plaintext)
        #expect(decrypted == plaintext)
    }

    @Test
    func decryptWithWrongPassphraseThrowsInvalidPassphrase() async throws {
        let pair = try await makeKeyPair()
        let ciphertext = try await pgp.cipher.encrypt(Data("x".utf8), to: [pair.publicKey])

        await #expect(throws: PGPError.invalidPassphrase) {
            try await pgp.cipher.decrypt(
                ciphertext,
                using: pair.privateKey,
                passphrase: PGPPassphrase("wrong")
            )
        }
    }

    @Test
    func encryptWithoutRecipientsThrowsInvalidInput() async {
        await #expect(throws: PGPError.invalidInput) {
            try await pgp.cipher.encrypt(Data("x".utf8), to: [])
        }
    }

    @Test
    func signThenVerifySucceeds() async throws {
        let pair = try await makeKeyPair()
        let data = Data("payload".utf8)

        let signature = try await pgp.signer.sign(data, using: pair.privateKey, passphrase: passphrase)

        try await pgp.signer.verify(data, signature: signature, with: pair.publicKey)
    }

    @Test
    func verifyTamperedDataThrowsSignatureInvalid() async throws {
        let pair = try await makeKeyPair()
        let signature = try await pgp.signer.sign(
            Data("payload".utf8),
            using: pair.privateKey,
            passphrase: passphrase
        )

        await #expect(throws: PGPError.signatureInvalid) {
            try await pgp.signer.verify(Data("tampered".utf8), signature: signature, with: pair.publicKey)
        }
    }

    @Test
    func armoredPrivateKeyImportsBackToSameFingerprint() async throws {
        let pair = try await makeKeyPair()

        let armored = try await pgp.armorer.armor(pair.privateKey.data, as: .privateKey)
        let imported = try await pgp.keys.importPrivateKey(from: Data(armored.utf8))

        #expect(armored.hasPrefix("-----BEGIN PGP PRIVATE KEY BLOCK-----"))
        #expect(imported.fingerprint == pair.privateKey.fingerprint)
    }

    @Test
    func armorMessageRoundTripsThroughDearmor() async throws {
        let pair = try await makeKeyPair()
        let ciphertext = try await pgp.cipher.encrypt(Data("hello".utf8), to: [pair.publicKey])

        let armored = try await pgp.armorer.armor(ciphertext, as: .message)
        let binary = try await pgp.armorer.dearmor(armored)
        let decrypted = try await pgp.cipher.decrypt(
            Data(armored.utf8),
            using: pair.privateKey,
            passphrase: passphrase
        )

        #expect(binary == ciphertext)
        #expect(decrypted == Data("hello".utf8))
    }

    @Test
    func changePassphraseInvalidatesOldOne() async throws {
        let pair = try await makeKeyPair()
        let newPassphrase = PGPPassphrase("new one")

        let rekeyed = try await pgp.keys.changePassphrase(
            of: pair.privateKey,
            from: passphrase,
            to: newPassphrase
        )
        let ciphertext = try await pgp.cipher.encrypt(Data("x".utf8), to: [pair.publicKey])

        #expect(try await pgp.cipher
            .decrypt(ciphertext, using: rekeyed, passphrase: newPassphrase) == Data("x".utf8))
        await #expect(throws: PGPError.invalidPassphrase) {
            try await pgp.cipher.decrypt(ciphertext, using: rekeyed, passphrase: passphrase)
        }
    }

    @Test
    func publicKeyDerivedFromPrivateMatchesGeneratedOne() async throws {
        let pair = try await makeKeyPair()

        let derived = try await pgp.keys.publicKey(from: pair.privateKey)

        #expect(derived.fingerprint == pair.publicKey.fingerprint)
    }

    @Test
    func rsaBelowMinimumBitsIsRejected() async {
        await #expect(throws: PGPError.invalidInput) {
            try await pgp.keys.generateKeyPair(
                for: identity,
                algorithm: .rsa(bits: 2_048),
                passphrase: passphrase
            )
        }
    }

    @Test
    func overridingOneCapabilityKeepsTheOthersOnGopenPGP() async throws {
        let marker = Data("faked".utf8)
        let overridden = PGP.gopenPGP(cipher: PGPCipherFake(onEncrypt: { _, _ in marker }))
        let pair = try await overridden.keys.generateKeyPair(
            for: identity,
            algorithm: .curve25519,
            passphrase: passphrase
        )

        #expect(try await overridden.cipher.encrypt(Data(), to: [pair.publicKey]) == marker)
        #expect(!pair.publicKey.fingerprint.isEmpty)
    }
}
