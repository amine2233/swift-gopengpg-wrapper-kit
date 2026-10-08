import Foundation
import PGPKit
import PGPKitGopenPGP
import Testing

struct ExampleResourcesTests {
    private let pgp = PGP.gopenPGP()

    private func aliceKeys() async throws -> (publicKey: PGPPublicKey, privateKey: PGPPrivateKey) {
        let publicKey = try await pgp.keys.importPublicKey(from: ExampleResources.bundled("alice.public.asc"))
        let privateKey = try await pgp.keys.importPrivateKey(from: ExampleResources.bundled("alice.private.asc"))
        return (publicKey, privateKey)
    }

    @Test
    func armoredAndBinaryKeyFilesDescribeTheSameKey() async throws {
        let armoredPublic = try await pgp.keys.importPublicKey(from: ExampleResources.bundled("alice.public.asc"))
        let binaryPublic = try await pgp.keys.importPublicKey(from: ExampleResources.bundled("alice.public.gpg"))
        let armoredPrivate = try await pgp.keys.importPrivateKey(from: ExampleResources.bundled("alice.private.asc"))
        let binaryPrivate = try await pgp.keys.importPrivateKey(from: ExampleResources.bundled("alice.private.gpg"))

        #expect(armoredPublic.fingerprint == binaryPublic.fingerprint)
        #expect(armoredPrivate.fingerprint == binaryPrivate.fingerprint)
        #expect(armoredPublic.fingerprint == armoredPrivate.fingerprint)
    }

    @Test
    func aliceDecryptsTheBinaryGPGExample() async throws {
        let keys = try await aliceKeys()

        let decrypted = try await pgp.cipher.decrypt(
            ExampleResources.bundled("message.txt.gpg"),
            using: keys.privateKey,
            passphrase: Fixture.passphrase
        )

        #expect(decrypted == (try ExampleResources.bundled("message.txt")))
        #expect(decrypted == (try ExampleResources.bundled("message.decrypted.txt")))
    }

    @Test
    func aliceDecryptsTheArmoredAscExample() async throws {
        let keys = try await aliceKeys()
        let armored = try ExampleResources.bundledText("message.txt.asc")

        let decrypted = try await pgp.cipher.decrypt(
            Data(armored.utf8),
            using: keys.privateKey,
            passphrase: Fixture.passphrase
        )

        #expect(armored.hasPrefix("-----BEGIN PGP MESSAGE-----"))
        #expect(decrypted == (try ExampleResources.bundled("message.txt")))
    }

    @Test
    func wrongPassphraseCannotOpenTheExample() async throws {
        let keys = try await aliceKeys()

        await #expect(throws: PGPError.invalidPassphrase) {
            try await pgp.cipher.decrypt(
                ExampleResources.bundled("message.txt.gpg"),
                using: keys.privateKey,
                passphrase: PGPPassphrase("not the passphrase")
            )
        }
    }

    @Test
    func signatureExamplesVerifyAgainstTheMessage() async throws {
        let keys = try await aliceKeys()
        let message = try ExampleResources.bundled("message.txt")

        try await pgp.signer.verify(message, signature: ExampleResources.bundled("message.txt.sig"), with: keys.publicKey)
        try await pgp.signer.verify(message, signature: ExampleResources.bundled("message.txt.sig.asc"), with: keys.publicKey)
    }

    @Test
    func signatureExampleRejectsAModifiedMessage() async throws {
        let keys = try await aliceKeys()

        await #expect(throws: PGPError.signatureInvalid) {
            try await pgp.signer.verify(
                Data("modified".utf8),
                signature: ExampleResources.bundled("message.txt.sig"),
                with: keys.publicKey
            )
        }
    }

    @Test
    func sdkDecryptsAFileEncryptedByTheGPGCommandLine() async throws {
        let bob = try await pgp.keys.importPrivateKey(from: ExampleResources.bundled("bob.private.asc"))

        let decrypted = try await pgp.cipher.decrypt(
            ExampleResources.bundled("gnupg-encrypted.txt.gpg"),
            using: bob,
            passphrase: Fixture.passphrase
        )

        #expect(decrypted == (try ExampleResources.bundled("gnupg-plain.txt")))
    }

    @Test
    func sdkDecryptsItsOwnFileForAGnuPGGeneratedKey() async throws {
        let bob = try await pgp.keys.importPrivateKey(from: ExampleResources.bundled("bob.private.asc"))

        let decrypted = try await pgp.cipher.decrypt(
            ExampleResources.bundled("sdk-to-bob.txt.gpg"),
            using: bob,
            passphrase: Fixture.passphrase
        )

        #expect(decrypted == (try ExampleResources.bundled("sdk-to-bob.decrypted.txt")))
    }
}
