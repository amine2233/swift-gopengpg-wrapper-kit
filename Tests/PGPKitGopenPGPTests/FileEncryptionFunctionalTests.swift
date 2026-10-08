import Foundation
import PGPKit
import PGPKitGopenPGP
import Testing

struct FileEncryptionFunctionalTests {
    private let pgp = PGP.gopenPGP()

    private func makeKeyPair() async throws -> PGPKeyPair {
        try await pgp.keys.generateKeyPair(
            for: Fixture.identity,
            algorithm: .curve25519,
            passphrase: Fixture.passphrase
        )
    }

    @Test
    func encryptedFileOnDiskIsBinaryPGPAndDecryptsBackToTheOriginal() async throws {
        let workspace = try Workspace()
        defer { workspace.remove() }
        let pair = try await makeKeyPair()
        let source = workspace.file("report.txt")
        try Data("quarterly numbers".utf8).write(to: source)

        let encrypted = try await pgp.cipher.encrypt(Data(contentsOf: source), to: [pair.publicKey])
        let encryptedFile = workspace.file("report.txt.gpg")
        try encrypted.write(to: encryptedFile)

        let onDisk = try Data(contentsOf: encryptedFile)
        #expect(onDisk.first.map { $0 & 0x80 != 0 } == true)
        #expect(try onDisk != Data(contentsOf: source))

        let decrypted = try await pgp.cipher.decrypt(
            onDisk,
            using: pair.privateKey,
            passphrase: Fixture.passphrase
        )
        let restored = workspace.file("report.restored.txt")
        try decrypted.write(to: restored)

        #expect(try Data(contentsOf: restored) == Data(contentsOf: source))
    }

    @Test
    func armoredAscFileIsReadableTextAndDecrypts() async throws {
        let workspace = try Workspace()
        defer { workspace.remove() }
        let pair = try await makeKeyPair()
        let plaintext = Data("armored payload".utf8)

        let encrypted = try await pgp.cipher.encrypt(plaintext, to: [pair.publicKey])
        let armored = try await pgp.armorer.armor(encrypted, as: .message)
        let ascFile = workspace.file("message.asc")
        try armored.write(to: ascFile, atomically: true, encoding: .utf8)

        let text = try String(contentsOf: ascFile, encoding: .utf8)
        #expect(text.hasPrefix("-----BEGIN PGP MESSAGE-----"))
        #expect(text.contains("-----END PGP MESSAGE-----"))

        let decrypted = try await pgp.cipher.decrypt(
            Data(text.utf8),
            using: pair.privateKey,
            passphrase: Fixture.passphrase
        )
        #expect(decrypted == plaintext)
    }

    @Test
    func keysExportedToAscFilesWorkInAFreshSDKInstance() async throws {
        let workspace = try Workspace()
        defer { workspace.remove() }
        let pair = try await makeKeyPair()
        let publicFile = workspace.file("alice.pub.asc")
        let privateFile = workspace.file("alice.key.asc")
        try await pgp.armorer.armor(pair.publicKey.data, as: .publicKey)
            .write(to: publicFile, atomically: true, encoding: .utf8)
        try await pgp.armorer.armor(pair.privateKey.data, as: .privateKey)
            .write(to: privateFile, atomically: true, encoding: .utf8)

        let freshSDK = PGP.gopenPGP()
        let publicKey = try await freshSDK.keys.importPublicKey(from: Data(contentsOf: publicFile))
        let privateKey = try await freshSDK.keys.importPrivateKey(from: Data(contentsOf: privateFile))
        let encrypted = try await freshSDK.cipher.encrypt(Data("round trip".utf8), to: [publicKey])
        let decrypted = try await freshSDK.cipher.decrypt(
            encrypted,
            using: privateKey,
            passphrase: Fixture.passphrase
        )

        #expect(publicKey.fingerprint == pair.publicKey.fingerprint)
        #expect(privateKey.fingerprint == pair.privateKey.fingerprint)
        #expect(decrypted == Data("round trip".utf8))
    }

    @Test
    func privateKeyFileStaysLockedWithoutThePassphrase() async throws {
        let workspace = try Workspace()
        defer { workspace.remove() }
        let pair = try await makeKeyPair()
        let privateFile = workspace.file("alice.key")
        try pair.privateKey.data.write(to: privateFile)
        let encrypted = try await pgp.cipher.encrypt(Data("x".utf8), to: [pair.publicKey])
        let reloaded = try await pgp.keys.importPrivateKey(from: Data(contentsOf: privateFile))

        await #expect(throws: PGPError.invalidPassphrase) {
            try await pgp.cipher.decrypt(encrypted, using: reloaded, passphrase: PGPPassphrase(""))
        }
    }

    @Test
    func fileEncryptedForSeveralRecipientsOpensForEachButNotForOutsiders() async throws {
        let workspace = try Workspace()
        defer { workspace.remove() }
        let alice = try await makeKeyPair()
        let bob = try await pgp.keys.generateKeyPair(
            for: PGPIdentity(name: "Bob", email: "bob@example.com"),
            algorithm: .curve25519,
            passphrase: PGPPassphrase("bob secret")
        )
        let carol = try await pgp.keys.generateKeyPair(
            for: PGPIdentity(name: "Carol", email: "carol@example.com"),
            algorithm: .curve25519,
            passphrase: PGPPassphrase("carol secret")
        )
        let file = workspace.file("shared.gpg")
        try await pgp.cipher.encrypt(Data("team secret".utf8), to: [alice.publicKey, bob.publicKey])
            .write(to: file)
        let ciphertext = try Data(contentsOf: file)

        #expect(try await pgp.cipher.decrypt(
            ciphertext,
            using: alice.privateKey,
            passphrase: Fixture.passphrase
        )
            == Data("team secret".utf8))
        #expect(try await pgp.cipher.decrypt(
            ciphertext,
            using: bob.privateKey,
            passphrase: PGPPassphrase("bob secret")
        )
            == Data("team secret".utf8))
        await #expect(throws: PGPError.self) {
            try await pgp.cipher.decrypt(
                ciphertext,
                using: carol.privateKey,
                passphrase: PGPPassphrase("carol secret")
            )
        }
    }

    @Test
    func largeBinaryFileSurvivesTheRoundTripByteForByte() async throws {
        let workspace = try Workspace()
        defer { workspace.remove() }
        let pair = try await makeKeyPair()
        let source = workspace.file("blob.bin")
        try Fixture.randomData(count: 1_000_000).write(to: source)

        let encryptedFile = workspace.file("blob.bin.gpg")
        try await pgp.cipher.encrypt(Data(contentsOf: source), to: [pair.publicKey]).write(to: encryptedFile)
        let decrypted = try await pgp.cipher.decrypt(
            Data(contentsOf: encryptedFile),
            using: pair.privateKey,
            passphrase: Fixture.passphrase
        )

        #expect(try decrypted == Data(contentsOf: source))
    }

    @Test
    func emptyFileRoundTrips() async throws {
        let pair = try await makeKeyPair()

        let encrypted = try await pgp.cipher.encrypt(Data(), to: [pair.publicKey])
        let decrypted = try await pgp.cipher.decrypt(
            encrypted,
            using: pair.privateKey,
            passphrase: Fixture.passphrase
        )

        #expect(decrypted.isEmpty)
    }

    @Test
    func corruptedEncryptedFileIsRejected() async throws {
        let pair = try await makeKeyPair()
        var encrypted = try await pgp.cipher.encrypt(Data("payload".utf8), to: [pair.publicKey])
        encrypted[encrypted.count - 3] ^= 0xFF

        await #expect(throws: PGPError.self) {
            try await pgp.cipher.decrypt(encrypted, using: pair.privateKey, passphrase: Fixture.passphrase)
        }
    }

    @Test
    func garbageFileIsRejectedAsInvalidInputOrDecryptionFailure() async throws {
        let pair = try await makeKeyPair()

        await #expect(throws: PGPError.self) {
            try await pgp.cipher.decrypt(
                Fixture.randomData(count: 64),
                using: pair.privateKey,
                passphrase: Fixture.passphrase
            )
        }
    }

    @Test
    func detachedSignatureFileDetectsAnyChangeToTheDocument() async throws {
        let workspace = try Workspace()
        defer { workspace.remove() }
        let pair = try await makeKeyPair()
        let document = workspace.file("contract.txt")
        let signatureFile = workspace.file("contract.txt.sig")
        try Data("pay 100".utf8).write(to: document)
        try await pgp.signer.sign(
            Data(contentsOf: document),
            using: pair.privateKey,
            passphrase: Fixture.passphrase
        )
        .write(to: signatureFile)

        try await pgp.signer.verify(
            Data(contentsOf: document),
            signature: Data(contentsOf: signatureFile),
            with: pair.publicKey
        )

        try Data("pay 900".utf8).write(to: document)
        await #expect(throws: PGPError.signatureInvalid) {
            try await pgp.signer.verify(
                Data(contentsOf: document),
                signature: Data(contentsOf: signatureFile),
                with: pair.publicKey
            )
        }
    }

    @Test
    func armoredSignatureFileVerifies() async throws {
        let workspace = try Workspace()
        defer { workspace.remove() }
        let pair = try await makeKeyPair()
        let data = Data("signed text".utf8)
        let signature = try await pgp.signer.sign(
            data,
            using: pair.privateKey,
            passphrase: Fixture.passphrase
        )
        let armored = try await pgp.armorer.armor(signature, as: .signature)
        let ascFile = workspace.file("data.sig.asc")
        try armored.write(to: ascFile, atomically: true, encoding: .utf8)

        let text = try String(contentsOf: ascFile, encoding: .utf8)

        #expect(text.hasPrefix("-----BEGIN PGP SIGNATURE-----"))
        try await pgp.signer.verify(data, signature: Data(text.utf8), with: pair.publicKey)
    }

    @Test
    func signatureFromAnotherKeyIsRejected() async throws {
        let signer = try await makeKeyPair()
        let stranger = try await pgp.keys.generateKeyPair(
            for: PGPIdentity(name: "Mallory", email: "mallory@example.com"),
            algorithm: .curve25519,
            passphrase: PGPPassphrase("mallory")
        )
        let data = Data("hello".utf8)
        let signature = try await pgp.signer.sign(
            data,
            using: signer.privateKey,
            passphrase: Fixture.passphrase
        )

        await #expect(throws: PGPError.signatureInvalid) {
            try await pgp.signer.verify(data, signature: signature, with: stranger.publicKey)
        }
    }

    @Test
    func dearmoredKeyFileMatchesTheBinaryKey() async throws {
        let pair = try await makeKeyPair()

        let armored = try await pgp.armorer.armor(pair.publicKey.data, as: .publicKey)
        let binary = try await pgp.armorer.dearmor(armored)
        let reimported = try await pgp.keys.importPublicKey(from: binary)

        #expect(armored.hasPrefix("-----BEGIN PGP PUBLIC KEY BLOCK-----"))
        #expect(reimported.fingerprint == pair.publicKey.fingerprint)
    }

    @Test
    func rotatedPassphraseIsPersistedInTheKeyFile() async throws {
        let workspace = try Workspace()
        defer { workspace.remove() }
        let pair = try await makeKeyPair()
        let newPassphrase = PGPPassphrase("rotated")
        let rotated = try await pgp.keys.changePassphrase(
            of: pair.privateKey,
            from: Fixture.passphrase,
            to: newPassphrase
        )
        let keyFile = workspace.file("alice.rotated.key")
        try rotated.data.write(to: keyFile)
        let encrypted = try await pgp.cipher.encrypt(Data("after rotation".utf8), to: [pair.publicKey])

        let reloaded = try await pgp.keys.importPrivateKey(from: Data(contentsOf: keyFile))

        #expect(try await pgp.cipher.decrypt(encrypted, using: reloaded, passphrase: newPassphrase)
            == Data("after rotation".utf8))
        await #expect(throws: PGPError.invalidPassphrase) {
            try await pgp.cipher.decrypt(encrypted, using: reloaded, passphrase: Fixture.passphrase)
        }
    }
}
