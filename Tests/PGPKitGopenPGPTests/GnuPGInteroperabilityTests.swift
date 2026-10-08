import Foundation
import PGPKit
import PGPKitGopenPGP
import Testing

@Suite(.serialized, .enabled(if: GPGHome.executable != nil, "gpg is not installed"))
struct GnuPGInteroperabilityTests {
    private let pgp = PGP.gopenPGP()

    private func makeKeyPair() async throws -> PGPKeyPair {
        try await pgp.keys.generateKeyPair(
            for: Fixture.identity,
            algorithm: .curve25519,
            passphrase: Fixture.passphrase
        )
    }

    private func importSecretKey(_ pair: PGPKeyPair, into gpg: GPGHome, workspace: Workspace) async throws {
        let file = workspace.file("secret.asc")
        try await pgp.armorer.armor(pair.privateKey.data, as: .privateKey)
            .write(to: file, atomically: true, encoding: .utf8)
        let result = try gpg.runWithPassphrase(Fixture.passphrase, ["--import", file.path])
        #expect(result.status == 0, "\(result.errorOutput)")
    }

    private func importPublicKey(_ key: PGPPublicKey, into gpg: GPGHome, workspace: Workspace) async throws {
        let file = workspace.file("public.asc")
        try await pgp.armorer.armor(key.data, as: .publicKey)
            .write(to: file, atomically: true, encoding: .utf8)
        let result = try gpg.run(["--import", file.path])
        #expect(result.status == 0, "\(result.errorOutput)")
    }

    @Test
    func gpgDecryptsAFileEncryptedByTheSDK() async throws {
        let workspace = try Workspace()
        let gpg = try GPGHome()
        defer { workspace.remove(); gpg.shutdown() }
        let pair = try await makeKeyPair()
        try await importSecretKey(pair, into: gpg, workspace: workspace)
        let plaintext = Data("decrypted by gpg".utf8)
        let encryptedFile = workspace.file("note.txt.gpg")
        try await pgp.cipher.encrypt(plaintext, to: [pair.publicKey]).write(to: encryptedFile)

        let result = try gpg.runWithPassphrase(Fixture.passphrase, ["--decrypt", encryptedFile.path])

        #expect(result.status == 0, "\(result.errorOutput)")
        #expect(result.output == plaintext)
    }

    @Test
    func gpgReadsTheSDKEncryptedFileAsAPublicKeyEncryptedMessage() async throws {
        let workspace = try Workspace()
        let gpg = try GPGHome()
        defer { workspace.remove(); gpg.shutdown() }
        let pair = try await makeKeyPair()
        let encryptedFile = workspace.file("note.gpg")
        try await pgp.cipher.encrypt(Data("x".utf8), to: [pair.publicKey]).write(to: encryptedFile)

        let result = try gpg.run(["--list-packets", encryptedFile.path])

        #expect(result.text.contains("pubkey enc packet"))
        #expect(result.text.contains("encrypted data packet") || result.text.contains("encrypted data"))
        #expect(result.errorOutput.contains("ECDH"))
    }

    @Test
    func sdkDecryptsAFileEncryptedByGPG() async throws {
        let workspace = try Workspace()
        let gpg = try GPGHome()
        defer { workspace.remove(); gpg.shutdown() }
        let pair = try await makeKeyPair()
        try await importPublicKey(pair.publicKey, into: gpg, workspace: workspace)
        let source = workspace.file("input.txt")
        let encryptedFile = workspace.file("input.txt.gpg")
        try Data("encrypted by gpg".utf8).write(to: source)

        let result = try gpg.run([
            "--trust-model", "always",
            "--recipient", pair.publicKey.fingerprint,
            "--output", encryptedFile.path,
            "--encrypt", source.path,
        ])
        #expect(result.status == 0, "\(result.errorOutput)")

        let decrypted = try await pgp.cipher.decrypt(
            Data(contentsOf: encryptedFile),
            using: pair.privateKey,
            passphrase: Fixture.passphrase
        )
        #expect(decrypted == Data("encrypted by gpg".utf8))
    }

    @Test
    func sdkDecryptsAnArmoredFileEncryptedByGPG() async throws {
        let workspace = try Workspace()
        let gpg = try GPGHome()
        defer { workspace.remove(); gpg.shutdown() }
        let pair = try await makeKeyPair()
        try await importPublicKey(pair.publicKey, into: gpg, workspace: workspace)
        let source = workspace.file("input.txt")
        let armoredFile = workspace.file("input.txt.asc")
        try Data("armored by gpg".utf8).write(to: source)

        let result = try gpg.run([
            "--trust-model", "always",
            "--armor",
            "--recipient", pair.publicKey.fingerprint,
            "--output", armoredFile.path,
            "--encrypt", source.path,
        ])
        #expect(result.status == 0, "\(result.errorOutput)")

        let text = try String(contentsOf: armoredFile, encoding: .utf8)
        let decrypted = try await pgp.cipher.decrypt(
            Data(text.utf8),
            using: pair.privateKey,
            passphrase: Fixture.passphrase
        )
        #expect(text.hasPrefix("-----BEGIN PGP MESSAGE-----"))
        #expect(decrypted == Data("armored by gpg".utf8))
    }

    @Test
    func sdkImportsAKeyGeneratedByGPGAndRoundTripsWithIt() async throws {
        let workspace = try Workspace()
        let gpg = try GPGHome()
        defer { workspace.remove(); gpg.shutdown() }
        let generated = try gpg.runWithPassphrase(Fixture.passphrase, [
            "--quick-generate-key", "GPG User <gpg.user@example.com>", "default", "default", "never",
        ])
        #expect(generated.status == 0, "\(generated.errorOutput)")
        let publicExport = try gpg.run(["--armor", "--export", "gpg.user@example.com"])
        let secretExport = try gpg.runWithPassphrase(
            Fixture.passphrase,
            ["--armor", "--export-secret-keys", "gpg.user@example.com"]
        )
        #expect(publicExport.status == 0 && secretExport.status == 0, "\(secretExport.errorOutput)")

        let publicKey = try await pgp.keys.importPublicKey(from: publicExport.output)
        let privateKey = try await pgp.keys.importPrivateKey(from: secretExport.output)
        let encrypted = try await pgp.cipher.encrypt(Data("to a gpg key".utf8), to: [publicKey])
        let encryptedFile = workspace.file("to-gpg.gpg")
        try encrypted.write(to: encryptedFile)

        let byGPG = try gpg.runWithPassphrase(Fixture.passphrase, ["--decrypt", encryptedFile.path])
        let bySDK = try await pgp.cipher.decrypt(encrypted, using: privateKey, passphrase: Fixture.passphrase)

        #expect(byGPG.output == Data("to a gpg key".utf8), "\(byGPG.errorOutput)")
        #expect(bySDK == Data("to a gpg key".utf8))
        #expect(publicKey.fingerprint.lowercased() == privateKey.fingerprint.lowercased())
    }

    @Test
    func gpgVerifiesADetachedSignatureCreatedByTheSDK() async throws {
        let workspace = try Workspace()
        let gpg = try GPGHome()
        defer { workspace.remove(); gpg.shutdown() }
        let pair = try await makeKeyPair()
        try await importPublicKey(pair.publicKey, into: gpg, workspace: workspace)
        let document = workspace.file("doc.txt")
        let signatureFile = workspace.file("doc.txt.sig")
        try Data("signed by the sdk".utf8).write(to: document)
        try await pgp.signer.sign(Data(contentsOf: document), using: pair.privateKey, passphrase: Fixture.passphrase)
            .write(to: signatureFile)

        let valid = try gpg.run(["--verify", signatureFile.path, document.path])
        try Data("tampered".utf8).write(to: document)
        let tampered = try gpg.run(["--verify", signatureFile.path, document.path])

        #expect(valid.status == 0, "\(valid.errorOutput)")
        #expect(tampered.status != 0)
    }

    @Test
    func sdkVerifiesADetachedSignatureCreatedByGPG() async throws {
        let workspace = try Workspace()
        let gpg = try GPGHome()
        defer { workspace.remove(); gpg.shutdown() }
        let pair = try await makeKeyPair()
        try await importSecretKey(pair, into: gpg, workspace: workspace)
        let document = workspace.file("doc.txt")
        let signatureFile = workspace.file("doc.txt.sig")
        try Data("signed by gpg".utf8).write(to: document)

        let result = try gpg.runWithPassphrase(Fixture.passphrase, [
            "--detach-sign", "--output", signatureFile.path, document.path,
        ])
        #expect(result.status == 0, "\(result.errorOutput)")

        try await pgp.signer.verify(
            Data(contentsOf: document),
            signature: Data(contentsOf: signatureFile),
            with: pair.publicKey
        )
        try Data("tampered".utf8).write(to: document)
        await #expect(throws: PGPError.signatureInvalid) {
            try await pgp.signer.verify(
                Data(contentsOf: document),
                signature: Data(contentsOf: signatureFile),
                with: pair.publicKey
            )
        }
    }
}
