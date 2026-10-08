import Foundation
import PGPKit
import PGPKitTesting
import Testing

struct PGPFacadeTests {
    private let publicKey = PGPPublicKey(data: Data("pub".utf8), fingerprint: "AAAA")
    private let privateKey = PGPPrivateKey(data: Data("prv".utf8), fingerprint: "AAAA")

    @Test
    func facadeRoutesEachCapabilityToItsInjectedFake() async throws {
        let publicKey = publicKey
        let privateKey = privateKey
        let pgp = PGP(
            keys: PGPKeyManagerFake(onImportPublicKey: { _ in publicKey }),
            cipher: PGPCipherFake(onEncrypt: { plaintext, _ in
                plaintext.reversed().reduce(into: Data()) { $0.append($1) }
            }),
            signer: PGPSignerFake(onSign: { _, _, _ in Data("sig".utf8) }),
            armorer: PGPArmorerFake(onArmor: { _, _ in "armored" })
        )

        #expect(try await pgp.keys.importPublicKey(from: Data()) == publicKey)
        #expect(try await pgp.cipher.encrypt(Data("abc".utf8), to: [publicKey]) == Data("cba".utf8))
        #expect(try await pgp.signer
            .sign(Data(), using: privateKey, passphrase: PGPPassphrase("x")) == Data("sig".utf8))
        #expect(try await pgp.armorer.armor(Data(), as: .message) == "armored")
    }

    @Test
    func consumerDependingOnSingleProtocolOnlyNeedsThatFake() async throws {
        let publicKey = publicKey
        let cipher: any PGPCipher = PGPCipherFake(onEncrypt: { plaintext, recipients in
            #expect(recipients == [publicKey])
            return plaintext
        })

        #expect(try await cipher.encrypt(Data("hi".utf8), to: [publicKey]) == Data("hi".utf8))
    }

    @Test
    func fakeErrorsPropagateAsPGPError() async {
        let signer: any PGPSigner = PGPSignerFake()

        await #expect(throws: PGPError.signatureInvalid) {
            try await signer.verify(
                Data(),
                signature: Data(),
                with: PGPPublicKey(data: Data(), fingerprint: "")
            )
        }
    }

    @Test
    func secretsAreRedactedInDescriptions() {
        #expect(!"\(PGPPassphrase("hunter2"))".contains("hunter2"))
        #expect(!"\(privateKey)".contains("prv"))
    }
}
