# Testing your app

Replace the engine with closure-based fakes so tests are fast, deterministic and free of real keys.

## Overview

`PGPKitTesting` ships one fake per capability: `PGPKeyManagerFake`, `PGPCipherFake`, `PGPSignerFake` and `PGPArmorerFake`. Each exposes its behavior as a closure. Anything you do not set throws, so a test fails loudly if the code under test calls something unexpected.

Link `PGPKitTesting` from your test target only.

## Unit-test a view model with a fake

Because `NoteVault` takes `any PGPCipher`, the test supplies only the capability it needs.

```swift
import Foundation
import PGPKit
import PGPKitTesting
import Testing
@testable import NotesFeature

struct NoteVaultTests {
    private let publicKey = PGPPublicKey(data: Data("pub".utf8), fingerprint: "AAAA")

    @Test @MainActor
    func sealEncryptsForTheStoredPublicKey() async throws {
        let publicKey = publicKey
        let cipher = PGPCipherFake(onEncrypt: { plaintext, recipients in
            #expect(recipients == [publicKey])
            return Data(plaintext.reversed())
        })
        let vault = NoteVault(
            keys: PGPKeyManagerFake(),
            cipher: cipher,
            keyStore: KeyStoreStub(publicKey: publicKey)
        )

        let sealed = try await vault.seal("abc")

        #expect(sealed == Data("cba".utf8))
    }

    @Test @MainActor
    func openSurfacesAWrongPassphrase() async {
        let cipher = PGPCipherFake(onDecrypt: { _, _, _ in throw PGPError.invalidPassphrase })
        let vault = NoteVault(
            keys: PGPKeyManagerFake(),
            cipher: cipher,
            keyStore: KeyStoreStub(privateKey: PGPPrivateKey(data: Data(), fingerprint: "AAAA"))
        )

        await #expect(throws: PGPError.invalidPassphrase) {
            try await vault.open(Data(), passphrase: PGPPassphrase("nope"))
        }
    }
}
```

## Test failure paths you cannot easily trigger for real

A fake can return any ``PGPError`` on demand, such as ``PGPError/signatureInvalid`` or ``PGPError/decryptionFailed``, so you can test your error UI without crafting corrupt messages.

```swift
let signer = PGPSignerFake(onVerify: { _, _, _ in throw PGPError.signatureInvalid })
```

## Run an end-to-end test with the real engine

For a few high-value tests, build the real SDK and exercise the round trip. Keep these in a separate test target that links `PGPKitGopenPGP`.

```swift
import PGPKit
import PGPKitGopenPGP
import Testing

@Test func encryptThenDecrypt() async throws {
    let pgp = PGP.gopenPGP()
    let passphrase = PGPPassphrase("correct horse")
    let pair = try await pgp.keys.generateKeyPair(
        for: PGPIdentity(name: "Test", email: "test@example.com"),
        algorithm: .curve25519,
        passphrase: passphrase
    )

    let sealed = try await pgp.cipher.encrypt(Data("x".utf8), to: [pair.publicKey])

    #expect(try await pgp.cipher.decrypt(sealed, using: pair.privateKey, passphrase: passphrase) == Data("x".utf8))
}
```

Mix the two: use the real engine for one capability and a fake for another with `PGP.gopenPGP(cipher: PGPCipherFake(...))`.

## Use fakes in SwiftUI previews

```swift
#Preview {
    NotesRoot(
        vault: NoteVault(
            keys: PGPKeyManagerFake(),
            cipher: PGPCipherFake(onEncrypt: { data, _ in data }, onDecrypt: { data, _, _ in data }),
            keyStore: KeyStoreStub()
        )
    )
}
```
