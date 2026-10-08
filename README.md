# swift-gopengpg-wrapper-kit

Protocol-first Swift SDK over [GopenPGP](https://github.com/ProtonMail/gopenpgp), consumed through the `spm-gopengpg` binary package. Apps depend on `PGPKit` protocols; only the composition root imports `PGPKitGopenPGP`.

| Product | Role |
|---|---|
| `PGPKit` | Protocols, value types, `PGPError`. No dependencies. |
| `PGPKitGopenPGP` | GopenPGP-backed adapters and `PGP.gopenPGP()`. |
| `PGPKitTesting` | Closure-based fakes for each protocol. |

## Quick start

```swift
import PGPKit
import PGPKitGopenPGP

let pgp = PGP.gopenPGP()
let passphrase = PGPPassphrase("correct horse")
let pair = try await pgp.keys.generateKeyPair(
    for: PGPIdentity(name: "Ada", email: "ada@example.com"), algorithm: .curve25519, passphrase: passphrase)
let ciphertext = try await pgp.cipher.encrypt(Data("hello".utf8), to: [pair.publicKey])
let plaintext = try await pgp.cipher.decrypt(ciphertext, using: pair.privateKey, passphrase: passphrase)
let signature = try await pgp.signer.sign(plaintext, using: pair.privateKey, passphrase: passphrase)
try await pgp.signer.verify(plaintext, signature: signature, with: pair.publicKey)
```

Override a single capability: `PGP.gopenPGP(cipher: myCipher)`.
Depend on one capability only: `func seal(using cipher: any PGPCipher)`.

## Limits

- Secrets are `Data` copied across the gomobile bridge; Go-side memory cannot be wiped from Swift.
- RSA keys below 3072 bits are rejected.
