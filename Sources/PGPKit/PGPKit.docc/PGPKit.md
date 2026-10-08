# ``PGPKit``

A protocol-first OpenPGP SDK: depend on small capabilities, inject the engine at the edge of your app.

## Overview

PGPKit defines what your app needs from OpenPGP — keys, encryption, signatures, armoring — as small protocols. It never exposes the engine underneath. The `PGPKitGopenPGP` product provides the default engine, backed by [GopenPGP](https://github.com/ProtonMail/gopenpgp), and `PGPKitTesting` provides fakes.

Your feature code imports only `PGPKit`. Your app target is the one place that imports `PGPKitGopenPGP` and builds the default implementation.

```swift
import PGPKit
import PGPKitGopenPGP

let pgp = PGP.gopenPGP()
let pair = try await pgp.keys.generateKeyPair(
    for: PGPIdentity(name: "Ada", email: "ada@example.com"),
    algorithm: .curve25519,
    passphrase: PGPPassphrase("correct horse")
)
```

## Topics

### Essentials

- <doc:GettingStarted>
- <doc:IntegratingInAnApp>
- <doc:TestingYourApp>
- <doc:SecurityConsiderations>

### Facade

- ``PGP``

### Capabilities

- ``PGPKeyManager``
- ``PGPCipher``
- ``PGPSigner``
- ``PGPArmorer``

### Values

- ``PGPIdentity``
- ``PGPKeyAlgorithm``
- ``PGPKeyPair``
- ``PGPPublicKey``
- ``PGPPrivateKey``
- ``PGPPassphrase``
- ``PGPArmorType``

### Errors

- ``PGPError``
