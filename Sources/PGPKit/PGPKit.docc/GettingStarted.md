# Getting started

Add the package, build the default SDK, and run a full encrypt, decrypt, sign and verify round trip.

## Add the package

```swift
dependencies: [
    .package(url: "https://github.com/amine2233/swift-gopengpg-wrapper-kit", from: "1.0.0")
],
targets: [
    .target(name: "Notes", dependencies: [.product(name: "PGPKit", package: "swift-gopengpg-wrapper-kit")]),
    .executableTarget(name: "NotesApp", dependencies: [
        "Notes",
        .product(name: "PGPKitGopenPGP", package: "swift-gopengpg-wrapper-kit"),
    ]),
    .testTarget(name: "NotesTests", dependencies: [
        "Notes",
        .product(name: "PGPKitTesting", package: "swift-gopengpg-wrapper-kit"),
    ]),
]
```

Only the app target links `PGPKitGopenPGP`. Feature targets and tests never see the engine.

## Round trip

```swift
import PGPKit
import PGPKitGopenPGP

let pgp = PGP.gopenPGP()
let passphrase = PGPPassphrase("correct horse")

let pair = try await pgp.keys.generateKeyPair(
    for: PGPIdentity(name: "Ada", email: "ada@example.com"),
    algorithm: .curve25519,
    passphrase: passphrase
)

let ciphertext = try await pgp.cipher.encrypt(Data("hello".utf8), to: [pair.publicKey])
let plaintext = try await pgp.cipher.decrypt(ciphertext, using: pair.privateKey, passphrase: passphrase)

let signature = try await pgp.signer.sign(plaintext, using: pair.privateKey, passphrase: passphrase)
try await pgp.signer.verify(plaintext, signature: signature, with: pair.publicKey)
```

## Share keys and messages as text

Use ``PGPArmorer`` to turn binary data into the `-----BEGIN PGP ...-----` form for export, email or QR codes.

```swift
let armoredPublicKey = try await pgp.armorer.armor(pair.publicKey.data, as: .publicKey)
let imported = try await pgp.keys.importPublicKey(from: Data(armoredPublicKey.utf8))
```

``PGPKeyManager`` and ``PGPCipher`` accept both binary and armored input, so an armored message can go straight to `decrypt`.

## Handle errors

Every capability throws ``PGPError``, and nothing else.

```swift
do {
    _ = try await pgp.cipher.decrypt(ciphertext, using: pair.privateKey, passphrase: typed)
} catch PGPError.invalidPassphrase {
    // ask the person to try again
} catch PGPError.decryptionFailed {
    // this key cannot open this message
}
```

## Replace one capability

Every argument of `PGP.gopenPGP` is optional and replaces just that capability.

```swift
let pgp = PGP.gopenPGP(cipher: MyHardwareBackedCipher())
```
