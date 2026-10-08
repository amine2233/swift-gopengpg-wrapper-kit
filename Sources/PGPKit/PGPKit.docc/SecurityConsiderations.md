# Security considerations

What PGPKit protects, what it cannot, and what your app is still responsible for.

## Secrets in memory

Passphrases and keys cross into the Go runtime as copies. Go owns those copies, and Swift cannot wipe them. PGPKit keeps secrets as `Data` rather than `String` where it can and redacts ``PGPPassphrase`` and ``PGPPrivateKey`` in `print`, string interpolation and the debugger, but it cannot guarantee zeroing. Treat a process memory dump as exposing anything you decrypted or unlocked.

## Never log secrets

``PGPPassphrase/description`` and ``PGPPrivateKey/description`` are safe to log. The raw `data` properties and decrypted plaintext are not. Do not log them.

## Passphrases

- Do not persist the passphrase. Ask for it at the point of use, or gate it with biometrics.
- Clear any text field that held it once the call returns.
- A wrong passphrase surfaces as ``PGPError/invalidPassphrase`` and nothing else, so you can distinguish it from a corrupt key or message.

## Private key storage

The private key is stored locked by its passphrase. Still, keep it in the Keychain with `kSecAttrAccessibleWhenUnlockedThisDeviceOnly` (or stricter) instead of files or `UserDefaults`, so it is not synced or backed up unintentionally.

## Key sizes

RSA keys below 3072 bits are rejected with ``PGPError/invalidInput``. Prefer ``PGPKeyAlgorithm/curve25519`` unless you need RSA for interoperability.

## Verify before you trust

``PGPSigner/verify(_:signature:with:)`` proves the data matches a signature made by the matching private key. It does not prove the public key belongs to the person you think. Compare fingerprints out of band before trusting a key you imported.
