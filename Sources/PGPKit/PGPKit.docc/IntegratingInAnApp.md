# Integrating in a real app

Wire PGPKit into a SwiftUI app: one composition root, feature code that depends on protocols, and keys kept in the Keychain.

## Overview

This walkthrough builds a small encrypted notes app. The shape is the one to copy:

```
NotesApp (app target)   imports PGPKit + PGPKitGopenPGP   builds PGP.gopenPGP()
   └── NotesFeature     imports PGPKit only               takes any PGPCipher / any PGPKeyManager
```

Because `NotesFeature` only knows protocols, it compiles without the engine, previews with fakes, and can switch engines without changes.

## Build the SDK once, at the composition root

The app target is the only place that names a concrete engine.

```swift
import SwiftUI
import PGPKit
import PGPKitGopenPGP
import NotesFeature

@main
struct NotesApp: App {
    private let pgp = PGP.gopenPGP()

    var body: some Scene {
        WindowGroup {
            NotesRoot(
                vault: NoteVault(
                    keys: pgp.keys,
                    cipher: pgp.cipher,
                    keyStore: KeyStoreKeychain()
                )
            )
        }
    }
}
```

## Depend on capabilities, not on the facade

A type that only encrypts takes `any PGPCipher`. A type that manages keys takes `any PGPKeyManager`. This keeps each dependency small and each test cheap.

```swift
import Foundation
import Observation
import PGPKit

public protocol KeyStore: Sendable {
    func loadPublicKey() throws -> PGPPublicKey?
    func loadPrivateKey() throws -> PGPPrivateKey?
    func save(_ pair: PGPKeyPair) throws
}

@MainActor @Observable
public final class NoteVault {
    public private(set) var isReady = false
    public private(set) var errorMessage: String?

    private let keys: any PGPKeyManager
    private let cipher: any PGPCipher
    private let keyStore: any KeyStore

    public init(keys: any PGPKeyManager, cipher: any PGPCipher, keyStore: any KeyStore) {
        self.keys = keys
        self.cipher = cipher
        self.keyStore = keyStore
        self.isReady = (try? keyStore.loadPublicKey()) != nil
    }

    public func onboard(name: String, email: String, passphrase: PGPPassphrase) async {
        do {
            let pair = try await keys.generateKeyPair(
                for: PGPIdentity(name: name, email: email),
                algorithm: .curve25519,
                passphrase: passphrase
            )
            try keyStore.save(pair)
            isReady = true
        } catch {
            errorMessage = "Could not create your key."
        }
    }

    public func seal(_ note: String) async throws -> Data {
        guard let publicKey = try keyStore.loadPublicKey() else { throw PGPError.invalidKey }
        return try await cipher.encrypt(Data(note.utf8), to: [publicKey])
    }

    public func open(_ sealed: Data, passphrase: PGPPassphrase) async throws -> String {
        guard let privateKey = try keyStore.loadPrivateKey() else { throw PGPError.invalidKey }
        let plaintext = try await cipher.decrypt(sealed, using: privateKey, passphrase: passphrase)
        return String(decoding: plaintext, as: UTF8.self)
    }
}
```

The crypto calls run off the main actor, so awaiting them from a `@MainActor` view model does not block the UI.

## Persist keys in the Keychain

The key store is app code, not SDK code. The private key stays locked by the passphrase, so the stored bytes are useless without it.

```swift
import Foundation
import PGPKit
import Security

struct KeyStoreKeychain: KeyStore {
    private enum Account: String {
        case publicKey = "pgp.public"
        case privateKey = "pgp.private"
    }

    func loadPublicKey() throws -> PGPPublicKey? {
        try read(.publicKey).map { PGPPublicKey(data: $0, fingerprint: "") }
    }

    func loadPrivateKey() throws -> PGPPrivateKey? {
        try read(.privateKey).map { PGPPrivateKey(data: $0, fingerprint: "") }
    }

    func save(_ pair: PGPKeyPair) throws {
        try write(pair.publicKey.data, as: .publicKey)
        try write(pair.privateKey.data, as: .privateKey)
    }

    private func write(_ data: Data, as account: Account) throws {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrAccount as String: account.rawValue,
        ]
        SecItemDelete(query as CFDictionary)
        let attributes = query.merging([
            kSecValueData as String: data,
            kSecAttrAccessible as String: kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
        ]) { _, new in new }
        guard SecItemAdd(attributes as CFDictionary, nil) == errSecSuccess else {
            throw PGPError.invalidKey
        }
    }

    private func read(_ account: Account) throws -> Data? {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrAccount as String: account.rawValue,
            kSecReturnData as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne,
        ]
        var result: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        guard status != errSecItemNotFound else { return nil }
        guard status == errSecSuccess else { throw PGPError.invalidKey }
        return result as? Data
    }
}
```

> Tip: store the fingerprint next to the key if you need it before importing. Call ``PGPKeyManager/importPublicKey(from:)`` to recover it from the key bytes.

## Ask for the passphrase when you need it

Never store the passphrase. Ask for it at the moment of use, or protect it with biometrics, and drop it as soon as the call returns.

```swift
struct NoteDetail: View {
    let vault: NoteVault
    let sealed: Data
    @State private var passphrase = ""
    @State private var text: String?
    @State private var failed = false

    var body: some View {
        VStack {
            if let text {
                Text(text)
            } else {
                SecureField("Passphrase", text: $passphrase)
                Button("Unlock") {
                    Task { await unlock() }
                }
                if failed { Text("Wrong passphrase").foregroundStyle(.red) }
            }
        }
    }

    private func unlock() async {
        do {
            text = try await vault.open(sealed, passphrase: PGPPassphrase(passphrase))
        } catch PGPError.invalidPassphrase {
            failed = true
        } catch {
            failed = true
        }
        passphrase = ""
    }
}
```

## Exchange keys with other people

Export your public key as armored text, and import theirs the same way. Encrypt to several recipients at once by passing several keys.

```swift
let shareable = try await pgp.armorer.armor(myPublicKey.data, as: .publicKey)

let theirKey = try await pgp.keys.importPublicKey(from: Data(pastedText.utf8))
let message = try await pgp.cipher.encrypt(payload, to: [myPublicKey, theirKey])
```

To prove who wrote something, sign it and send the detached signature next to the data. The receiver calls ``PGPSigner/verify(_:signature:with:)``, which throws ``PGPError/signatureInvalid`` on any mismatch.
