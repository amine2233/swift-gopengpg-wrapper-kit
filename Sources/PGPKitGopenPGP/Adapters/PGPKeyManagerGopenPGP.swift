import Foundation
import Gopenpgp
import PGPKit

struct PGPKeyManagerGopenPGP: PGPKeyManager {
    static let minimumRSABits = 3_072

    @concurrent
    func generateKeyPair(
        for identity: PGPIdentity,
        algorithm: PGPKeyAlgorithm,
        passphrase: PGPPassphrase
    ) async throws -> PGPKeyPair {
        let keyType: String
        let bits: Int
        switch algorithm {
        case .curve25519:
            keyType = "x25519"
            bits = 0
        case let .rsa(requestedBits):
            guard requestedBits >= Self.minimumRSABits else {
                throw PGPError.invalidInput
            }

            keyType = "rsa"
            bits = requestedBits
        }

        var error: NSError?
        guard let generated = CryptoGenerateKey(identity.name, identity.email, keyType, bits, &error),
              error == nil else {
            throw PGPError.keyGenerationFailed
        }

        return try GopenPGPSupport.perform {
            let locked = try generated.lock(passphrase.data)
            let publicKey = try generated.toPublic()
            return try PGPKeyPair(
                publicKey: PGPPublicKey(
                    data: publicKey.serialize(),
                    fingerprint: publicKey.getFingerprint()
                ),
                privateKey: PGPPrivateKey(data: locked.serialize(), fingerprint: locked.getFingerprint())
            )
        }
    }

    @concurrent
    func importPublicKey(from data: Data) async throws -> PGPPublicKey {
        let key = try GopenPGPSupport.loadKey(from: data)
        return try GopenPGPSupport.perform {
            let publicKey = key.isPrivate() ? try key.toPublic() : key
            return try PGPPublicKey(data: publicKey.serialize(), fingerprint: publicKey.getFingerprint())
        }
    }

    @concurrent
    func importPrivateKey(from data: Data) async throws -> PGPPrivateKey {
        let key = try GopenPGPSupport.loadKey(from: data)
        guard key.isPrivate() else {
            throw PGPError.invalidKey
        }

        return try GopenPGPSupport.perform {
            try PGPPrivateKey(data: key.serialize(), fingerprint: key.getFingerprint())
        }
    }

    @concurrent
    func publicKey(from privateKey: PGPPrivateKey) async throws -> PGPPublicKey {
        try await importPublicKey(from: privateKey.data)
    }

    @concurrent
    func changePassphrase(
        of privateKey: PGPPrivateKey,
        from current: PGPPassphrase,
        to new: PGPPassphrase
    ) async throws -> PGPPrivateKey {
        let unlocked = try GopenPGPSupport.unlockedKey(from: privateKey, passphrase: current)
        return try GopenPGPSupport.perform {
            let relocked = try unlocked.lock(new.data)
            return try PGPPrivateKey(data: relocked.serialize(), fingerprint: relocked.getFingerprint())
        }
    }
}
