import Foundation
import Gopenpgp
import PGPKit

struct PGPCipherGopenPGP: PGPCipher {
    @concurrent
    func encrypt(_ plaintext: Data, to recipients: [PGPPublicKey]) async throws -> Data {
        let keyRing = try GopenPGPSupport.keyRing(
            from: recipients.map { try GopenPGPSupport.loadKey(from: $0.data) }
        )
        let message = try GopenPGPSupport.plainMessage(from: plaintext)
        return try GopenPGPSupport.perform {
            guard let binary = try keyRing.encrypt(message, privateKey: nil).getBinary() else {
                throw PGPError.invalidInput
            }

            return binary
        }
    }

    @concurrent
    func decrypt(
        _ ciphertext: Data,
        using privateKey: PGPPrivateKey,
        passphrase: PGPPassphrase
    ) async throws -> Data {
        let unlocked = try GopenPGPSupport.unlockedKey(from: privateKey, passphrase: passphrase)
        let keyRing = try GopenPGPSupport.keyRing(from: [unlocked])
        let message = try GopenPGPSupport.message(from: ciphertext)
        return try GopenPGPSupport.perform {
            try keyRing.decrypt(message, verifyKey: nil, verifyTime: 0).getBinary() ?? Data()
        }
    }
}
