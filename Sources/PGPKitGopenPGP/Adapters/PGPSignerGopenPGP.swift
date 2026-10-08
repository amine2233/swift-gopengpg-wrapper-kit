import Foundation
import Gopenpgp
import PGPKit

struct PGPSignerGopenPGP: PGPSigner {
    @concurrent
    func sign(
        _ data: Data,
        using privateKey: PGPPrivateKey,
        passphrase: PGPPassphrase
    ) async throws -> Data {
        let unlocked = try GopenPGPSupport.unlockedKey(from: privateKey, passphrase: passphrase)
        let keyRing = try GopenPGPSupport.keyRing(from: [unlocked])
        let message = try GopenPGPSupport.plainMessage(from: data)
        return try GopenPGPSupport.perform {
            guard let binary = try keyRing.signDetached(message).getBinary() else {
                throw PGPError.invalidInput
            }

            return binary
        }
    }

    @concurrent
    func verify(_ data: Data, signature: Data, with publicKey: PGPPublicKey) async throws {
        let keyRing = try GopenPGPSupport.keyRing(from: [GopenPGPSupport.loadKey(from: publicKey.data)])
        let message = try GopenPGPSupport.plainMessage(from: data)
        let pgpSignature = try GopenPGPSupport.signature(from: signature)
        do {
            try keyRing.verifyDetached(message, signature: pgpSignature, verifyTime: 0)
        } catch {
            throw PGPError.signatureInvalid
        }
    }
}
