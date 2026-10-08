import Foundation
import Gopenpgp
import PGPKit

struct PGPArmorerGopenPGP: PGPArmorer {
    @concurrent
    func armor(_ data: Data, as type: PGPArmorType) async throws -> String {
        var error: NSError?
        let armored: String
        switch type {
        case .message:
            guard let message = CryptoNewPGPMessage(data) else {
                throw PGPError.invalidInput
            }

            armored = message.getArmored(&error)
        case .signature:
            guard let signature = CryptoNewPGPSignature(data) else {
                throw PGPError.invalidInput
            }

            armored = signature.getArmored(&error)
        case .publicKey:
            armored = try GopenPGPSupport.loadKey(from: data).getArmoredPublicKey(&error)
        case .privateKey:
            let key = try GopenPGPSupport.loadKey(from: data)
            guard key.isPrivate() else {
                throw PGPError.invalidKey
            }

            armored = key.armor(&error)
        }
        guard error == nil else {
            throw GopenPGPSupport.map(error!) // non-nil checked on the previous line
        }

        return armored
    }

    @concurrent
    func dearmor(_ armored: String) async throws -> Data {
        var error: NSError?
        let binary: Data?
        if armored.contains("-----BEGIN PGP MESSAGE-----") {
            binary = CryptoNewPGPMessageFromArmored(armored, &error)?.getBinary()
        } else if armored.contains("-----BEGIN PGP SIGNATURE-----") {
            binary = CryptoNewPGPSignatureFromArmored(armored, &error)?.getBinary()
        } else if armored.contains("-----BEGIN PGP PUBLIC KEY BLOCK-----")
            || armored.contains("-----BEGIN PGP PRIVATE KEY BLOCK-----") {
            binary = try CryptoNewKeyFromArmored(armored, &error)?.serialize()
        } else {
            throw PGPError.invalidInput
        }
        guard let binary, error == nil else {
            throw PGPError.invalidInput
        }

        return binary
    }
}
