import Foundation
import Gopenpgp
import PGPKit

enum GopenPGPSupport {
    static func perform<Value>(_ body: () throws -> Value) throws -> Value {
        do {
            return try body()
        } catch {
            throw map(error)
        }
    }

    static func map(_ error: any Error) -> PGPError {
        if let pgpError = error as? PGPError {
            return pgpError
        }
        let nsError = error as NSError
        let message = nsError.localizedDescription
        if message.contains("checksum failure") {
            return .invalidPassphrase
        }
        if message.contains("incorrect key") {
            return .decryptionFailed
        }
        return .engine(code: nsError.code)
    }

    static func isArmored(_ data: Data) -> Bool {
        data.starts(with: Data("-----BEGIN PGP".utf8))
    }

    static func loadKey(from data: Data) throws -> CryptoKey {
        var error: NSError?
        let key: CryptoKey? = if isArmored(data) {
            CryptoNewKeyFromArmored(String(decoding: data, as: UTF8.self), &error)
        } else {
            CryptoNewKey(data, &error)
        }
        guard let key, error == nil else {
            throw PGPError.invalidKey
        }

        return key
    }

    static func unlockedKey(from privateKey: PGPPrivateKey, passphrase: PGPPassphrase) throws -> CryptoKey {
        let key = try loadKey(from: privateKey.data)
        guard key.isPrivate() else {
            throw PGPError.invalidKey
        }

        var isLocked: ObjCBool = false
        try perform { try key.isLocked(&isLocked) }
        guard isLocked.boolValue else {
            return key
        }

        return try perform { try key.unlock(passphrase.data) }
    }

    static func keyRing(from keys: [CryptoKey]) throws -> CryptoKeyRing {
        guard let first = keys.first else {
            throw PGPError.invalidInput
        }

        var error: NSError?
        guard let keyRing = CryptoNewKeyRing(first, &error), error == nil else {
            throw PGPError.invalidKey
        }

        for key in keys.dropFirst() {
            try perform { try keyRing.add(key) }
        }
        return keyRing
    }

    static func message(from data: Data) throws -> CryptoPGPMessage {
        var error: NSError?
        let message: CryptoPGPMessage? = if isArmored(data) {
            CryptoNewPGPMessageFromArmored(String(decoding: data, as: UTF8.self), &error)
        } else {
            CryptoNewPGPMessage(data)
        }
        guard let message, error == nil else {
            throw PGPError.invalidInput
        }

        return message
    }

    static func signature(from data: Data) throws -> CryptoPGPSignature {
        var error: NSError?
        let signature: CryptoPGPSignature? = if isArmored(data) {
            CryptoNewPGPSignatureFromArmored(String(decoding: data, as: UTF8.self), &error)
        } else {
            CryptoNewPGPSignature(data)
        }
        guard let signature, error == nil else {
            throw PGPError.invalidInput
        }

        return signature
    }

    static func plainMessage(from data: Data) throws -> CryptoPlainMessage {
        guard let message = CryptoNewPlainMessage(data) else {
            throw PGPError.invalidInput
        }

        return message
    }
}
