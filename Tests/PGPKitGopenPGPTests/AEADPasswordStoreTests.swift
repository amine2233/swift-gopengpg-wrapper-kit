import Foundation
import PGPKit
import PGPKitGopenPGP
import Testing

struct AEADPasswordStoreTests {
    private let pgp = PGP.gopenPGP()

    @Test
    func fixtureIsAnOCBAEADPacketNotAClassicCFBPacket() throws {
        let tags = try OpenPGPPackets.tags(in: ExampleResources.bundled("pass-entry.ocb.gpg"))

        #expect(tags.contains(OpenPGPPackets.aeadEncryptedData))
        #expect(!tags.contains(OpenPGPPackets.symmetricallyEncryptedIntegrityProtected))
        #expect(tags.first == OpenPGPPackets.publicKeyEncryptedSessionKey)
    }

    @Test
    func sdkDecryptsAGnuPGOCBEntryEncryptedToAnRSA4096Key() async throws {
        let privateKey = try await pgp.keys
            .importPrivateKey(from: ExampleResources.bundled("pass-store.private.asc"))

        let decrypted = try await pgp.cipher.decrypt(
            ExampleResources.bundled("pass-entry.ocb.gpg"),
            using: privateKey,
            passphrase: Fixture.passphrase
        )

        #expect(try decrypted == (ExampleResources.bundled("pass-entry.txt")))
    }

    @Test
    func wrongPassphraseOnAnOCBEntryIsReportedAsInvalidPassphrase() async throws {
        let privateKey = try await pgp.keys
            .importPrivateKey(from: ExampleResources.bundled("pass-store.private.asc"))

        await #expect(throws: PGPError.invalidPassphrase) {
            try await pgp.cipher.decrypt(
                ExampleResources.bundled("pass-entry.ocb.gpg"),
                using: privateKey,
                passphrase: PGPPassphrase("wrong")
            )
        }
    }

    @Test
    func sdkKeepsReadingTheEntryAfterTheKeyFileIsReimported() async throws {
        let publicKey = try await pgp.keys
            .importPublicKey(from: ExampleResources.bundled("pass-store.public.asc"))
        let privateKey = try await pgp.keys
            .importPrivateKey(from: ExampleResources.bundled("pass-store.private.asc"))

        #expect(publicKey.fingerprint == privateKey.fingerprint)
    }
}

enum OpenPGPPackets {
    static let publicKeyEncryptedSessionKey = 1
    static let symmetricallyEncryptedIntegrityProtected = 18
    static let aeadEncryptedData = 20

    static func tags(in data: Data) -> [Int] {
        let bytes = [UInt8](data)
        var tags: [Int] = []
        var index = 0
        while index < bytes.count {
            let header = bytes[index]
            guard header & 0x80 != 0 else {
                return tags
            }

            index += 1
            if header & 0x40 != 0 {
                tags.append(Int(header & 0x3F))
                guard index < bytes.count else {
                    return tags
                }

                let first = Int(bytes[index])
                switch first {
                case ..<192:
                    index += 1 + first
                case 192 ..< 224:
                    guard index + 1 < bytes.count else {
                        return tags
                    }

                    index += 2 + ((first - 192) << 8) + Int(bytes[index + 1]) + 192
                case 255:
                    guard index + 4 < bytes.count else {
                        return tags
                    }

                    let length = bytes[(index + 1) ... (index + 4)].reduce(0) { ($0 << 8) | Int($1) }
                    index += 5 + length
                default:
                    return tags
                }
            } else {
                tags.append(Int((header >> 2) & 0x0F))
                let lengthSize = [1, 2, 4, 0][Int(header & 0x03)]
                guard lengthSize > 0, index + lengthSize <= bytes.count else {
                    return tags
                }

                let length = bytes[index ..< index + lengthSize].reduce(0) { ($0 << 8) | Int($1) }
                index += lengthSize + length
            }
        }
        return tags
    }
}
