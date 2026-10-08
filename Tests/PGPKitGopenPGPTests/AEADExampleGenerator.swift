import Foundation
import PGPKit
import Testing

@Suite(
    .serialized,
    .enabled(
        if: ExampleResources.isGenerationEnabled && GPGHome.executable != nil,
        "set PGPKIT_GENERATE_EXAMPLES=1"
    )
)
struct AEADExampleGenerator {
    @Test
    func generateGnuPGOCBPasswordStoreEntry() throws {
        let gpg = try GPGHome()
        defer { gpg.shutdown() }
        let email = "pass-store@example.com"
        let directory = ExampleResources.sourceDirectory
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)

        let generated = try gpg.runWithPassphrase(Fixture.passphrase, [
            "--quick-generate-key", "Pass Store <\(email)>", "rsa4096", "default", "never"
        ])
        #expect(generated.status == 0, "\(generated.errorOutput)")
        let primary = try #require(
            try gpg.run(["--with-colons", "--fingerprint", email]).text
                .split(separator: "\n")
                .first { $0.hasPrefix("fpr:") }
                .flatMap { $0.split(separator: ":").last.map(String.init) }
        )
        let subkey = try gpg.runWithPassphrase(Fixture.passphrase, [
            "--quick-add-key", primary, "rsa4096", "encr", "never"
        ])
        #expect(subkey.status == 0, "\(subkey.errorOutput)")

        let preferences = try gpg.run(["--list-options", "show-pref-verbose", "--list-keys", email])
        #expect(preferences.text.contains("AEAD: OCB"), "the generated key must advertise AEAD: OCB")

        let plain = directory.appendingPathComponent("pass-entry.txt")
        let encrypted = directory.appendingPathComponent("pass-entry.ocb.gpg")
        try Data("hunter2-sample-password\nusername: amine\n".utf8).write(to: plain)
        let encrypt = try gpg.run([
            "--force-ocb", "--trust-model", "always", "--recipient", email, "--output", encrypted.path,
            "--encrypt",
            plain.path
        ])
        #expect(encrypt.status == 0, "\(encrypt.errorOutput)")

        let packets = try gpg.run(["--list-packets", encrypted.path])
        let listing = packets.text + packets.errorOutput
        #expect(listing.contains("tag=20") || listing.contains("aead encrypted packet"))

        try gpg.run(["--armor", "--export", email]).output
            .write(to: directory.appendingPathComponent("pass-store.public.asc"))
        try gpg.runWithPassphrase(Fixture.passphrase, ["--armor", "--export-secret-keys", email]).output
            .write(to: directory.appendingPathComponent("pass-store.private.asc"))
    }
}
