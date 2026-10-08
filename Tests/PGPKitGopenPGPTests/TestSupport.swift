import Foundation
import PGPKit
import Testing

struct Workspace {
    let url: URL

    init(base: URL = FileManager.default.temporaryDirectory) throws {
        url = base.appendingPathComponent("pgpkit-\(UUID().uuidString.prefix(8))")
        try FileManager.default.createDirectory(
            at: url,
            withIntermediateDirectories: true,
            attributes: [.posixPermissions: 0o700]
        )
    }

    func file(_ name: String) -> URL {
        url.appendingPathComponent(name)
    }

    func remove() {
        try? FileManager.default.removeItem(at: url)
    }
}

enum Fixture {
    static let passphrase = PGPPassphrase("correct horse")
    static let identity = PGPIdentity(name: "Alice Example", email: "alice@example.com")

    static func randomData(count: Int) -> Data {
        var generator = SystemRandomNumberGenerator()
        return Data((0 ..< count).map { _ in UInt8.random(in: .min ... .max, using: &generator) })
    }
}

struct GPGResult {
    let status: Int32
    let output: Data
    let errorOutput: String

    var text: String {
        String(decoding: output, as: UTF8.self)
    }
}

struct GPGHome {
    static let executable: URL? = [
        "/opt/homebrew/bin/gpg",
        "/usr/local/bin/gpg",
        "/usr/local/MacGPG2/bin/gpg",
    ]
    .map { URL(fileURLWithPath: $0) }
    .first { FileManager.default.isExecutableFile(atPath: $0.path) }

    let url: URL

    init() throws {
        url = try Workspace(base: URL(fileURLWithPath: "/tmp")).url
    }

    @discardableResult
    func run(_ arguments: [String]) throws -> GPGResult {
        let process = Process()
        process.executableURL = try #require(Self.executable)
        process.arguments = ["--homedir", url.path, "--batch", "--yes", "--no-tty"] + arguments
        let output = Pipe()
        let errorOutput = Pipe()
        process.standardOutput = output
        process.standardError = errorOutput
        try process.run()
        let outputData = output.fileHandleForReading.readDataToEndOfFile()
        let errorData = errorOutput.fileHandleForReading.readDataToEndOfFile()
        process.waitUntilExit()
        return GPGResult(
            status: process.terminationStatus,
            output: outputData,
            errorOutput: String(decoding: errorData, as: UTF8.self)
        )
    }

    func runWithPassphrase(_ passphrase: PGPPassphrase, _ arguments: [String]) throws -> GPGResult {
        try run(["--pinentry-mode", "loopback", "--passphrase", String(decoding: passphrase.data, as: UTF8.self)] + arguments)
    }

    func shutdown() {
        let process = Process()
        if let gpgconf = GPGHome.executable?.deletingLastPathComponent().appendingPathComponent("gpgconf"),
           FileManager.default.isExecutableFile(atPath: gpgconf.path) {
            process.executableURL = gpgconf
            process.arguments = ["--homedir", url.path, "--kill", "all"]
            try? process.run()
            process.waitUntilExit()
        }
        try? FileManager.default.removeItem(at: url)
    }
}
