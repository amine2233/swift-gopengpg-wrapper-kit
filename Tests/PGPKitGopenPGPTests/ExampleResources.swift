import Foundation
import Testing

enum ExampleResources {
    static let generationFlag = "PGPKIT_GENERATE_EXAMPLES"

    static var isGenerationEnabled: Bool {
        ProcessInfo.processInfo.environment[generationFlag] == "1"
    }

    static var sourceDirectory: URL {
        URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent()
            .appendingPathComponent("Resources", isDirectory: true)
    }

    static func bundled(_ name: String) throws -> Data {
        let resourceURL = try #require(Bundle.module.resourceURL)
        let candidates = [
            resourceURL.appendingPathComponent("Resources/\(name)"),
            resourceURL.appendingPathComponent(name)
        ]
        let url = try #require(candidates.first { FileManager.default.fileExists(atPath: $0.path) })
        return try Data(contentsOf: url)
    }

    static func bundledText(_ name: String) throws -> String {
        try String(decoding: bundled(name), as: UTF8.self)
    }
}
