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
        return try Data(contentsOf: resourceURL.appendingPathComponent("Resources/\(name)"))
    }

    static func bundledText(_ name: String) throws -> String {
        try String(decoding: bundled(name), as: UTF8.self)
    }
}
