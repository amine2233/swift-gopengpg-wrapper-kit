// swift-tools-version: 6.1

import PackageDescription

let package = Package(
    name: "swift-gopengpg-wrapper-kit",
    platforms: [.iOS(.v18), .macOS(.v15)],
    products: [
        .library(name: "PGPKit", targets: ["PGPKit"]),
        .library(name: "PGPKitGopenPGP", targets: ["PGPKitGopenPGP"]),
        .library(name: "PGPKitTesting", targets: ["PGPKitTesting"])
    ],
    dependencies: [
        .package(url: "https://github.com/amine2233/spm-gopengpg", from: "2.10.0")
    ],
    targets: [
        .target(
            name: "PGPKit",
            swiftSettings: [.enableUpcomingFeature("ApproachableConcurrency")]
        ),
        .target(
            name: "PGPKitGopenPGP",
            dependencies: [
                "PGPKit",
                .product(name: "Gopenpgp", package: "spm-gopengpg")
            ],
            swiftSettings: [.enableUpcomingFeature("ApproachableConcurrency")]
        ),
        .target(
            name: "PGPKitTesting",
            dependencies: ["PGPKit"],
            swiftSettings: [.enableUpcomingFeature("ApproachableConcurrency")]
        ),
        .testTarget(
            name: "PGPKitTests",
            dependencies: ["PGPKit", "PGPKitTesting"],
            swiftSettings: [.enableUpcomingFeature("ApproachableConcurrency")]
        ),
        .testTarget(
            name: "PGPKitGopenPGPTests",
            dependencies: ["PGPKit", "PGPKitGopenPGP", "PGPKitTesting"],
            resources: [.copy("Resources")],
            swiftSettings: [.enableUpcomingFeature("ApproachableConcurrency")]
        )
    ]
)
