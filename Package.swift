// swift-tools-version:5.3
// The swift-tools-version declares the minimum version of Swift required to build this package.

import PackageDescription

let package = Package(
    name: "Anchor",
    products: [
        .library(
            name: "Anchor",
            targets: ["Anchor"]),
    ],
    dependencies: [
    ],
    targets: [
        .target(
          name: "CAnchorBoringSSL",
          exclude: ["hash.txt", "include/boringssl_prefix_symbols_nasm.inc"]
        ),
        .target(
            name: "Anchor",
            dependencies: ["CAnchorBoringSSL"]
        ),
        .testTarget(
            name: "AnchorTests",
            dependencies: ["Anchor"],
            resources: [
                .copy("Resources")
            ]
        ),
    ]
)
