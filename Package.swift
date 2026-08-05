// swift-tools-version: 5.9

import PackageDescription

let package = Package(
    name: "fbd",
    platforms: [
        .macOS(.v13),
        .iOS(.v16),
    ],
    products: [
        .executable(name: "fbd", targets: ["fbd"]),
        .executable(name: "fbdctl", targets: ["fbdctl"]),
        .library(name: "Base", targets: ["Base"]),
        .library(name: "ExtCrypto", targets: ["ExtCrypto"]),
        .library(name: "Protocol", targets: ["Protocol"]),
        .library(name: "Script", targets: ["Script"]),
        .library(name: "Consensus", targets: ["Consensus"]),
        .library(name: "Covenants", targets: ["Covenants"]),
        .library(name: "Urkel", targets: ["Urkel"]),
        .library(name: "Chain", targets: ["Chain"]),
        .library(name: "Mempool", targets: ["Mempool"]),
        .library(name: "Net", targets: ["Net"]),
        .library(name: "DNS", targets: ["DNS"]),
        .library(name: "RPC", targets: ["RPC"]),
        .library(name: "Mining", targets: ["Mining"]),
        .library(name: "Node", targets: ["Node"]),
        .library(name: "Storage", targets: ["Storage"]),
        .library(name: "Wallet", targets: ["Wallet"]),
    ],
    dependencies: [
        .package(url: "https://github.com/apple/swift-crypto.git", from: "3.2.0"),
        .package(url: "https://github.com/apple/swift-argument-parser.git", from: "1.3.0"),
        .package(url: "https://github.com/apple/swift-log.git", from: "1.5.0"),
    ],
    targets: [
        // MARK: - Layer 0: Core Primitives

        .target(
            name: "Base",
            dependencies: [],
            path: "Sources/Base"
        ),

        // MARK: - Vendored C: secp256k1

        .target(
            name: "CSecp256k1",
            dependencies: [],
            path: "Sources/CSecp256k1",
            sources: ["src"],
            publicHeadersPath: "include",
            cSettings: [
                .headerSearchPath("src"),
                .headerSearchPath("include"),
                .define("ECMULT_GEN_PREC_BITS", to: "4"),
                .define("ECMULT_WINDOW_SIZE", to: "15"),
                .define("ENABLE_MODULE_RECOVERY"),
                .define("ENABLE_MODULE_ECDH"),
            ]
        ),

        // MARK: - Vendored C: SHA3/Keccak

        .target(
            name: "CSHA3",
            dependencies: [],
            path: "Sources/CSHA3",
            sources: ["src"],
            publicHeadersPath: "include",
            cSettings: [
                .headerSearchPath("include"),
            ]
        ),

        // MARK: - Vendored C++: LevelDB

        .target(
            name: "CLevelDB",
            dependencies: [],
            path: "Sources/CLevelDB",
            exclude: ["LICENSE"],
            sources: ["leveldb", "snappy"],
            publicHeadersPath: "include",
            cxxSettings: [
                .headerSearchPath("leveldb"),
                .headerSearchPath("leveldb/include"),
                .headerSearchPath("snappy"),
                .define("LEVELDB_PLATFORM_POSIX", .when(platforms: [.macOS, .iOS, .linux, .android])),
                .define("LEVELDB_PLATFORM_WINDOWS", .when(platforms: [.windows])),
                .define("LEVELDB_IS_BIG_ENDIAN", to: "0"),
                .define("HAVE_SNAPPY", to: "1"),
                .define("HAVE_CONFIG_H", to: "0"),
                .define("HAVE_SYS_UIO_H", to: "1", .when(platforms: [.macOS, .iOS, .linux, .android])),
                .define("HAVE_SYS_MMAN_H", to: "1", .when(platforms: [.macOS, .iOS, .linux, .android])),
                .define("HAVE_UNISTD_H", to: "1", .when(platforms: [.macOS, .iOS, .linux, .android])),
                .define("HAVE_BUILTIN_EXPECT", to: "1"),
                .define("HAVE_BUILTIN_CTZ", to: "1"),
                .define("HAVE_ATTRIBUTE_ALWAYS_INLINE", to: "1"),
                // Disable CPU-specific instructions for portable binaries
                .define("SNAPPY_HAVE_BMI2", to: "0"),
                .define("SNAPPY_HAVE_X86_CRC32", to: "0"),
                .define("SNAPPY_HAVE_SSSE3", to: "0"),
            ]
        ),

        // MARK: - Storage (LevelDB wrapper)

        .target(
            name: "Storage",
            dependencies: [
                "CLevelDB",
            ],
            path: "Sources/Storage"
        ),

        // MARK: - Layer 1: Cryptography

        .target(
            name: "ExtCrypto",
            dependencies: [
                "Base",
                "CSHA3",
                .product(name: "Crypto", package: "swift-crypto"),
                .product(name: "_CryptoExtras", package: "swift-crypto"),
                "CSecp256k1",
            ],
            path: "Sources/ExtCrypto"
        ),

        // MARK: - Layer 2: Protocol Types

        .target(
            name: "Protocol",
            dependencies: [
                "Base",
                "ExtCrypto",
            ],
            path: "Sources/Protocol"
        ),

        // MARK: - Layer 3: Script

        .target(
            name: "Script",
            dependencies: [
                "Base",
                "ExtCrypto",
                "Protocol",
            ],
            path: "Sources/Script"
        ),

        // MARK: - Layer 4: Consensus

        .target(
            name: "Consensus",
            dependencies: [
                "Base",
                "ExtCrypto",
                "Protocol",
                "Script",
            ],
            path: "Sources/Consensus"
        ),

        // MARK: - Layer 5: Covenants & Urkel Tree

        .target(
            name: "Covenants",
            dependencies: [
                "Base",
                "ExtCrypto",
                "Protocol",
                "Consensus",
            ],
            path: "Sources/Covenants"
        ),

        .target(
            name: "Urkel",
            dependencies: [
                "Base",
                "ExtCrypto",
            ],
            path: "Sources/Urkel"
        ),

        // MARK: - Layer 6: Chain & Mempool

        .target(
            name: "Chain",
            dependencies: [
                "Base",
                "ExtCrypto",
                "Protocol",
                "Script",
                "Consensus",
                "Covenants",
                "Urkel",
                "Storage",
            ],
            path: "Sources/Chain"
        ),

        .target(
            name: "Mempool",
            dependencies: [
                "Base",
                "Protocol",
                "Script",
                "Consensus",
                "Chain",
                "Covenants",
            ],
            path: "Sources/Mempool"
        ),

        // MARK: - Layer 7: Networking

        .target(
            name: "Net",
            dependencies: [
                "Base",
                "ExtCrypto",
                "Protocol",
                "Consensus",
                "Chain",
                "Mempool",
                .product(name: "Crypto", package: "swift-crypto"),
                .product(name: "Logging", package: "swift-log"),
            ],
            path: "Sources/Net"
        ),

        // MARK: - Layer 8: DNS

        .target(
            name: "DNS",
            dependencies: [
                "Base",
                "ExtCrypto",
                "Chain",
                "Covenants",
                "Urkel",
                .product(name: "Logging", package: "swift-log"),
            ],
            path: "Sources/DNS"
        ),

        // MARK: - Layer 9: RPC & Mining

        .target(
            name: "RPC",
            dependencies: [
                "Base",
                "Covenants",
                "ExtCrypto",
                "Protocol",
                "Chain",
                "Mempool",
                "Net",
                "Wallet",
                .product(name: "Logging", package: "swift-log"),
            ],
            path: "Sources/RPC"
        ),

        .target(
            name: "Mining",
            dependencies: [
                "Base",
                "ExtCrypto",
                "Protocol",
                "Consensus",
                "Chain",
                "Mempool",
            ],
            path: "Sources/Mining"
        ),

        // MARK: - Wallet

        .target(
            name: "Wallet",
            dependencies: [
                "Base",
                "Consensus",
                "Covenants",
                "ExtCrypto",
                "Protocol",
                "Script",
                "Storage",
                .product(name: "Crypto", package: "swift-crypto"),
            ],
            path: "Sources/Wallet"
        ),

        // MARK: - Layer 10: Node & CLI

        .target(
            name: "Node",
            dependencies: [
                "Base",
                "ExtCrypto",
                "Protocol",
                "Consensus",
                "Chain",
                "Script",
                "Mempool",
                "Net",
                "DNS",
                "RPC",
                "Mining",
                "Storage",
                "Wallet",
                .product(name: "Logging", package: "swift-log"),
            ],
            path: "Sources/Node"
        ),

        .executableTarget(
            name: "fbd",
            dependencies: [
                "Node",
                "Base",
                .product(name: "ArgumentParser", package: "swift-argument-parser"),
                .product(name: "Logging", package: "swift-log"),
            ],
            path: "Sources/FBD"
        ),

        .executableTarget(
            name: "fbdctl",
            dependencies: [
                .product(name: "ArgumentParser", package: "swift-argument-parser"),
                "Base",
            ],
            path: "Sources/FBDCtl"
        ),

        .executableTarget(
            name: "mine-genesis",
            dependencies: ["Chain", "Consensus", "ExtCrypto", "Protocol", "Base"],
            path: "Sources/MineGenesis"
        ),

        // MARK: - Tests

        .testTarget(
            name: "BaseTests",
            dependencies: ["Base"],
            path: "Tests/BaseTests"
        ),

        .testTarget(
            name: "ExtCryptoTests",
            dependencies: ["ExtCrypto", "Base"],
            path: "Tests/ExtCryptoTests"
        ),

        .testTarget(
            name: "ProtocolTests",
            dependencies: ["Protocol", "Base", "ExtCrypto", "Consensus"],
            path: "Tests/ProtocolTests"
        ),

        .testTarget(
            name: "ScriptTests",
            dependencies: ["Script", "Base", "ExtCrypto", "Protocol"],
            path: "Tests/ScriptTests"
        ),

        .testTarget(
            name: "ConsensusTests",
            dependencies: ["Consensus", "Base", "ExtCrypto", "Protocol"],
            path: "Tests/ConsensusTests"
        ),

        .testTarget(
            name: "CovenantsTests",
            dependencies: ["Covenants", "Base", "ExtCrypto", "Protocol", "Consensus"],
            path: "Tests/CovenantsTests"
        ),

        .testTarget(
            name: "UrkelTests",
            dependencies: ["Urkel", "Base", "ExtCrypto"],
            path: "Tests/UrkelTests"
        ),

        .testTarget(
            name: "ChainTests",
            dependencies: ["Chain", "Base", "ExtCrypto", "Protocol", "Consensus", "Storage"],
            path: "Tests/ChainTests"
        ),

        .testTarget(
            name: "MempoolTests",
            dependencies: ["Mempool", "Chain", "Base", "ExtCrypto", "Protocol", "Consensus"],
            path: "Tests/MempoolTests"
        ),

        .testTarget(
            name: "NetTests",
            dependencies: [
                "Net", "Base", "ExtCrypto", "Protocol",
                "Consensus", "Chain", "Mining", "Mempool",
                .product(name: "Crypto", package: "swift-crypto"),
                .product(name: "Logging", package: "swift-log"),
            ],
            path: "Tests/NetTests"
        ),

        .testTarget(
            name: "DNSTests",
            dependencies: [
                "DNS", "Base",
            ],
            path: "Tests/DNSTests"
        ),

        .testTarget(
            name: "MiningTests",
            dependencies: [
                "Mining", "Base", "ExtCrypto", "Protocol", "Consensus", "Chain", "Mempool",
                .product(name: "Logging", package: "swift-log"),
            ],
            path: "Tests/MiningTests"
        ),

        .testTarget(
            name: "RPCTests",
            dependencies: [
                "RPC", "Base", "Protocol", "Chain",
            ],
            path: "Tests/RPCTests"
        ),

        .testTarget(
            name: "NodeTests",
            dependencies: ["Node", "Base", "RPC", "Wallet", "Chain", "Mempool", "Protocol", "Covenants", "ExtCrypto", "Consensus"],
            path: "Tests/NodeTests"
        ),

        .testTarget(
            name: "WalletTests",
            dependencies: ["Wallet", "Base", "ExtCrypto", "Protocol", "Consensus"],
            path: "Tests/WalletTests"
        ),

        .testTarget(
            name: "StorageTests",
            dependencies: ["Storage"],
            path: "Tests/StorageTests"
        ),
    ]
)
