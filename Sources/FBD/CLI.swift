/// fbd-cli - Executable entry point for the fbd full node.
///
/// Parses command-line arguments and launches the Node.
/// Config file at <datadir>/fbd.conf provides defaults; CLI args override.
import ArgumentParser
import Base
import Foundation
import Node
import Logging
#if canImport(Android)
import Android
#elseif canImport(Glibc)
import Glibc
#elseif canImport(Musl)
import Musl
#elseif canImport(Darwin)
import Darwin
#endif

@main
struct FBD: AsyncParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "fbd",
        abstract: "A Fistbump full node daemon for the FBC network.",
        version: FullNode.fullVersion
    )

    static func main() async {
        let args = CommandLine.arguments.dropFirst()
        if args.contains("--help") || args.contains("-h") {
            print("fbd v\(FullNode.fullVersion)")
            print("https://fbd.dev")
            return
        }
        if args.contains("--version") {
            print(FullNode.fullVersion)
            return
        }
        do {
            let command = try parseAsRoot()
            if var asyncCommand = command as? AsyncParsableCommand {
                try await asyncCommand.run()
            }
        } catch {
            exit(withError: error)
        }
    }

    // MARK: - Network

    @Option(name: .shortAndLong, help: "Network: main, testnet, regtest, simnet.")
    var network: String?

    // MARK: - Data

    @Option(name: .shortAndLong, help: "Base data directory.")
    var datadir: String?

    // MARK: - P2P

    @Option(name: .long, help: "P2P listen host.")
    var host: String?

    @Option(name: .shortAndLong, help: "P2P listen port (0 = network default).")
    var port: Int?

    @Option(name: .long, help: "Maximum outbound peer connections.")
    var maxOutbound: Int?

    @Option(name: .long, help: "Maximum inbound peer connections.")
    var maxInbound: Int?

    @Option(name: .long, parsing: .upToNextOption, help: "Seed peer addresses (also uses DNS seeds).")
    var seeds: [String] = []

    @Option(name: .long, parsing: .upToNextOption, help: "Connect ONLY to these peers (no DNS seeds).")
    var nodes: [String] = []

    @Option(name: .long, help: "Custom user agent suffix (e.g. /fbd:X.Y.Z/YourName/).")
    var agent: String?

    // MARK: - RPC

    @Option(name: .long, help: "RPC listen host.")
    var rpcHost: String?

    @Option(name: .long, help: "RPC listen port (0 = network default).")
    var rpcPort: Int?

    @Option(name: .long, help: "RPC API key.")
    var apiKey: String?

    @Flag(name: .long, help: "Disable RPC authentication.")
    var noAuth: Bool = false

    // MARK: - DNS

    @Option(name: .long, help: "Authoritative DNS listen host.")
    var nsHost: String?

    @Option(name: .long, help: "Authoritative DNS listen port (0 = network default).")
    var nsPort: Int?

    // MARK: - Mining

    @Option(name: .long, help: "Coinbase payout address (enables mining).")
    var minerAddress: String?

    @Option(name: .long, help: "Number of CPU miner threads (0 = auto, max = cores - 1).")
    var minerThreads: Int?

    // MARK: - Logging

    @Option(name: .long, help: "Log level: trace, debug, info, notice, warning, error, critical.")
    var logLevel: String?

    // MARK: - Indexing

    @Flag(name: .long, help: "Maintain a transaction index.")
    var indexTx: Bool = false

    @Flag(name: .long, help: "Maintain an address index.")
    var indexAddress: Bool = false

    @Flag(name: .long, help: "Keep full auction history (disable pruning of closed auctions).")
    var indexAuctions: Bool = false

    // MARK: - Run

    func run() async throws {
        // Ignore SIGPIPE — writing to a closed socket must return an error,
        // not silently kill the process. NIO did this internally; we must do it
        // ourselves now that we use raw sockets.
        #if !os(Windows)
        signal(SIGPIPE, SIG_IGN)
        #endif

        // Disable Swift runtime's crash backtracing on Linux.
        // The env var is checked at crash time, so setting it here is fine.
        #if canImport(Glibc) || canImport(Musl) || canImport(Android)
        setenv("SWIFT_BACKTRACE", "enable=no", 0)
        #endif

        // Install custom log formatter before any Logger is created
        LoggingSystem.bootstrap { label in FBDLogHandler(label: label) }

        // Load config file (datadir resolved: CLI > default)
        let baseDir = datadir ?? NodeConfig.defaultDataDir
        var conf = Self.loadConfigFile(dataDir: baseDir)

        // Merge: CLI arg > config file > built-in default
        let finalNetwork = network ?? conf["network"] ?? "main"

        // Load network-specific config (e.g. ~/.fbd/regtest/fbd.conf) and merge
        if finalNetwork != "main" {
            let networkConf = Self.loadConfigFile(dataDir: baseDir + "/\(finalNetwork)")
            for (key, value) in networkConf {
                conf[key] = value
            }
        }
        let finalDataDir = datadir ?? conf["datadir"] ?? NodeConfig.defaultDataDir
        let finalHost = host ?? conf["host"] ?? "127.0.0.1"
        let finalPort = port ?? conf["port"].flatMap(Int.init) ?? 0
        var finalMaxOutbound = maxOutbound ?? conf["max-outbound"].flatMap(Int.init) ?? 8
        let finalMaxInbound = maxInbound ?? conf["max-inbound"].flatMap(Int.init) ?? 64
        let finalSeeds = !seeds.isEmpty ? seeds : (conf["seeds"]?.split(separator: ",").map { String($0.trimmingCharacters(in: .whitespaces)) } ?? [])
        let confNodes = conf["nodes"]
        let finalNodes: [String]
        if !nodes.isEmpty {
            finalNodes = nodes
        } else if let raw = confNodes {
            finalNodes = raw.split(separator: ",").map { String($0.trimmingCharacters(in: .whitespaces)) }.filter { !$0.isEmpty }
        } else {
            finalNodes = []
        }
        // node = (empty) in config means listen-only: no outbound connections
        if confNodes != nil && finalNodes.isEmpty && nodes.isEmpty {
            finalMaxOutbound = 0
        }
        let finalAgent = agent ?? conf["agent"]
        let finalRpcHost = rpcHost ?? conf["rpc-host"] ?? "127.0.0.1"
        let finalRpcPort = rpcPort ?? conf["rpc-port"].flatMap(Int.init) ?? 0
        let finalApiKey = apiKey ?? conf["api-key"]
        let finalNoAuth = noAuth || conf["no-auth"] == "true"
        let finalNsHost = nsHost ?? conf["ns-host"] ?? "127.0.0.1"
        let finalNsPort = nsPort ?? conf["ns-port"].flatMap(Int.init) ?? 0
        let finalMinerAddress = minerAddress ?? conf["miner-address"]
        let finalMinerThreads = minerThreads ?? conf["miner-threads"].flatMap(Int.init) ?? 0

        let finalLogLevel = logLevel ?? conf["log-level"] ?? "info"
        let finalIndexTx = indexTx || conf["index-tx"] == "true"
        let finalIndexAddress = indexAddress || conf["index-address"] == "true"
        let finalIndexAuctions = indexAuctions || conf["index-auctions"] == "true"

        // Parse network type
        guard let networkType = NetworkType(rawValue: finalNetwork) else {
            throw ValidationError("Invalid network '\(finalNetwork)'. Use: main, testnet, regtest, simnet.")
        }

        // Parse log level
        let level = parseLogLevel(finalLogLevel)

        // Build configuration
        let config = NodeConfig(
            network: networkType,
            dataDir: finalDataDir,
            host: finalHost,
            port: UInt16(clamping: finalPort),
            maxOutbound: finalMaxOutbound,
            maxInbound: finalMaxInbound,
            seeds: finalSeeds,
            nodes: finalNodes,
            agent: finalAgent,
            rpcHost: finalRpcHost,
            rpcPort: UInt16(clamping: finalRpcPort),
            rpcApiKey: finalApiKey,
            rpcNoAuth: finalNoAuth,
            nsHost: finalNsHost,
            nsPort: UInt16(clamping: finalNsPort),
            minerAddress: finalMinerAddress,
            minerThreads: finalMinerThreads,

            logLevel: level,
            indexTx: finalIndexTx,
            indexAddress: finalIndexAddress,
            indexAuctions: finalIndexAuctions
        )

        // Create and initialize node
        let node = FullNode(config: config)

        node.logger.info("fbd v\(FullNode.fullVersion)", source: "Node")

        if !conf.isEmpty {
            let path = baseDir + "/fbd.conf"
            node.logger.debug("Loaded \(path)",
                              metadata: Dictionary(uniqueKeysWithValues: conf.sorted(by: { $0.key < $1.key }).map { ($0.key, "\($0.value)") }),
                              source: "Node")
        }

        node.logger.info("Starting",
                         metadata: [
                            "network": "\(config.network.rawValue)",
                            "datadir": "\(config.networkDataDir)",
                            "p2p": "\(config.effectivePort)",
                            "rpc": "\(config.effectiveRPCPort)",
                            "dns": "\(config.effectiveNSPort)",
                         ],
                         source: "Node")

        let components = try node.initialize()

        // Start all network services and run until shutdown signal
        do {
            try await node.start(components: components)
        } catch is NodeError {
            // FullNode already logged a clean error — exit without ArgumentParser reprinting it
            throw ExitCode.failure
        }
    }

    // MARK: - Config File

    /// Load key=value config from `<datadir>/fbd.conf`.
    ///
    /// Format:
    /// ```
    /// # Comment
    /// network = testnet
    /// nodes = 1.2.3.4:32867, 5.6.7.8:32867
    /// index-tx = true
    /// ```
    private static func loadConfigFile(dataDir: String) -> [String: String] {
        let expanded = expandTilde(dataDir)
        let path = expanded + "/fbd.conf"
        guard let data = try? String(contentsOfFile: path, encoding: .utf8) else {
            return [:]
        }
        var result = [String: String]()
        for line in data.split(separator: "\n", omittingEmptySubsequences: false) {
            let trimmed = String(line).trimmingCharacters(in: CharacterSet.whitespaces)
            if trimmed.isEmpty || trimmed.hasPrefix("#") { continue }
            guard let eqIdx = trimmed.firstIndex(of: "=") else { continue }
            let key = String(trimmed[trimmed.startIndex..<eqIdx]).trimmingCharacters(in: CharacterSet.whitespaces).lowercased()
            let value = String(trimmed[trimmed.index(after: eqIdx)...]).trimmingCharacters(in: CharacterSet.whitespaces)
            if !key.isEmpty {
                result[key] = value
            }
        }
        return result
    }

    private static func expandTilde(_ path: String) -> String {
        guard path.hasPrefix("~") else { return path }
        if let home = ProcessInfo.processInfo.environment["HOME"] {
            return home + path.dropFirst()
        }
        return path
    }

    // MARK: - Helpers

    private func parseLogLevel(_ string: String) -> Logger.Level {
        switch string.lowercased() {
        case "trace":    return .trace
        case "debug":    return .debug
        case "info":     return .info
        case "notice":   return .notice
        case "warning":  return .warning
        case "error":    return .error
        case "critical": return .critical
        default:         return .info
        }
    }
}
