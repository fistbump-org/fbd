import XCTest
@testable import Node
@testable import Base
@testable import RPC
import Logging

// MARK: - Node Config Tests

final class NodeConfigTests: XCTestCase {

    func testDefaultConfig() {
        let config = NodeConfig()
        XCTAssertEqual(config.network, .main)
        XCTAssertEqual(config.dataDir, "~/.fbd")
        XCTAssertEqual(config.host, "0.0.0.0")
        XCTAssertEqual(config.port, 0)
        XCTAssertEqual(config.maxOutbound, 8)
        XCTAssertEqual(config.maxInbound, 64)
        XCTAssertEqual(config.rpcHost, "127.0.0.1")
        XCTAssertFalse(config.rpcNoAuth)
        XCTAssertNil(config.minerAddress)
        XCTAssertFalse(config.indexTx)
        XCTAssertFalse(config.indexAddress)
    }

    func testEffectivePortsMainnet() {
        let config = NodeConfig(network: .main)
        XCTAssertEqual(config.effectivePort, 32867)
        XCTAssertEqual(config.effectiveRPCPort, 32869)
        XCTAssertEqual(config.effectiveNSPort, 32870)
    }

    func testEffectivePortsTestnet() {
        let config = NodeConfig(network: .testnet)
        XCTAssertEqual(config.effectivePort, 42867)
        XCTAssertEqual(config.effectiveRPCPort, 42869)
        XCTAssertEqual(config.effectiveNSPort, 42870)
    }

    func testEffectivePortsRegtest() {
        let config = NodeConfig(network: .regtest)
        XCTAssertEqual(config.effectivePort, 52867)
        XCTAssertEqual(config.effectiveRPCPort, 52869)
        XCTAssertEqual(config.effectiveNSPort, 52870)
    }

    func testEffectivePortsSimnet() {
        let config = NodeConfig(network: .simnet)
        XCTAssertEqual(config.effectivePort, 62867)
        XCTAssertEqual(config.effectiveRPCPort, 62869)
        XCTAssertEqual(config.effectiveNSPort, 62870)
    }

    func testCustomPortOverridesDefault() {
        let config = NodeConfig(network: .main, port: 9999, rpcPort: 8888, nsPort: 7777)
        XCTAssertEqual(config.effectivePort, 9999)
        XCTAssertEqual(config.effectiveRPCPort, 8888)
        XCTAssertEqual(config.effectiveNSPort, 7777)
    }

    func testSeedsDefault() {
        let config = NodeConfig(network: .main)
        XCTAssertTrue(config.seeds.isEmpty, "Default seeds should be empty (DNS seeds used)")
    }

    func testSeedsCustom() {
        let config = NodeConfig(seeds: ["my.seed.com"])
        XCTAssertEqual(config.seeds, ["my.seed.com"])
    }

    func testNodesExclusive() {
        let config = NodeConfig(nodes: ["192.168.1.1:32867"])
        XCTAssertEqual(config.nodes, ["192.168.1.1:32867"])
    }

    func testNetworkDataDirMainnet() {
        let config = NodeConfig(network: .main, dataDir: "/data")
        XCTAssertEqual(config.networkDataDir, "/data")
    }

    func testNetworkDataDirTestnet() {
        let config = NodeConfig(network: .testnet, dataDir: "/data")
        XCTAssertEqual(config.networkDataDir, "/data/testnet")
    }

    func testNetworkDataDirRegtest() {
        let config = NodeConfig(network: .regtest, dataDir: "/data")
        XCTAssertEqual(config.networkDataDir, "/data/regtest")
    }
}

// MARK: - Node State Tests

final class NodeStateTests: XCTestCase {

    func testInitialState() {
        let state = NodeState()
        XCTAssertFalse(state.isRunning)
        XCTAssertEqual(state.chainHeight, 0)
        XCTAssertEqual(state.bestHash, .zero)
        XCTAssertEqual(state.peerCount, 0)
        XCTAssertEqual(state.mempoolSize, 0)
        XCTAssertEqual(state.syncProgress, 0)
    }

    func testStateMutation() {
        var state = NodeState()
        state.isRunning = true
        state.chainHeight = 1000
        state.peerCount = 8
        state.syncProgress = 0.5

        XCTAssertTrue(state.isRunning)
        XCTAssertEqual(state.chainHeight, 1000)
        XCTAssertEqual(state.peerCount, 8)
        XCTAssertEqual(state.syncProgress, 0.5)
    }
}

// MARK: - Node Phase Tests

final class NodePhaseTests: XCTestCase {

    func testPhaseValues() {
        XCTAssertEqual(NodePhase.initializing.rawValue, "initializing")
        XCTAssertEqual(NodePhase.loading.rawValue, "loading")
        XCTAssertEqual(NodePhase.syncing.rawValue, "syncing")
        XCTAssertEqual(NodePhase.running.rawValue, "running")
        XCTAssertEqual(NodePhase.stopping.rawValue, "stopping")
        XCTAssertEqual(NodePhase.stopped.rawValue, "stopped")
    }
}

// MARK: - Node Error Tests

final class NodeErrorTests: XCTestCase {

    func testConfigurationError() {
        let error = NodeError.configurationError("bad config")
        if case .configurationError(let msg) = error {
            XCTAssertEqual(msg, "bad config")
        } else {
            XCTFail("Wrong error type")
        }
    }

    func testStartupFailed() {
        let error = NodeError.startupFailed("port in use")
        if case .startupFailed(let msg) = error {
            XCTAssertEqual(msg, "port in use")
        } else {
            XCTFail("Wrong error type")
        }
    }
}

// MARK: - Full Node Tests

final class FullNodeTests: XCTestCase {

    func testNodeUserAgent() {
        XCTAssertEqual(FullNode.userAgent(), "/fbd:\(FullNode.version)/")
    }

    func testNodeInitialize() throws {
        let config = NodeConfig(network: .regtest)
        let node = FullNode(config: config)
        let components = try node.initialize()

        // RPC config should reflect the node config
        XCTAssertEqual(components.rpcConfig.port, Int(NetworkType.regtest.rpcPort))
    }

    func testNodeInitialState() {
        let config = NodeConfig()
        let node = FullNode(config: config)
        let state = node.initialState()

        XCTAssertFalse(state.isRunning)
        XCTAssertEqual(state.chainHeight, 0)
        XCTAssertEqual(state.bestHash, .zero)
    }

    func testNodeRPCConfig() throws {
        let config = NodeConfig(network: .testnet, rpcHost: "0.0.0.0", rpcApiKey: "mykey")
        let node = FullNode(config: config)
        let components = try node.initialize()

        XCTAssertEqual(components.rpcConfig.host, "0.0.0.0")
        XCTAssertEqual(components.rpcConfig.port, Int(NetworkType.testnet.rpcPort))
        XCTAssertEqual(components.rpcConfig.apiKey, "mykey")
    }

    func testEmptyDataDirFails() {
        let config = NodeConfig(dataDir: "")
        let node = FullNode(config: config)
        XCTAssertThrowsError(try node.initialize())
    }

    // MARK: - Agent Validation

    func testUserAgentWithSuffix() {
        XCTAssertEqual(FullNode.userAgent(suffix: "MyNode"), "/fbd:\(FullNode.version)/MyNode/")
    }

    func testValidAgentAccepted() throws {
        let config = NodeConfig(network: .regtest, agent: "Eskimo.Software")
        let node = FullNode(config: config)
        // Should not throw — printable ASCII is fine
        _ = try node.initialize()
    }

    func testAgentRejectsControlCharacters() {
        // Tab character (0x09)
        let config = NodeConfig(network: .regtest, agent: "Bad\tAgent")
        let node = FullNode(config: config)
        XCTAssertThrowsError(try node.initialize()) { error in
            XCTAssertTrue("\(error)".contains("non-printable"), "\(error)")
        }
    }

    func testAgentRejectsNullByte() {
        let config = NodeConfig(network: .regtest, agent: "Bad\0Agent")
        let node = FullNode(config: config)
        XCTAssertThrowsError(try node.initialize()) { error in
            XCTAssertTrue("\(error)".contains("non-printable"), "\(error)")
        }
    }

    func testAgentRejectsNewline() {
        let config = NodeConfig(network: .regtest, agent: "Bad\nAgent")
        let node = FullNode(config: config)
        XCTAssertThrowsError(try node.initialize()) { error in
            XCTAssertTrue("\(error)".contains("non-printable"), "\(error)")
        }
    }

    func testAgentRejectsTooLong() {
        let long = String(repeating: "A", count: 256)
        let config = NodeConfig(network: .regtest, agent: long)
        let node = FullNode(config: config)
        XCTAssertThrowsError(try node.initialize()) { error in
            XCTAssertTrue("\(error)".contains("too long"), "\(error)")
        }
    }
}
