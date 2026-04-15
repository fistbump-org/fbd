import XCTest
@testable import Chain
import Base
import Protocol
import Covenants
@testable import Consensus
import ExtCrypto

final class CovenantProcessorTests: XCTestCase {

    // MARK: - Helpers

    private let nameParams = NameParams.regtest
    private let network = NetworkType.regtest

    /// Create a simple NameDB for testing.
    private func makeNameDB() -> NameDB { NameDB() }

    /// Create a mock chain (header-only, no coinDB).
    private func makeChain() throws -> Chain {
        try Chain(network: .regtest)
    }

    /// Make a dummy txHash from an integer seed.
    private func txHash(_ seed: UInt8) -> Hash256 {
        Hash256(unchecked: [UInt8](repeating: seed, count: 32))
    }

    /// Make a simple outpoint.
    private func outpoint(_ seed: UInt8, _ index: UInt32) -> Outpoint {
        Outpoint(hash: txHash(seed), index: index)
    }

    /// Create a CoinView with a single coin pre-loaded.
    private func viewWithCoin(
        at op: Outpoint, value: UInt64, covenant: Covenant, height: Int = 100
    ) -> CoinView {
        var view = CoinView()
        let output = Output(value: value, address: .null, covenant: covenant)
        let entry = CoinEntry.fromOutput(output, height: height, coinbase: false)
        view.addEntry(op, entry)
        return view
    }

    /// Compute the SHA3-256 name hash for a test name.
    private func nameHash(for name: String) -> NameHash {
        NameRules.hashName(name)
    }

    /// Build a simple transaction with one input and one output.
    private func simpleTx(
        input: Outpoint,
        outputValue: UInt64,
        covenant: Covenant
    ) -> Transaction {
        Transaction(
            inputs: [Input(prevout: input)],
            outputs: [Output(value: outputValue, address: .null, covenant: covenant)]
        )
    }

    // MARK: - NameDB Tests

    func testNameDBGetPutRoundtrip() throws {
        let db = makeNameDB()
        let nh = nameHash(for: "testname")

        // Initially nil
        XCTAssertNil(try db.getNameState(nh))

        // Put and retrieve
        var ns = NameState(nameHash: nh, name: Array("testname".utf8))
        ns.height = 42
        ns.renewal = 42
        db.putNameState(nh, ns)

        let retrieved = try db.getNameState(nh)
        XCTAssertNotNil(retrieved)
        XCTAssertEqual(retrieved?.height, 42)
    }

    func testNameDBCommit() throws {
        let db = makeNameDB()
        let nh = nameHash(for: "committest")

        var ns = NameState(nameHash: nh, name: Array("committest".utf8))
        ns.height = 10
        ns.renewal = 10
        db.putNameState(nh, ns)

        // Before commit, tree root should be zero (pending not yet flushed)
        let rootBefore = try db.treeRoot()
        XCTAssertEqual(rootBefore, [UInt8](repeating: 0, count: 32))

        // After commit, tree root should change
        try db.commit()
        let rootAfter = try db.treeRoot()
        XCTAssertNotEqual(rootAfter, [UInt8](repeating: 0, count: 32))

        // Should still be retrievable from tree after commit
        let retrieved = try db.getNameState(nh)
        XCTAssertNotNil(retrieved)
        XCTAssertEqual(retrieved?.height, 10)
    }

    // MARK: - OPEN Tests

    func testOpenValid() throws {
        let db = makeNameDB()
        let chain = try makeChain()
        let name = "testopen"
        let nh = nameHash(for: name)
        let height = 10 // regtest: noRollout, auctionStart = 0

        let covenant = CovenantData.makeOpen(nameHash: nh, name: Array(name.utf8))
        let tx = simpleTx(input: .null, outputValue: 0, covenant: covenant)
        var view = CoinView()
        view.addTX(tx, height: height)

        try CovenantProcessor.processCovenants(
            tx: tx, txIndex: 0, coinView: view, nameDB: db,
            height: height, network: network, nameParams: nameParams,
            chain: chain, consensusParams: ConsensusParams.params(for: .regtest)
        )

        let ns = try db.getNameState(nh)
        XCTAssertNotNil(ns)
        XCTAssertEqual(ns?.height, height)
        XCTAssertEqual(ns?.renewal, height)
    }

    func testOpenDuplicateInBlock() throws {
        let db = makeNameDB()
        let chain = try makeChain()
        let name = "dupopen"
        let nh = nameHash(for: name)
        let height = 10

        let covenant = CovenantData.makeOpen(nameHash: nh, name: Array(name.utf8))
        // Two outputs with the same name OPEN in one tx — hsd allows this
        let tx = Transaction(
            inputs: [Input(prevout: .null), Input(prevout: .null)],
            outputs: [
                Output(value: 0, address: .null, covenant: covenant),
                Output(value: 0, address: .null, covenant: covenant),
            ]
        )
        var view = CoinView()
        view.addTX(tx, height: height)

        // hsd does NOT reject duplicate name outputs per tx
        XCTAssertNoThrow(try CovenantProcessor.processCovenants(
            tx: tx, txIndex: 0, coinView: view, nameDB: db,
            height: height, network: network, nameParams: nameParams,
            chain: chain, consensusParams: ConsensusParams.params(for: .regtest)
        ))
    }

    func testOpenNameAlreadyActive() throws {
        let db = makeNameDB()
        let chain = try makeChain()
        let name = "active"
        let nh = nameHash(for: name)
        let height = 10

        // Pre-populate an active name state
        var existing = NameState(nameHash: nh, name: Array(name.utf8))
        existing.height = 5
        existing.renewal = 5
        db.putNameState(nh, existing)

        let covenant = CovenantData.makeOpen(nameHash: nh, name: Array(name.utf8))
        let tx = simpleTx(input: .null, outputValue: 0, covenant: covenant)
        var view = CoinView()
        view.addTX(tx, height: height)

        XCTAssertThrowsError(try CovenantProcessor.processCovenants(
            tx: tx, txIndex: 0, coinView: view, nameDB: db,
            height: height, network: network, nameParams: nameParams,
            chain: chain, consensusParams: ConsensusParams.params(for: .regtest)
        ))
    }

    // MARK: - BID Tests

    func testBidInBiddingPhase() throws {
        let db = makeNameDB()
        let chain = try makeChain()
        let name = "bidtest"
        let nh = nameHash(for: name)
        // regtest: openPeriod = 6
        let openHeight = 10
        let bidHeight = openHeight + nameParams.openPeriod // Should be in bidding

        // Create name state at openHeight
        var ns = NameState(nameHash: nh, name: Array(name.utf8))
        ns.height = openHeight
        ns.renewal = openHeight
        db.putNameState(nh, ns)

        // Verify we're in bidding state
        XCTAssertEqual(ns.state(at: bidHeight, params: nameParams), .bidding)

        let bidValue: UInt64 = 200_000_000 // 200 FBC (above minimum bid)
        let blind = try BlindBid.blind(value: bidValue, nonce: BidNonce(unchecked: [UInt8](repeating: 0xAA, count: 32)))
        let covenant = CovenantData.makeBid(
            nameHash: nh, startHeight: openHeight,
            name: Array(name.utf8), blind: blind
        )
        let tx = simpleTx(input: outpoint(0x01, 0), outputValue: bidValue, covenant: covenant)
        let view = viewWithCoin(at: outpoint(0x01, 0), value: bidValue, covenant: .none)

        try CovenantProcessor.processCovenants(
            tx: tx, txIndex: 0, coinView: view, nameDB: db,
            height: bidHeight, network: network, nameParams: nameParams,
            chain: chain, consensusParams: ConsensusParams.params(for: .regtest)
        )
        // BID doesn't modify state, just validates
    }

    func testBidOutsideBiddingFails() throws {
        let db = makeNameDB()
        let chain = try makeChain()
        let name = "bidfail"
        let nh = nameHash(for: name)
        let openHeight = 10
        // During reveal period (after bidding ends)
        let revealHeight = openHeight + nameParams.openPeriod + nameParams.biddingPeriod

        var ns = NameState(nameHash: nh, name: Array(name.utf8))
        ns.height = openHeight
        ns.renewal = openHeight
        db.putNameState(nh, ns)

        XCTAssertEqual(ns.state(at: revealHeight, params: nameParams), .reveal)

        let blind = try BlindBid.blind(value: 1000, nonce: BidNonce(unchecked: [UInt8](repeating: 0xBB, count: 32)))
        let covenant = CovenantData.makeBid(
            nameHash: nh, startHeight: openHeight,
            name: Array(name.utf8), blind: blind
        )
        let tx = simpleTx(input: outpoint(0x02, 0), outputValue: 1000, covenant: covenant)
        let view = viewWithCoin(at: outpoint(0x02, 0), value: 1000, covenant: .none)

        XCTAssertThrowsError(try CovenantProcessor.processCovenants(
            tx: tx, txIndex: 0, coinView: view, nameDB: db,
            height: revealHeight, network: network, nameParams: nameParams,
            chain: chain, consensusParams: ConsensusParams.params(for: .regtest)
        ))
    }

    // MARK: - REVEAL Tests

    func testRevealVerifiesBlind() throws {
        let db = makeNameDB()
        let chain = try makeChain()
        let name = "revealtest"
        let nh = nameHash(for: name)
        let openHeight = 10
        let revealHeight = openHeight + nameParams.openPeriod + nameParams.biddingPeriod

        var ns = NameState(nameHash: nh, name: Array(name.utf8))
        ns.height = openHeight
        ns.renewal = openHeight
        db.putNameState(nh, ns)

        XCTAssertEqual(ns.state(at: revealHeight, params: nameParams), .reveal)

        let nonce = BidNonce(unchecked: [UInt8](repeating: 0xCC, count: 32))
        let bidValue: UInt64 = 5000
        let blind = try BlindBid.blind(value: bidValue, nonce: nonce)

        // BID covenant for the input coin
        let bidCovenant = CovenantData.makeBid(
            nameHash: nh, startHeight: openHeight,
            name: Array(name.utf8), blind: blind
        )
        let bidOutpoint = outpoint(0x03, 0)

        // REVEAL covenant for the output
        let revealCovenant = CovenantData.makeReveal(
            nameHash: nh, startHeight: openHeight, nonce: nonce
        )
        let tx = simpleTx(input: bidOutpoint, outputValue: bidValue, covenant: revealCovenant)
        let view = viewWithCoin(at: bidOutpoint, value: bidValue, covenant: bidCovenant)

        try CovenantProcessor.processCovenants(
            tx: tx, txIndex: 0, coinView: view, nameDB: db,
            height: revealHeight, network: network, nameParams: nameParams,
            chain: chain, consensusParams: ConsensusParams.params(for: .regtest)
        )

        let updated = try db.getNameState(nh)
        XCTAssertEqual(updated?.highest, Int64(bidValue))
    }

    func testRevealWrongBlindFails() throws {
        let db = makeNameDB()
        let chain = try makeChain()
        let name = "badreveal"
        let nh = nameHash(for: name)
        let openHeight = 10
        let revealHeight = openHeight + nameParams.openPeriod + nameParams.biddingPeriod

        var ns = NameState(nameHash: nh, name: Array(name.utf8))
        ns.height = openHeight
        ns.renewal = openHeight
        db.putNameState(nh, ns)

        let nonce = BidNonce(unchecked: [UInt8](repeating: 0xDD, count: 32))
        let blind = try BlindBid.blind(value: 1000, nonce: nonce)
        let bidCovenant = CovenantData.makeBid(
            nameHash: nh, startHeight: openHeight,
            name: Array(name.utf8), blind: blind
        )
        let bidOutpoint = outpoint(0x04, 0)

        // REVEAL with wrong value (2000 instead of 1000)
        let revealCovenant = CovenantData.makeReveal(
            nameHash: nh, startHeight: openHeight, nonce: nonce
        )
        let tx = simpleTx(input: bidOutpoint, outputValue: 2000, covenant: revealCovenant)
        let view = viewWithCoin(at: bidOutpoint, value: 1000, covenant: bidCovenant)

        XCTAssertThrowsError(try CovenantProcessor.processCovenants(
            tx: tx, txIndex: 0, coinView: view, nameDB: db,
            height: revealHeight, network: network, nameParams: nameParams,
            chain: chain, consensusParams: ConsensusParams.params(for: .regtest)
        ))
    }

    // MARK: - Vickrey Auction Tests

    func testRevealVickreyAuction() throws {
        let db = makeNameDB()
        let chain = try makeChain()
        let name = "vickrey"
        let nh = nameHash(for: name)
        let openHeight = 10
        let revealHeight = openHeight + nameParams.openPeriod + nameParams.biddingPeriod

        var ns = NameState(nameHash: nh, name: Array(name.utf8))
        ns.height = openHeight
        ns.renewal = openHeight
        db.putNameState(nh, ns)

        // First reveal: 3000
        let nonce1 = BidNonce(unchecked: [UInt8](repeating: 0x01, count: 32))
        let blind1 = try BlindBid.blind(value: 3000, nonce: nonce1)
        let bidCov1 = CovenantData.makeBid(nameHash: nh, startHeight: openHeight, name: Array(name.utf8), blind: blind1)
        let bidOp1 = outpoint(0x10, 0)
        let revealCov1 = CovenantData.makeReveal(nameHash: nh, startHeight: openHeight, nonce: nonce1)
        let tx1 = simpleTx(input: bidOp1, outputValue: 3000, covenant: revealCov1)
        let view1 = viewWithCoin(at: bidOp1, value: 3000, covenant: bidCov1)

        try CovenantProcessor.processCovenants(
            tx: tx1, txIndex: 0, coinView: view1, nameDB: db,
            height: revealHeight, network: network, nameParams: nameParams,
            chain: chain, consensusParams: ConsensusParams.params(for: .regtest)
        )

        // Second reveal: 5000 (higher)
        let nonce2 = BidNonce(unchecked: [UInt8](repeating: 0x02, count: 32))
        let blind2 = try BlindBid.blind(value: 5000, nonce: nonce2)
        let bidCov2 = CovenantData.makeBid(nameHash: nh, startHeight: openHeight, name: Array(name.utf8), blind: blind2)
        let bidOp2 = outpoint(0x11, 0)
        let revealCov2 = CovenantData.makeReveal(nameHash: nh, startHeight: openHeight, nonce: nonce2)
        let tx2 = simpleTx(input: bidOp2, outputValue: 5000, covenant: revealCov2)
        let view2 = viewWithCoin(at: bidOp2, value: 5000, covenant: bidCov2)

        try CovenantProcessor.processCovenants(
            tx: tx2, txIndex: 1, coinView: view2, nameDB: db,
            height: revealHeight, network: network, nameParams: nameParams,
            chain: chain, consensusParams: ConsensusParams.params(for: .regtest)
        )

        let updated = try db.getNameState(nh)
        // Highest bid is 5000, second-highest (Vickrey price) is 3000
        XCTAssertEqual(updated?.highest, 5000)
        XCTAssertEqual(updated?.value, 3000)
    }

    // MARK: - REGISTER Tests

    func testRegisterOnlyWinner() throws {
        let db = makeNameDB()
        let chain = try makeChain()
        let name = "regwinner"
        let nh = nameHash(for: name)
        let openHeight = 10
        let closedHeight = openHeight + nameParams.openPeriod + nameParams.biddingPeriod + nameParams.revealPeriod

        // Set up a closed name with owner at (0x20, 0)
        var ns = NameState(nameHash: nh, name: Array(name.utf8))
        ns.height = openHeight
        ns.renewal = openHeight
        ns.owner = NameState.Outpoint(hash: txHash(0x20).bytes, index: 0)
        ns.value = 3000
        ns.highest = 5000
        db.putNameState(nh, ns)

        XCTAssertEqual(ns.state(at: closedHeight, params: nameParams), .closed)

        // Non-owner tries to register
        let loserOutpoint = outpoint(0x21, 0)
        let revealCov = CovenantData.makeReveal(
            nameHash: nh, startHeight: openHeight,
            nonce: .zero
        )
        let registerCov = CovenantData.makeRegister(
            nameHash: nh, startHeight: openHeight,
            resource: [], blockHash: [UInt8](repeating: 0, count: 32)
        )
        let tx = simpleTx(input: loserOutpoint, outputValue: 3000, covenant: registerCov)
        let view = viewWithCoin(at: loserOutpoint, value: 3000, covenant: revealCov)

        XCTAssertThrowsError(try CovenantProcessor.processCovenants(
            tx: tx, txIndex: 0, coinView: view, nameDB: db,
            height: closedHeight, network: network, nameParams: nameParams,
            chain: chain, consensusParams: ConsensusParams.params(for: .regtest)
        ))
    }

    // MARK: - TRANSFER / FINALIZE Tests

    func testTransferFinalizeLockup() throws {
        let db = makeNameDB()
        let chain = try makeChain()
        let name = "xfertest"
        let nh = nameHash(for: name)
        let openHeight = 10
        let closedHeight = openHeight + nameParams.openPeriod + nameParams.biddingPeriod + nameParams.revealPeriod

        let ownerOp = outpoint(0x30, 0)
        var ns = NameState(nameHash: nh, name: Array(name.utf8))
        ns.height = openHeight
        ns.renewal = openHeight
        ns.registered = true
        ns.owner = NameState.Outpoint(hash: txHash(0x30).bytes, index: 0)
        ns.value = 1000
        ns.highest = 2000
        ns.transfer = closedHeight // Transfer initiated at closedHeight
        db.putNameState(nh, ns)

        // FINALIZE too early (before transferLockup elapses)
        let tooEarlyHeight = closedHeight + nameParams.transferLockup - 1

        let transferCov = CovenantData.makeTransfer(
            nameHash: nh, startHeight: openHeight,
            version: 0, addressHash: [UInt8](repeating: 0, count: 20)
        )
        let finalizeCov = CovenantData.makeFinalize(
            nameHash: nh, startHeight: openHeight,
            name: Array(name.utf8), flags: 0,
            claimed: 0, renewals: 0,
            blockHash: [UInt8](repeating: 0, count: 32)
        )

        let transferOutpoint = outpoint(0x31, 0)
        let tx = simpleTx(input: transferOutpoint, outputValue: 1000, covenant: finalizeCov)
        let view = viewWithCoin(at: transferOutpoint, value: 1000, covenant: transferCov)

        XCTAssertThrowsError(try CovenantProcessor.processCovenants(
            tx: tx, txIndex: 0, coinView: view, nameDB: db,
            height: tooEarlyHeight, network: network, nameParams: nameParams,
            chain: chain, consensusParams: ConsensusParams.params(for: .regtest)
        ))
    }

    // MARK: - REVOKE Tests

    func testRevokeTerminal() throws {
        let db = makeNameDB()
        let chain = try makeChain()
        let name = "revoketest"
        let nh = nameHash(for: name)
        let openHeight = 10
        let closedHeight = openHeight + nameParams.openPeriod + nameParams.biddingPeriod + nameParams.revealPeriod

        let ownerOp = outpoint(0x40, 0)
        var ns = NameState(nameHash: nh, name: Array(name.utf8))
        ns.height = openHeight
        ns.renewal = openHeight
        ns.registered = true
        ns.owner = NameState.Outpoint(hash: txHash(0x40).bytes, index: 0)
        ns.value = 1000
        ns.highest = 2000
        ns.data = [1, 2, 3]
        db.putNameState(nh, ns)

        let registerCov = CovenantData.makeRegister(
            nameHash: nh, startHeight: openHeight,
            resource: [1, 2, 3], blockHash: [UInt8](repeating: 0, count: 32)
        )
        let revokeCov = CovenantData.makeRevoke(nameHash: nh, startHeight: openHeight)

        let tx = simpleTx(input: ownerOp, outputValue: 0, covenant: revokeCov)
        let view = viewWithCoin(at: ownerOp, value: 1000, covenant: registerCov)

        try CovenantProcessor.processCovenants(
            tx: tx, txIndex: 0, coinView: view, nameDB: db,
            height: closedHeight, network: network, nameParams: nameParams,
            chain: chain, consensusParams: ConsensusParams.params(for: .regtest)
        )

        let updated = try db.getNameState(nh)
        XCTAssertEqual(updated?.revoked, closedHeight)
        XCTAssertEqual(updated?.data, [])
        XCTAssertEqual(updated?.transfer, 0)
    }

    // MARK: - Tree Root Tests

    func testTreeRootStableAfterCommit() throws {
        let db = makeNameDB()
        let nh = nameHash(for: "treetest")

        var ns = NameState(nameHash: nh, name: Array("treetest".utf8))
        ns.height = 5
        ns.renewal = 5
        db.putNameState(nh, ns)
        try db.commit()

        let root1 = try db.treeRoot()

        // Same state committed again should produce same root
        db.putNameState(nh, ns)
        try db.commit()

        let root2 = try db.treeRoot()
        XCTAssertEqual(root1, root2)
    }

    func testTreeRootChangesWithDifferentState() throws {
        let db = makeNameDB()
        let nh = nameHash(for: "changetree")

        var ns = NameState(nameHash: nh, name: Array("changetree".utf8))
        ns.height = 5
        ns.renewal = 5
        db.putNameState(nh, ns)
        try db.commit()
        let root1 = try db.treeRoot()

        // Modify the state
        ns.height = 10
        ns.renewal = 10
        db.putNameState(nh, ns)
        try db.commit()
        let root2 = try db.treeRoot()

        XCTAssertNotEqual(root1, root2)
    }

    // MARK: - NameParams Factory Tests

    func testNameParamsFactory() {
        let main = NameParams.params(for: .main)
        XCTAssertEqual(main.treeInterval, 30)
        XCTAssertFalse(main.noRollout)

        let regtest = NameParams.params(for: .regtest)
        XCTAssertEqual(regtest.treeInterval, 5)
        XCTAssertTrue(regtest.noRollout)

        let simnet = NameParams.params(for: .simnet)
        XCTAssertEqual(simnet.treeInterval, 5)
    }

    // MARK: - Edge Case: OPEN nameHash mismatch

    func testOpenRejectsNameHashMismatch() throws {
        let db = makeNameDB()
        let chain = try makeChain()
        let name = "mismatch"
        let height = 10

        // Use a bogus nameHash that does NOT equal SHA3(rawName)
        let bogusHash = NameHash(unchecked: [UInt8](repeating: 0xDE, count: 32))
        let covenant = CovenantData.makeOpen(nameHash: bogusHash, name: Array(name.utf8))
        let tx = simpleTx(input: .null, outputValue: 0, covenant: covenant)
        var view = CoinView()
        view.addTX(tx, height: height)

        XCTAssertThrowsError(try CovenantProcessor.processCovenants(
            tx: tx, txIndex: 0, coinView: view, nameDB: db,
            height: height, network: network, nameParams: nameParams,
            chain: chain, consensusParams: ConsensusParams.params(for: .regtest)
        )) { error in
            guard let covErr = error as? CovenantsError else {
                return XCTFail("Expected CovenantsError, got \(error)")
            }
            if case .malformedCovenant(let msg) = covErr {
                XCTAssertTrue(msg.contains("nameHash"), "Expected nameHash mismatch message, got: \(msg)")
            } else {
                XCTFail("Expected malformedCovenant, got \(covErr)")
            }
        }
    }

    // MARK: - Edge Case: OPEN invalid name

    func testOpenRejectsInvalidName() throws {
        let db = makeNameDB()
        let chain = try makeChain()
        let height = 10

        // Uppercase letters in the name should be rejected
        let invalidName = "BadName"
        let nh = nameHash(for: invalidName)
        let covenant = CovenantData.makeOpen(nameHash: nh, name: Array(invalidName.utf8))
        let tx = simpleTx(input: .null, outputValue: 0, covenant: covenant)
        var view = CoinView()
        view.addTX(tx, height: height)

        XCTAssertThrowsError(try CovenantProcessor.processCovenants(
            tx: tx, txIndex: 0, coinView: view, nameDB: db,
            height: height, network: network, nameParams: nameParams,
            chain: chain, consensusParams: ConsensusParams.params(for: .regtest)
        )) { error in
            guard let covErr = error as? CovenantsError else {
                return XCTFail("Expected CovenantsError, got \(error)")
            }
            if case .malformedCovenant(let msg) = covErr {
                XCTAssertTrue(msg.contains("invalid name"), "Expected invalid name message, got: \(msg)")
            } else {
                XCTFail("Expected malformedCovenant, got \(covErr)")
            }
        }

        // Also test special characters
        let specialName = "bad!name"
        let nh2 = nameHash(for: specialName)
        let covenant2 = CovenantData.makeOpen(nameHash: nh2, name: Array(specialName.utf8))
        let tx2 = simpleTx(input: .null, outputValue: 0, covenant: covenant2)
        var view2 = CoinView()
        view2.addTX(tx2, height: height)

        XCTAssertThrowsError(try CovenantProcessor.processCovenants(
            tx: tx2, txIndex: 0, coinView: view2, nameDB: db,
            height: height, network: network, nameParams: nameParams,
            chain: chain, consensusParams: ConsensusParams.params(for: .regtest)
        ))
    }

    // MARK: - Edge Case: UPDATE requires owner outpoint

    /// Helper: set up a registered name and return the name hash, open height, and closed height.
    private func setupRegisteredName(
        _ name: String,
        db: NameDB,
        ownerSeed: UInt8
    ) -> (nh: NameHash, openHeight: Int, closedHeight: Int) {
        let nh = nameHash(for: name)
        let openHeight = 10
        let closedHeight = openHeight + nameParams.openPeriod + nameParams.biddingPeriod + nameParams.revealPeriod

        var ns = NameState(nameHash: nh, name: Array(name.utf8))
        ns.height = openHeight
        ns.renewal = openHeight
        ns.registered = true
        ns.owner = NameState.Outpoint(hash: txHash(ownerSeed).bytes, index: 0)
        ns.value = 1000
        ns.highest = 2000
        db.putNameState(nh, ns)

        return (nh, openHeight, closedHeight)
    }

    func testUpdateRequiresOwnerOutpoint() throws {
        let db = makeNameDB()
        let chain = try makeChain()
        let (nh, openHeight, closedHeight) = setupRegisteredName("updown", db: db, ownerSeed: 0x50)

        // Non-owner input tries to UPDATE
        let nonOwnerOp = outpoint(0x99, 0)
        let registerCov = CovenantData.makeRegister(
            nameHash: nh, startHeight: openHeight,
            resource: [], blockHash: [UInt8](repeating: 0, count: 32)
        )
        let updateCov = CovenantData.makeUpdate(nameHash: nh, startHeight: openHeight, resource: [])
        let tx = simpleTx(input: nonOwnerOp, outputValue: 1000, covenant: updateCov)
        let view = viewWithCoin(at: nonOwnerOp, value: 1000, covenant: registerCov)

        XCTAssertThrowsError(try CovenantProcessor.processCovenants(
            tx: tx, txIndex: 0, coinView: view, nameDB: db,
            height: closedHeight, network: network, nameParams: nameParams,
            chain: chain, consensusParams: ConsensusParams.params(for: .regtest)
        )) { error in
            guard let covErr = error as? CovenantsError else {
                return XCTFail("Expected CovenantsError, got \(error)")
            }
            if case .wrongAuctionState(let msg) = covErr {
                XCTAssertTrue(msg.contains("only owner can UPDATE"), "Got: \(msg)")
            } else {
                XCTFail("Expected wrongAuctionState, got \(covErr)")
            }
        }
    }

    // MARK: - Edge Case: TRANSFER requires owner outpoint

    func testTransferRequiresOwnerOutpoint() throws {
        let db = makeNameDB()
        let chain = try makeChain()
        let (nh, openHeight, closedHeight) = setupRegisteredName("xferbad", db: db, ownerSeed: 0x51)

        let nonOwnerOp = outpoint(0x99, 0)
        let registerCov = CovenantData.makeRegister(
            nameHash: nh, startHeight: openHeight,
            resource: [], blockHash: [UInt8](repeating: 0, count: 32)
        )
        let transferCov = CovenantData.makeTransfer(
            nameHash: nh, startHeight: openHeight,
            version: 0, addressHash: [UInt8](repeating: 0, count: 20)
        )
        let tx = simpleTx(input: nonOwnerOp, outputValue: 1000, covenant: transferCov)
        let view = viewWithCoin(at: nonOwnerOp, value: 1000, covenant: registerCov)

        XCTAssertThrowsError(try CovenantProcessor.processCovenants(
            tx: tx, txIndex: 0, coinView: view, nameDB: db,
            height: closedHeight, network: network, nameParams: nameParams,
            chain: chain, consensusParams: ConsensusParams.params(for: .regtest)
        )) { error in
            guard let covErr = error as? CovenantsError else {
                return XCTFail("Expected CovenantsError, got \(error)")
            }
            if case .wrongAuctionState(let msg) = covErr {
                XCTAssertTrue(msg.contains("only owner can TRANSFER"), "Got: \(msg)")
            } else {
                XCTFail("Expected wrongAuctionState, got \(covErr)")
            }
        }
    }

    // MARK: - Edge Case: RENEW requires owner outpoint

    func testRenewRequiresOwnerOutpoint() throws {
        let db = makeNameDB()
        let chain = try makeChain()
        let (nh, openHeight, closedHeight) = setupRegisteredName("renewbad", db: db, ownerSeed: 0x52)

        let nonOwnerOp = outpoint(0x99, 0)
        let registerCov = CovenantData.makeRegister(
            nameHash: nh, startHeight: openHeight,
            resource: [], blockHash: [UInt8](repeating: 0, count: 32)
        )
        let renewCov = CovenantData.makeRenew(
            nameHash: nh, startHeight: openHeight,
            blockHash: [UInt8](repeating: 0, count: 32)
        )
        let tx = simpleTx(input: nonOwnerOp, outputValue: 1000, covenant: renewCov)
        let view = viewWithCoin(at: nonOwnerOp, value: 1000, covenant: registerCov)

        XCTAssertThrowsError(try CovenantProcessor.processCovenants(
            tx: tx, txIndex: 0, coinView: view, nameDB: db,
            height: closedHeight, network: network, nameParams: nameParams,
            chain: chain, consensusParams: ConsensusParams.params(for: .regtest)
        )) { error in
            guard let covErr = error as? CovenantsError else {
                return XCTFail("Expected CovenantsError, got \(error)")
            }
            if case .wrongAuctionState(let msg) = covErr {
                XCTAssertTrue(msg.contains("only owner can RENEW"), "Got: \(msg)")
            } else {
                XCTFail("Expected wrongAuctionState, got \(covErr)")
            }
        }
    }

    // MARK: - Edge Case: FINALIZE requires owner outpoint

    func testFinalizeRequiresOwnerOutpoint() throws {
        let db = makeNameDB()
        let chain = try makeChain()
        let (nh, openHeight, closedHeight) = setupRegisteredName("finbad", db: db, ownerSeed: 0x53)

        // Set up transfer so FINALIZE is otherwise valid
        var ns = try db.getNameState(nh)!
        ns.transfer = closedHeight
        db.putNameState(nh, ns)

        let finalizeHeight = closedHeight + nameParams.transferLockup

        let nonOwnerOp = outpoint(0x99, 0)
        let transferCov = CovenantData.makeTransfer(
            nameHash: nh, startHeight: openHeight,
            version: 0, addressHash: [UInt8](repeating: 0, count: 20)
        )
        let finalizeCov = CovenantData.makeFinalize(
            nameHash: nh, startHeight: openHeight,
            name: Array("finbad".utf8), flags: 0,
            claimed: 0, renewals: 0,
            blockHash: [UInt8](repeating: 0, count: 32)
        )
        let tx = simpleTx(input: nonOwnerOp, outputValue: 1000, covenant: finalizeCov)
        let view = viewWithCoin(at: nonOwnerOp, value: 1000, covenant: transferCov)

        XCTAssertThrowsError(try CovenantProcessor.processCovenants(
            tx: tx, txIndex: 0, coinView: view, nameDB: db,
            height: finalizeHeight, network: network, nameParams: nameParams,
            chain: chain, consensusParams: ConsensusParams.params(for: .regtest)
        )) { error in
            guard let covErr = error as? CovenantsError else {
                return XCTFail("Expected CovenantsError, got \(error)")
            }
            if case .wrongAuctionState(let msg) = covErr {
                XCTAssertTrue(msg.contains("only owner can FINALIZE"), "Got: \(msg)")
            } else {
                XCTFail("Expected wrongAuctionState, got \(covErr)")
            }
        }
    }

    // MARK: - Edge Case: REVOKE requires owner outpoint

    func testRevokeRequiresOwnerOutpoint() throws {
        let db = makeNameDB()
        let chain = try makeChain()
        let (nh, openHeight, closedHeight) = setupRegisteredName("revbad", db: db, ownerSeed: 0x54)

        let nonOwnerOp = outpoint(0x99, 0)
        let registerCov = CovenantData.makeRegister(
            nameHash: nh, startHeight: openHeight,
            resource: [], blockHash: [UInt8](repeating: 0, count: 32)
        )
        let revokeCov = CovenantData.makeRevoke(nameHash: nh, startHeight: openHeight)
        let tx = simpleTx(input: nonOwnerOp, outputValue: 0, covenant: revokeCov)
        let view = viewWithCoin(at: nonOwnerOp, value: 1000, covenant: registerCov)

        XCTAssertThrowsError(try CovenantProcessor.processCovenants(
            tx: tx, txIndex: 0, coinView: view, nameDB: db,
            height: closedHeight, network: network, nameParams: nameParams,
            chain: chain, consensusParams: ConsensusParams.params(for: .regtest)
        )) { error in
            guard let covErr = error as? CovenantsError else {
                return XCTFail("Expected CovenantsError, got \(error)")
            }
            if case .wrongAuctionState(let msg) = covErr {
                XCTAssertTrue(msg.contains("only owner can REVOKE"), "Got: \(msg)")
            } else {
                XCTFail("Expected wrongAuctionState, got \(covErr)")
            }
        }
    }

    // MARK: - Edge Case: UPDATE rejects wrong input covenant type

    func testUpdateRejectsWrongInputCovenantType() throws {
        let db = makeNameDB()
        let chain = try makeChain()
        let name = "badtrans"
        let nh = nameHash(for: name)
        let openHeight = 10
        let closedHeight = openHeight + nameParams.openPeriod + nameParams.biddingPeriod + nameParams.revealPeriod

        // Set up a registered name where the owner outpoint matches what we will use
        let ownerOp = outpoint(0x60, 0)
        var ns = NameState(nameHash: nh, name: Array(name.utf8))
        ns.height = openHeight
        ns.renewal = openHeight
        ns.registered = true
        ns.owner = NameState.Outpoint(hash: txHash(0x60).bytes, index: 0)
        ns.value = 1000
        ns.highest = 2000
        db.putNameState(nh, ns)

        // Input coin has a .bid covenant (invalid for UPDATE transition)
        let bidCov = CovenantData.makeBid(
            nameHash: nh, startHeight: openHeight,
            name: Array(name.utf8),
            blind: [UInt8](repeating: 0, count: 32)
        )
        let updateCov = CovenantData.makeUpdate(nameHash: nh, startHeight: openHeight, resource: [])
        let tx = simpleTx(input: ownerOp, outputValue: 1000, covenant: updateCov)
        let view = viewWithCoin(at: ownerOp, value: 1000, covenant: bidCov)

        XCTAssertThrowsError(try CovenantProcessor.processCovenants(
            tx: tx, txIndex: 0, coinView: view, nameDB: db,
            height: closedHeight, network: network, nameParams: nameParams,
            chain: chain, consensusParams: ConsensusParams.params(for: .regtest)
        )) { error in
            guard let covErr = error as? CovenantsError else {
                return XCTFail("Expected CovenantsError, got \(error)")
            }
            if case .invalidStateTransition = covErr {
                // Expected
            } else {
                XCTFail("Expected invalidStateTransition, got \(covErr)")
            }
        }
    }

    // MARK: - Edge Case: REGISTER rejects nil owner

    func testRegisterRejectsNilOwner() throws {
        let db = makeNameDB()
        let chain = try makeChain()
        let name = "nilowner"
        let nh = nameHash(for: name)
        let openHeight = 10
        let closedHeight = openHeight + nameParams.openPeriod + nameParams.biddingPeriod + nameParams.revealPeriod

        // Set up a name in closed state but with owner = nil (no reveals happened)
        var ns = NameState(nameHash: nh, name: Array(name.utf8))
        ns.height = openHeight
        ns.renewal = openHeight
        // owner is nil by default — nobody revealed
        db.putNameState(nh, ns)

        XCTAssertEqual(ns.state(at: closedHeight, params: nameParams), .closed)

        let revealCov = CovenantData.makeReveal(
            nameHash: nh, startHeight: openHeight,
            nonce: .zero
        )
        let registerCov = CovenantData.makeRegister(
            nameHash: nh, startHeight: openHeight,
            resource: [], blockHash: [UInt8](repeating: 0, count: 32)
        )
        let inputOp = outpoint(0x70, 0)
        let tx = simpleTx(input: inputOp, outputValue: 0, covenant: registerCov)
        let view = viewWithCoin(at: inputOp, value: 1000, covenant: revealCov)

        XCTAssertThrowsError(try CovenantProcessor.processCovenants(
            tx: tx, txIndex: 0, coinView: view, nameDB: db,
            height: closedHeight, network: network, nameParams: nameParams,
            chain: chain, consensusParams: ConsensusParams.params(for: .regtest)
        )) { error in
            guard let covErr = error as? CovenantsError else {
                return XCTFail("Expected CovenantsError, got \(error)")
            }
            // Owner is nil, so the owner check guard will fail
            if case .wrongAuctionState(let msg) = covErr {
                XCTAssertTrue(msg.contains("owner"), "Expected owner-related message, got: \(msg)")
            } else {
                XCTFail("Expected wrongAuctionState for nil owner, got \(covErr)")
            }
        }
    }

    // MARK: - Edge Case: REDEEM validates input type

    func testRedeemValidatesInputType() throws {
        let db = makeNameDB()
        let chain = try makeChain()
        let name = "redeemval"
        let nh = nameHash(for: name)
        let openHeight = 10
        let closedHeight = openHeight + nameParams.openPeriod + nameParams.biddingPeriod + nameParams.revealPeriod

        // Set up a closed name with an owner (so it is closed, not expired)
        var ns = NameState(nameHash: nh, name: Array(name.utf8))
        ns.height = openHeight
        ns.renewal = openHeight
        ns.registered = true
        ns.owner = NameState.Outpoint(hash: txHash(0xAA).bytes, index: 0)
        ns.value = 1000
        ns.highest = 2000
        db.putNameState(nh, ns)

        XCTAssertEqual(ns.state(at: closedHeight, params: nameParams), .closed)

        // Input coin has a .bid covenant (invalid: REDEEM input must be REVEAL)
        let bidCov = CovenantData.makeBid(
            nameHash: nh, startHeight: openHeight,
            name: Array(name.utf8),
            blind: [UInt8](repeating: 0, count: 32)
        )
        let redeemCov = CovenantData.makeRedeem(nameHash: nh, startHeight: openHeight)
        let inputOp = outpoint(0x71, 0)
        let tx = simpleTx(input: inputOp, outputValue: 0, covenant: redeemCov)
        let view = viewWithCoin(at: inputOp, value: 1000, covenant: bidCov)

        XCTAssertThrowsError(try CovenantProcessor.processCovenants(
            tx: tx, txIndex: 0, coinView: view, nameDB: db,
            height: closedHeight, network: network, nameParams: nameParams,
            chain: chain, consensusParams: ConsensusParams.params(for: .regtest)
        )) { error in
            guard let covErr = error as? CovenantsError else {
                return XCTFail("Expected CovenantsError, got \(error)")
            }
            if case .invalidStateTransition = covErr {
                // Expected: REDEEM input must be REVEAL
            } else {
                XCTFail("Expected invalidStateTransition, got \(covErr)")
            }
        }
    }

    // MARK: - Edge Case: REGISTER delegation check after flags

    func testRegisterDelegationCheckAfterFlags() throws {
        let db = makeNameDB()
        let chain = try makeChain()
        let name = "subdelflag"
        let nh = nameHash(for: name)
        let openHeight = 0
        let height = 5 // below regtest renewalMaturity (10) so zeroed blockHash passes

        let ownerOp = outpoint(0x80, 0)
        var ns = NameState(nameHash: nh, name: Array(name.utf8))
        ns.height = openHeight
        ns.renewal = openHeight
        ns.registered = true // enables early .closed state at low heights
        ns.owner = NameState.Outpoint(hash: txHash(0x80).bytes, index: 0)
        ns.value = 1000
        ns.highest = 2000
        // flags = 0 initially (auctionSubdomains not yet set)
        db.putNameState(nh, ns)

        XCTAssertEqual(ns.state(at: height, params: nameParams), .closed)

        // Resource containing a delegation record (NS record, type=1)
        // Resource format: [version=0] [type=1 (NS)] [DNS name "ns.example" encoded]
        let delegationResource: [UInt8] = [
            0x00,       // version
            0x01,       // NS record type
            0x02, 0x6E, 0x73, // "ns" label (len=2)
            0x07, 0x65, 0x78, 0x61, 0x6D, 0x70, 0x6C, 0x65, // "example" label (len=7)
            0x00,       // end of name
        ]

        // REGISTER with flags=1 (enable auctionSubdomains) AND delegation resource
        let registerCov = CovenantData.makeRegister(
            nameHash: nh, startHeight: openHeight,
            resource: delegationResource,
            blockHash: [UInt8](repeating: 0, count: 32),
            flags: 1  // enable auctionSubdomains
        )
        let revealCov = CovenantData.makeReveal(
            nameHash: nh, startHeight: openHeight,
            nonce: .zero
        )

        let tx = simpleTx(input: ownerOp, outputValue: 0, covenant: registerCov)
        let view = viewWithCoin(at: ownerOp, value: 1000, covenant: revealCov)

        // Should throw delegationNotAllowedWithSubdomains because:
        // 1. flags are applied first (enabling auctionSubdomains)
        // 2. then delegation check sees auctionSubdomains=true + delegation records
        XCTAssertThrowsError(try CovenantProcessor.processCovenants(
            tx: tx, txIndex: 0, coinView: view, nameDB: db,
            height: height, network: network, nameParams: nameParams,
            chain: chain, consensusParams: ConsensusParams.params(for: .regtest)
        )) { error in
            guard let covErr = error as? CovenantsError else {
                return XCTFail("Expected CovenantsError, got \(error)")
            }
            XCTAssertEqual(covErr, CovenantsError.delegationNotAllowedWithSubdomains)
        }
    }

    // MARK: - Edge Case: Claimed outputs prevents payment reuse

    func testClaimedOutputsPreventsPaymentReuse() throws {
        let db = makeNameDB()
        let chain = try makeChain()
        let cp = ConsensusParams.regtest

        // Register two names that both need dev fund payment
        let name1 = "claimone"
        let name2 = "claimtwo"
        let nh1 = nameHash(for: name1)
        let nh2 = nameHash(for: name2)
        let openHeight = 0
        let height = 5 // below regtest renewalMaturity (10) so zeroed blockHash passes

        let ownerOp1 = outpoint(0x81, 0)
        let ownerOp2 = outpoint(0x82, 0)

        // Set up name1 with a non-zero value so payment is required
        var ns1 = NameState(nameHash: nh1, name: Array(name1.utf8))
        ns1.height = openHeight
        ns1.renewal = openHeight
        ns1.registered = true // enables early .closed state at low heights
        ns1.owner = NameState.Outpoint(hash: txHash(0x81).bytes, index: 0)
        ns1.value = 1000
        ns1.highest = 2000
        db.putNameState(nh1, ns1)

        // Set up name2 with a non-zero value so payment is required
        var ns2 = NameState(nameHash: nh2, name: Array(name2.utf8))
        ns2.height = openHeight
        ns2.renewal = openHeight
        ns2.registered = true // enables early .closed state at low heights
        ns2.owner = NameState.Outpoint(hash: txHash(0x82).bytes, index: 0)
        ns2.value = 1000
        ns2.highest = 2000
        db.putNameState(nh2, ns2)

        let revealCov1 = CovenantData.makeReveal(
            nameHash: nh1, startHeight: openHeight,
            nonce: BidNonce(unchecked: [UInt8](repeating: 0x01, count: 32))
        )
        let revealCov2 = CovenantData.makeReveal(
            nameHash: nh2, startHeight: openHeight,
            nonce: BidNonce(unchecked: [UInt8](repeating: 0x02, count: 32))
        )
        let registerCov1 = CovenantData.makeRegister(
            nameHash: nh1, startHeight: openHeight,
            resource: [], blockHash: [UInt8](repeating: 0, count: 32)
        )
        let registerCov2 = CovenantData.makeRegister(
            nameHash: nh2, startHeight: openHeight,
            resource: [], blockHash: [UInt8](repeating: 0, count: 32)
        )

        let devFundAddr = Address(unchecked: cp.devFundVersion, hash: cp.devFundAddress)
        // regtest registrationBurnPercent = 50, so devShare = value * 50 / 100 = 500
        // Only ONE dev fund payment output (should be claimed by first REGISTER)
        let tx = Transaction(
            inputs: [
                Input(prevout: ownerOp1),
                Input(prevout: ownerOp2),
            ],
            outputs: [
                Output(value: 0, address: .null, covenant: registerCov1),
                Output(value: 0, address: .null, covenant: registerCov2),
                Output(value: 500, address: devFundAddr, covenant: .none), // single payment
                Output(value: 500, address: .null, covenant: .none), // burn for first
            ]
        )
        var view = CoinView()
        view.addEntry(ownerOp1, CoinEntry.fromOutput(
            Output(value: 1000, address: .null, covenant: revealCov1),
            height: 1, coinbase: false))
        view.addEntry(ownerOp2, CoinEntry.fromOutput(
            Output(value: 1000, address: .null, covenant: revealCov2),
            height: 1, coinbase: false))

        // Second REGISTER should fail because the dev fund payment was already claimed
        XCTAssertThrowsError(try CovenantProcessor.processCovenants(
            tx: tx, txIndex: 0, coinView: view, nameDB: db,
            height: height, network: network, nameParams: nameParams,
            chain: chain, consensusParams: cp
        )) { error in
            guard let covErr = error as? CovenantsError else {
                return XCTFail("Expected CovenantsError, got \(error)")
            }
            // Should fail on burn or dev fund insufficient for the second register
            switch covErr {
            case .devFundPaymentInsufficient, .burnPaymentInsufficient:
                break // expected
            default:
                XCTFail("Expected payment insufficient error, got \(covErr)")
            }
        }
    }

    // MARK: - Edge Case: UPDATE rejects address mismatch

    func testUpdateRejectsAddressMismatch() throws {
        let db = makeNameDB()
        let chain = try makeChain()
        let name = "addrmis"
        let nh = nameHash(for: name)
        let openHeight = 10
        let closedHeight = openHeight + nameParams.openPeriod + nameParams.biddingPeriod + nameParams.revealPeriod

        let ownerOp = outpoint(0x61, 0)
        let inputAddr = Address(unchecked: 0, hash: [UInt8](repeating: 0x11, count: 20))
        let outputAddr = Address(unchecked: 0, hash: [UInt8](repeating: 0x22, count: 20))

        var ns = NameState(nameHash: nh, name: Array(name.utf8))
        ns.height = openHeight
        ns.renewal = openHeight
        ns.registered = true
        ns.owner = NameState.Outpoint(hash: txHash(0x61).bytes, index: 0)
        ns.value = 1000
        ns.highest = 2000
        db.putNameState(nh, ns)

        let registerCov = CovenantData.makeRegister(
            nameHash: nh, startHeight: openHeight,
            resource: [], blockHash: [UInt8](repeating: 0, count: 32)
        )
        let updateCov = CovenantData.makeUpdate(nameHash: nh, startHeight: openHeight, resource: [])

        // Input coin has inputAddr, output has different outputAddr
        let tx = Transaction(
            inputs: [Input(prevout: ownerOp)],
            outputs: [Output(value: 1000, address: outputAddr, covenant: updateCov)]
        )
        let inputOutput = Output(value: 1000, address: inputAddr, covenant: registerCov)
        let entry = CoinEntry.fromOutput(inputOutput, height: 100, coinbase: false)
        var view = CoinView()
        view.addEntry(ownerOp, entry)

        XCTAssertThrowsError(try CovenantProcessor.processCovenants(
            tx: tx, txIndex: 0, coinView: view, nameDB: db,
            height: closedHeight, network: network, nameParams: nameParams,
            chain: chain, consensusParams: ConsensusParams.params(for: .regtest)
        )) { error in
            guard let covErr = error as? CovenantsError else {
                return XCTFail("Expected CovenantsError, got \(error)")
            }
            if case .wrongAuctionState(let msg) = covErr {
                XCTAssertTrue(msg.contains("address mismatch"), "Got: \(msg)")
            } else {
                XCTFail("Expected wrongAuctionState with address mismatch, got \(covErr)")
            }
        }
    }

    // MARK: - Edge Case: maybeExpire resets state

    func testMaybeExpireResetsState() throws {
        let name = "expirethis"
        let nh = nameHash(for: name)
        let openHeight = 10

        var ns = NameState(nameHash: nh, name: Array(name.utf8))
        ns.height = openHeight
        ns.renewal = openHeight
        ns.registered = true
        ns.owner = NameState.Outpoint(hash: txHash(0xBB).bytes, index: 0)
        ns.value = 5000
        ns.highest = 10000
        ns.data = [1, 2, 3]

        // Advance past the renewal window
        let expiredHeight = openHeight + nameParams.renewalWindow + 1

        // Verify name is expired
        XCTAssertTrue(ns.isExpired(at: expiredHeight, params: nameParams))

        // Apply maybeExpire
        let didExpire = ns.maybeExpire(at: expiredHeight, params: nameParams)
        XCTAssertTrue(didExpire)

        // State should be reset
        XCTAssertEqual(ns.height, expiredHeight)
        XCTAssertEqual(ns.renewal, expiredHeight)
        XCTAssertNil(ns.owner)
        XCTAssertEqual(ns.value, 0)
        XCTAssertEqual(ns.highest, 0)
        XCTAssertFalse(ns.registered)
        XCTAssertTrue(ns.expired)

        // After expiry, name should be back in opening state
        XCTAssertEqual(ns.state(at: expiredHeight, params: nameParams), .opening)
    }

    // MARK: - Edge Case: REGISTER deadline enforced

    func testRegisterDeadlineEnforced() throws {
        let db = makeNameDB()
        let chain = try makeChain()
        let name = "deadlined"
        let nh = nameHash(for: name)
        let openHeight = 10
        let closedHeight = openHeight + nameParams.openPeriod + nameParams.biddingPeriod + nameParams.revealPeriod

        let ownerOp = outpoint(0x90, 0)
        var ns = NameState(nameHash: nh, name: Array(name.utf8))
        ns.height = openHeight
        ns.renewal = openHeight
        ns.owner = NameState.Outpoint(hash: txHash(0x90).bytes, index: 0)
        ns.value = 1000
        ns.highest = 2000
        // NOT yet registered
        db.putNameState(nh, ns)

        let deadlineHeight = ns.registerDeadlineHeight(params: nameParams)

        let revealCov = CovenantData.makeReveal(
            nameHash: nh, startHeight: openHeight,
            nonce: .zero
        )
        let registerCov = CovenantData.makeRegister(
            nameHash: nh, startHeight: openHeight,
            resource: [], blockHash: [UInt8](repeating: 0, count: 32)
        )
        let tx = simpleTx(input: ownerOp, outputValue: 0, covenant: registerCov)
        let view = viewWithCoin(at: ownerOp, value: 1000, covenant: revealCov)

        // At exactly the deadline height, the deadline check should pass
        // (it may still fail on renewal block validation since we use a dummy hash,
        // but should NOT fail with "deadline has passed")
        do {
            try CovenantProcessor.processCovenants(
                tx: tx, txIndex: 0, coinView: view, nameDB: db,
                height: deadlineHeight, network: network, nameParams: nameParams,
                chain: chain, consensusParams: ConsensusParams.params(for: .regtest)
            )
        } catch let error as CovenantsError {
            if case .wrongAuctionState(let msg) = error {
                XCTAssertFalse(msg.contains("deadline"),
                    "Deadline check should pass at exactly the deadline height, got: \(msg)")
            }
        } catch {}

        // One block after the deadline should fail with a deadline error
        XCTAssertThrowsError(try CovenantProcessor.processCovenants(
            tx: tx, txIndex: 0, coinView: view, nameDB: db,
            height: deadlineHeight + 1, network: network, nameParams: nameParams,
            chain: chain, consensusParams: ConsensusParams.params(for: .regtest)
        )) { error in
            guard let covErr = error as? CovenantsError else {
                return XCTFail("Expected CovenantsError, got \(error)")
            }
            if case .wrongAuctionState(let msg) = covErr {
                XCTAssertTrue(msg.contains("deadline") || msg.contains("expired"),
                              "Expected deadline-related message, got: \(msg)")
            } else {
                XCTFail("Expected wrongAuctionState, got \(covErr)")
            }
        }
    }

    // MARK: - Edge Case: Renewal fee required

    func testRenewalFeeRequired() throws {
        let db = makeNameDB()
        let chain = try makeChain()
        let cp = ConsensusParams.regtest
        let name = "renewfee"
        let nh = nameHash(for: name)
        let openHeight = 0
        let height = 5 // below regtest renewalMaturity (10) so zeroed blockHash passes

        let ownerOp = outpoint(0x91, 0)
        var ns = NameState(nameHash: nh, name: Array(name.utf8))
        ns.height = openHeight
        ns.renewal = openHeight
        ns.registered = true // enables early .closed state at low heights
        ns.owner = NameState.Outpoint(hash: txHash(0x91).bytes, index: 0)
        ns.value = 100_000 // High enough that 1% renewal fee > 0
        ns.highest = 200_000
        db.putNameState(nh, ns)

        let registerCov = CovenantData.makeRegister(
            nameHash: nh, startHeight: openHeight,
            resource: [], blockHash: [UInt8](repeating: 0, count: 32)
        )
        let renewCov = CovenantData.makeRenew(
            nameHash: nh, startHeight: openHeight,
            blockHash: [UInt8](repeating: 0, count: 32)
        )

        // Transaction with NO dev fund payment output
        let tx = simpleTx(input: ownerOp, outputValue: 100_000, covenant: renewCov)
        let view = viewWithCoin(at: ownerOp, value: 100_000, covenant: registerCov, height: 1)

        XCTAssertThrowsError(try CovenantProcessor.processCovenants(
            tx: tx, txIndex: 0, coinView: view, nameDB: db,
            height: height, network: network, nameParams: nameParams,
            chain: chain, consensusParams: cp
        )) { error in
            guard let covErr = error as? CovenantsError else {
                return XCTFail("Expected CovenantsError, got \(error)")
            }
            if case .renewalFeeTooLow = covErr {
                // Expected (individual validation)
            } else if case .devFundPaymentInsufficient = covErr {
                // Expected (deferred batch validation)
            } else {
                XCTFail("Expected renewalFeeTooLow or devFundPaymentInsufficient, got \(covErr)")
            }
        }
    }

    // MARK: - Edge Case: Minimum bid enforced

    func testMinimumBidEnforced() throws {
        let db = makeNameDB()
        let chain = try makeChain()
        let name = "lowbid"
        let nh = nameHash(for: name)
        let openHeight = 10
        let bidHeight = openHeight + nameParams.openPeriod

        var ns = NameState(nameHash: nh, name: Array(name.utf8))
        ns.height = openHeight
        ns.renewal = openHeight
        db.putNameState(nh, ns)

        XCTAssertEqual(ns.state(at: bidHeight, params: nameParams), .bidding)

        // Use mainnet params where minimumBid > 0
        let mainParams = NameParams.mainnet
        let mainBidHeight = openHeight + mainParams.openPeriod

        // Reset name state for mainnet timing
        var nsMain = NameState(nameHash: nh, name: Array(name.utf8))
        nsMain.height = openHeight
        nsMain.renewal = openHeight
        db.putNameState(nh, nsMain)

        XCTAssertEqual(nsMain.state(at: mainBidHeight, params: mainParams), .bidding)

        let minBid = mainParams.minimumBid(atHeight: mainBidHeight, rawName: Array(name.utf8))
        // Ensure minimum bid is > 0 for this test to be meaningful
        guard minBid > 0 else {
            // If minimum bid is 0 on mainnet for this name, the test is not applicable.
            // This should not happen for standard TLD names on mainnet.
            return
        }

        let tooLowValue = UInt64(minBid - 1)
        let blind = try BlindBid.blind(value: tooLowValue, nonce: BidNonce(unchecked: [UInt8](repeating: 0xEE, count: 32)))
        let bidCov = CovenantData.makeBid(
            nameHash: nh, startHeight: openHeight,
            name: Array(name.utf8), blind: blind
        )
        let tx = simpleTx(input: outpoint(0x92, 0), outputValue: tooLowValue, covenant: bidCov)
        let view = viewWithCoin(at: outpoint(0x92, 0), value: tooLowValue, covenant: .none)

        let mainChain = try Chain(network: .main)

        XCTAssertThrowsError(try CovenantProcessor.processCovenants(
            tx: tx, txIndex: 0, coinView: view, nameDB: db,
            height: mainBidHeight, network: .main, nameParams: mainParams,
            chain: mainChain, consensusParams: ConsensusParams.params(for: .main)
        )) { error in
            guard let covErr = error as? CovenantsError else {
                return XCTFail("Expected CovenantsError, got \(error)")
            }
            if case .bidTooLow(let minimum, let actual) = covErr {
                XCTAssertEqual(minimum, minBid)
                XCTAssertEqual(actual, Int64(tooLowValue))
            } else {
                XCTFail("Expected bidTooLow, got \(covErr)")
            }
        }
    }

    // MARK: - Edge Case: FINALIZE rejects address mismatch with TRANSFER target

    func testFinalizeRejectsAddressMismatch() throws {
        let db = makeNameDB()
        let chain = try makeChain()
        let name = "finaddr"
        let nh = nameHash(for: name)
        // Use openHeight=9 so finalizeHeight=50, keeping genesis (height 0)
        // within the renewal window: age=50, renewalMaturity=10, renewalPeriod=50.
        let openHeight = 9
        let closedHeight = openHeight + nameParams.openPeriod + nameParams.biddingPeriod + nameParams.revealPeriod

        let ownerOp = outpoint(0xA0, 0)
        var ns = NameState(nameHash: nh, name: Array(name.utf8))
        ns.height = openHeight
        ns.renewal = openHeight
        ns.registered = true
        ns.owner = NameState.Outpoint(hash: txHash(0xA0).bytes, index: 0)
        ns.value = 1000
        ns.highest = 2000
        ns.transfer = closedHeight // Transfer initiated at closedHeight
        db.putNameState(nh, ns)

        let finalizeHeight = closedHeight + nameParams.transferLockup

        // TRANSFER covenant targets address 0xAA*20 with version 0
        let transferAddrHash = [UInt8](repeating: 0xAA, count: 20)
        let transferCov = CovenantData.makeTransfer(
            nameHash: nh, startHeight: openHeight,
            version: 0, addressHash: transferAddrHash
        )

        // FINALIZE output uses a DIFFERENT address hash (0xBB*20)
        // Use the genesis block hash as a valid renewal block reference.
        let mismatchedAddr = Address(unchecked: 0, hash: [UInt8](repeating: 0xBB, count: 20))
        let finalizeCov = CovenantData.makeFinalize(
            nameHash: nh, startHeight: openHeight,
            name: Array(name.utf8), flags: 0,
            claimed: 0, renewals: 0,
            blockHash: chain.tip.hash.bytes
        )

        let tx = Transaction(
            inputs: [Input(prevout: ownerOp)],
            outputs: [Output(value: 1000, address: mismatchedAddr, covenant: finalizeCov)]
        )
        let view = viewWithCoin(at: ownerOp, value: 1000, covenant: transferCov)

        XCTAssertThrowsError(try CovenantProcessor.processCovenants(
            tx: tx, txIndex: 0, coinView: view, nameDB: db,
            height: finalizeHeight, network: network, nameParams: nameParams,
            chain: chain, consensusParams: ConsensusParams.params(for: .regtest)
        )) { error in
            guard let covErr = error as? CovenantsError else {
                return XCTFail("Expected CovenantsError, got \(error)")
            }
            if case .wrongAuctionState(let msg) = covErr {
                XCTAssertTrue(msg.contains("FINALIZE output address must match TRANSFER target"),
                    "Expected TRANSFER target mismatch message, got: \(msg)")
            } else {
                XCTFail("Expected wrongAuctionState, got \(covErr)")
            }
        }
    }

    // MARK: - Auction Cycle Value-Flow
    //
    // Scenario under test:
    //   BID locks 10_000 (lockup), committing to trueBid = 1_000 via a blind.
    //   Expected (per auction spec): winner pays regPrice and the remaining
    //   lockup comes back at REGISTER; loser gets the full lockup back at REDEEM.
    //
    // These tests document the CURRENT behaviour at each stage so we can see
    // which step (if any) deviates from the spec.

    func testAuctionCycle_reveal_releasesLockupMinusTrueBidAsChange() throws {
        let db = makeNameDB()
        let chain = try makeChain()
        let name = "flowreveal"
        let nh = nameHash(for: name)
        let openHeight = 10
        let revealHeight = openHeight + nameParams.openPeriod + nameParams.biddingPeriod

        var ns = NameState(nameHash: nh, name: Array(name.utf8))
        ns.height = openHeight
        ns.renewal = openHeight
        db.putNameState(nh, ns)
        XCTAssertEqual(ns.state(at: revealHeight, params: nameParams), .reveal)

        let lockup: UInt64 = 10_000
        let trueBid: UInt64 = 1_000

        let nonce = BidNonce(unchecked: [UInt8](repeating: 0xAB, count: 32))
        let blind = try BlindBid.blind(value: trueBid, nonce: nonce)
        let bidCov = CovenantData.makeBid(
            nameHash: nh, startHeight: openHeight,
            name: Array(name.utf8), blind: blind
        )
        let bidOp = outpoint(0xB0, 0)
        let revealCov = CovenantData.makeReveal(
            nameHash: nh, startHeight: openHeight, nonce: nonce
        )

        // BID input (10_000) -> REVEAL output (1_000) + .none change (9_000).
        // If the spec were "lockup stays locked until REGISTER/REDEEM", this
        // tx would be rejected — the REVEAL should be forced to value=lockup.
        let revealTx = Transaction(
            inputs: [Input(prevout: bidOp)],
            outputs: [
                Output(value: trueBid, address: .null, covenant: revealCov),
                Output(value: lockup - trueBid, address: .null, covenant: .none),
            ]
        )
        let view = viewWithCoin(at: bidOp, value: lockup, covenant: bidCov)

        try CovenantProcessor.processCovenants(
            tx: revealTx, txIndex: 0, coinView: view, nameDB: db,
            height: revealHeight, network: network, nameParams: nameParams,
            chain: chain, consensusParams: ConsensusParams.params(for: .regtest)
        )

        // CURRENT: REVEAL accepts trueBid < lockup. The (lockup - trueBid)
        // difference is spendable on the REVEAL tx as an ordinary .none change
        // output — the lockup is NOT preserved past REVEAL.
        let after = try db.getNameState(nh)
        XCTAssertEqual(after?.highest, Int64(trueBid),
            "ns.highest tracks trueBid (output.value), not the original lockup")
    }

    func testAuctionCycle_redeem_refundsOnlyTrueBidNotLockup() throws {
        let db = makeNameDB()
        let chain = try makeChain()
        let name = "flowredeem"
        let nh = nameHash(for: name)
        let openHeight = 10
        let closedHeight = openHeight + nameParams.openPeriod + nameParams.biddingPeriod + nameParams.revealPeriod

        // Loser scenario: someone else is the winner/owner.
        var ns = NameState(nameHash: nh, name: Array(name.utf8))
        ns.height = openHeight
        ns.renewal = openHeight
        ns.owner = NameState.Outpoint(hash: txHash(0xF0).bytes, index: 0)
        ns.highest = 5_000
        ns.value = 1_000
        db.putNameState(nh, ns)
        XCTAssertEqual(ns.state(at: closedHeight, params: nameParams), .closed)

        // After REVEAL, the loser's UTXO has value = trueBid = 1_000.
        // (The other 9_000 of the original 10_000 lockup was already taken
        // as change during REVEAL; see testAuctionCycle_reveal_releasesLockupMinusTrueBidAsChange.)
        let trueBid: UInt64 = 1_000
        let loserRevealOp = outpoint(0xB1, 0)
        let loserRevealCov = CovenantData.makeReveal(
            nameHash: nh, startHeight: openHeight, nonce: .zero
        )
        let redeemCov = CovenantData.makeRedeem(nameHash: nh, startHeight: openHeight)

        // REDEEM output can be at most the REVEAL input value = trueBid = 1_000.
        // There is no way to refund the original 10_000 lockup at REDEEM —
        // the coins simply aren't here to spend.
        let redeemTx = simpleTx(input: loserRevealOp, outputValue: trueBid, covenant: redeemCov)
        let view = viewWithCoin(at: loserRevealOp, value: trueBid, covenant: loserRevealCov)

        try CovenantProcessor.processCovenants(
            tx: redeemTx, txIndex: 0, coinView: view, nameDB: db,
            height: closedHeight, network: network, nameParams: nameParams,
            chain: chain, consensusParams: ConsensusParams.params(for: .regtest)
        )
        // CURRENT: loser's total refund = 9_000 (at REVEAL) + 1_000 (at REDEEM) = 10_000.
        // The refund happens in TWO stages, not one — 10_000 does NOT arrive at REDEEM.
    }

    func testAuctionCycle_register_soleBidderPaysZeroAndOnlyTrueBidIsChange() throws {
        let db = makeNameDB()
        let chain = try makeChain()
        let name = "flowregister"
        let nh = nameHash(for: name)
        // openHeight=0 + height=5 < renewalMaturity(10) lets the zeroed
        // blockHash renewal pass; `registered=true` forces .closed early.
        let openHeight = 0
        let height = 5

        let trueBid: UInt64 = 1_000
        let ownerOp = outpoint(0xB2, 0)

        var ns = NameState(nameHash: nh, name: Array(name.utf8))
        ns.height = openHeight
        ns.renewal = openHeight
        ns.registered = true
        ns.owner = NameState.Outpoint(hash: ownerOp.hash.bytes, index: Int(ownerOp.index))
        ns.highest = Int64(trueBid)
        ns.value = 0  // sole bidder: no second-price
        db.putNameState(nh, ns)
        XCTAssertEqual(ns.state(at: height, params: nameParams), .closed)

        // Finding 1: on regtest, minimumBid returns 0 (numerators are 0).
        // Combined with ns.value=0 → regPrice = max(0, 0) = 0.
        let regMinBid = nameParams.minimumBid(atHeight: height, rawName: Array(name.utf8))
        XCTAssertEqual(regMinBid, 0,
            "regtest tldMinBidNumerator=0 → minimumBid=0 → sole bidders pay nothing")

        let revealCov = CovenantData.makeReveal(
            nameHash: nh, startHeight: openHeight, nonce: .zero
        )
        let registerCov = CovenantData.makeRegister(
            nameHash: nh, startHeight: openHeight,
            resource: [], blockHash: [UInt8](repeating: 0, count: 32)
        )

        // REGISTER input is the winner's REVEAL UTXO = trueBid = 1_000.
        // REGISTER output value must be 0. regPrice = 0, so the entire 1_000
        // comes back as .none change — that's the ONLY change at REGISTER.
        // There is no way to produce 9_000 of change here — the coins aren't
        // in the input set (they were released at REVEAL).
        let registerTx = Transaction(
            inputs: [Input(prevout: ownerOp)],
            outputs: [
                Output(value: 0, address: .null, covenant: registerCov),
                Output(value: trueBid, address: .null, covenant: .none),
            ]
        )
        let view = viewWithCoin(at: ownerOp, value: trueBid, covenant: revealCov)

        try CovenantProcessor.processCovenants(
            tx: registerTx, txIndex: 0, coinView: view, nameDB: db,
            height: height, network: network, nameParams: nameParams,
            chain: chain, consensusParams: ConsensusParams.params(for: .regtest)
        )

        // CURRENT:
        //   - regPrice = 0 (regtest minBid=0, sole bidder's ns.value=0) → FREE NAME
        //   - Max change at REGISTER = REVEAL input value = 1_000 (trueBid),
        //     NOT 9_000 (lockup - trueBid) and NOT 10_000 (full lockup).
        let after = try db.getNameState(nh)
        XCTAssertTrue(after?.registered ?? false)
        XCTAssertEqual(after?.value, 0,
            "Sole bidder on regtest paid 0 — name was free")
    }

    // MARK: - Auction Cycle Value-Flow (MAINNET params)
    //
    // Same three stages as the regtest tests above, but using
    // NameParams.mainnet / ConsensusParams.mainnet / NetworkType.main
    // to confirm that the behaviour described by the user matches
    // what a real mainnet node will do.

    private func makeMainnetChain() throws -> Chain {
        try Chain(network: .main)
    }

    func testMainnetAuctionCycle_reveal_releasesLockupMinusTrueBidAsChange() throws {
        let db = makeNameDB()
        let chain = try makeMainnetChain()
        let mainParams = NameParams.mainnet
        let mainNetwork = NetworkType.main
        let mainCP = ConsensusParams.params(for: .main)

        // Post-auctionStart (10_080), pre-first-halving.
        let name = "mainflowreveal"
        let nh = nameHash(for: name)
        let openHeight = 10_100
        let revealHeight = openHeight + mainParams.openPeriod + mainParams.biddingPeriod

        var ns = NameState(nameHash: nh, name: Array(name.utf8))
        ns.height = openHeight
        ns.renewal = openHeight
        db.putNameState(nh, ns)
        XCTAssertEqual(ns.state(at: revealHeight, params: mainParams), .reveal)

        // User's scenario: 10k lockup, 1k trueBid.
        // (We don't process BID here, so BID-time minBid isn't enforced —
        // we're isolating the REVEAL stage's value-flow behaviour.)
        let lockup: UInt64 = 10_000
        let trueBid: UInt64 = 1_000

        let nonce = BidNonce(unchecked: [UInt8](repeating: 0xAB, count: 32))
        let blind = try BlindBid.blind(value: trueBid, nonce: nonce)
        let bidCov = CovenantData.makeBid(
            nameHash: nh, startHeight: openHeight,
            name: Array(name.utf8), blind: blind
        )
        let bidOp = outpoint(0xC0, 0)
        let revealCov = CovenantData.makeReveal(
            nameHash: nh, startHeight: openHeight, nonce: nonce
        )

        // BID input (10_000) -> REVEAL (1_000) + .none change (9_000).
        let revealTx = Transaction(
            inputs: [Input(prevout: bidOp)],
            outputs: [
                Output(value: trueBid, address: .null, covenant: revealCov),
                Output(value: lockup - trueBid, address: .null, covenant: .none),
            ]
        )
        let view = viewWithCoin(at: bidOp, value: lockup, covenant: bidCov)

        try CovenantProcessor.processCovenants(
            tx: revealTx, txIndex: 0, coinView: view, nameDB: db,
            height: revealHeight, network: mainNetwork, nameParams: mainParams,
            chain: chain, consensusParams: mainCP
        )

        let after = try db.getNameState(nh)
        XCTAssertEqual(after?.highest, Int64(trueBid),
            "MAINNET: REVEAL tracks trueBid (1_000), not lockup (10_000). The 9_000 exits as change here, not at REGISTER.")
    }

    func testMainnetAuctionCycle_redeem_refundsOnlyTrueBidNotLockup() throws {
        let db = makeNameDB()
        let chain = try makeMainnetChain()
        let mainParams = NameParams.mainnet
        let mainNetwork = NetworkType.main
        let mainCP = ConsensusParams.params(for: .main)

        let name = "mainflowredeem"
        let nh = nameHash(for: name)
        let openHeight = 10_100
        let closedHeight = openHeight + mainParams.openPeriod + mainParams.biddingPeriod + mainParams.revealPeriod

        var ns = NameState(nameHash: nh, name: Array(name.utf8))
        ns.height = openHeight
        ns.renewal = openHeight
        ns.owner = NameState.Outpoint(hash: txHash(0xF0).bytes, index: 0) // someone else won
        ns.highest = 5_000
        ns.value = 1_000
        db.putNameState(nh, ns)
        XCTAssertEqual(ns.state(at: closedHeight, params: mainParams), .closed)

        // Loser's REVEAL UTXO carries only their trueBid (1_000), not the
        // original lockup (10_000). The rest was taken as REVEAL change.
        let trueBid: UInt64 = 1_000
        let loserRevealOp = outpoint(0xC1, 0)
        let loserRevealCov = CovenantData.makeReveal(
            nameHash: nh, startHeight: openHeight, nonce: .zero
        )
        let redeemCov = CovenantData.makeRedeem(nameHash: nh, startHeight: openHeight)
        let redeemTx = simpleTx(input: loserRevealOp, outputValue: trueBid, covenant: redeemCov)
        let view = viewWithCoin(at: loserRevealOp, value: trueBid, covenant: loserRevealCov)

        try CovenantProcessor.processCovenants(
            tx: redeemTx, txIndex: 0, coinView: view, nameDB: db,
            height: closedHeight, network: mainNetwork, nameParams: mainParams,
            chain: chain, consensusParams: mainCP
        )
        // MAINNET: loser's total refund = 9_000 at REVEAL + 1_000 at REDEEM.
        // The user's expectation ("10_000 back at REDEEM") is NOT what happens.
    }

    func testMainnetAuctionCycle_register_soleBidderPaysMinBid() throws {
        let db = makeNameDB()
        let chain = try makeMainnetChain()
        let mainParams = NameParams.mainnet
        let mainNetwork = NetworkType.main
        let mainCP = ConsensusParams.params(for: .main)

        // TLD. On mainnet: tldMinBidNumerator=20, denom=1 → minBid = 20 * reward.
        // At height < halvingInterval (1_051_200), reward = 500 FBC = 500_000_000 bumps.
        // So minBid = 10_000 FBC = 10_000_000_000 bumps.
        //
        // For REGISTER to actually be payable out of the REVEAL input under
        // current rules, trueBid must cover regPrice — scale the example up
        // (20k FBC trueBid, 30k FBC lockup) so the math works.
        let name = "mainflowregister"
        let nh = nameHash(for: name)
        let openHeight = 10_100
        let height = 10_500  // < renewalMaturity (21_600), zeroed blockHash passes
        //                      and < revealEnd so `registered=true` forces .closed.

        let trueBid: UInt64 = 20_000_000_000  // 20,000 FBC
        let lockup:  UInt64 = 30_000_000_000  // 30,000 FBC ("blind" difference: 10,000 FBC)
        XCTAssertEqual(lockup - trueBid, 10_000_000_000,
            "The 10,000 FBC difference was already released as REVEAL change, not reaching this REGISTER.")

        let ownerOp = outpoint(0xC2, 0)

        var ns = NameState(nameHash: nh, name: Array(name.utf8))
        ns.height = openHeight
        ns.renewal = openHeight
        ns.registered = true
        ns.owner = NameState.Outpoint(hash: ownerOp.hash.bytes, index: Int(ownerOp.index))
        ns.highest = Int64(trueBid)
        ns.value = 0  // sole bidder
        db.putNameState(nh, ns)
        XCTAssertEqual(ns.state(at: height, params: mainParams), .closed)

        // Confirm mainnet minBid is 10_000 FBC for a TLD at this height.
        let regMinBid = mainParams.minimumBid(atHeight: height, rawName: Array(name.utf8))
        XCTAssertEqual(regMinBid, 10_000_000_000,
            "MAINNET: TLD minimumBid = 20 * 500 FBC = 10,000 FBC")

        // Sole bidder: regPrice = max(0, minBid) = minBid = 10,000 FBC.
        //   burnShare = 50% = 5,000 FBC  → .null
        //   devShare  = 50% = 5,000 FBC  → devFund
        // Change to winner = trueBid - regPrice = 10,000 FBC.
        let regPrice: UInt64 = 10_000_000_000
        let burnShare: UInt64 = 5_000_000_000
        let devShare: UInt64 = 5_000_000_000
        let winnerChange: UInt64 = trueBid - regPrice   // 10,000 FBC
        let devFundAddr = Address(unchecked: mainCP.devFundVersion, hash: mainCP.devFundAddress)

        let revealCov = CovenantData.makeReveal(
            nameHash: nh, startHeight: openHeight, nonce: .zero
        )
        let registerCov = CovenantData.makeRegister(
            nameHash: nh, startHeight: openHeight,
            resource: [], blockHash: [UInt8](repeating: 0, count: 32)
        )

        let registerTx = Transaction(
            inputs: [Input(prevout: ownerOp)],
            outputs: [
                Output(value: 0, address: .null, covenant: registerCov),
                Output(value: burnShare, address: .null, covenant: .none),
                Output(value: devShare, address: devFundAddr, covenant: .none),
                Output(value: winnerChange, address: .null, covenant: .none),
            ]
        )
        let view = viewWithCoin(at: ownerOp, value: trueBid, covenant: revealCov)

        try CovenantProcessor.processCovenants(
            tx: registerTx, txIndex: 0, coinView: view, nameDB: db,
            height: height, network: mainNetwork, nameParams: mainParams,
            chain: chain, consensusParams: mainCP
        )

        // MAINNET confirmed behaviour:
        //   ✓ Sole bidder pays minBid (10,000 FBC) — NOT free.
        //   ✗ Winner's REGISTER change = trueBid - regPrice = 10,000 FBC.
        //     User's spec says it should be lockup - regPrice = 20,000 FBC.
        //     The missing 10,000 FBC already walked out at REVEAL as change.
        //     Total returned to winner across the cycle:
        //       10,000 (REVEAL change) + 10,000 (REGISTER change) = 20,000 FBC,
        //     which equals lockup - regPrice — but split across two txs.
        let after = try db.getNameState(nh)
        XCTAssertTrue(after?.registered ?? false)
        XCTAssertEqual(after?.value, Int64(regPrice),
            "Sole bidder on mainnet pays minBid (10,000 FBC), confirming that side of the spec")
    }

    func testMainnetAuctionCycle_revealAccepts_trueBidBelowMinBid() throws {
        // User's literal scenario: 10k lockup, 1k trueBid on mainnet.
        // On mainnet TLD, minBid at BID time requires lockup >= 10,000 FBC,
        // but trueBid is NEVER validated against minBid — only the blind-hash
        // commitment. So a bidder can reveal a trueBid far below minBid as long
        // as the blind matches. This test confirms that "gap".
        let db = makeNameDB()
        let chain = try makeMainnetChain()
        let mainParams = NameParams.mainnet
        let mainNetwork = NetworkType.main
        let mainCP = ConsensusParams.params(for: .main)

        let name = "mainlowreveal"
        let nh = nameHash(for: name)
        let openHeight = 10_100
        let revealHeight = openHeight + mainParams.openPeriod + mainParams.biddingPeriod

        var ns = NameState(nameHash: nh, name: Array(name.utf8))
        ns.height = openHeight
        ns.renewal = openHeight
        db.putNameState(nh, ns)

        // Lockup satisfies mainnet TLD BID minBid (10,000 FBC); trueBid is
        // intentionally TINY (1 bump) — far below minBid.
        let lockup: UInt64 = 10_000_000_000  // 10,000 FBC (matches minBid exactly)
        let trueBid: UInt64 = 1

        let nonce = BidNonce(unchecked: [UInt8](repeating: 0xCC, count: 32))
        let blind = try BlindBid.blind(value: trueBid, nonce: nonce)
        let bidCov = CovenantData.makeBid(
            nameHash: nh, startHeight: openHeight,
            name: Array(name.utf8), blind: blind
        )
        let bidOp = outpoint(0xC3, 0)
        let revealCov = CovenantData.makeReveal(
            nameHash: nh, startHeight: openHeight, nonce: nonce
        )

        let revealTx = Transaction(
            inputs: [Input(prevout: bidOp)],
            outputs: [
                Output(value: trueBid, address: .null, covenant: revealCov),
                Output(value: lockup - trueBid, address: .null, covenant: .none),
            ]
        )
        let view = viewWithCoin(at: bidOp, value: lockup, covenant: bidCov)

        // Processor accepts — no minBid check at REVEAL.
        try CovenantProcessor.processCovenants(
            tx: revealTx, txIndex: 0, coinView: view, nameDB: db,
            height: revealHeight, network: mainNetwork, nameParams: mainParams,
            chain: chain, consensusParams: mainCP
        )

        let after = try db.getNameState(nh)
        XCTAssertEqual(after?.highest, 1,
            "MAINNET: sole bidder reveals trueBid=1 bump. ns.highest=1, ns.value=0.")
        // Follow-up: REGISTER for this name would require paying regPrice=10,000 FBC
        // from a REVEAL input of only 1 bump — impossible unless the winner supplies
        // extra inputs. So this sole bidder's REVEAL UTXO is effectively stuck
        // (or forfeit) under the current design. Under the proposed fix
        // (REVEAL preserves lockup), the 10,000 FBC is still in the REVEAL UTXO
        // and fully covers regPrice.
    }
}
