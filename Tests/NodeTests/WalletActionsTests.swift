import XCTest
@testable import Node
@testable import RPC
@testable import Base
@testable import Wallet
@testable import Chain
@testable import Mempool
import Protocol
import Covenants
import ExtCrypto
import Consensus

/// Regression tests for how `getwalletactions` classifies a closed auction.
///
/// A losing bidder keeps an unspent REVEAL coin until they redeem it, so
/// "do we hold a reveal for this name" does not answer "did we win". Only
/// the reveal the chain records as `NameState.owner` can be registered —
/// which is exactly what `sendmany register` enforces. When the two
/// disagree the wallet offers a "Register" button that always fails with
/// "nothing to do — no eligible names found", and hides the "Redeem"
/// action the loser actually needs to get their lockup back.
final class WalletActionsTests: XCTestCase {

    private var tmpDir: String!

    /// Auction opened at height 1. With regtest params (open 6, bid 10,
    /// reveal 20) it closes at 37, and the register deadline is 57.
    private let auctionStart = 1
    private let revealHeight = 20
    private let chainHeight = 40
    private let auctionName = "universe"

    override func setUp() {
        super.setUp()
        tmpDir = NSTemporaryDirectory() + "fbd-actions-test-\(UUID().uuidString)"
        try? FileManager.default.createDirectory(
            atPath: tmpDir + "/blocks", withIntermediateDirectories: true)
    }

    override func tearDown() {
        if let dir = tmpDir {
            try? FileManager.default.removeItem(atPath: dir)
        }
        super.tearDown()
    }

    // MARK: - Harness

    private func makeHarness() throws -> (RPCDispatcher, WalletDB, Chain) {
        let wallet = try WalletDB(path: tmpDir + "/wallets/test", network: .regtest)
        _ = try wallet.create(mnemonic: "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about")

        let blockStore = try BlockStore(blocksDir: tmpDir + "/blocks", network: .regtest)
        let coinDB = try CoinDatabase(path: tmpDir + "/coins", network: .regtest)
        let chain = try Chain(network: .regtest, blockStore: blockStore, coinDB: coinDB)

        // `getwalletactions` reads the auction clock off chain.storedHeight,
        // which is just the block store's count. The blocks are never read
        // back, so empty ones are enough to put the auction past its close.
        for h in 0...chainHeight {
            try blockStore.storeBlock(makeBlock(time: UInt64(h), txs: [makeCoinbase()]), height: h)
        }

        let ctx = NodeContext()
        ctx.setWallet("test", wallet)
        ctx.chain = chain
        ctx.mempool = Mempool()

        let node = FullNode(config: NodeConfig(network: .regtest, dataDir: tmpDir))
        return (node.buildRPCDispatcher(ctx: ctx), wallet, chain)
    }

    private func makeHeader(time: UInt64) -> BlockHeader {
        BlockHeader(nonce: 0, time: time, bits: 0x207f_ffff)
    }

    private func makeBlock(time: UInt64, txs: [Transaction]) -> Block {
        let header = makeHeader(time: time)
        return Block(header: header, transactions: txs, balloonProof: regtestProof(for: header))
    }

    private func makeCoinbase(value: UInt64 = 100_000) -> Transaction {
        Transaction(
            version: 0,
            inputs: [Input(prevout: .null, sequence: 0xFFFF_FFFF)],
            outputs: [Output(value: value, address: Address(unchecked: 0, hash: [UInt8](repeating: 0xAB, count: 20)))],
            locktime: 0,
            witnesses: [Witness(items: [])]
        )
    }

    /// Confirm an unspent REVEAL coin for `name` into the wallet and return
    /// its outpoint. This models a bid that was revealed and not yet
    /// redeemed — true for winner and loser alike.
    @discardableResult
    private func addRevealCoin(_ wallet: WalletDB, value: UInt64) throws -> Outpoint {
        let addr = try wallet.getReceiveAddress()
        let covenant = CovenantData.makeReveal(
            nameHash: NameRules.hashName(auctionName),
            startHeight: auctionStart,
            nonce: BidNonce(unchecked: [UInt8](repeating: 0x11, count: 32))
        )
        let revealTx = Transaction(
            version: 0,
            inputs: [Input(prevout: Outpoint(hash: Hash256(unchecked: [UInt8](repeating: 0xBB, count: 32)), index: 0))],
            outputs: [Output(value: value, address: addr, covenant: covenant)],
            locktime: 0,
            witnesses: [Witness(items: [])]
        )
        let block = makeBlock(time: UInt64(revealHeight), txs: [makeCoinbase(), revealTx])
        try wallet.indexBlock(block, height: revealHeight)
        return Outpoint(hash: revealTx.txHash(), index: 0)
    }

    /// Record the bid whose BID coin was already consumed by the reveal.
    private func saveBid(_ wallet: WalletDB, value: UInt64) throws {
        try wallet.saveBid(BidRecord(
            nameHash: NameRules.hashName(auctionName),
            outpoint: Outpoint(hash: Hash256(unchecked: [UInt8](repeating: 0xCC, count: 32)), index: 0),
            nonce: BidNonce(unchecked: [UInt8](repeating: 0x11, count: 32)),
            value: value,
            lockup: value,
            height: 12
        ))
    }

    /// Write a closed, unregistered auction whose winning reveal is `owner`.
    private func putClosedAuction(_ chain: Chain, owner: Outpoint, winningBid: Int64) {
        let nameHash = NameRules.hashName(auctionName)
        var ns = NameState(nameHash: nameHash, name: Array(auctionName.utf8))
        ns.height = auctionStart
        ns.value = winningBid
        ns.highest = winningBid
        ns.owner = NameState.Outpoint(hash: owner.hash.bytes, index: Int(owner.index))
        chain.nameDBRef.putNameState(nameHash, ns)
    }

    /// Names listed under one action bucket of `getwalletactions`.
    private func actionNames(_ dispatcher: RPCDispatcher, _ key: String) throws -> [String] {
        let response = dispatcher.dispatch(
            RPCRequest(method: "getwalletactions", params: [], wallet: "test"))
        XCTAssertNil(response.error, "getwalletactions failed: \(response.error?.message ?? "")")
        guard case .object(let fields) = response.result,
              let bucket = fields.first(where: { $0.0 == key })?.1,
              case .array(let entries) = bucket else {
            XCTFail("expected an array for action bucket '\(key)'")
            return []
        }
        return entries.compactMap { entry in
            guard case .object(let f) = entry else { return nil }
            return f.first(where: { $0.0 == "name" })?.1.stringValue
        }
    }

    // MARK: - Tests

    func testLosingBidderIsNotOfferedRegister() throws {
        let (dispatcher, wallet, chain) = try makeHarness()

        // We bid 300k and revealed; the reveal coin is still unspent.
        try addRevealCoin(wallet, value: 300_000 * 1_000_000)
        try saveBid(wallet, value: 300_000 * 1_000_000)

        // Someone else's reveal won at 500k and owns the name.
        let theirReveal = Outpoint(
            hash: Hash256(unchecked: [UInt8](repeating: 0xDD, count: 32)), index: 0)
        putClosedAuction(chain, owner: theirReveal, winningBid: 500_000 * 1_000_000)

        XCTAssertEqual(try actionNames(dispatcher, "register"), [],
                       "a name we lost must not be offered for registration")
        XCTAssertEqual(try actionNames(dispatcher, "redeem"), [auctionName],
                       "the losing reveal must be offered for redemption")
    }

    func testWinningBidderIsOfferedRegister() throws {
        let (dispatcher, wallet, chain) = try makeHarness()

        let ourReveal = try addRevealCoin(wallet, value: 500_000 * 1_000_000)
        try saveBid(wallet, value: 500_000 * 1_000_000)
        putClosedAuction(chain, owner: ourReveal, winningBid: 500_000 * 1_000_000)

        XCTAssertEqual(try actionNames(dispatcher, "register"), [auctionName],
                       "the name we won must be offered for registration")
        XCTAssertEqual(try actionNames(dispatcher, "redeem"), [],
                       "the winning reveal is spent by REGISTER, not redeemed")
    }
}

/// Compute a real BalloonProof for a header using regtest params (4 slots, instant).
private func regtestProof(for header: BlockHeader) -> BalloonProof {
    try! ProofOfWork.powHashWithProof(for: header, params: ConsensusParams.params(for: .regtest)).proof
}
