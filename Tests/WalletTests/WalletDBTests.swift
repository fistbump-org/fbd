import XCTest
@testable import Wallet
import Base
import Covenants
import ExtCrypto
import Consensus
import Protocol

final class WalletDBTests: XCTestCase {

    private var tmpDir: String!

    override func setUp() {
        super.setUp()
        tmpDir = NSTemporaryDirectory() + "fbd-wallet-test-\(UUID().uuidString)"
    }

    override func tearDown() {
        if let dir = tmpDir {
            try? FileManager.default.removeItem(atPath: dir)
        }
        super.tearDown()
    }

    // MARK: - Wallet Creation

    func testCreateWallet() throws {
        let wallet = try WalletDB(path: tmpDir, network: .main)
        let phrase = try wallet.create()

        XCTAssertTrue(wallet.initialized)
        XCTAssertTrue(BIP39.validateMnemonic(phrase))
        XCTAssertEqual(wallet.mnemonic, phrase)
        XCTAssertEqual(wallet.addressCount, 200, "Should derive 100 receive + 100 change addresses")
    }

    func testCreateWithMnemonic() throws {
        let wallet = try WalletDB(path: tmpDir, network: .main)
        let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
        let phrase = try wallet.create(mnemonic: mnemonic)

        XCTAssertEqual(phrase, mnemonic)
        XCTAssertTrue(wallet.initialized)
    }

    func testCreateWalletTwiceFails() throws {
        let wallet = try WalletDB(path: tmpDir, network: .main)
        _ = try wallet.create()

        XCTAssertThrowsError(try wallet.create()) { error in
            guard case WalletError.alreadyInitialized = error else {
                XCTFail("Expected alreadyInitialized error, got \(error)")
                return
            }
        }
    }

    func testInvalidMnemonicFails() throws {
        let wallet = try WalletDB(path: tmpDir, network: .main)
        XCTAssertThrowsError(try wallet.create(mnemonic: "not a valid mnemonic")) { error in
            guard case WalletError.invalidMnemonic = error else {
                XCTFail("Expected invalidMnemonic error, got \(error)")
                return
            }
        }
    }

    // MARK: - Address Derivation

    func testGetReceiveAddress() throws {
        let wallet = try WalletDB(path: tmpDir, network: .main)
        _ = try wallet.create(mnemonic: "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about")

        let addr = try wallet.getReceiveAddress()
        XCTAssertEqual(addr.version, 0)
        XCTAssertEqual(addr.hash.count, 20)

        let bech32 = addr.toBech32(network: .main)
        XCTAssertTrue(bech32.hasPrefix("fb1"), "Mainnet address should start with fb1")
    }

    func testGetChangeAddress() throws {
        let wallet = try WalletDB(path: tmpDir, network: .main)
        _ = try wallet.create(mnemonic: "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about")

        let addr = try wallet.getChangeAddress()
        XCTAssertEqual(addr.version, 0)
        XCTAssertEqual(addr.hash.count, 20)

        let bech32 = addr.toBech32(network: .main)
        XCTAssertTrue(bech32.hasPrefix("fb1"))
    }

    func testReceiveAndChangeDiffer() throws {
        let wallet = try WalletDB(path: tmpDir, network: .main)
        _ = try wallet.create(mnemonic: "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about")

        let receive = try wallet.getReceiveAddress()
        let change = try wallet.getChangeAddress()
        XCTAssertNotEqual(receive, change, "Receive and change addresses should differ")
    }

    func testAdvanceReceiveAddressReturnsDifferent() throws {
        let wallet = try WalletDB(path: tmpDir, network: .main)
        _ = try wallet.create(mnemonic: "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about")

        let addr1 = try wallet.advanceReceiveAddress()
        let addr2 = try wallet.advanceReceiveAddress()
        let addr3 = try wallet.advanceReceiveAddress()

        XCTAssertNotEqual(addr1, addr2, "Each advance should return a different address")
        XCTAssertNotEqual(addr2, addr3, "Each advance should return a different address")
        XCTAssertNotEqual(addr1, addr3, "Each advance should return a different address")
    }

    func testAdvanceChangeAddressReturnsDifferent() throws {
        let wallet = try WalletDB(path: tmpDir, network: .main)
        _ = try wallet.create(mnemonic: "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about")

        let addr1 = try wallet.advanceChangeAddress()
        let addr2 = try wallet.advanceChangeAddress()
        let addr3 = try wallet.advanceChangeAddress()

        XCTAssertNotEqual(addr1, addr2, "Each advance should return a different address")
        XCTAssertNotEqual(addr2, addr3, "Each advance should return a different address")
        XCTAssertNotEqual(addr1, addr3, "Each advance should return a different address")
    }

    func testAdvanceReceiveMatchesGetReceive() throws {
        let wallet = try WalletDB(path: tmpDir, network: .main)
        _ = try wallet.create(mnemonic: "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about")

        // getReceiveAddress peeks at index 0 (receiveIndex=-1, so idx=0)
        let peek = try wallet.getReceiveAddress()
        // advanceReceiveAddress should advance to index 0 and return same address
        let advanced = try wallet.advanceReceiveAddress()
        XCTAssertEqual(peek, advanced, "First advance should match the peek address")

        // Now peek should be at index 1
        let peek2 = try wallet.getReceiveAddress()
        let advanced2 = try wallet.advanceReceiveAddress()
        XCTAssertEqual(peek2, advanced2, "Second advance should match the next peek")
        XCTAssertNotEqual(peek, peek2)
    }

    func testDeterministicAddresses() throws {
        let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"

        let wallet1 = try WalletDB(path: tmpDir + "/w1", network: .main)
        _ = try wallet1.create(mnemonic: mnemonic)
        let addr1 = try wallet1.getReceiveAddress()

        let wallet2 = try WalletDB(path: tmpDir + "/w2", network: .main)
        _ = try wallet2.create(mnemonic: mnemonic)
        let addr2 = try wallet2.getReceiveAddress()

        XCTAssertEqual(addr1, addr2, "Same mnemonic should produce same addresses")
    }

    // MARK: - Balance

    func testEmptyBalance() throws {
        let wallet = try WalletDB(path: tmpDir, network: .main)
        _ = try wallet.create()
        let balance = try wallet.getBalance()
        XCTAssertEqual(balance, 0)
    }

    // MARK: - Block Indexing

    func testIndexBlockWithWalletOutput() throws {
        let wallet = try WalletDB(path: tmpDir, network: .main)
        _ = try wallet.create(mnemonic: "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about")

        let addr = try wallet.getReceiveAddress()

        // Create a fake block with a transaction paying to our address
        let coinbaseOutput = Output(value: 500_000_000, address: addr)
        let coinbaseTx = Transaction(
            version: 0,
            inputs: [Input(prevout: .null, sequence: 0xFFFF_FFFF)],
            outputs: [coinbaseOutput],
            locktime: 0,
            witnesses: [Witness(items: [])]
        )
        let header = makeTestHeader()
        let block = Block(header: header, transactions: [coinbaseTx], balloonProof: regtestProof(for: header))

        try wallet.indexBlock(block, height: 1)

        let balance = try wallet.getBalance()
        XCTAssertEqual(balance, 500_000_000, "Should have the coinbase output value")

        let coins = try wallet.listUnspent()
        XCTAssertEqual(coins.count, 1)
        XCTAssertEqual(coins[0].value, 500_000_000)
        XCTAssertEqual(coins[0].coinbase, true)
        XCTAssertEqual(coins[0].height, 1)
    }

    func testIndexBlockSpendsCoin() throws {
        let wallet = try WalletDB(path: tmpDir, network: .main)
        _ = try wallet.create(mnemonic: "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about")

        let addr = try wallet.getReceiveAddress()

        // Block 1: Create a coin
        let coinbaseOutput = Output(value: 1_000_000, address: addr)
        let coinbaseTx = Transaction(
            version: 0,
            inputs: [Input(prevout: .null, sequence: 0xFFFF_FFFF)],
            outputs: [coinbaseOutput],
            locktime: 0,
            witnesses: [Witness(items: [])]
        )
        let block1 = Block(header: makeTestHeader(), transactions: [coinbaseTx], balloonProof: regtestProof(for: makeTestHeader()))
        try wallet.indexBlock(block1, height: 1)

        XCTAssertEqual(try wallet.getBalance(), 1_000_000)

        // Block 2: Spend the coin
        let coinbaseHash = coinbaseTx.txHash()
        let spendInput = Input(prevout: Outpoint(hash: coinbaseHash, index: 0))
        let someOtherAddr = Address(unchecked: 0, hash: [UInt8](repeating: 0xAB, count: 20))
        let spendTx = Transaction(
            version: 0,
            inputs: [spendInput],
            outputs: [Output(value: 900_000, address: someOtherAddr)],
            locktime: 0,
            witnesses: [Witness(items: [])]
        )
        // Block still needs a coinbase
        let block2Coinbase = Transaction(
            version: 0,
            inputs: [Input(prevout: .null, sequence: 0xFFFF_FFFF)],
            outputs: [Output(value: 100_000, address: someOtherAddr)],
            locktime: 0,
            witnesses: [Witness(items: [])]
        )
        let block2 = Block(header: makeTestHeader(), transactions: [block2Coinbase, spendTx], balloonProof: regtestProof(for: makeTestHeader()))
        try wallet.indexBlock(block2, height: 2)

        XCTAssertEqual(try wallet.getBalance(), 0, "Coin should be spent")
        XCTAssertEqual(try wallet.listUnspent().count, 0)
    }

    func testScanHeight() throws {
        let wallet = try WalletDB(path: tmpDir, network: .main)
        _ = try wallet.create()

        XCTAssertEqual(wallet.scanHeight, -1)

        let block = Block(header: makeTestHeader(), transactions: [makeTestCoinbase()], balloonProof: regtestProof(for: makeTestHeader()))
        // First block can be any height (scanHeight == -1 means "not started")
        try wallet.indexBlock(block, height: 5)
        XCTAssertEqual(wallet.scanHeight, 5)

        // Sequential block must be scanHeight + 1
        try wallet.indexBlock(block, height: 6)
        XCTAssertEqual(wallet.scanHeight, 6)

        // Non-sequential block must fail
        XCTAssertThrowsError(try wallet.indexBlock(block, height: 10)) { error in
            guard case WalletError.heightMismatch = error else {
                XCTFail("Expected heightMismatch, got \(error)")
                return
            }
        }
        XCTAssertEqual(wallet.scanHeight, 6, "scanHeight should not change on error")
    }

    // MARK: - Import Address

    func testImportAddress() throws {
        let wallet = try WalletDB(path: tmpDir, network: .main)
        _ = try wallet.create()

        let countBefore = wallet.addressCount
        let addr = try Address(version: 0, hash: [UInt8](repeating: 0x42, count: 20))
        try wallet.importAddress(addr)

        XCTAssertEqual(wallet.addressCount, countBefore + 1)
    }

    // MARK: - Persistence

    func testWalletPersistence() throws {
        let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"

        // Create wallet
        let wallet1 = try WalletDB(path: tmpDir, network: .main)
        _ = try wallet1.create(mnemonic: mnemonic)
        let addr1 = try wallet1.getReceiveAddress()
        wallet1.close()

        // Reopen
        let wallet2 = try WalletDB(path: tmpDir, network: .main)
        XCTAssertTrue(wallet2.initialized)
        XCTAssertEqual(wallet2.mnemonic, mnemonic)
        let addr2 = try wallet2.getReceiveAddress()
        XCTAssertEqual(addr1, addr2, "Address should be same after reopen")
        wallet2.close()
    }

    // MARK: - Bech32 Address Round-Trip

    func testBech32AddressRoundTrip() throws {
        let wallet = try WalletDB(path: tmpDir, network: .main)
        _ = try wallet.create(mnemonic: "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about")

        let addr = try wallet.getReceiveAddress()
        let bech32 = addr.toBech32(network: .main)

        let decoded = try Address(bech32: bech32, network: .main)
        XCTAssertEqual(decoded, addr)
    }

    func testBech32NetworkMismatch() throws {
        let addr = try Address(version: 0, hash: [UInt8](repeating: 0, count: 20))
        let mainnet = addr.toBech32(network: .main)

        XCTAssertThrowsError(try Address(bech32: mainnet, network: .testnet)) { error in
            guard case ProtocolError.invalidBech32Address = error else {
                XCTFail("Expected invalidBech32Address, got \(error)")
                return
            }
        }
    }

    // MARK: - Bid Records

    func testSaveBidAndRetrieve() throws {
        let wallet = try WalletDB(path: tmpDir, network: .main)
        _ = try wallet.create()

        let nameHash = NameHash(unchecked: [UInt8](repeating: 0xAA, count: 32))
        let txHash = Hash256(unchecked: [UInt8](repeating: 0xBB, count: 32))
        let bid = BidRecord(
            nameHash: nameHash,
            outpoint: Outpoint(hash: txHash, index: 0),
            nonce: BidNonce(unchecked: [UInt8](repeating: 0xCC, count: 32)),
            value: 50_000,
            lockup: 60_000
        )

        try wallet.saveBid(bid)
        let bids = try wallet.getBidsForName(nameHash: nameHash)
        XCTAssertEqual(bids.count, 1)
        XCTAssertEqual(bids[0].nameHash, nameHash)
        XCTAssertEqual(bids[0].outpoint.hash, txHash)
        XCTAssertEqual(bids[0].outpoint.index, 0)
        XCTAssertEqual(bids[0].value, 50_000)
        XCTAssertEqual(bids[0].lockup, 60_000)
        XCTAssertEqual(bids[0].nonce, BidNonce(unchecked: [UInt8](repeating: 0xCC, count: 32)))
    }

    func testGetBidsForNameFiltersCorrectly() throws {
        let wallet = try WalletDB(path: tmpDir, network: .main)
        _ = try wallet.create()

        let nameHash1 = NameHash(unchecked: [UInt8](repeating: 0x01, count: 32))
        let nameHash2 = NameHash(unchecked: [UInt8](repeating: 0x02, count: 32))

        try wallet.saveBid(BidRecord(
            nameHash: nameHash1,
            outpoint: Outpoint(hash: Hash256(unchecked: [UInt8](repeating: 0x10, count: 32)), index: 0),
            nonce: .zero, value: 100, lockup: 200
        ))
        try wallet.saveBid(BidRecord(
            nameHash: nameHash2,
            outpoint: Outpoint(hash: Hash256(unchecked: [UInt8](repeating: 0x20, count: 32)), index: 0),
            nonce: .zero, value: 300, lockup: 400
        ))
        try wallet.saveBid(BidRecord(
            nameHash: nameHash1,
            outpoint: Outpoint(hash: Hash256(unchecked: [UInt8](repeating: 0x30, count: 32)), index: 1),
            nonce: .zero, value: 500, lockup: 600
        ))

        let bids1 = try wallet.getBidsForName(nameHash: nameHash1)
        XCTAssertEqual(bids1.count, 2)

        let bids2 = try wallet.getBidsForName(nameHash: nameHash2)
        XCTAssertEqual(bids2.count, 1)
        XCTAssertEqual(bids2[0].value, 300)
    }

    func testGetAllBidsReturnsAll() throws {
        let wallet = try WalletDB(path: tmpDir, network: .main)
        _ = try wallet.create()

        for i: UInt8 in 0..<5 {
            try wallet.saveBid(BidRecord(
                nameHash: NameHash(unchecked: [UInt8](repeating: i, count: 32)),
                outpoint: Outpoint(hash: Hash256(unchecked: [UInt8](repeating: i, count: 32)), index: UInt32(i)),
                nonce: .zero, value: UInt64(i) * 1000, lockup: UInt64(i) * 2000
            ))
        }

        let all = try wallet.getAllBids()
        XCTAssertEqual(all.count, 5)
    }

    func testGetAllBidsEmpty() throws {
        let wallet = try WalletDB(path: tmpDir, network: .main)
        _ = try wallet.create()

        let all = try wallet.getAllBids()
        XCTAssertEqual(all.count, 0)
    }

    func testRemoveBid() throws {
        let wallet = try WalletDB(path: tmpDir, network: .main)
        _ = try wallet.create()

        let nameHash = NameHash(unchecked: [UInt8](repeating: 0xAA, count: 32))
        let txHash = Hash256(unchecked: [UInt8](repeating: 0xBB, count: 32))
        let outpoint = Outpoint(hash: txHash, index: 0)

        try wallet.saveBid(BidRecord(
            nameHash: nameHash, outpoint: outpoint,
            nonce: .zero, value: 1000, lockup: 2000
        ))
        XCTAssertEqual(try wallet.getBidsForName(nameHash: nameHash).count, 1)

        try wallet.removeBid(nameHash: nameHash, outpoint: outpoint)
        XCTAssertEqual(try wallet.getBidsForName(nameHash: nameHash).count, 0)
    }

    // MARK: - Owned Names

    func testGetOwnedNamesEmpty() throws {
        let wallet = try WalletDB(path: tmpDir, network: .main)
        _ = try wallet.create()

        let names = try wallet.getOwnedNames()
        XCTAssertEqual(names.count, 0)
    }

    func testGetOwnedNamesFindsRegisterCoins() throws {
        let wallet = try WalletDB(path: tmpDir, network: .main)
        _ = try wallet.create(mnemonic: "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about")
        let addr = try wallet.getReceiveAddress()

        let nameHash = NameHash(unchecked: [UInt8](repeating: 0xAA, count: 32))
        let registerCov = Covenant(type: .register, items: [nameHash.bytes, [UInt8](repeating: 0, count: 4), []])
        let registerOutput = Output(value: 10_000, address: addr, covenant: registerCov)
        let tx = Transaction(
            version: 0,
            inputs: [Input(prevout: .null, sequence: 0xFFFF_FFFF)],
            outputs: [registerOutput],
            locktime: 0,
            witnesses: [Witness(items: [])]
        )
        let block = Block(header: makeTestHeader(), transactions: [makeTestCoinbase(), tx], balloonProof: regtestProof(for: makeTestHeader()))
        try wallet.indexBlock(block, height: 1)

        let names = try wallet.getOwnedNames()
        XCTAssertEqual(names.count, 1)
        XCTAssertEqual(names[0].nameHash, nameHash)
        XCTAssertEqual(names[0].coin.covenant.type, .register)
    }

    func testGetOwnedNamesDeduplicatesByNameHash() throws {
        let wallet = try WalletDB(path: tmpDir, network: .main)
        _ = try wallet.create(mnemonic: "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about")
        let addr = try wallet.getReceiveAddress()

        let nameHash = NameHash(unchecked: [UInt8](repeating: 0xBB, count: 32))
        // Two UTXO for the same name (e.g. REGISTER then UPDATE)
        let registerOutput = Output(value: 10_000, address: addr,
            covenant: Covenant(type: .register, items: [nameHash.bytes, [UInt8](repeating: 0, count: 4), []]))
        let updateOutput = Output(value: 10_000, address: addr,
            covenant: Covenant(type: .update, items: [nameHash.bytes, [UInt8](repeating: 0, count: 4), []]))
        let tx = Transaction(
            version: 0,
            inputs: [Input(prevout: .null, sequence: 0xFFFF_FFFF)],
            outputs: [registerOutput, updateOutput],
            locktime: 0,
            witnesses: [Witness(items: [])]
        )
        let block = Block(header: makeTestHeader(), transactions: [makeTestCoinbase(), tx], balloonProof: regtestProof(for: makeTestHeader()))
        try wallet.indexBlock(block, height: 1)

        let names = try wallet.getOwnedNames()
        XCTAssertEqual(names.count, 1, "Should deduplicate by nameHash")
    }

    func testGetOwnedNamesIgnoresNonOwnerTypes() throws {
        let wallet = try WalletDB(path: tmpDir, network: .main)
        _ = try wallet.create(mnemonic: "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about")
        let addr = try wallet.getReceiveAddress()

        let nameHash = NameHash(unchecked: [UInt8](repeating: 0xCC, count: 32))
        // A BID coin — not an ownership type
        let bidOutput = Output(value: 10_000, address: addr,
            covenant: Covenant(type: .bid, items: [nameHash.bytes, [UInt8](repeating: 0, count: 4), []]))
        let tx = Transaction(
            version: 0,
            inputs: [Input(prevout: .null, sequence: 0xFFFF_FFFF)],
            outputs: [bidOutput],
            locktime: 0,
            witnesses: [Witness(items: [])]
        )
        let block = Block(header: makeTestHeader(), transactions: [makeTestCoinbase(), tx], balloonProof: regtestProof(for: makeTestHeader()))
        try wallet.indexBlock(block, height: 1)

        let names = try wallet.getOwnedNames()
        XCTAssertEqual(names.count, 0, "BID coins should not count as owned names")
    }

    // MARK: - ismine

    func testIsmineOwnAddress() throws {
        let wallet = try WalletDB(path: tmpDir, network: .main)
        _ = try wallet.create(mnemonic: "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about")

        let addr = try wallet.getReceiveAddress()
        XCTAssertTrue(wallet.ismine(addr))
    }

    func testIsmineUnknownAddress() throws {
        let wallet = try WalletDB(path: tmpDir, network: .main)
        _ = try wallet.create()

        let unknown = Address(unchecked: 0, hash: [UInt8](repeating: 0xFF, count: 20))
        XCTAssertFalse(wallet.ismine(unknown))
    }

    func testIsmineImportedAddress() throws {
        let wallet = try WalletDB(path: tmpDir, network: .main)
        _ = try wallet.create()

        let addr = try Address(version: 0, hash: [UInt8](repeating: 0x42, count: 20))
        XCTAssertFalse(wallet.ismine(addr))

        try wallet.importAddress(addr)
        XCTAssertTrue(wallet.ismine(addr))
    }

    // MARK: - birthHeight

    func testBirthHeightNoTransactions() throws {
        let wallet = try WalletDB(path: tmpDir, network: .main)
        _ = try wallet.create()

        // No transactions — should return max(scanHeight, 0)
        // scanHeight starts at -1, so max(-1, 0) = 0
        XCTAssertEqual(wallet.birthHeight, 0)
    }

    func testBirthHeightAfterSync() throws {
        let wallet = try WalletDB(path: tmpDir, network: .main)
        _ = try wallet.create()

        // Advance scanHeight to simulate synced state
        try wallet.setScanHeight(99)
        let block = Block(header: makeTestHeader(), transactions: [makeTestCoinbase()], balloonProof: regtestProof(for: makeTestHeader()))
        try wallet.indexBlock(block, height: 100)

        // No wallet transactions, but scanHeight is 100
        XCTAssertEqual(wallet.birthHeight, 100)
    }

    func testBirthHeightWithTransaction() throws {
        let wallet = try WalletDB(path: tmpDir, network: .main)
        _ = try wallet.create(mnemonic: "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about")
        let addr = try wallet.getReceiveAddress()

        // Index blocks with no wallet txs first
        let emptyBlock = Block(header: makeTestHeader(), transactions: [makeTestCoinbase()], balloonProof: regtestProof(for: makeTestHeader()))
        try wallet.setScanHeight(49)
        try wallet.indexBlock(emptyBlock, height: 50)

        // Block at height 100 with a tx paying to our address
        let tx = Transaction(
            version: 0,
            inputs: [Input(prevout: .null, sequence: 0xFFFF_FFFF)],
            outputs: [Output(value: 1_000_000, address: addr)],
            locktime: 0,
            witnesses: [Witness(items: [])]
        )
        let block = Block(header: makeTestHeader(), transactions: [makeTestCoinbase(), tx], balloonProof: regtestProof(for: makeTestHeader()))
        try wallet.setScanHeight(99)
        try wallet.indexBlock(block, height: 100)

        XCTAssertEqual(wallet.birthHeight, 100)
    }

    func testBirthHeightMultipleTransactions() throws {
        let wallet = try WalletDB(path: tmpDir, network: .main)
        _ = try wallet.create(mnemonic: "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about")
        let addr = try wallet.getReceiveAddress()

        // Block at height 50
        let tx1 = Transaction(
            version: 0,
            inputs: [Input(prevout: .null, sequence: 0xFFFF_FFFF)],
            outputs: [Output(value: 1_000_000, address: addr)],
            locktime: 0,
            witnesses: [Witness(items: [])]
        )
        let block1 = Block(header: makeTestHeader(), transactions: [makeTestCoinbase(), tx1], balloonProof: regtestProof(for: makeTestHeader()))
        try wallet.indexBlock(block1, height: 50)

        // Advance scanHeight to allow indexing at height 200
        try wallet.setScanHeight(199)

        // Block at height 200
        let tx2 = Transaction(
            version: 0,
            inputs: [Input(prevout: .null, sequence: 0xFFFF_FFFF)],
            outputs: [Output(value: 2_000_000, address: addr)],
            locktime: 0,
            witnesses: [Witness(items: [])]
        )
        let block2 = Block(header: makeTestHeader(), transactions: [makeTestCoinbase(), tx2], balloonProof: regtestProof(for: makeTestHeader()))
        try wallet.indexBlock(block2, height: 200)

        XCTAssertEqual(wallet.birthHeight, 50, "Should return earliest transaction height")
    }

    // MARK: - Name Coin Lookup

    func testFindNameCoins() throws {
        let wallet = try WalletDB(path: tmpDir, network: .main)
        _ = try wallet.create(mnemonic: "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about")
        let addr = try wallet.getReceiveAddress()

        let nameHash = NameHash(unchecked: [UInt8](repeating: 0xDD, count: 32))
        let bidOutput = Output(value: 50_000, address: addr,
            covenant: Covenant(type: .bid, items: [nameHash.bytes, [UInt8](repeating: 0, count: 4), [UInt8](repeating: 0, count: 32)]))
        let tx = Transaction(
            version: 0,
            inputs: [Input(prevout: .null, sequence: 0xFFFF_FFFF)],
            outputs: [bidOutput],
            locktime: 0,
            witnesses: [Witness(items: [])]
        )
        let block = Block(header: makeTestHeader(), transactions: [makeTestCoinbase(), tx], balloonProof: regtestProof(for: makeTestHeader()))
        try wallet.indexBlock(block, height: 1)

        let bidCoins = try wallet.findNameCoins(nameHash: nameHash, covenantType: .bid)
        XCTAssertEqual(bidCoins.count, 1)
        XCTAssertEqual(bidCoins[0].value, 50_000)

        let registerCoins = try wallet.findNameCoins(nameHash: nameHash, covenantType: .register)
        XCTAssertEqual(registerCoins.count, 0)
    }

    func testFindCurrentNameCoin() throws {
        let wallet = try WalletDB(path: tmpDir, network: .main)
        _ = try wallet.create(mnemonic: "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about")
        let addr = try wallet.getReceiveAddress()

        let nameHash = NameHash(unchecked: [UInt8](repeating: 0xEE, count: 32))

        // No name coins yet
        XCTAssertNil(try wallet.findCurrentNameCoin(nameHash: nameHash))

        // Add a REGISTER coin
        let registerOutput = Output(value: 10_000, address: addr,
            covenant: Covenant(type: .register, items: [nameHash.bytes, [UInt8](repeating: 0, count: 4), []]))
        let tx = Transaction(
            version: 0,
            inputs: [Input(prevout: .null, sequence: 0xFFFF_FFFF)],
            outputs: [registerOutput],
            locktime: 0,
            witnesses: [Witness(items: [])]
        )
        let block = Block(header: makeTestHeader(), transactions: [makeTestCoinbase(), tx], balloonProof: regtestProof(for: makeTestHeader()))
        try wallet.indexBlock(block, height: 1)

        let found = try wallet.findCurrentNameCoin(nameHash: nameHash)
        XCTAssertNotNil(found)
        XCTAssertEqual(found?.covenant.type, .register)
    }

    func testFindCurrentNameCoinRecognizesFinalize() throws {
        let wallet = try WalletDB(path: tmpDir, network: .main)
        _ = try wallet.create(mnemonic: "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about")
        let addr = try wallet.getReceiveAddress()

        let nameHash = NameHash(unchecked: [UInt8](repeating: 0xAA, count: 32))
        // Only a FINALIZE coin — the state a wallet is in right after
        // receiving a transferred name, before its first UPDATE.
        let finalizeOutput = Output(value: 10_000, address: addr,
            covenant: Covenant(type: .finalize, items: [
                nameHash.bytes,
                [UInt8](repeating: 0, count: 4),
                [UInt8]("name".utf8),
                [0],
                [UInt8](repeating: 0, count: 4),
                [UInt8](repeating: 0, count: 4),
                [UInt8](repeating: 0, count: 32),
            ]))
        let tx = Transaction(
            version: 0,
            inputs: [Input(prevout: .null, sequence: 0xFFFF_FFFF)],
            outputs: [finalizeOutput],
            locktime: 0,
            witnesses: [Witness(items: [])]
        )
        let block = Block(header: makeTestHeader(), transactions: [makeTestCoinbase(), tx], balloonProof: regtestProof(for: makeTestHeader()))
        try wallet.indexBlock(block, height: 1)

        let found = try wallet.findCurrentNameCoin(nameHash: nameHash)
        XCTAssertNotNil(found,
                        "FINALIZE coin must count as ownership so the recipient of a transfer can update/renew the name")
        XCTAssertEqual(found?.covenant.type, .finalize)
    }

    func testFindCurrentNameCoinIgnoresNonOwnerTypes() throws {
        let wallet = try WalletDB(path: tmpDir, network: .main)
        _ = try wallet.create(mnemonic: "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about")
        let addr = try wallet.getReceiveAddress()

        let nameHash = NameHash(unchecked: [UInt8](repeating: 0xFF, count: 32))
        // Only a BID coin — not an ownership type
        let bidOutput = Output(value: 50_000, address: addr,
            covenant: Covenant(type: .bid, items: [nameHash.bytes, [UInt8](repeating: 0, count: 4), [UInt8](repeating: 0, count: 32)]))
        let tx = Transaction(
            version: 0,
            inputs: [Input(prevout: .null, sequence: 0xFFFF_FFFF)],
            outputs: [bidOutput],
            locktime: 0,
            witnesses: [Witness(items: [])]
        )
        let block = Block(header: makeTestHeader(), transactions: [makeTestCoinbase(), tx], balloonProof: regtestProof(for: makeTestHeader()))
        try wallet.indexBlock(block, height: 1)

        XCTAssertNil(try wallet.findCurrentNameCoin(nameHash: nameHash),
                     "BID coin should not be found by findCurrentNameCoin")
    }

    // MARK: - Transaction Building

    func testCreateTransaction() throws {
        let wallet = try WalletDB(path: tmpDir, network: .main)
        _ = try wallet.create(mnemonic: "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about")
        let addr = try wallet.getReceiveAddress()

        // Fund the wallet with a non-coinbase tx (txIndex > 0)
        let fundTx = Transaction(
            version: 0,
            inputs: [Input(prevout: Outpoint(hash: Hash256(unchecked: [UInt8](repeating: 0x11, count: 32)), index: 0))],
            outputs: [Output(value: 10_000_000, address: addr)],
            locktime: 0,
            witnesses: [Witness(items: [])]
        )
        let block = Block(header: makeTestHeader(), transactions: [makeTestCoinbase(), fundTx], balloonProof: regtestProof(for: makeTestHeader()))
        try wallet.indexBlock(block, height: 1)

        // Create a transaction sending 1 FBD to another address
        let dest = Address(unchecked: 0, hash: [UInt8](repeating: 0xAB, count: 20))
        let tx = try wallet.createTransaction(destination: dest, amount: 1_000_000, currentHeight: 10)

        // Transaction should have at least 1 input and 2 outputs (send + change)
        XCTAssertFalse(tx.inputs.isEmpty)
        XCTAssertTrue(tx.outputs.count >= 1)

        // First output should be the send
        XCTAssertEqual(tx.outputs[0].value, 1_000_000)
        XCTAssertEqual(tx.outputs[0].address, dest)

        // Should have witnesses for each input
        XCTAssertEqual(tx.witnesses.count, tx.inputs.count)

        // Each witness should have sig + pubkey
        for witness in tx.witnesses {
            XCTAssertEqual(witness.items.count, 2)
            XCTAssertEqual(witness.items[0].count, 65, "Signature should be 64 + 1 sighash byte")
            XCTAssertEqual(witness.items[1].count, 33, "Compressed public key should be 33 bytes")
        }
    }

    func testCreateTransactionInsufficientFunds() throws {
        let wallet = try WalletDB(path: tmpDir, network: .main)
        _ = try wallet.create(mnemonic: "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about")

        // Empty wallet — should fail
        let dest = Address(unchecked: 0, hash: [UInt8](repeating: 0xAB, count: 20))
        XCTAssertThrowsError(try wallet.createTransaction(destination: dest, amount: 1_000_000, currentHeight: 10))
    }

    func testCreateTransactionSubtractFee() throws {
        let wallet = try WalletDB(path: tmpDir, network: .main)
        _ = try wallet.create(mnemonic: "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about")
        let addr = try wallet.getReceiveAddress()

        let fundTx = Transaction(
            version: 0,
            inputs: [Input(prevout: Outpoint(hash: Hash256(unchecked: [UInt8](repeating: 0x22, count: 32)), index: 0))],
            outputs: [Output(value: 5_000_000, address: addr)],
            locktime: 0,
            witnesses: [Witness(items: [])]
        )
        let block = Block(header: makeTestHeader(), transactions: [makeTestCoinbase(), fundTx], balloonProof: regtestProof(for: makeTestHeader()))
        try wallet.indexBlock(block, height: 1)

        let dest = Address(unchecked: 0, hash: [UInt8](repeating: 0xCD, count: 20))
        // Send 3M with subtractFee — send output should be less than 3M
        let tx = try wallet.createTransaction(destination: dest, amount: 3_000_000, currentHeight: 10, subtractFee: true)

        XCTAssertTrue(tx.outputs[0].value < 3_000_000, "Fee should be subtracted from send amount")
        XCTAssertEqual(tx.outputs[0].address, dest)
    }

    func testCreateCovenantTransaction() throws {
        let wallet = try WalletDB(path: tmpDir, network: .main)
        _ = try wallet.create(mnemonic: "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about")
        let addr = try wallet.getReceiveAddress()

        // Fund wallet
        let fundTx = Transaction(
            version: 0,
            inputs: [Input(prevout: Outpoint(hash: Hash256(unchecked: [UInt8](repeating: 0x33, count: 32)), index: 0))],
            outputs: [Output(value: 10_000_000, address: addr)],
            locktime: 0,
            witnesses: [Witness(items: [])]
        )
        let block = Block(header: makeTestHeader(), transactions: [makeTestCoinbase(), fundTx], balloonProof: regtestProof(for: makeTestHeader()))
        try wallet.indexBlock(block, height: 1)

        // Create an OPEN covenant transaction
        let nameHash = NameHash(unchecked: [UInt8](repeating: 0xAA, count: 32))
        let openCov = Covenant(type: .open, items: [nameHash.bytes])
        let tx = try wallet.createCovenantTransaction(
            covenant: openCov,
            value: 0,
            address: addr,
            currentHeight: 10
        )

        XCTAssertFalse(tx.inputs.isEmpty)
        // First output should have the OPEN covenant
        XCTAssertEqual(tx.outputs[0].covenant.type, .open)
        XCTAssertEqual(tx.outputs[0].covenant.items[0], nameHash.bytes)
        XCTAssertEqual(tx.witnesses.count, tx.inputs.count)
    }

    func testCreateBatchCovenantTransaction() throws {
        let wallet = try WalletDB(path: tmpDir, network: .main)
        _ = try wallet.create(mnemonic: "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about")
        let addr = try wallet.getReceiveAddress()

        // Fund wallet generously
        let fundTx = Transaction(
            version: 0,
            inputs: [Input(prevout: Outpoint(hash: Hash256(unchecked: [UInt8](repeating: 0x44, count: 32)), index: 0))],
            outputs: [Output(value: 100_000_000, address: addr)],
            locktime: 0,
            witnesses: [Witness(items: [])]
        )
        let block = Block(header: makeTestHeader(), transactions: [makeTestCoinbase(), fundTx], balloonProof: regtestProof(for: makeTestHeader()))
        try wallet.indexBlock(block, height: 1)

        // Batch: two OPEN covenants
        let name1 = [UInt8](repeating: 0xAA, count: 32)
        let name2 = [UInt8](repeating: 0xBB, count: 32)
        let ops = [
            WalletDB.CovenantOp(covenant: Covenant(type: .open, items: [name1]), value: 0, address: addr),
            WalletDB.CovenantOp(covenant: Covenant(type: .open, items: [name2]), value: 0, address: addr),
        ]

        let tx = try wallet.createBatchCovenantTransaction(ops: ops, currentHeight: 10)

        // Should have 2 covenant outputs + change
        XCTAssertTrue(tx.outputs.count >= 2)
        XCTAssertEqual(tx.outputs[0].covenant.type, .open)
        XCTAssertEqual(tx.outputs[1].covenant.type, .open)
        XCTAssertEqual(tx.outputs[0].covenant.items[0], name1)
        XCTAssertEqual(tx.outputs[1].covenant.items[0], name2)
        XCTAssertEqual(tx.witnesses.count, tx.inputs.count)
    }

    func testCreateBatchEmptyOpsFails() throws {
        let wallet = try WalletDB(path: tmpDir, network: .main)
        _ = try wallet.create()

        XCTAssertThrowsError(try wallet.createBatchCovenantTransaction(ops: [], currentHeight: 10))
    }

    func testCreateTransactionChangeAddress() throws {
        let wallet = try WalletDB(path: tmpDir, network: .main)
        _ = try wallet.create(mnemonic: "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about")
        let addr = try wallet.getReceiveAddress()
        _ = try wallet.getChangeAddress()

        // Fund wallet with enough for a transaction + change
        let fundTx = Transaction(
            version: 0,
            inputs: [Input(prevout: Outpoint(hash: Hash256(unchecked: [UInt8](repeating: 0x55, count: 32)), index: 0))],
            outputs: [Output(value: 50_000_000, address: addr)],
            locktime: 0,
            witnesses: [Witness(items: [])]
        )
        let block = Block(header: makeTestHeader(), transactions: [makeTestCoinbase(), fundTx], balloonProof: regtestProof(for: makeTestHeader()))
        try wallet.indexBlock(block, height: 1)

        let dest = Address(unchecked: 0, hash: [UInt8](repeating: 0xEE, count: 20))
        let tx = try wallet.createTransaction(destination: dest, amount: 1_000_000, currentHeight: 10)

        // Should have 2 outputs: send + change
        XCTAssertEqual(tx.outputs.count, 2)

        // Change output should go to a wallet address
        let changeOutput = tx.outputs[1]
        XCTAssertTrue(wallet.ismine(changeOutput.address), "Change should go to a wallet address")
    }

    // MARK: - WalletCoin Serialization

    func testWalletCoinSerializeRoundTrip() throws {
        let addr = Address(unchecked: 0, hash: [UInt8](repeating: 0x42, count: 20))
        let cov = Covenant(type: .register, items: [
            [UInt8](repeating: 0xAA, count: 32),
            [UInt8](repeating: 0, count: 4),
            [1, 2, 3]
        ])
        let outpoint = Outpoint(hash: Hash256(unchecked: [UInt8](repeating: 0xBB, count: 32)), index: 7)
        let coin = WalletCoin(value: 123_456_789, height: 42, coinbase: false,
                              address: addr, covenant: cov, outpoint: outpoint)

        let data = coin.serialize()
        let restored = WalletCoin.deserialize(data, outpoint: outpoint)

        XCTAssertNotNil(restored)
        XCTAssertEqual(restored?.value, 123_456_789)
        XCTAssertEqual(restored?.height, 42)
        XCTAssertEqual(restored?.coinbase, false)
        XCTAssertEqual(restored?.address, addr)
        XCTAssertEqual(restored?.covenant.type, .register)
        XCTAssertEqual(restored?.covenant.items.count, 3)
    }

    func testWalletCoinSerializeCoinbase() throws {
        let addr = Address(unchecked: 0, hash: [UInt8](repeating: 0, count: 20))
        let outpoint = Outpoint(hash: .zero, index: 0)
        let coin = WalletCoin(value: 2_000_000_000, height: 1, coinbase: true,
                              address: addr, covenant: .none, outpoint: outpoint)

        let data = coin.serialize()
        let restored = WalletCoin.deserialize(data, outpoint: outpoint)

        XCTAssertNotNil(restored)
        XCTAssertEqual(restored?.coinbase, true)
        XCTAssertEqual(restored?.value, 2_000_000_000)
    }

    // MARK: - Detailed Balance

    func testGetDetailedBalanceEmpty() throws {
        let wallet = try WalletDB(path: tmpDir, network: .main)
        _ = try wallet.create()

        let bal = try wallet.getDetailedBalance()
        XCTAssertEqual(bal.confirmed, 0)
        XCTAssertEqual(bal.unconfirmed, 0)
        XCTAssertEqual(bal.lockedConfirmed, 0)
        XCTAssertEqual(bal.lockedUnconfirmed, 0)
    }

    func testGetDetailedBalanceConfirmed() throws {
        let wallet = try WalletDB(path: tmpDir, network: .main)
        _ = try wallet.create(mnemonic: "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about")
        let addr = try wallet.getReceiveAddress()

        // Confirmed coin (height >= 0, NONE covenant = spendable)
        let coinbaseOutput = Output(value: 5_000_000, address: addr)
        let coinbaseTx = Transaction(
            version: 0,
            inputs: [Input(prevout: .null, sequence: 0xFFFF_FFFF)],
            outputs: [coinbaseOutput],
            locktime: 0,
            witnesses: [Witness(items: [])]
        )
        let block = Block(header: makeTestHeader(), transactions: [coinbaseTx], balloonProof: regtestProof(for: makeTestHeader()))
        try wallet.indexBlock(block, height: 1)

        let bal = try wallet.getDetailedBalance()
        XCTAssertEqual(bal.confirmed, 5_000_000)
        XCTAssertEqual(bal.unconfirmed, 5_000_000, "unconfirmed equals confirmed when no pending txs")
        XCTAssertEqual(bal.lockedConfirmed, 0)
        XCTAssertEqual(bal.lockedUnconfirmed, 0)
    }

    func testGetDetailedBalanceLocked() throws {
        let wallet = try WalletDB(path: tmpDir, network: .main)
        _ = try wallet.create(mnemonic: "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about")
        let addr = try wallet.getReceiveAddress()

        // A BID covenant is "nonspendable" (locked)
        let nameHash = NameHash(unchecked: [UInt8](repeating: 0xAA, count: 32))
        let bidOutput = Output(value: 3_000_000, address: addr,
            covenant: Covenant(type: .bid, items: [nameHash.bytes, [UInt8](repeating: 0, count: 4), [UInt8](repeating: 0, count: 32)]))
        let tx = Transaction(
            version: 0,
            inputs: [Input(prevout: .null, sequence: 0xFFFF_FFFF)],
            outputs: [bidOutput],
            locktime: 0,
            witnesses: [Witness(items: [])]
        )
        let block = Block(header: makeTestHeader(), transactions: [makeTestCoinbase(), tx], balloonProof: regtestProof(for: makeTestHeader()))
        try wallet.indexBlock(block, height: 1)

        let bal = try wallet.getDetailedBalance()
        XCTAssertEqual(bal.confirmed, 3_000_000)
        XCTAssertEqual(bal.lockedConfirmed, 3_000_000, "BID coins should be locked")
    }

    func testGetDetailedBalanceVsGetBalance() throws {
        let wallet = try WalletDB(path: tmpDir, network: .main)
        _ = try wallet.create(mnemonic: "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about")
        let addr = try wallet.getReceiveAddress()

        let coinbaseOutput = Output(value: 7_000_000, address: addr)
        let coinbaseTx = Transaction(
            version: 0,
            inputs: [Input(prevout: .null, sequence: 0xFFFF_FFFF)],
            outputs: [coinbaseOutput],
            locktime: 0,
            witnesses: [Witness(items: [])]
        )
        let block = Block(header: makeTestHeader(), transactions: [coinbaseTx], balloonProof: regtestProof(for: makeTestHeader()))
        try wallet.indexBlock(block, height: 1)

        let simple = try wallet.getBalance()
        let detailed = try wallet.getDetailedBalance()
        XCTAssertEqual(simple, detailed.unconfirmed,
                       "getBalance should equal unconfirmed (which includes confirmed)")
    }

    // MARK: - Import Xpriv

    func testImportXpriv() throws {
        // First, derive an xpriv from the known mnemonic
        let refWallet = try WalletDB(path: tmpDir + "/ref", network: .main)
        _ = try refWallet.create(mnemonic: "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about")
        guard let xpriv = refWallet.xpriv else {
            XCTFail("Reference wallet should have xpriv")
            return
        }

        // Import into a new wallet
        let wallet = try WalletDB(path: tmpDir + "/imported", network: .main)
        try wallet.importXpriv(xpriv)

        XCTAssertTrue(wallet.initialized)
        XCTAssertNil(wallet.mnemonic, "Xpriv import should not have mnemonic")
        XCTAssertEqual(wallet.xpriv, xpriv)
        XCTAssertEqual(wallet.addressCount, 200, "Should derive 100 receive + 100 change addresses")

        // Addresses should match the reference wallet
        let refAddr = try refWallet.getReceiveAddress()
        let importedAddr = try wallet.getReceiveAddress()
        XCTAssertEqual(refAddr, importedAddr, "Same xpriv should produce same addresses")
    }

    func testImportXprivCannotDoubleInit() throws {
        let refWallet = try WalletDB(path: tmpDir + "/ref2", network: .main)
        _ = try refWallet.create(mnemonic: "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about")
        guard let xpriv = refWallet.xpriv else {
            XCTFail("Reference wallet should have xpriv")
            return
        }

        let wallet = try WalletDB(path: tmpDir + "/imp2", network: .main)
        try wallet.importXpriv(xpriv)

        XCTAssertThrowsError(try wallet.importXpriv(xpriv)) { error in
            guard case WalletError.alreadyInitialized = error else {
                XCTFail("Expected alreadyInitialized error, got \(error)")
                return
            }
        }
    }

    // MARK: - Index Transaction (mempool)

    func testIndexTransactionAddsUnconfirmedCoin() throws {
        let wallet = try WalletDB(path: tmpDir, network: .main)
        _ = try wallet.create(mnemonic: "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about")
        let addr = try wallet.getReceiveAddress()

        let tx = Transaction(
            version: 0,
            inputs: [Input(prevout: Outpoint(hash: Hash256(unchecked: [UInt8](repeating: 0x11, count: 32)), index: 0))],
            outputs: [Output(value: 2_000_000, address: addr)],
            locktime: 0,
            witnesses: [Witness(items: [])]
        )

        let result = try wallet.indexTransaction(tx)
        XCTAssertTrue(result, "Should return true when tx touches wallet")

        let coins = try wallet.listUnspent()
        XCTAssertEqual(coins.count, 1)
        XCTAssertEqual(coins[0].value, 2_000_000)
        XCTAssertEqual(coins[0].height, -1, "Mempool tx should have height -1")

        // Balance should show as unconfirmed
        let bal = try wallet.getDetailedBalance()
        XCTAssertEqual(bal.unconfirmed, 2_000_000)
        XCTAssertEqual(bal.confirmed, 0)
    }

    func testIndexTransactionReturnsFalseForIrrelevant() throws {
        let wallet = try WalletDB(path: tmpDir, network: .main)
        _ = try wallet.create()

        let otherAddr = Address(unchecked: 0, hash: [UInt8](repeating: 0xFF, count: 20))
        let tx = Transaction(
            version: 0,
            inputs: [Input(prevout: Outpoint(hash: Hash256(unchecked: [UInt8](repeating: 0x22, count: 32)), index: 0))],
            outputs: [Output(value: 1_000_000, address: otherAddr)],
            locktime: 0,
            witnesses: [Witness(items: [])]
        )

        let result = try wallet.indexTransaction(tx)
        XCTAssertFalse(result, "Should return false when tx doesn't touch wallet")
    }

    func testIndexTransactionSpendsCoin() throws {
        let wallet = try WalletDB(path: tmpDir, network: .main)
        _ = try wallet.create(mnemonic: "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about")
        let addr = try wallet.getReceiveAddress()

        // First, add a confirmed coin via indexBlock
        let fundTx = Transaction(
            version: 0,
            inputs: [Input(prevout: .null, sequence: 0xFFFF_FFFF)],
            outputs: [Output(value: 3_000_000, address: addr)],
            locktime: 0,
            witnesses: [Witness(items: [])]
        )
        let block = Block(header: makeTestHeader(), transactions: [fundTx], balloonProof: regtestProof(for: makeTestHeader()))
        try wallet.indexBlock(block, height: 1)
        XCTAssertEqual(try wallet.getBalance(), 3_000_000)

        // Now index a mempool tx that spends the coin
        let fundHash = fundTx.txHash()
        let otherAddr = Address(unchecked: 0, hash: [UInt8](repeating: 0xAB, count: 20))
        let spendTx = Transaction(
            version: 0,
            inputs: [Input(prevout: Outpoint(hash: fundHash, index: 0))],
            outputs: [Output(value: 2_500_000, address: otherAddr)],
            locktime: 0,
            witnesses: [Witness(items: [])]
        )
        let result = try wallet.indexTransaction(spendTx)
        XCTAssertTrue(result)
        XCTAssertEqual(try wallet.getBalance(), 0, "Coin should be spent by mempool tx")
    }

    // MARK: - Reset For Rescan

    func testResetForRescan() throws {
        let wallet = try WalletDB(path: tmpDir, network: .main)
        _ = try wallet.create(mnemonic: "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about")
        let addr = try wallet.getReceiveAddress()

        // Add some coins
        let coinbaseOutput = Output(value: 5_000_000, address: addr)
        let coinbaseTx = Transaction(
            version: 0,
            inputs: [Input(prevout: .null, sequence: 0xFFFF_FFFF)],
            outputs: [coinbaseOutput],
            locktime: 0,
            witnesses: [Witness(items: [])]
        )
        let block = Block(header: makeTestHeader(), transactions: [coinbaseTx], balloonProof: regtestProof(for: makeTestHeader()))
        try wallet.indexBlock(block, height: 50)

        XCTAssertEqual(try wallet.getBalance(), 5_000_000)
        XCTAssertEqual(wallet.scanHeight, 50)

        // Reset
        try wallet.resetForRescan()

        XCTAssertEqual(wallet.scanHeight, -1)
        XCTAssertEqual(try wallet.getBalance(), 0, "Balance should be 0 after reset")
        XCTAssertEqual(try wallet.listUnspent().count, 0)
        XCTAssertTrue(wallet.initialized, "Wallet should still be initialized")
    }

    // MARK: - Set Indices / Ensure Addresses

    func testSetIndicesPersistence() throws {
        let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
        let wallet = try WalletDB(path: tmpDir, network: .main)
        _ = try wallet.create(mnemonic: mnemonic)

        try wallet.setIndices(receive: 5, change: 3, nextReceive: 25, nextChange: 23)
        let indices = wallet.walletIndices
        XCTAssertEqual(indices.receive, 5)
        XCTAssertEqual(indices.change, 3)
        XCTAssertEqual(indices.nextReceive, 25)
        XCTAssertEqual(indices.nextChange, 23)

        // Reopen and verify persistence
        wallet.close()
        let wallet2 = try WalletDB(path: tmpDir, network: .main)
        let indices2 = wallet2.walletIndices
        XCTAssertEqual(indices2.receive, 5)
        XCTAssertEqual(indices2.change, 3)
        XCTAssertEqual(indices2.nextReceive, 25)
        XCTAssertEqual(indices2.nextChange, 23)
    }

    func testEnsureAddressesExtendsPool() throws {
        let wallet = try WalletDB(path: tmpDir, network: .main)
        _ = try wallet.create(mnemonic: "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about")

        // Initial: 100 receive + 100 change = 200
        let initialCount = wallet.addressCount
        XCTAssertEqual(initialCount, 200)

        // Extend to 110 receive, 105 change
        try wallet.ensureAddresses(receive: 110, change: 105)
        XCTAssertTrue(wallet.addressCount > initialCount, "Should have derived more addresses")

        let indices = wallet.walletIndices
        XCTAssertGreaterThanOrEqual(indices.nextReceive, 110)
        XCTAssertGreaterThanOrEqual(indices.nextChange, 105)
    }

    func testEnsureAddressesNoOpWhenSufficient() throws {
        let wallet = try WalletDB(path: tmpDir, network: .main)
        _ = try wallet.create(mnemonic: "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about")

        let initialCount = wallet.addressCount

        // Request fewer than what's already derived
        try wallet.ensureAddresses(receive: 10, change: 10)
        XCTAssertEqual(wallet.addressCount, initialCount, "Should not derive more addresses")
    }

    // MARK: - Dust Threshold

    func testDustThresholdDropsSmallChange() throws {
        let wallet = try WalletDB(path: tmpDir, network: .main)
        _ = try wallet.create(mnemonic: "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about")
        let addr = try wallet.getReceiveAddress()

        // Fund with a non-coinbase tx
        let fundTx = Transaction(
            version: 0,
            inputs: [Input(prevout: Outpoint(hash: Hash256(unchecked: [UInt8](repeating: 0x66, count: 32)), index: 0))],
            outputs: [Output(value: 1_001_000, address: addr)],
            locktime: 0,
            witnesses: [Witness(items: [])]
        )
        let block = Block(header: makeTestHeader(), transactions: [makeTestCoinbase(), fundTx], balloonProof: regtestProof(for: makeTestHeader()))
        try wallet.indexBlock(block, height: 1)

        let dest = Address(unchecked: 0, hash: [UInt8](repeating: 0xAB, count: 20))
        // Send nearly all — change should be below dust threshold (500)
        let tx = try wallet.createTransaction(destination: dest, amount: 1_000_000, currentHeight: 10)

        // If change would be below 500 bumps, it's dropped
        // With 1,001,000 input and 1,000,000 send + fee, the change is tiny
        // Transaction should either have 1 output (no change) or 2 outputs (if change > dust)
        if tx.outputs.count == 1 {
            // Change was dropped (dust)
            XCTAssertEqual(tx.outputs[0].address, dest)
        } else {
            // Change exists, must be above dust threshold
            let changeOutput = tx.outputs[1]
            XCTAssertGreaterThanOrEqual(changeOutput.value, 500, "Change must be above dust threshold")
        }
    }

    // MARK: - Coin Selection Edge Cases

    func testCoinbaseMaturityExcludesImmatureCoins() throws {
        let wallet = try WalletDB(path: tmpDir, network: .main)
        _ = try wallet.create(mnemonic: "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about")
        let addr = try wallet.getReceiveAddress()

        // Coinbase at height 1
        let coinbaseOutput = Output(value: 10_000_000, address: addr)
        let coinbaseTx = Transaction(
            version: 0,
            inputs: [Input(prevout: .null, sequence: 0xFFFF_FFFF)],
            outputs: [coinbaseOutput],
            locktime: 0,
            witnesses: [Witness(items: [])]
        )
        let block = Block(header: makeTestHeader(), transactions: [coinbaseTx], balloonProof: regtestProof(for: makeTestHeader()))
        try wallet.indexBlock(block, height: 1)

        let dest = Address(unchecked: 0, hash: [UInt8](repeating: 0xAB, count: 20))
        // At height 10, the coinbase is immature (needs 100 confirmations)
        XCTAssertThrowsError(try wallet.createTransaction(destination: dest, amount: 1_000_000, currentHeight: 10),
                             "Should fail because coinbase is immature")
    }

    func testLargestFirstCoinSelection() throws {
        let wallet = try WalletDB(path: tmpDir, network: .main)
        _ = try wallet.create(mnemonic: "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about")
        let addr = try wallet.getReceiveAddress()

        // Create three non-coinbase coins of different sizes
        for (i, value) in [(0x11, 1_000_000), (0x22, 5_000_000), (0x33, 3_000_000)] as [(Int, UInt64)] {
            let fundTx = Transaction(
                version: 0,
                inputs: [Input(prevout: Outpoint(hash: Hash256(unchecked: [UInt8](repeating: UInt8(i), count: 32)), index: 0))],
                outputs: [Output(value: value, address: addr)],
                locktime: 0,
                witnesses: [Witness(items: [])]
            )
            let block = Block(header: makeTestHeader(), transactions: [makeTestCoinbase(), fundTx], balloonProof: regtestProof(for: makeTestHeader()))
            try wallet.setScanHeight(Int(i) - 1)
            try wallet.indexBlock(block, height: Int(i))
        }

        let dest = Address(unchecked: 0, hash: [UInt8](repeating: 0xAB, count: 20))
        // Request 4M — should use the 5M coin first (largest-first)
        let tx = try wallet.createTransaction(destination: dest, amount: 4_000_000, currentHeight: 200)

        // Should only need 1 input (the 5M coin)
        XCTAssertEqual(tx.inputs.count, 1)
    }

    // MARK: - Fee Estimation

    func testTransactionHasFee() throws {
        let wallet = try WalletDB(path: tmpDir, network: .main)
        _ = try wallet.create(mnemonic: "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about")
        let addr = try wallet.getReceiveAddress()

        let fundTx = Transaction(
            version: 0,
            inputs: [Input(prevout: Outpoint(hash: Hash256(unchecked: [UInt8](repeating: 0x77, count: 32)), index: 0))],
            outputs: [Output(value: 50_000_000, address: addr)],
            locktime: 0,
            witnesses: [Witness(items: [])]
        )
        let block = Block(header: makeTestHeader(), transactions: [makeTestCoinbase(), fundTx], balloonProof: regtestProof(for: makeTestHeader()))
        try wallet.indexBlock(block, height: 1)

        let dest = Address(unchecked: 0, hash: [UInt8](repeating: 0xAB, count: 20))
        let tx = try wallet.createTransaction(destination: dest, amount: 1_000_000, currentHeight: 10)

        // Sum of inputs > sum of outputs (the difference is the fee)
        let inputValue: UInt64 = 50_000_000 // we know the single input value
        let outputSum = tx.outputs.reduce(UInt64(0)) { $0 + $1.value }
        XCTAssertGreaterThan(inputValue, outputSum, "Fee should be positive")

        let fee = inputValue - outputSum
        XCTAssertGreaterThan(fee, 0)
        XCTAssertLessThan(fee, 100_000, "Fee should be reasonable")
    }

    func testWeightCalculation() throws {
        // A simple transaction should have weight = baseSize*4 + witnessSize
        let wallet = try WalletDB(path: tmpDir, network: .main)
        _ = try wallet.create(mnemonic: "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about")
        let addr = try wallet.getReceiveAddress()

        let fundTx = Transaction(
            version: 0,
            inputs: [Input(prevout: Outpoint(hash: Hash256(unchecked: [UInt8](repeating: 0x88, count: 32)), index: 0))],
            outputs: [Output(value: 10_000_000, address: addr)],
            locktime: 0,
            witnesses: [Witness(items: [])]
        )
        let block = Block(header: makeTestHeader(), transactions: [makeTestCoinbase(), fundTx], balloonProof: regtestProof(for: makeTestHeader()))
        try wallet.indexBlock(block, height: 1)

        let dest = Address(unchecked: 0, hash: [UInt8](repeating: 0xAB, count: 20))
        let tx = try wallet.createTransaction(destination: dest, amount: 1_000_000, currentHeight: 10)

        let weight = tx.weight
        XCTAssertGreaterThan(weight, 0)
        // Weight should be reasonable for a 1-in, 2-out P2WPKH tx
        XCTAssertGreaterThan(weight, 200)
        XCTAssertLessThan(weight, 2000)
    }

    // MARK: - Multisig

    func testListMultisigEmpty() throws {
        let wallet = try WalletDB(path: tmpDir, network: .main)
        _ = try wallet.create(mnemonic: "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about")

        let configs = try wallet.listMultisig()
        XCTAssertEqual(configs.count, 0)
    }

    // MARK: - Transaction History

    func testListTransactionsAfterIndexBlock() throws {
        let wallet = try WalletDB(path: tmpDir, network: .main)
        _ = try wallet.create(mnemonic: "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about")
        let addr = try wallet.getReceiveAddress()

        let coinbaseOutput = Output(value: 5_000_000, address: addr)
        let coinbaseTx = Transaction(
            version: 0,
            inputs: [Input(prevout: .null, sequence: 0xFFFF_FFFF)],
            outputs: [coinbaseOutput],
            locktime: 0,
            witnesses: [Witness(items: [])]
        )
        let block = Block(header: makeTestHeader(), transactions: [coinbaseTx], balloonProof: regtestProof(for: makeTestHeader()))
        try wallet.indexBlock(block, height: 1)

        let records = try wallet.listTransactions()
        XCTAssertGreaterThan(records.count, 0, "Should have at least one transaction record")
        XCTAssertEqual(records[0].received, 5_000_000)
    }

    func testListTransactionsReverseOrder() throws {
        let wallet = try WalletDB(path: tmpDir, network: .main)
        _ = try wallet.create(mnemonic: "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about")
        let addr = try wallet.getReceiveAddress()

        // Index two blocks with wallet transactions
        for (height, value) in [(1, UInt64(1_000_000)), (2, UInt64(2_000_000))] {
            let tx = Transaction(
                version: 0,
                inputs: [Input(prevout: .null, sequence: 0xFFFF_FFFF)],
                outputs: [Output(value: value, address: addr)],
                locktime: 0,
                witnesses: [Witness(items: [])]
            )
            let block = Block(header: makeTestHeader(), transactions: [tx], balloonProof: regtestProof(for: makeTestHeader()))
            try wallet.indexBlock(block, height: height)
        }

        let records = try wallet.listTransactions()
        XCTAssertEqual(records.count, 2)
        // Most recent (height 2) should come first
        XCTAssertGreaterThanOrEqual(records[0].height, records[1].height)
    }

    func testListTransactionsPagination() throws {
        let wallet = try WalletDB(path: tmpDir, network: .main)
        _ = try wallet.create(mnemonic: "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about")
        let addr = try wallet.getReceiveAddress()

        // Index 5 blocks with wallet transactions
        for height in 1...5 {
            let tx = Transaction(
                version: 0,
                inputs: [Input(prevout: .null, sequence: 0xFFFF_FFFF)],
                outputs: [Output(value: UInt64(height) * 100_000, address: addr)],
                locktime: 0,
                witnesses: [Witness(items: [])]
            )
            let block = Block(header: makeTestHeader(), transactions: [tx], balloonProof: regtestProof(for: makeTestHeader()))
            try wallet.indexBlock(block, height: height)
        }

        let page1 = try wallet.listTransactions(count: 2, offset: 0)
        let page2 = try wallet.listTransactions(count: 2, offset: 2)
        XCTAssertEqual(page1.count, 2)
        XCTAssertEqual(page2.count, 2)
        // Pages should have different entries
        XCTAssertNotEqual(page1[0].txHash, page2[0].txHash)
    }

    // MARK: - Serialization

    func testWalletCoinRoundTripLargeCovenant() throws {
        let addr = Address(unchecked: 0, hash: [UInt8](repeating: 0x42, count: 20))
        // Large covenant with many items
        let items: [[UInt8]] = (0..<10).map { [UInt8](repeating: UInt8($0), count: 32) }
        let cov = Covenant(type: .finalize, items: items)
        let outpoint = Outpoint(hash: Hash256(unchecked: [UInt8](repeating: 0xCC, count: 32)), index: 3)
        let coin = WalletCoin(value: 999_999, height: 100, coinbase: false,
                              address: addr, covenant: cov, outpoint: outpoint)

        let data = coin.serialize()
        let restored = WalletCoin.deserialize(data, outpoint: outpoint)

        XCTAssertNotNil(restored)
        XCTAssertEqual(restored?.value, 999_999)
        XCTAssertEqual(restored?.height, 100)
        XCTAssertEqual(restored?.covenant.type, .finalize)
        XCTAssertEqual(restored?.covenant.items.count, 10)
        for i in 0..<10 {
            XCTAssertEqual(restored?.covenant.items[i], [UInt8](repeating: UInt8(i), count: 32))
        }
    }

    func testTransactionRecordRoundTrip() throws {
        let wallet = try WalletDB(path: tmpDir, network: .main)
        _ = try wallet.create(mnemonic: "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about")
        let addr = try wallet.getReceiveAddress()

        // Create a tx that will produce a TransactionRecord
        let tx = Transaction(
            version: 0,
            inputs: [Input(prevout: .null, sequence: 0xFFFF_FFFF)],
            outputs: [Output(value: 7_654_321, address: addr)],
            locktime: 0,
            witnesses: [Witness(items: [])]
        )
        let block = Block(header: makeTestHeader(), transactions: [tx], balloonProof: regtestProof(for: makeTestHeader()))
        try wallet.indexBlock(block, height: 42)

        // Retrieve and verify
        let records = try wallet.listTransactions()
        XCTAssertEqual(records.count, 1)
        let record = records[0]
        XCTAssertEqual(record.received, 7_654_321)
        XCTAssertEqual(record.height, 42)
        XCTAssertEqual(record.txHash, tx.txHash())
    }

    // MARK: - xpriv in getwalletinfo

    func testXprivAndXpubAvailable() throws {
        let wallet = try WalletDB(path: tmpDir, network: .main)
        _ = try wallet.create(mnemonic: "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about")

        XCTAssertNotNil(wallet.xpriv, "xpriv should be available")
        XCTAssertNotNil(wallet.xpub, "xpub should be available")

        // xpriv should start with "xprv"
        let xpriv = wallet.xpriv!
        XCTAssertTrue(xpriv.hasPrefix("xprv"), "xpriv should start with 'xprv'")

        // xpub should start with "xpub"
        let xpub = wallet.xpub!
        XCTAssertTrue(xpub.hasPrefix("xpub"), "xpub should start with 'xpub'")
    }

    // MARK: - Multiple Coins Spent in One Block

    func testMultipleCoinsSpentInOneBlock() throws {
        let wallet = try WalletDB(path: tmpDir, network: .main)
        _ = try wallet.create(mnemonic: "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about")
        let addr = try wallet.getReceiveAddress()

        // Fund wallet with two non-coinbase coins
        let fundTx1 = Transaction(
            version: 0,
            inputs: [Input(prevout: Outpoint(hash: Hash256(unchecked: [UInt8](repeating: 0xA1, count: 32)), index: 0))],
            outputs: [Output(value: 1_000_000, address: addr)],
            locktime: 0,
            witnesses: [Witness(items: [])]
        )
        let fundTx2 = Transaction(
            version: 0,
            inputs: [Input(prevout: Outpoint(hash: Hash256(unchecked: [UInt8](repeating: 0xA2, count: 32)), index: 0))],
            outputs: [Output(value: 2_000_000, address: addr)],
            locktime: 0,
            witnesses: [Witness(items: [])]
        )
        let block1 = Block(header: makeTestHeader(), transactions: [makeTestCoinbase(), fundTx1, fundTx2], balloonProof: regtestProof(for: makeTestHeader()))
        try wallet.indexBlock(block1, height: 1)

        XCTAssertEqual(try wallet.getBalance(), 3_000_000)
        XCTAssertEqual(try wallet.listUnspent().count, 2)

        // Spend both in one tx
        let otherAddr = Address(unchecked: 0, hash: [UInt8](repeating: 0xBB, count: 20))
        let spendTx = Transaction(
            version: 0,
            inputs: [
                Input(prevout: Outpoint(hash: fundTx1.txHash(), index: 0)),
                Input(prevout: Outpoint(hash: fundTx2.txHash(), index: 0)),
            ],
            outputs: [Output(value: 2_500_000, address: otherAddr)],
            locktime: 0,
            witnesses: [Witness(items: []), Witness(items: [])]
        )
        let block2 = Block(header: makeTestHeader(), transactions: [makeTestCoinbase(), spendTx], balloonProof: regtestProof(for: makeTestHeader()))
        try wallet.indexBlock(block2, height: 2)

        XCTAssertEqual(try wallet.getBalance(), 0)
        XCTAssertEqual(try wallet.listUnspent().count, 0)
    }

    // MARK: - Helpers

    private func makeTestHeader() -> BlockHeader {
        BlockHeader(
            nonce: 0,
            time: 0,
            prevBlock: .zero,
            treeRoot: .zero,
            bits: 0x2000_FFFF
        )
    }

    private func makeTestCoinbase() -> Transaction {
        Transaction(
            version: 0,
            inputs: [Input(prevout: .null, sequence: 0xFFFF_FFFF)],
            outputs: [Output(value: 0, address: .null)],
            locktime: 0,
            witnesses: [Witness(items: [])]
        )
    }
}

/// Compute a real BalloonProof for a header using regtest params (4 slots, instant).
private func regtestProof(for header: BlockHeader) -> BalloonProof {
    try! ProofOfWork.powHashWithProof(for: header, params: ConsensusParams.params(for: .regtest)).proof
}
