import Storage
import Foundation
import Base
import Consensus
import Covenants
import ExtCrypto
import Protocol
import Script
import Crypto

/// Detailed wallet balance breakdown.
public struct WalletBalance: Sendable {
    /// Total balance from confirmed transactions only.
    public let confirmed: UInt64
    /// Total balance including unconfirmed (confirmed + mempool pending).
    /// Equals `confirmed` when there are no pending transactions.
    public let unconfirmed: UInt64
    /// Confirmed balance locked in name covenants (bids, reveals, registers, etc.).
    public let lockedConfirmed: UInt64
    /// Locked balance including unconfirmed covenant operations.
    /// Equals `lockedConfirmed` when there are no pending transactions.
    public let lockedUnconfirmed: UInt64
    /// Confirmed coinbase balance that has not yet reached maturity.
    public let immatureCoinbase: UInt64
}

/// A wallet UTXO tracked in the database.
public struct WalletCoin: Sendable {
    /// The output value in bumps.
    public let value: UInt64
    /// The block height this coin was confirmed at.
    public let height: Int
    /// Whether this is a coinbase output.
    public let coinbase: Bool
    /// The output address.
    public let address: Address
    /// The output covenant.
    public let covenant: Covenant
    /// The outpoint (txid + index) of this coin.
    public let outpoint: Outpoint

    func serialize() -> [UInt8] {
        var w = BufferWriter(capacity: 64)
        w.writeUInt64LE(value)
        w.writeInt32LE(Int32(height))
        w.writeUInt8(coinbase ? 1 : 0)
        w.writeUInt8(address.version)
        w.writeUInt8(UInt8(address.hash.count))
        w.writeBytes(address.hash)
        w.writeUInt8(covenant.type.rawValue)
        w.writeUInt8(UInt8(min(covenant.items.count, 255)))
        for item in covenant.items {
            w.writeUInt16LE(UInt16(min(item.count, 65535)))
            w.writeBytes(item)
        }
        return w.data
    }

    static func deserialize(_ data: [UInt8], outpoint: Outpoint) -> WalletCoin? {
        var r = BufferReader(data)
        guard r.remaining >= 14 else { return nil }
        guard let value = try? r.readUInt64LE(),
              let height = try? r.readInt32LE(),
              let cb = try? r.readUInt8(),
              let addrVersion = try? r.readUInt8(),
              let hashLen = try? r.readUInt8(),
              let addrHash = try? r.readBytes(Int(hashLen)),
              let covRaw = try? r.readUInt8(),
              let itemCount = try? r.readUInt8()
        else { return nil }

        let covType = CovenantType(rawValue: covRaw) ?? .none
        var items = [[UInt8]]()
        for _ in 0..<itemCount {
            guard let len = try? r.readUInt16LE(),
                  let item = try? r.readBytes(Int(len))
            else { break }
            items.append(item)
        }

        let addr = Address(unchecked: addrVersion, hash: addrHash)
        let cov = Covenant(type: covType, items: items)
        return WalletCoin(value: value, height: Int(height), coinbase: cb == 1,
                         address: addr, covenant: cov, outpoint: outpoint)
    }
}

/// Key used for the in-memory address set (version + hash).
struct AddressKey: Hashable {
    let version: UInt8
    let hash: [UInt8]

    init(_ address: Address) {
        self.version = address.version
        self.hash = address.hash
    }
}

/// A bid record storing the nonce needed for reveal.
public struct BidRecord: Sendable {
    /// The name hash this bid is for.
    public let nameHash: NameHash
    /// The outpoint of the BID UTXO.
    public let outpoint: Outpoint
    /// The secret nonce (32 bytes).
    public let nonce: BidNonce
    /// The actual bid value in bumps.
    public let value: UInt64
    /// The lockup amount (value + mask) sent on-chain.
    public let lockup: UInt64
    /// The block height the bid was confirmed in (0 if unconfirmed).
    public let height: Int

    public init(nameHash: NameHash, outpoint: Outpoint, nonce: BidNonce, value: UInt64, lockup: UInt64, height: Int = 0) {
        self.nameHash = nameHash
        self.outpoint = outpoint
        self.nonce = nonce
        self.value = value
        self.lockup = lockup
        self.height = height
    }
}

/// A historical transaction record stored in the wallet.
public struct TransactionRecord: Sendable {
    /// Transaction hash.
    public let txHash: Hash256
    /// Total value of wallet inputs consumed (sent from wallet).
    public let sent: UInt64
    /// Total value of wallet outputs created (received by wallet).
    public let received: UInt64
    /// Transaction fee (only known when all inputs are ours, else 0).
    public let fee: UInt64
    /// Block height (-1 for unconfirmed).
    public let height: Int32
    /// Block timestamp or current time.
    public let timestamp: UInt64
    /// Bitmask of covenant types seen in wallet-relevant outputs.
    public let covenantTypes: UInt16
    /// Whether this is a coinbase (mining reward) transaction.
    public var coinbase: Bool = false

    func serialize() -> [UInt8] {
        var w = BufferWriter(capacity: 38)
        w.writeUInt64LE(sent)
        w.writeUInt64LE(received)
        w.writeUInt64LE(fee)
        w.writeInt32LE(height)
        w.writeUInt64LE(timestamp)
        w.writeUInt16LE(covenantTypes)
        return w.data
    }

    static func deserialize(_ data: [UInt8], txHash: Hash256) -> TransactionRecord? {
        var r = BufferReader(data)
        guard r.remaining >= 36 else { return nil }
        guard let sent = try? r.readUInt64LE(),
              let received = try? r.readUInt64LE(),
              let fee = try? r.readUInt64LE(),
              let height = try? r.readInt32LE(),
              let timestamp = try? r.readUInt64LE()
        else { return nil }
        // Backwards compat with old 36-byte format (no covenantTypes)
        let covTypes = (try? r.readUInt16LE()) ?? 0
        return TransactionRecord(txHash: txHash, sent: sent, received: received,
                                 fee: fee, height: height, timestamp: timestamp,
                                 covenantTypes: covTypes)
    }
}

/// Configuration for a multisig address (stored in scriptsDB).
public struct MultisigConfig: Sendable {
    /// Required number of signatures (m in m-of-n).
    public let m: Int
    /// Total number of keys (n in m-of-n).
    public let n: Int
    /// Sorted 33-byte compressed public keys (BIP67 order).
    public let publicKeys: [[UInt8]]
    /// The full multisig redeem script.
    public let redeemScript: [UInt8]
    /// Indices into `publicKeys` that are controlled by this wallet.
    public let localKeyIndices: [Int]

    /// Serialize for storage: m(1) + n(1) + localCount(1) + localIndices(N) + keys(n*33) + scriptLen(2) + script.
    public func serialize() -> [UInt8] {
        var w = BufferWriter(capacity: 3 + localKeyIndices.count + n * 33 + 2 + redeemScript.count)
        w.writeUInt8(UInt8(m))
        w.writeUInt8(UInt8(n))
        w.writeUInt8(UInt8(localKeyIndices.count))
        for idx in localKeyIndices { w.writeUInt8(UInt8(idx)) }
        for pk in publicKeys { w.writeBytes(pk) }
        w.writeUInt16LE(UInt16(redeemScript.count))
        w.writeBytes(redeemScript)
        return w.data
    }

    /// Deserialize from storage.
    public static func deserialize(_ data: [UInt8]) -> MultisigConfig? {
        var r = BufferReader(data)
        guard let m = try? r.readUInt8(),
              let n = try? r.readUInt8(),
              let localCount = try? r.readUInt8()
        else { return nil }

        var localIndices = [Int]()
        for _ in 0..<localCount {
            guard let idx = try? r.readUInt8() else { return nil }
            localIndices.append(Int(idx))
        }

        var keys = [[UInt8]]()
        for _ in 0..<Int(n) {
            guard let pk = try? r.readBytes(33) else { return nil }
            keys.append(pk)
        }

        guard let scriptLen = try? r.readUInt16LE(),
              let script = try? r.readBytes(Int(scriptLen))
        else { return nil }

        return MultisigConfig(
            m: Int(m), n: Int(n), publicKeys: keys,
            redeemScript: script, localKeyIndices: localIndices
        )
    }
}

/// A partially-signed transaction supporting both P2WPKH and P2WSH inputs.
///
/// For P2WPKH inputs: `configs[i]` is nil, `signatures[i]` has 1 slot, `pubkeys[i]` holds the compressed pubkey.
/// For P2WSH inputs: `configs[i]` is non-nil, `signatures[i]` has n slots, `pubkeys[i]` is nil.
public struct PartiallySignedTx: Sendable {
    /// The transaction (with empty witnesses).
    public let tx: Transaction
    /// Input coins (for value/address lookup during signing).
    public let coins: [WalletCoin]
    /// Per-input multisig configuration (nil for P2WPKH inputs).
    public let configs: [MultisigConfig?]
    /// Per-input signatures: 1 slot for P2WPKH, n slots for P2WSH.
    public var signatures: [[[UInt8]]]
    /// Per-input public key: set for P2WPKH so finalize needs no wallet, nil for P2WSH.
    public var pubkeys: [[UInt8]?]

    /// Serialize to bytes for exchange between cosigners.
    ///
    /// V1 format: version(1) + txRaw + coinCount(2) + per-coin + per-input type/config/sigs/pubkey.
    public func serialize() -> [UInt8] {
        var w = BufferWriter()
        w.writeUInt8(1) // version byte

        // Transaction raw bytes
        var txWriter = BufferWriter()
        tx.write(to: &txWriter)
        w.writeUInt32LE(UInt32(txWriter.count))
        w.writeBytes(txWriter.data)

        w.writeUInt16LE(UInt16(coins.count))
        for coin in coins {
            w.writeUInt64LE(coin.value)
            w.writeUInt8(coin.address.version)
            w.writeUInt8(UInt8(coin.address.hash.count))
            w.writeBytes(coin.address.hash)
            w.writeBytes(coin.outpoint.hash.bytes)
            w.writeUInt32LE(coin.outpoint.index)
        }

        for i in 0..<coins.count {
            if let config = configs[i] {
                w.writeUInt8(0x01)
                let configData = config.serialize()
                w.writeUInt16LE(UInt16(configData.count))
                w.writeBytes(configData)
                for sig in signatures[i] {
                    w.writeUInt8(UInt8(sig.count))
                    w.writeBytes(sig)
                }
            } else {
                w.writeUInt8(0x00)
                let sig = signatures[i].first ?? []
                w.writeUInt8(UInt8(sig.count))
                w.writeBytes(sig)
                if let pk = pubkeys[i], pk.count == 33 {
                    w.writeUInt8(33)
                    w.writeBytes(pk)
                } else {
                    w.writeUInt8(0)
                }
            }
        }

        return w.data
    }

    /// Deserialize from raw bytes. Supports both v0 (legacy P2WSH-only) and v1 (unified) formats.
    public static func deserialize(_ data: [UInt8]) -> PartiallySignedTx? {
        guard data.count >= 6 else { return nil }
        // v1 starts with 0x01 version byte; v0 starts with txLen (always > 1)
        if data[0] == 1, let result = deserializeV1(data) { return result }
        return deserializeV0(data)
    }

    /// Read a length-prefixed signature list from the reader.
    private static func readSigs(_ r: inout BufferReader, count: Int) -> [[UInt8]]? {
        var sigs = [[UInt8]]()
        for _ in 0..<count {
            guard let len = try? r.readUInt8() else { return nil }
            guard let sig = try? r.readBytes(Int(len)) else { return nil }
            sigs.append(sig)
        }
        return sigs
    }

    /// Read the shared tx + coins section used by both v0 and v1.
    private static func readTxAndCoins(_ r: inout BufferReader) -> (Transaction, Int, [WalletCoin])? {
        guard let txLen = try? r.readUInt32LE(),
              let txBytes = try? r.readBytes(Int(txLen)) else { return nil }
        var txReader = BufferReader(txBytes)
        guard let tx = try? Transaction.read(from: &txReader) else { return nil }

        guard let coinCount = try? r.readUInt16LE() else { return nil }
        var coins = [WalletCoin]()
        for _ in 0..<coinCount {
            guard let value = try? r.readUInt64LE(),
                  let addrVersion = try? r.readUInt8(),
                  let hashLen = try? r.readUInt8(),
                  let addrHash = try? r.readBytes(Int(hashLen)),
                  let opHash = try? r.readBytes(32),
                  let opIdx = try? r.readUInt32LE()
            else { return nil }
            coins.append(WalletCoin(
                value: value, height: 0, coinbase: false,
                address: Address(unchecked: addrVersion, hash: addrHash),
                covenant: Covenant(type: .none, items: []),
                outpoint: Outpoint(hash: Hash256(unchecked: opHash), index: opIdx)
            ))
        }
        return (tx, Int(coinCount), coins)
    }

    /// Deserialize v1 format (unified P2WPKH + P2WSH).
    private static func deserializeV1(_ data: [UInt8]) -> PartiallySignedTx? {
        guard data.count >= 7, data[0] == 1 else { return nil }
        var r = BufferReader(Array(data.dropFirst()))

        guard let (tx, coinCount, coins) = readTxAndCoins(&r) else { return nil }

        var configs = [MultisigConfig?]()
        var signatures = [[[UInt8]]]()
        var pubkeys = [[UInt8]?]()

        for _ in 0..<coinCount {
            guard let inputType = try? r.readUInt8() else { return nil }
            if inputType == 0x01 {
                guard let configLen = try? r.readUInt16LE(),
                      let configData = try? r.readBytes(Int(configLen)),
                      let config = MultisigConfig.deserialize(configData),
                      let sigs = readSigs(&r, count: config.n)
                else { return nil }
                configs.append(config)
                signatures.append(sigs)
                pubkeys.append(nil)
            } else {
                guard let sigs = readSigs(&r, count: 1) else { return nil }
                guard let pkLen = try? r.readUInt8() else { return nil }
                let pk: [UInt8]? = pkLen == 33 ? (try? r.readBytes(33)) : nil
                configs.append(nil)
                signatures.append(sigs)
                pubkeys.append(pk)
            }
        }

        return PartiallySignedTx(tx: tx, coins: coins, configs: configs,
                                 signatures: signatures, pubkeys: pubkeys)
    }

    /// Deserialize v0 format (legacy P2WSH-only, for backwards compatibility).
    private static func deserializeV0(_ data: [UInt8]) -> PartiallySignedTx? {
        var r = BufferReader(data)
        guard let (tx, coinCount, coins) = readTxAndCoins(&r) else { return nil }

        var configs = [MultisigConfig?]()
        for _ in 0..<coinCount {
            guard let configLen = try? r.readUInt16LE(),
                  let configData = try? r.readBytes(Int(configLen)),
                  let config = MultisigConfig.deserialize(configData)
            else { return nil }
            configs.append(config)
        }

        var signatures = [[[UInt8]]]()
        for i in 0..<coinCount {
            guard let sigs = readSigs(&r, count: configs[i]!.n) else { return nil }
            signatures.append(sigs)
        }

        return PartiallySignedTx(tx: tx, coins: coins, configs: configs,
                                 signatures: signatures,
                                 pubkeys: [[UInt8]?](repeating: nil, count: coinCount))
    }
}

/// Type of wallet (regular P2WPKH or multisig P2WSH).
public enum WalletType: UInt8, Sendable {
    case regular = 0
    case multisig = 1
    /// Watch-only wallet: holds an xpub, no private keys. Cannot sign;
    /// signing is delegated to an external signer (e.g. a hardware wallet).
    case watchOnly = 2
}

/// LevelDB-backed wallet with HD key derivation and UTXO tracking.
///
/// Stores master seed, derived keys, addresses, and wallet UTXOs.
/// Indexes blocks as they connect to track balance.
public final class WalletDB {
    var store: LevelDBStore

    /// Lock to protect concurrent mutation (e.g. indexBlock vs RPC).
    let lock = NSLock()

    // LevelDB database prefixes
    var metaDB: UInt8 = 0
    var keysDB: UInt8 = 0
    var addressesDB: UInt8 = 0
    var coinsDB: UInt8 = 0
    var indexDB: UInt8 = 0
    var undoDB: UInt8 = 0
    var historyDB: UInt8 = 0
    var bidsDB: UInt8 = 0
    var scriptsDB: UInt8 = 0

    /// The network this wallet is for.
    public let network: NetworkType

    /// In-memory set of watched addresses for O(1) block scanning.
    var addressSet = Set<AddressKey>()

    /// Highest used receive address index.
    var receiveIndex: Int = -1

    /// Highest used change address index.
    var changeIndex: Int = -1

    /// Next unused receive address index.
    var nextReceiveIndex: Int = 0

    /// Next unused change address index.
    var nextChangeIndex: Int = 0

    /// Lookahead: always keep this many addresses ahead of the highest used index.
    let lookahead = 100

    /// Current scan height.
    public internal(set) var scanHeight: Int = -1

    /// Whether a rescan is in progress (blocks onBlockConnected from double-indexing).
    public var isRescanning: Bool = false


    /// Whether a wallet has been created.
    public internal(set) var initialized: Bool = false

    /// The wallet type (regular or multisig).
    public internal(set) var walletType: WalletType = .regular

    /// Required signatures for multisig wallets.
    public internal(set) var multisigM: Int = 0

    /// Cosigner extended public key strings (for multisig wallets).
    public internal(set) var cosignerXpubs: [String] = []

    /// Cached master seed (kept in memory for key derivation).
    var masterSeed: [UInt8]?

    /// Cached account-level extended private key (m/44'/14159'/0').
    /// Set directly for xpriv imports, or derived from masterSeed.
    var storedAccountKey: ExtendedPrivateKey?

    /// Cached mnemonic phrase.
    var storedMnemonic: String?

    // MARK: - Encryption State

    /// Whether the wallet has been encrypted with a passphrase.
    public internal(set) var isEncrypted: Bool = false

    /// Whether an encrypted wallet has been unlocked (keys in memory).
    /// Always true for unencrypted wallets.
    public var isUnlocked: Bool {
        if !isEncrypted { return true }
        return encryptionUnlocked
    }

    /// Internal unlock flag for encrypted wallets.
    var encryptionUnlocked: Bool = false

    /// Stored account xpub string for address derivation while locked.
    var storedAccountXpub: ExtendedPublicKey?

    /// Auto-lock timeout (seconds). 0 = no auto-lock.
    var unlockTimeout: Int = 0

    /// Timestamp when the wallet was unlocked (for auto-lock).
    var unlockTime: Date?

    /// Open (or create) the wallet database.
    ///
    /// - Parameters:
    ///   - path: Directory path for the LevelDB data files.
    ///   - network: The network type.
    public init(path: String, network: NetworkType) throws {
        self.network = network

        store = try LevelDBStore(path: path, cacheSize: 8 * 1024 * 1024)

        metaDB = store.openDatabase(name: "meta")
        keysDB = store.openDatabase(name: "keys")
        addressesDB = store.openDatabase(name: "addresses")
        coinsDB = store.openDatabase(name: "coins")
        indexDB = store.openDatabase(name: "index")
        undoDB = store.openDatabase(name: "undo")
        historyDB = store.openDatabase(name: "history")
        bidsDB = store.openDatabase(name: "bids")
        scriptsDB = store.openDatabase(name: "scripts")

        try loadState()
    }

    /// Create a new wallet with a generated or provided mnemonic.
    ///
    /// - Parameters:
    ///   - mnemonic: Optional existing mnemonic. If nil, a new 24-word phrase is generated.
    ///   - passphrase: Optional BIP39 passphrase.
    /// - Returns: The mnemonic phrase (for user backup).
    @discardableResult
    public func create(mnemonic: String? = nil, passphrase: String = "") throws -> String {
        guard !initialized else {
            throw WalletError.alreadyInitialized
        }

        let phrase = mnemonic ?? BIP39.generateMnemonic(strength: 256)
        guard BIP39.validateMnemonic(phrase) else {
            throw WalletError.invalidMnemonic
        }

        let seed = BIP39.toSeed(mnemonic: phrase, passphrase: passphrase)
        masterSeed = seed
        storedMnemonic = phrase

        // Store seed and mnemonic
        try put(db: metaDB, key: Array("seed".utf8), value: seed)
        try put(db: metaDB, key: Array("mnemonic".utf8), value: Array(phrase.utf8))
        try put(db: metaDB, key: Array("height".utf8), value: intToBytes(-1))

        // Derive initial addresses (account 0)
        try deriveAddresses(receive: lookahead, change: lookahead)

        initialized = true
        try put(db: metaDB, key: Array("initialized".utf8), value: [1])

        return phrase
    }

    /// Import an existing wallet from a mnemonic phrase.
    public func importSeed(mnemonic: String, passphrase: String = "") throws -> String {
        try create(mnemonic: mnemonic, passphrase: passphrase)
    }

    /// Import a wallet from an account-level xpriv (m/44'/14159'/0').
    ///
    /// - Parameter xpriv: Base58Check-encoded extended private key string.
    public func importXpriv(_ xpriv: String) throws {
        guard !initialized else {
            throw WalletError.alreadyInitialized
        }

        let accountKey = try ExtendedPrivateKey.deserialize(xpriv)
        storedAccountKey = accountKey

        try put(db: metaDB, key: Array("accountKey".utf8), value: serializeAccountKey(accountKey))
        try put(db: metaDB, key: Array("height".utf8), value: intToBytes(-1))

        // Derive initial addresses
        try deriveAddresses(receive: lookahead, change: lookahead)

        initialized = true
        try put(db: metaDB, key: Array("initialized".utf8), value: [1])
    }

    /// Import a watch-only wallet from an account-level xpub (m/44'/14159'/account').
    ///
    /// The wallet derives addresses and tracks UTXOs but holds no private key
    /// material — signing must happen out-of-band (e.g. on a Ledger device) and
    /// the signed PSTX submitted via `broadcasttx`.
    ///
    /// - Parameter xpub: Base58Check-encoded extended public key string.
    public func importXpub(_ xpub: String) throws {
        guard !initialized else {
            throw WalletError.alreadyInitialized
        }

        let accountPub = try ExtendedPublicKey.deserialize(xpub)
        storedAccountXpub = accountPub
        walletType = .watchOnly

        try put(db: metaDB, key: Array("accountXpub".utf8), value: Array(xpub.utf8))
        try put(db: metaDB, key: Array("walletType".utf8), value: [WalletType.watchOnly.rawValue])
        try put(db: metaDB, key: Array("height".utf8), value: intToBytes(-1))

        // Derive initial addresses (uses xpub-only path).
        try deriveAddresses(receive: lookahead, change: lookahead)

        initialized = true
        try put(db: metaDB, key: Array("initialized".utf8), value: [1])
    }

    // MARK: - State Loading

    func loadState() throws {
        // Check if initialized
        if let val = try get(db: metaDB, key: Array("initialized".utf8)), val == [1] {
            initialized = true
        } else {
            return
        }

        // Check if wallet is encrypted
        if let _ = try get(db: metaDB, key: Array("encrypted".utf8)) {
            isEncrypted = true
            encryptionUnlocked = false
            // Load stored xpub for address derivation while locked
            if let xpubData = try get(db: metaDB, key: Array("accountXpub".utf8)),
               let xpubStr = String(bytes: xpubData, encoding: .utf8) {
                storedAccountXpub = try? ExtendedPublicKey.deserialize(xpubStr)
            }
            // Skip loading plaintext keys — they don't exist
        } else {
            // Unencrypted: load keys normally
            // Load seed (mnemonic-based wallet)
            masterSeed = try get(db: metaDB, key: Array("seed".utf8))

            // Load stored account key (xpriv-imported wallet)
            if let data = try get(db: metaDB, key: Array("accountKey".utf8)), data.count == 73 {
                let key = Array(data[0..<32])
                let chainCode = Array(data[32..<64])
                let depth = data[64]
                let fingerprint = UInt32(data[65]) << 24 | UInt32(data[66]) << 16
                    | UInt32(data[67]) << 8 | UInt32(data[68])
                let index = UInt32(data[69]) << 24 | UInt32(data[70]) << 16
                    | UInt32(data[71]) << 8 | UInt32(data[72])
                storedAccountKey = ExtendedPrivateKey(
                    key: key, chainCode: chainCode,
                    depth: depth, fingerprint: fingerprint, index: index
                )
            }

            // Load mnemonic
            if let data = try get(db: metaDB, key: Array("mnemonic".utf8)) {
                storedMnemonic = String(bytes: data, encoding: .utf8)
            }

            // Load stored xpub (fallback for multisig address derivation)
            if let xpubData = try get(db: metaDB, key: Array("accountXpub".utf8)),
               let xpubStr = String(bytes: xpubData, encoding: .utf8) {
                storedAccountXpub = try? ExtendedPublicKey.deserialize(xpubStr)
            }
        }

        // Load scan height
        if let data = try get(db: metaDB, key: Array("height".utf8)) {
            scanHeight = bytesToInt(data)
        }

        // Load persisted derive indices
        if let data = try get(db: metaDB, key: Array("nextReceive".utf8)) {
            nextReceiveIndex = bytesToInt(data)
        }
        if let data = try get(db: metaDB, key: Array("nextChange".utf8)) {
            nextChangeIndex = bytesToInt(data)
        }

        // Load persisted used indices
        if let data = try get(db: metaDB, key: Array("usedReceive".utf8)) {
            receiveIndex = bytesToInt(data)
        }
        if let data = try get(db: metaDB, key: Array("usedChange".utf8)) {
            changeIndex = bytesToInt(data)
        }

        // Load wallet type metadata
        if let data = try get(db: metaDB, key: Array("walletType".utf8)), data.count >= 1 {
            walletType = WalletType(rawValue: data[0]) ?? .regular
        }
        if let data = try get(db: metaDB, key: Array("multisigM".utf8)) {
            multisigM = bytesToInt(data)
        }
        if let data = try get(db: metaDB, key: Array("cosignerXpubs".utf8)),
           let str = String(bytes: data, encoding: .utf8), !str.isEmpty {
            cosignerXpubs = str.split(separator: "\n").map(String.init)
        }

        // Load all addresses into memory
        try forEachEntry(db: addressesDB) { key, value in
            guard key.count >= 2 else { return }
            let ver = key[0]
            let hash = Array(key[1...])
            addressSet.insert(AddressKey(Address(unchecked: ver, hash: hash)))
        }
    }

    /// Close the wallet database.
    public func close() {
        store.close()
    }

    deinit {
        close()
    }
}

/// Wallet errors.
public enum WalletError: Error, Sendable, LocalizedError {
    case alreadyInitialized
    case notInitialized
    case invalidMnemonic
    case databaseError(String)
    case insufficientFunds(have: UInt64, need: UInt64)
    case noSpendableCoins
    case keyNotFound(Address)
    case amountTooSmall
    case invalidMultisigParams
    case noMultisigConfigs
    case insufficientSignatures(have: Int, need: Int, input: Int)
    case heightMismatch(expected: Int, got: Int)
    case walletLocked
    case alreadyEncrypted
    case notEncrypted
    case wrongPassphrase
    case emptyPassphrase
    case invalidSignature(String)
    case watchOnly

    public var errorDescription: String? {
        switch self {
        case .alreadyInitialized: return "Wallet is already initialized."
        case .notInitialized: return "Wallet is not initialized."
        case .invalidMnemonic: return "Invalid recovery phrase."
        case .databaseError(let msg): return "Database error: \(msg)"
        case .insufficientFunds(let have, let need):
            return "Insufficient funds (have \(have), need \(need))."
        case .noSpendableCoins: return "No spendable coins available. Funds may be locked or immature."
        case .keyNotFound: return "Private key not found for this address."
        case .amountTooSmall: return "Amount is too small."
        case .invalidMultisigParams: return "Invalid multisig parameters (m must be 1..n, n must be 1..15)."
        case .noMultisigConfigs: return "No multisig configuration found for this input."
        case .insufficientSignatures(let have, let need, let input):
            return "Input \(input) has \(have) signatures but needs \(need)."
        case .heightMismatch(let expected, let got):
            return "Block height mismatch (expected \(expected), got \(got))."
        case .walletLocked: return "Wallet is locked. Use walletpassphrase to unlock."
        case .alreadyEncrypted: return "Wallet is already encrypted."
        case .notEncrypted: return "Wallet is not encrypted."
        case .wrongPassphrase: return "Incorrect passphrase."
        case .emptyPassphrase: return "Passphrase must not be empty."
        case .invalidSignature(let msg): return "Invalid signature: \(msg)"
        case .watchOnly: return "Wallet is watch-only — sign with the external signer (e.g. hardware wallet) and submit via broadcasttx."
        }
    }
}
