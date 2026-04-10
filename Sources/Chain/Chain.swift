import Foundation
import Base
import Protocol
import Consensus
import ExtCrypto
import Script
import Covenants
import Urkel
import Storage

/// Errors specific to the header chain index.
public enum HeaderError: Error, Sendable {
    /// The header's hash already exists in the chain. Carries the existing
    /// entry so callers (compact block handling) can access the correct
    /// hash without having to look it up via byHeight, which would return
    /// the wrong entry for forked headers.
    case duplicateHeader(existing: ChainEntry)
    /// The header's prevBlock is not in the chain (orphan).
    case orphanHeader
    /// The difficulty bits do not match the expected value.
    case badDifficulty
    /// The block header does not match the expected chain entry.
    case headerMismatch
    /// The block's merkle root does not match the computed value.
    case invalidMerkleRoot(height: Int, expected: String, computed: String, txCount: Int, tx0Hash: String)
    /// The block's witness root does not match the computed value.
    case invalidWitnessRoot
}

/// In-memory header chain index with validation.
///
/// Stores all known block headers and tracks the best (most work) chain tip.
/// Validates PoW, timestamps, MTP, and difficulty retargets on insertion.
public final class Chain: @unchecked Sendable {

    /// Lock protecting all mutable state on this chain.
    let lock = NSLock()

    /// All known chain entries, keyed by block hash.
    var byHash: [Hash256: ChainEntry] = [:]

    /// Best-chain entries keyed by height (only the active chain).
    var byHeight: [Int: ChainEntry] = [:]

    /// The current best chain tip (internal storage).
    var _tip: ChainEntry

    /// The current best chain tip (thread-safe accessor).
    public var tip: ChainEntry {
        lock.lock()
        defer { lock.unlock() }
        return _tip
    }

    /// The network type.
    public let network: NetworkType

    /// Consensus parameters for this chain.
    public let params: ConsensusParams

    /// Optional persistent store for chain entries.
    let store: ChainStore?

    /// Optional persistent store for full blocks.
    let blockStore: BlockStore?

    /// Optional UTXO database for contextual validation.
    let coinDB: CoinDatabase?

    /// Urkel tree + pending name state map for covenant validation.
    var nameDB: NameDB?

    /// Tree data directory (for resetting during reindex).
    let treeDir: String?

    /// Name auction timing parameters for this network.
    let nameParams: NameParams

    /// Optional transaction index database (enabled with --index-tx).
    var txIndexStore: LevelDBStore?
    var txIndexDB: UInt8 = 0

    /// Optional address index database (enabled with --index-address).
    var addrIndexStore: LevelDBStore?
    var addrTxDB: UInt8 = 0
    var addrCoinDB: UInt8 = 0

    /// Optional callback invoked after a block is successfully connected.
    /// Parameters: (block, height).
    public var onBlockConnected: ((Block, Int) -> Void)?

    /// Optional callback invoked when a block is disconnected during a reorg.
    /// Parameters: (block, height).
    public var onBlockDisconnected: ((Block, Int) -> Void)?

    /// The height up to which entries have been persisted to disk.
    var persistedHeight: Int = 0

    /// BIP9 deployment state cache: keyed by bit, then by entry hash at window boundaries.
    /// Cleared on chain reorganization.
    var stateCache: [Int: [Hash256: ThresholdState]] = [:]

    /// Override for the wall-clock time used by timestamp validation.
    /// When set, `add(header:proof:)` uses this value instead of `Date()`.
    /// Intended for testing only.
    public var clockOverride: UInt64?

    /// Whether a block store is configured.
    public var hasBlockStore: Bool {
        lock.lock()
        defer { lock.unlock() }
        return blockStore != nil
    }

    /// Access to the name database for covenant validation.
    public var nameDBRef: NameDB {
        lock.lock()
        defer { lock.unlock() }
        guard let db = nameDB else { fatalError("nameDBRef accessed before nameDB initialized") }
        return db
    }

    /// Snapshot the name database's pending state for rollback.
    public func snapshotNameDB() -> NameDB.PendingSnapshot? {
        lock.lock()
        defer { lock.unlock() }
        return nameDB?.snapshotPending()
    }

    /// Restore a name database pending state snapshot.
    public func restoreNameDB(_ snapshot: NameDB.PendingSnapshot?) {
        lock.lock()
        defer { lock.unlock() }
        guard let snapshot = snapshot else { return }
        nameDB?.restorePending(snapshot)
    }

    /// Trial-run covenant validation under the chain lock.
    ///
    /// Holds the lock for the entire snapshot-process-restore cycle to prevent
    /// racing with connectBlock which also mutates nameDB.pending.
    public func trialValidateCovenants(
        tx: Transaction, coinView: CoinView, height: Int,
        network: NetworkType, nameParams: NameParams
    ) -> Error? {
        lock.lock()
        defer { lock.unlock() }
        guard let nameDB = nameDB else { return nil }
        let snapshot = nameDB.snapshotPending()
        defer { nameDB.restorePending(snapshot) }
        do {
            try CovenantProcessor.processCovenants(
                tx: tx, txIndex: 0, coinView: coinView, nameDB: nameDB,
                height: height, network: network, nameParams: nameParams,
                chain: self, blockTime: _medianTimePast(for: _tip),
                consensusParams: params
            )
            return nil
        } catch {
            return error
        }
    }

    /// Replace the name database (used by reindexBlocks and tree integrity repair).
    public func resetNameDB(_ newDB: NameDB) {
        self.nameDB = newDB
    }

    /// Close the name database (for tree wipe + rebuild).
    public func closeNameDB() {
        nameDB?.close()
    }

    /// The highest block height stored in the block store (-1 if none).
    public var storedHeight: Int {
        lock.lock()
        defer { lock.unlock() }
        guard let blockStore = blockStore else { return -1 }
        return blockStore.storedCount - 1
    }

    /// Reset the chain tip to `storedHeight`, removing entries above it.
    ///
    /// Used when the tip has advanced via headers but block data is missing
    /// (e.g. miner added entries that couldn't be connected, or sync peer
    /// disconnected before block download completed). After this call the
    /// node will re-sync headers from peers to discover the correct chain.
    public func resetToStoredHeight() throws {
        lock.lock()
        defer { lock.unlock() }
        guard let blockStore = blockStore else { return }
        let target = blockStore.storedCount - 1
        guard target >= 0, target < _tip.height else { return }
        guard let entry = byHeight[target] else { return }

        // Remove ALL in-memory entries above the stored height, including
        // fork entries in byHash. Leaving fork entries behind would orphan
        // them (their prev is being removed), which later causes findFork()
        // to return nil and block legitimate reorganizations to chains that
        // descend from those forks.
        for h in (target + 1)..._tip.height {
            byHeight.removeValue(forKey: h)
        }
        byHash = byHash.filter { $0.value.height <= target }

        // Truncate persistent entry store
        try store?.truncateToHeight(target)
        persistedHeight = target

        // Roll back name tree to match the new tip, otherwise stale
        // pending state causes tree root mismatches on re-sync.
        //
        // rollbackToHeight only restores the snapshot at the previous tree
        // commit boundary; replay covenants from (committedHeight + 1)...target
        // so pending matches the new tip. See _disconnectTo for the long form.
        if let nameDB = nameDB {
            try nameDB.rollbackToHeight(target, treeInterval: nameParams.treeInterval)
            let replayStart = nameDB.committedHeight + 1
            if replayStart <= target {
                for h in replayStart...target {
                    guard let block = try blockStore.loadBlock(height: h) else {
                        throw ChainError.validationFailed("missing block at height \(h) for tree replay")
                    }
                    try CovenantProcessor.replayCovenants(
                        block: block, nameDB: nameDB,
                        height: h, nameParams: nameParams
                    )
                }
            }
        }

        stateCache.removeAll()
        _tip = entry
    }

    /// Initialize the chain with the genesis block, optionally loading from a store.
    public init(network: NetworkType, store: ChainStore? = nil, blockStore: BlockStore? = nil, coinDB: CoinDatabase? = nil, treeDir: String? = nil, txIndexPath: String? = nil, addrIndexPath: String? = nil) throws {
        self.network = network
        self.params = ConsensusParams.params(for: network)
        self.store = store
        self.blockStore = blockStore
        self.coinDB = coinDB
        self.treeDir = treeDir
        self.nameParams = NameParams.params(for: network)
        if coinDB != nil, let treeDir = treeDir {
            self.nameDB = try NameDB(path: treeDir + "/names")
        } else if coinDB != nil {
            self.nameDB = NameDB()
        } else {
            self.nameDB = nil
        }
        if let txIndexPath = txIndexPath {
            let store = try LevelDBStore(path: txIndexPath)
            self.txIndexStore = store
            self.txIndexDB = store.openDatabase(name: nil)
        }
        if let addrIndexPath = addrIndexPath {
            let store = try LevelDBStore(path: addrIndexPath)
            self.addrIndexStore = store
            self.addrTxDB = store.openDatabase(name: "txs")
            self.addrCoinDB = store.openDatabase(name: "coins")
        }

        let genesis = try Genesis.entry(for: network)
        self._tip = genesis
        self.byHash[genesis.hash] = genesis
        self.byHeight[0] = genesis

        // Load persisted entries if store is provided
        if let store = store {
            let entries = try store.loadEntries()
            byHash.reserveCapacity(entries.count + 1)
            byHeight.reserveCapacity(entries.count + 1)

            // Detect gaps: only load entries up to the first discontinuity.
            // A gap means a previous flush persisted entries past a hole left
            // by an incomplete reorg. Truncate the store at the gap so the
            // node re-syncs the missing range from peers.
            var lastHeight = 0 // genesis
            var truncateAt: Int?
            for entry in entries {
                if entry.height != lastHeight + 1 {
                    truncateAt = lastHeight
                    break
                }
                byHash[entry.hash] = entry
                byHeight[entry.height] = entry
                lastHeight = entry.height
            }

            if let truncateAt = truncateAt {
                // Truncate the store to remove everything after the gap
                try store.truncateToHeight(truncateAt)
                FileHandle.standardError.write(Data("[Chain] Detected gap in entry store after height \(truncateAt), truncated (will re-sync)\n".utf8))
            }

            if let tip = byHeight[lastHeight], lastHeight > 0 {
                _tip = tip
            }
            persistedHeight = _tip.height
        }
    }

    /// Internal log output for chain operations (replaces stray print() calls).
    func chainLog(_ message: @autoclosure () -> String) {
        #if DEBUG
        print("[Chain] \(message())")
        #endif
    }

    /// Close all databases held by the chain (name tree, tx index, address index).
    public func close() {
        lock.lock()
        defer { lock.unlock() }
        nameDB?.close()
        nameDB = nil
        txIndexStore?.close()
        txIndexStore = nil
        addrIndexStore?.close()
        addrIndexStore = nil
    }

    // MARK: - Header Chain

    /// The current chain height.
    public var height: Int {
        lock.lock()
        defer { lock.unlock() }
        return _tip.height
    }

    /// Check if a block hash exists in the chain.
    public func has(hash: Hash256) -> Bool {
        lock.lock()
        defer { lock.unlock() }
        return byHash[hash] != nil
    }

    /// Get a chain entry by its hash (internal unlocked version).
    func _getEntry(hash: Hash256) -> ChainEntry? {
        byHash[hash]
    }

    /// Get a chain entry by its hash.
    public func getEntry(hash: Hash256) -> ChainEntry? {
        lock.lock()
        defer { lock.unlock() }
        return _getEntry(hash: hash)
    }

    /// Get a chain entry by height (internal unlocked version).
    func _getEntryByHeight(_ height: Int) -> ChainEntry? {
        byHeight[height]
    }

    /// Get a chain entry by height (best chain only).
    public func getEntryByHeight(_ height: Int) -> ChainEntry? {
        lock.lock()
        defer { lock.unlock() }
        return _getEntryByHeight(height)
    }

    /// Add a validated header to the chain.
    ///
    /// Performs full header validation:
    /// 1. Reject duplicates
    /// 2. Find parent (reject orphans)
    /// 3. Check PoW (full BalloonHash or proof-based fast verification)
    /// 4. Check timestamp (not too far in future)
    /// 5. Check median time past
    /// 6. Verify difficulty bits
    /// 7. Create entry and update chain
    ///
    /// - Parameter proof: BalloonProof for fast verification on mainnet/testnet.
    ///   Regtest/simnet skip proof verification and compute the hash directly
    ///   (their trivial 4-slot BalloonHash is fast enough).
    /// Add a validated header (internal unlocked version).
    ///
    /// Disconnect notifications from any reorganization are appended to `disconnectNotifications`.
    @discardableResult
    func _add(header: BlockHeader, proof: BalloonProof, disconnectNotifications: inout [(Block, Int)]) throws -> ChainEntry {
        // Fast duplicate/orphan check before expensive BalloonHash.
        // If prevBlock is unknown, it's an orphan — no need to hash.
        guard let prev = byHash[header.prevBlock] else {
            throw HeaderError.orphanHeader
        }
        // If the parent already has a child at the expected height with matching
        // header fields, it's a duplicate — no need to hash.
        if let existing = byHeight[prev.height + 1],
           existing.prevBlock == header.prevBlock
            && existing.merkleRoot == header.merkleRoot
            && existing.nonce == header.nonce
            && existing.time == header.time
            && existing.bits == header.bits {
            throw HeaderError.duplicateHeader(existing: existing)
        }

        // Verify proof samples and derive hash
        let hash = try ProofOfWork.verifyWithProof(header: header, proof: proof, params: params)
        if let existing = byHash[hash] {
            throw HeaderError.duplicateHeader(existing: existing)
        }

        // Check PoW (uses precomputed/verified hash)
        try BlockValidator.checkProofOfWork(header, hash: hash, params: params)

        // Check timestamp not too far in future
        let currentTime = clockOverride ?? UInt64(Date().timeIntervalSince1970)
        try BlockValidator.checkTimestamp(header, currentTime: currentTime, params: params)

        // Check MTP (only if we have enough history)
        let timestamps = _getPreviousTimestamps(prev, count: params.medianTimeSpan)
        if !timestamps.isEmpty {
            let mtp = MedianTime.compute(timestamps, span: params.medianTimeSpan)
            try BlockValidator.checkMedianTimePast(header, medianTimePast: mtp)
        }

        // Verify difficulty
        let newHeight = prev.height + 1
        try _verifyDifficulty(header: header, prev: prev, height: newHeight)

        // Create entry (uses precomputed hash)
        let entry = ChainEntry.fromBlock(header, hash: hash, prev: prev)

        // Store in hash index (always, even for non-best-chain entries)
        byHash[entry.hash] = entry

        // Best chain selection by cumulative chainwork
        if entry.chainwork > _tip.chainwork {
            if entry.prevBlock == _tip.hash {
                // Simple extension of current tip
                _tip = entry
                byHeight[entry.height] = entry
            } else {
                // Fork with more work — reorganize
                try _reorganize(newTip: entry, disconnectNotifications: &disconnectNotifications)
                _tip = entry
            }
        }

        return entry
    }

    @discardableResult
    public func add(header: BlockHeader, proof: BalloonProof) throws -> ChainEntry {
        lock.lock()
        var disconnectNotifications: [(Block, Int)] = []
        let entry: ChainEntry
        do {
            entry = try _add(header: header, proof: proof, disconnectNotifications: &disconnectNotifications)
        } catch {
            lock.unlock()
            throw error
        }
        let callback = onBlockDisconnected
        lock.unlock()
        for (block, h) in disconnectNotifications {
            callback?(block, h)
        }
        return entry
    }

    // MARK: - Chain Traversal

    /// Get timestamps of previous blocks (internal unlocked version).
    func _getPreviousTimestamps(_ entry: ChainEntry, count: Int) -> [UInt64] {
        var timestamps: [UInt64] = []
        timestamps.reserveCapacity(count)
        var current: ChainEntry? = entry
        while let e = current, timestamps.count < count {
            timestamps.append(e.time)
            if e.isGenesis { break }
            current = byHash[e.prevBlock]
        }
        return timestamps
    }

    /// Get timestamps of previous blocks (newest first) for MTP calculation.
    public func getPreviousTimestamps(_ entry: ChainEntry, count: Int) -> [UInt64] {
        lock.lock()
        defer { lock.unlock() }
        return _getPreviousTimestamps(entry, count: count)
    }

    /// Build a block locator from a starting entry (logarithmic spacing).
    public func getLocator(from entry: ChainEntry? = nil) -> [Hash256] {
        lock.lock()
        defer { lock.unlock() }
        var hashes: [Hash256] = []
        var step = 1
        var current = entry ?? _tip

        while true {
            hashes.append(current.hash)
            if current.isGenesis { break }

            let targetHeight = max(current.height - step, 0)
            if let target = byHeight[targetHeight] {
                current = target
            } else {
                break
            }

            if hashes.count > 10 {
                step *= 2
            }
        }

        return hashes
    }

    /// Find the common ancestor (fork point) of two chain entries.
    ///
    /// Walks both entries back through prevBlock pointers until they converge.
    func findFork(_ a: ChainEntry, _ b: ChainEntry) -> ChainEntry? {
        var entryA = a
        var entryB = b
        while entryA.hash != entryB.hash {
            if entryA.height > entryB.height {
                guard let prev = byHash[entryA.prevBlock] else { return nil }
                entryA = prev
            } else {
                guard let prev = byHash[entryB.prevBlock] else { return nil }
                entryB = prev
            }
        }
        return entryA
    }

    // MARK: - Mining helpers

    /// Compute the expected difficulty bits for the next block.
    public func getNextBits() -> UInt32 {
        lock.lock()
        defer { lock.unlock() }
        let prev = _tip
        let nextHeight = prev.height + 1

        if params.noRetargeting {
            return params.powBits
        }

        if nextHeight < params.targetWindow + 3 {
            return params.powBits
        }

        guard let windowStart = _getAncestor(entry: prev, height: prev.height - params.targetWindow) else {
            return params.powBits
        }

        let firstSuitable = _getSuitableBlock(windowStart)
        let lastSuitable = _getSuitableBlock(prev)

        return DifficultyRetarget.retarget(
            first: firstSuitable,
            last: lastSuitable,
            params: params
        )
    }

    /// Get the current tree root hash from the name database.
    public func getCurrentTreeRoot() throws -> Hash256 {
        lock.lock()
        defer { lock.unlock() }
        guard let nameDB = nameDB else {
            return .zero
        }
        let root = try nameDB.treeRoot()
        return Hash256(unchecked: root)
    }

    /// Look up an unspent coin by outpoint.
    public func getCoin(hash: Hash256, index: UInt32) -> CoinEntry? {
        lock.lock()
        defer { lock.unlock() }
        return coinDB?.getCoin(Outpoint(hash: hash, index: index))
    }

    /// Unlocked coin lookup — for use within already-locked code paths.
    func _getCoin(_ outpoint: Outpoint) -> CoinEntry? {
        coinDB?.getCoin(outpoint)
    }

    /// Get the "suitable block" (internal unlocked version).
    func _getSuitableBlock(_ entry: ChainEntry) -> DifficultyRetarget.BlockInfo {
        guard entry.height >= 2 else {
            return DifficultyRetarget.BlockInfo(time: entry.time, chainwork: entry.chainwork)
        }
        guard let parent = byHash[entry.prevBlock],
              let grandparent = byHash[parent.prevBlock] else {
            return DifficultyRetarget.BlockInfo(time: entry.time, chainwork: entry.chainwork)
        }

        return DifficultyRetarget.getSuitableBlock(
            DifficultyRetarget.BlockInfo(time: entry.time, chainwork: entry.chainwork),
            DifficultyRetarget.BlockInfo(time: parent.time, chainwork: parent.chainwork),
            DifficultyRetarget.BlockInfo(time: grandparent.time, chainwork: grandparent.chainwork)
        )
    }

    /// Walk back to find an ancestor at a specific height (internal unlocked version).
    func _getAncestor(entry: ChainEntry, height: Int) -> ChainEntry? {
        guard height >= 0, height <= entry.height else { return nil }

        // Fast path: only valid when `entry` is on the best chain. byHeight
        // only indexes best-chain entries, so taking this shortcut for a
        // fork entry would return the wrong ancestor — the best-chain
        // entry at that height rather than the fork's own ancestor. This
        // is catastrophic for difficulty retarget validation, which would
        // then compute expected bits from the wrong window and reject
        // valid fork headers as badDifficulty.
        if byHeight[entry.height]?.hash == entry.hash,
           let indexed = byHeight[height] {
            return indexed
        }

        // Slow path: walk back through prevBlock pointers. Required when
        // validating headers on a fork that isn't currently our best chain.
        var current = entry
        while current.height > height {
            guard let prev = byHash[current.prevBlock] else { return nil }
            current = prev
        }
        return current.height == height ? current : nil
    }

    // MARK: - Chain Reorganization

    /// Reorganize the chain to a new tip on a competing fork.
    ///
    /// 1. Find the fork point (common ancestor)
    /// 2. If blocks are stored, disconnect UTXO/name state for old chain
    /// 3. Rebuild `byHeight` index for new chain
    /// 4. Truncate persistent stores to the fork point
    /// 5. Update tip
    ///
    /// After this method returns, the block store is truncated to the fork
    /// point and new fork blocks can be connected via `connectBlock()`.
    private func _reorganize(newTip: ChainEntry, disconnectNotifications: inout [(Block, Int)]) throws {
        guard let fork = findFork(_tip, newTip) else {
            throw ChainError.validationFailed("cannot find fork point")
        }

        // Pre-verify: walk the new fork chain before modifying any state.
        // Every entry should be in byHash (chain.add ensures this). If the
        // walk can't reach the fork point, the index is corrupted — abort
        // instead of leaving byHeight with gaps that poison difficulty checks.
        var newChainEntries: [ChainEntry] = []
        var current = newTip
        while current.height > fork.height {
            newChainEntries.append(current)
            guard let prev = byHash[current.prevBlock] else {
                throw ChainError.validationFailed(
                    "reorg walk broken: missing parent for height \(current.height) in byHash"
                )
            }
            current = prev
        }

        // Disconnect old chain's UTXO/name state (if full validation is enabled)
        if coinDB != nil, blockStore != nil {
            try _disconnectTo(height: fork.height, notifications: &disconnectNotifications)
        }

        // Remove old chain entries above fork from byHeight
        for h in (fork.height + 1)..._tip.height {
            byHeight.removeValue(forKey: h)
        }

        // Apply new chain entries (walk was already verified above)
        for entry in newChainEntries {
            byHeight[entry.height] = entry
        }

        // Clear BIP9 state cache on reorg (states may change)
        stateCache.removeAll()

        // Truncate persistent stores to the fork point
        try store?.truncateToHeight(fork.height)
        try blockStore?.truncateToHeight(fork.height)
        persistedHeight = fork.height

        // Set tip to fork (not newTip) — the new fork blocks haven't been
        // connected yet. They will be connected via connectBlock() after
        // the reorganize returns.
        _tip = fork
    }

    /// Disconnect blocks from the current tip down to (but not including) `height`.
    ///
    /// For each disconnected block:
    /// - Reverses UTXO changes via CoinDatabase
    /// - Collects disconnect notifications into `notifications` (fired after lock release)
    ///
    /// After all blocks are disconnected, rolls back the name tree.
    /// If undo data is missing, falls back to a full UTXO rebuild.
    private func _disconnectTo(height: Int, notifications: inout [(Block, Int)]) throws {
        guard let coinDB = coinDB, let blockStore = blockStore else { return }

        // Roll back name tree first — it must happen before UTXO disconnects
        // so that covenant processing during reconnection sees correct state.
        //
        // rollbackToHeight only restores the snapshot at the previous tree
        // commit boundary (multiples of treeInterval) and clears pending. If
        // `height` is not itself a commit boundary, the pending state for
        // blocks (committedHeight + 1)...height is lost. Replay those shared
        // blocks from the blockstore so pending matches the new tip — without
        // this, the next commit produces a tree root that diverges from the
        // chain headers and fires "Tree root mismatch" auto-repair.
        if let nameDB = nameDB {
            try nameDB.rollbackToHeight(height, treeInterval: nameParams.treeInterval)
            let replayStart = nameDB.committedHeight + 1
            if replayStart <= height {
                for h in replayStart...height {
                    guard let block = try blockStore.loadBlock(height: h) else {
                        throw ChainError.validationFailed("missing block at height \(h) for tree replay")
                    }
                    try CovenantProcessor.replayCovenants(
                        block: block, nameDB: nameDB,
                        height: h, nameParams: nameParams
                    )
                }
            }
        }

        // Start from the highest stored block, not the header tip. The header
        // chain may be ahead of the block store (e.g., after restart when a header
        // was persisted but its block was never stored/connected to UTXO).
        let disconnectFrom = min(_tip.height, blockStore.storedCount - 1)
        for h in stride(from: disconnectFrom, through: height + 1, by: -1) {
            guard let block = try blockStore.loadBlock(height: h) else {
                throw ChainError.validationFailed("missing block at height \(h) for disconnect")
            }
            guard let entry = byHeight[h] else {
                throw ChainError.validationFailed("missing entry at height \(h) for disconnect")
            }

            // Load undo coins before disconnect (needed for address unindexing,
            // and disconnectBlock deletes the undo data)
            let undoCoins: [CoinEntry]
            if addrIndexStore != nil, let undo = try coinDB.getUndo(height: h) {
                undoCoins = undo
            } else {
                undoCoins = []
            }

            do {
                try coinDB.disconnectBlock(block, height: h, prevHash: entry.prevBlock)
            } catch {
                // Missing undo data — reset and rebuild UTXO set from scratch
                try rebuildUTXO(toHeight: height, coinDB: coinDB, blockStore: blockStore)

                // Clean up tx/address indexes and notify wallets for this
                // block and all remaining blocks down to the fork point.
                // The UTXO state is already correct from the rebuild, but
                // these secondary indexes and callbacks were skipped.
                for rh in stride(from: h, through: height + 1, by: -1) {
                    if let rBlock = try? blockStore.loadBlock(height: rh) {
                        if txIndexStore != nil {
                            for tx in rBlock.transactions {
                                removeTxIndex(txHash: tx.txHash())
                            }
                        }
                        if addrIndexStore != nil {
                            unindexAddresses(block: rBlock, height: rh, undoCoins: [])
                        }
                        notifications.append((rBlock, rh))
                    }
                }

                // Name tree already rolled back above
                return
            }

            // Remove tx index entries
            if txIndexStore != nil {
                for tx in block.transactions {
                    removeTxIndex(txHash: tx.txHash())
                }
            }

            // Remove address index entries
            if addrIndexStore != nil {
                unindexAddresses(block: block, height: h, undoCoins: undoCoins)
            }

            notifications.append((block, h))
        }
    }

    /// Reset the UTXO database and replay all blocks from genesis to `height`.
    ///
    /// WARNING: This is a recovery fallback when undo data is missing.
    /// It replays blocks without signature verification. If the original
    /// blocks were accepted under assumevalid with invalid signatures,
    /// those would be permanently solidified.
    private func rebuildUTXO(toHeight height: Int, coinDB: CoinDatabase, blockStore: BlockStore) throws {
        chainLog("WARNING: Rebuilding UTXO set from scratch — undo data missing. Replaying \(height + 1) blocks without signature verification.")
        try coinDB.reset()

        for h in 0...height {
            guard let block = try blockStore.loadBlock(height: h) else {
                throw ChainError.validationFailed("missing block at height \(h) for UTXO rebuild")
            }
            guard let entry = byHeight[h] else {
                throw ChainError.validationFailed("missing entry at height \(h) for UTXO rebuild")
            }

            if h == 0 {
                // Genesis: just add outputs
                var view = CoinView()
                for tx in block.transactions {
                    view.addTX(tx, height: 0)
                }
                try coinDB.saveView(view, height: 0, hash: entry.hash)
            } else {
                // Normal block: validate inputs, track fees, check coinbase, save
                var view = CoinView()
                var totalFees: Int64 = 0
                for (i, tx) in block.transactions.enumerated() {
                    if i > 0 {
                        for input in tx.inputs {
                            if view.getEntry(input.prevout) == nil {
                                guard let coin = coinDB.getCoin(input.prevout) else {
                                    throw ChainError.missingCoin("UTXO rebuild height \(h) tx \(i)")
                                }
                                view.addEntry(input.prevout, coin)
                            }
                        }
                        guard let fee = view.getFee(tx), fee >= 0 else {
                            throw ChainError.inputValueBelowOutput
                        }
                        let (newTotal, overflow) = totalFees.addingReportingOverflow(fee)
                        guard !overflow else {
                            throw ChainError.inputValueBelowOutput
                        }
                        totalFees = newTotal
                        view.spendInputs(tx)
                    }
                    view.addTX(tx, height: h)
                }
                try BlockValidator.checkCoinbaseValue(
                    block.transactions[0], height: h, fees: totalFees, params: params
                )
                try coinDB.saveView(view, height: h, hash: entry.hash)
            }
        }

        chainLog("UTXO rebuild complete height=\(height) coins=\(coinDB.coinCount)")
    }

    // MARK: - Median Time Past

    /// Compute the median time past for the current tip.
    public func medianTimePast() -> UInt64 {
        lock.lock()
        defer { lock.unlock() }
        let timestamps = _getPreviousTimestamps(_tip, count: params.medianTimeSpan)
        return MedianTime.compute(timestamps, span: params.medianTimeSpan)
    }

    /// Compute the median time past for a specific chain entry (internal unlocked version).
    func _medianTimePast(for entry: ChainEntry) -> UInt64 {
        let timestamps = _getPreviousTimestamps(entry, count: params.medianTimeSpan)
        return MedianTime.compute(timestamps, span: params.medianTimeSpan)
    }

    /// Compute the median time past for a specific chain entry.
    public func medianTimePast(for entry: ChainEntry) -> UInt64 {
        lock.lock()
        defer { lock.unlock() }
        return _medianTimePast(for: entry)
    }

    // MARK: - Public Queries

    /// Load a full block by height from the block store.
    public func getBlock(height: Int) throws -> Block? {
        lock.lock()
        defer { lock.unlock() }
        return try blockStore?.loadBlock(height: height)
    }

    /// Get a name state by name string (computes SHA3-256 hash internally).
    public func getNameState(name: String) throws -> NameState? {
        lock.lock()
        defer { lock.unlock() }
        guard let nameDB = nameDB else { return nil }
        let hash = NameRules.hashName(name)
        return try nameDB.getNameState(hash)
    }

    /// Get a name state by typed NameHash.
    public func getNameState(nameHash: NameHash) throws -> NameState? {
        lock.lock()
        defer { lock.unlock() }
        guard let nameDB = nameDB else { return nil }
        return try nameDB.getNameState(nameHash)
    }

    /// Flush the block store to disk.
    public func flushBlocks() throws {
        lock.lock()
        defer { lock.unlock() }
        try blockStore?.flush()
    }

    // MARK: - Persistence

    /// Flush unpersisted chain entries (internal unlocked version).
    func _flush() throws {
        guard let store = store else { return }
        guard _tip.height > persistedHeight else { return }

        var entries: [ChainEntry] = []
        for h in (persistedHeight + 1)..._tip.height {
            guard let entry = byHeight[h] else {
                // Gap detected — stop here to avoid persisting a discontinuous
                // chain. Entries up to the gap are flushed; the rest will be
                // written on the next flush once the gap is filled.
                break
            }
            entries.append(entry)
        }

        guard !entries.isEmpty else { return }

        try store.appendEntries(entries)
        persistedHeight = persistedHeight + entries.count
    }

    /// Flush unpersisted chain entries to the store.
    ///
    /// Writes all best-chain entries from `persistedHeight+1` through `tip.height`.
    /// No-op if no store is configured or there are no new entries.
    public func flush() throws {
        lock.lock()
        defer { lock.unlock() }
        try _flush()
    }
}
