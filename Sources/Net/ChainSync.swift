import Foundation
import Base
import Protocol
import Chain
import Consensus
import Mempool
import ExtCrypto
import Logging

/// Delegate for the chain sync state machine to interact with the peer manager.
public protocol ChainSyncDelegate: AnyObject {
    /// Get a peer context by ID.
    func syncGetPeer(id: UInt64) -> PeerContext?
    /// Get all fully handshaked peers.
    func syncGetHandshakedPeers() -> [PeerContext]
    /// Ban a misbehaving peer.
    func syncBanPeer(id: UInt64, reason: String)
    /// Announce a newly connected block to peers.
    func syncDidConnectBlock(hash: Hash256, header: BlockHeader, proof: BalloonProof, fromPeer: UInt64?)
}

/// Headers-first chain synchronization state machine.
///
/// Coordinates header download from a single sync peer at a time,
/// then downloads full blocks for validation and storage.
public final class ChainSync: @unchecked Sendable {

    /// The current sync state.
    public enum State: Sendable {
        /// Not syncing — waiting for a suitable peer.
        case idle
        /// Downloading headers from sync peer.
        case syncingHeaders
        /// Downloading full blocks from sync peer.
        case syncingBlocks
        /// Fully synced (headers + blocks).
        case synced
    }

    /// Maximum number of concurrent block requests.
    private static let blockWindowSize = 128

    /// Lock protecting all mutable state. Acquired by every public entry
    /// point so that concurrent calls from different peer dispatch threads
    /// are serialized. Lock ordering: ChainSync.lock → Chain.lock (Chain
    /// never calls back into ChainSync while holding its own lock).
    private let lock = NSLock()

    /// The current state.
    public private(set) var state: State = .idle

    /// The state before the current sync cycle (used to suppress logs for
    /// single-block catches when already synced).
    public private(set) var previousState: State = .idle

    /// Set once we finish the initial catch-up sync. Used by FullNode to
    /// suppress per-block "New block" logs during bulk sync.
    public private(set) var initialSyncDone = false

    /// The ID of the current sync peer (if any).
    public private(set) var syncPeerId: UInt64?

    /// The chain index.
    private let chain: Chain

    /// Delegate for peer interactions.
    private weak var delegate: ChainSyncDelegate?

    /// Logger.
    private let logger: Logger

    /// Block hashes we've requested but not yet received, mapped to their height and request time.
    private var pendingBlocks: [Hash256: (height: Int, time: Double)] = [:]

    /// Blocks received out of order, waiting to be connected sequentially.
    private var blockBuffer: [Int: Block] = [:]

    /// Whether we've already attempted a tree repair this session.
    /// Prevents infinite retry loops if the tree is genuinely wrong.
    private var didRepairTree = false

    /// The next block height to connect (process in order).
    private var nextConnectHeight: Int = 0

    /// The next block height to request from the peer.
    private var nextBlockHeight: Int = 0

    /// Rolling window for ETA: stores (timestamp, height) samples.
    private var etaSamples: [(time: Double, height: Int)] = []
    private static let etaWindowSize = 1000

    /// Compact block state: pending reconstruction awaiting blocktxn response.
    private var pendingCompactBlock: PendingCompactBlock?

    /// State for a compact block waiting for missing transactions.
    private struct PendingCompactBlock {
        let header: BlockHeader
        let balloonProof: BalloonProof
        let blockHash: Hash256
        let height: Int
        var txs: [Transaction?]
        let missingIndices: [UInt32]
        let requestTime: Double
    }

    /// Timestamp of the last block received from the sync peer.
    private var lastBlockReceived: Double = 0

    /// Timestamp when we last sent a getheaders request.
    private var lastHeaderRequest: Double = 0

    /// Consecutive orphan header re-requests without progress.
    private var orphanRetries: Int = 0

    /// Scheduled timeout task for header requests. Fires once after 30s
    /// if no response arrives, switching to a different sync peer.
    private var headerTimeoutTask: Task<Void, Never>?

    /// Timeout for blocktxn response (seconds).
    private static let blockTxnTimeout: TimeInterval = 10

    /// The mempool reference for compact block reconstruction.
    public var mempool: Mempool?

    /// Create a chain sync instance.
    public init(chain: Chain, delegate: ChainSyncDelegate, logger: Logger) {
        self.chain = chain
        self.delegate = delegate
        self.logger = logger
    }

    // MARK: - Events from PeerManager

    /// Called when a peer completes the version/verack handshake.
    public func onPeerHandshake(_ peer: PeerContext) {
        lock.lock()
        defer { lock.unlock() }
        guard state == .idle || state == .synced else { return }

        if peer.state.height > UInt32(chain.tip.height) {
            // Peer is ahead — start header sync (which transitions to block download)
            startSync(peer: peer)
        } else if state == .idle, chain.hasBlockStore && chain.storedHeight < chain.tip.height {
            // Headers already synced but blocks are behind — start block download directly
            state = .syncingBlocks
            syncPeerId = peer.id
            nextBlockHeight = chain.storedHeight + 1
            nextConnectHeight = nextBlockHeight
            etaSamples.removeAll()

            logger.debug("Starting block download (headers already synced)", metadata: [
                "peer": "\(peer.id)",
                "from_height": "\(nextBlockHeight)",
                "to_height": "\(chain.tip.height)",
            ])

            requestBlocks(peer: peer)
        } else {
            // Already caught up — mark as synced so we accept new block announcements
            initialSyncDone = true
            state = .synced
            logger.info("Chain fully synced", metadata: [
                "height": "\(chain.tip.height)",
            ])
        }
    }

    /// Called when a peer disconnects.
    public func onPeerDisconnect(_ peer: PeerContext) {
        lock.lock()
        defer { lock.unlock() }
        guard peer.id == syncPeerId else { return }

        logger.info("Sync peer disconnected", metadata: [
            "peer": "\(peer.id)",
        ])

        syncPeerId = nil
        pendingBlocks.removeAll()
        blockBuffer.removeAll()
        etaSamples.removeAll()
        lastBlockReceived = 0

        // Try to find a new sync peer
        if let peers = delegate?.syncGetHandshakedPeers() {
            let tipHeight = UInt32(chain.tip.height)
            if let newPeer = peers.first(where: { $0.id != peer.id && $0.state.height > tipHeight }) {
                startSync(peer: newPeer)
                return
            }
        }

        // No peer is ahead — handle any orphaned headers, then transition
        // to .synced so we keep accepting new block announcements via
        // sendheaders. Going to .idle would silently drop incoming
        // headers (the state guard in onHeaders rejects .idle), which
        // permanently strands the node in multi-miner clusters where
        // peers' announced height isn't strictly greater than ours.
        state = .idle
        recoverOrphanedHeaders()
        if state == .idle {
            state = .synced
        }
    }

    /// Called when we receive headers from a peer.
    public func onHeaders(_ peer: PeerContext, headers: [BlockHeader], proofs: [BalloonProof]) {
        lock.lock()
        defer { lock.unlock() }

        // While downloading blocks, still INDEX incoming header announcements
        // so we don't miss new tip extensions broadcast by other miners. We
        // can't change state or syncPeerId here (we'd disrupt the in-progress
        // block download), but we can add the headers to the chain index.
        // After the current block download finishes, onBlock's "caught up?"
        // check will see the higher tip and continue syncing automatically.
        //
        // Without this, a node that was passively serving block-getdata
        // requests would transition to .syncingBlocks the moment it received
        // its first header broadcast, and from that point on every other
        // miner's broadcast would be silently dropped — permanently stalling
        // the node at whichever block it happened to be downloading.
        if state == .syncingBlocks && !headers.isEmpty {
            for (idx, header) in headers.enumerated() {
                guard idx < proofs.count else { return }
                do {
                    _ = try chain.add(header: header, proof: proofs[idx])
                } catch {
                    // Orphans, duplicates, validation failures — all expected
                    // here since we may receive headers for any chain. The
                    // important thing is we tried.
                }
            }
            return
        }

        // When synced, accept new block headers from any peer (sendheaders
        // announcements). Adopt this peer as sync peer for block download.
        if state == .synced && !headers.isEmpty {
            previousState = .synced
            syncPeerId = peer.id
        }

        guard peer.id == syncPeerId else { return }
        guard state == .syncingHeaders || state == .synced else { return }

        // Reset header timeout — we got a response
        headerTimeoutTask?.cancel()
        lastHeaderRequest = 0

        if headers.isEmpty {
            finishHeaderSync(peer: peer)
            return
        }

        // Validate and add each header
        var addedCount = 0
        var hitOrphan = false
        for (idx, header) in headers.enumerated() {
            guard idx < proofs.count else {
                logger.warning("Missing proof for header at index \(idx), rejecting batch", metadata: [
                    "peer": "\(peer.id)",
                ])
                delegate?.syncBanPeer(id: peer.id, reason: "missing BalloonProof")
                return
            }
            do {
                let entry = try chain.add(header: header, proof: proofs[idx])
                addedCount += 1
                // Track the peer's advertised tip so subsequent "is this
                // peer ahead of us?" checks (used in peer selection after
                // disconnect/timeout) reflect their actual chain height.
                if UInt32(entry.height) > peer.state.height {
                    peer.state.height = UInt32(entry.height)
                }
                logger.debug("Added header \(entry.height)", metadata: [
                    "hash": "\(entry.hash.hex.prefix(16))…",
                    "progress": "\(addedCount)/\(headers.count)",
                ])
            } catch HeaderError.orphanHeader {
                hitOrphan = true
                // Orphan headers are normal — the peer may be announcing its
                // tip which we can't connect yet. Just stop processing this
                // batch and re-request headers using our locator so the peer
                // can respond with the full fork chain from the common ancestor.
                if state == .syncingHeaders {
                    logger.info("Orphan header during sync, re-requesting", metadata: [
                        "peer": "\(peer.id)",
                        "added": "\(addedCount)",
                        "tip_height": "\(chain.tip.height)",
                    ])
                } else if state == .synced {
                    // Peer is on a fork we haven't seen — transition to header
                    // sync to discover it via getheaders locator exchange.
                    logger.info("Orphan header from peer on unknown fork, syncing", metadata: [
                        "peer": "\(peer.id)",
                        "tip_height": "\(chain.tip.height)",
                    ])
                    state = .syncingHeaders
                    orphanRetries = 0 // Fresh sync cycle
                }
                break
            } catch HeaderError.duplicateHeader {
                // Duplicate header (locator overlap) — skip and continue
                // processing remaining headers which may be new.
                continue
            } catch {
                logger.warning("Invalid header from sync peer", metadata: [
                    "peer": "\(peer.id)",
                    "error": "\(error)",
                    "tip_height": "\(chain.tip.height)",
                ])
                delegate?.syncBanPeer(id: peer.id, reason: "invalid header: \(error)")
                syncPeerId = nil
                pendingBlocks.removeAll()
                state = .idle

                // Try another peer, or recover orphaned headers
                if let peers = delegate?.syncGetHandshakedPeers() {
                    let tipHeight = UInt32(chain.tip.height)
                    if let newPeer = peers.first(where: { $0.id != peer.id && $0.state.height > tipHeight }) {
                        startSync(peer: newPeer)
                    } else {
                        recoverOrphanedHeaders()
                    }
                }
                return
            }
        }

        // Orphan during header sync — re-request from our current tip
        if hitOrphan && state == .syncingHeaders {
            if addedCount > 0 {
                do { try chain.flush() } catch {
                    logger.error("Failed to persist headers", metadata: ["error": "\(error)"])
                }
                orphanRetries = 0 // Made progress, reset counter
            } else {
                orphanRetries += 1
                if orphanRetries >= 3 {
                    // Peer keeps sending unchainable headers — switch peers
                    logger.warning("Peer stuck sending orphan headers, switching", metadata: [
                        "peer": "\(peer.id)",
                        "retries": "\(orphanRetries)",
                    ])
                    orphanRetries = 0
                    syncPeerId = nil
                    state = .idle
                    if let peers = delegate?.syncGetHandshakedPeers() {
                        let tipHeight = UInt32(chain.tip.height)
                        if let newPeer = peers.first(where: { $0.id != peer.id && $0.state.height > tipHeight }) {
                            startSync(peer: newPeer)
                        }
                    }
                    return
                }
            }
            requestHeaders(peer: peer)
            return
        }

        // No new headers added (all duplicates)
        if addedCount == 0 {
            if state == .syncingHeaders {
                // Headers are caught up — check if blocks need downloading
                finishHeaderSync(peer: peer)
            }
            return
        }

        let peerHeight = delegate?.syncGetPeer(id: peer.id)?.state.height ?? 0

        // Log sync progress (only during initial sync, not single block announcements)
        if state == .syncingHeaders {
            let pct = peerHeight > 0 ? min(Double(chain.tip.height) / Double(peerHeight) * 100, 100) : 0
            logger.info("Headers: \(chain.tip.height)/\(peerHeight) (\(String(format: "%.3f", pct))%) count=\(headers.count) peer=\(peer.id)")
        }

        // Persist validated headers to disk
        do { try chain.flush() } catch {
            logger.error("Failed to persist headers", metadata: ["error": "\(error)"])
        }

        // Request more if we got a full batch or the peer is still ahead
        if headers.count >= NetConstants.maxHeaders || UInt32(chain.tip.height) < peerHeight {
            requestHeaders(peer: peer)
        } else {
            finishHeaderSync(peer: peer)
        }
    }

    /// Called when we receive a full block from a peer.
    public func onBlock(_ peer: PeerContext, block: Block) {
        lock.lock()
        defer { lock.unlock() }
        guard peer.id == syncPeerId else { return }
        guard state == .syncingBlocks else { return }

        // Look up block hash from chain index via prevBlock to avoid
        // recomputing BalloonHash (~30s). The header was already validated
        // and indexed during header sync.
        let blockHash: Hash256
        if let parent = chain.getEntry(hash: block.header.prevBlock),
           let entry = chain.getEntryByHeight(parent.height + 1),
           entry.prevBlock == block.header.prevBlock
            && entry.merkleRoot == block.header.merkleRoot
            && entry.nonce == block.header.nonce
            && entry.time == block.header.time
            && entry.bits == block.header.bits {
            blockHash = entry.hash
        } else {
            logger.trace("Received block with unknown parent", metadata: [
                "prevBlock": "\(block.header.prevBlock.hex)",
            ])
            return
        }

        guard let pending = pendingBlocks[blockHash] else {
            logger.trace("Received unrequested block", metadata: [
                "hash": "\(blockHash.hex)",
            ])
            return
        }
        let height = pending.height

        pendingBlocks.removeValue(forKey: blockHash)
        lastBlockReceived = Date().timeIntervalSinceReferenceDate

        // Buffer the block for sequential processing
        blockBuffer[height] = block

        // Drain buffer in order — connect all consecutive blocks
        while let nextBlock = blockBuffer.removeValue(forKey: nextConnectHeight) {
            let h = nextConnectHeight

            do {
                try chain.connectBlock(nextBlock, height: h)
            } catch {
                // Tree root mismatch likely means local tree corruption from
                // older builds that didn't roll back the tree on reset. Rebuild
                // the tree from stored blocks and retry once.
                if case ChainError.invalidTreeRoot = error, !didRepairTree {
                    logger.warning("Tree root mismatch — attempting auto-repair", metadata: [
                        "height": "\(h)",
                    ])
                    if let _ = try? chain.repairTreeFromStoredBlocks() {
                        didRepairTree = true
                        logger.info("Tree repair complete, retrying block \(h)")
                        blockBuffer[h] = nextBlock
                        continue
                    } else {
                        logger.error("Tree repair failed")
                    }
                }
                logger.warning("Invalid block from sync peer", metadata: [
                    "peer": "\(peer.id)",
                    "height": "\(h)",
                    "error": "\(error)",
                ])
                delegate?.syncBanPeer(id: peer.id, reason: "invalid block at \(h): \(error)")
                syncPeerId = nil
                pendingBlocks.removeAll()
                blockBuffer.removeAll()
                state = .idle

                // Try another peer, or recover orphaned headers
                if let peers = delegate?.syncGetHandshakedPeers() {
                    let tipHeight = UInt32(chain.tip.height)
                    if let newPeer = peers.first(where: { $0.id != peer.id && $0.state.height > tipHeight }) {
                        startSync(peer: newPeer)
                    } else {
                        recoverOrphanedHeaders()
                    }
                }
                return
            }

            // Announce new block to peers after initial sync
            if initialSyncDone, let entry = chain.getEntryByHeight(h) {
                delegate?.syncDidConnectBlock(hash: entry.hash, header: nextBlock.header, proof: nextBlock.balloonProof, fromPeer: peer.id)
            }

            nextConnectHeight += 1

            // Log progress every 20 blocks during IBD only
            if !initialSyncDone && h % 20 == 0 {
                let target = chain.tip.height
                let pct = target > 0 ? Double(h) / Double(target) * 100 : 0

                let now = Date().timeIntervalSinceReferenceDate
                etaSamples.append((time: now, height: h))
                if etaSamples.count > Self.etaWindowSize {
                    etaSamples.removeFirst(etaSamples.count - Self.etaWindowSize)
                }

                let eta: String
                if etaSamples.count >= 20, let first = etaSamples.first {
                    let elapsed = now - first.time
                    let processed = h - first.height
                    if elapsed > 0 && processed > 0 {
                        let rate = Double(processed) / elapsed
                        let remaining = Double(target - h) / rate
                        let hrs = Int(remaining) / 3600
                        let mins = (Int(remaining) % 3600) / 60
                        eta = hrs > 0 ? " eta=\(hrs)h\(mins)m" : " eta=\(mins)m"
                    } else {
                        eta = ""
                    }
                } else {
                    eta = ""
                }

                logger.info("Block \(h)/\(target) (\(String(format: "%.3f", pct))%)\(eta) txs=\(nextBlock.transactions.count)")
            }
        }

        // Check if we're caught up to the chain tip
        if chain.storedHeight >= chain.tip.height {
            do { try chain.flushBlocks() } catch {
                logger.error("Failed to flush blocks", metadata: ["error": "\(error)"])
            }

            if previousState != .synced {
                logger.info("Block sync complete", metadata: [
                    "height": "\(chain.storedHeight)",
                ])
            }

            initialSyncDone = true
            state = .synced
            syncPeerId = nil
            pendingBlocks.removeAll()
            blockBuffer.removeAll()

            // Block announcements from non-sync peers are dropped during
            // syncingHeaders/syncingBlocks, so request headers from all
            // connected peers to catch any blocks we missed.
            requestHeadersFromAllPeers()
            return
        }

        // Refill when half the window has been consumed, counting both
        // in-flight blocks (pending) and received-but-unprocessed blocks (buffer)
        // to avoid requesting faster than we can connect.
        let outstanding = pendingBlocks.count + blockBuffer.count
        if outstanding <= Self.blockWindowSize / 2 {
            requestBlocks(peer: peer)
        }
    }

    /// Called when we receive inventory announcements.
    public func onInv(_ peer: PeerContext, items: [InvItem]) {
        lock.lock()
        defer { lock.unlock() }
        let blockItems = items.filter { $0.type == .block }
        guard !blockItems.isEmpty else { return }

        // Bump peer.state.height for any announced block we already have in
        // our chain. Without this, peer height only updates when we *fetch*
        // a block from this specific peer — so peers stay tracked at stale
        // heights whenever recent blocks were sourced from someone else,
        // even though the peer has clearly told us they're at that tip.
        var maxKnownHeight: UInt32 = 0
        for item in blockItems {
            if let entry = chain.getEntry(hash: item.hash) {
                let h = UInt32(entry.height)
                if h > maxKnownHeight { maxKnownHeight = h }
            }
        }
        if maxKnownHeight > peer.state.height {
            peer.state.height = maxKnownHeight
        }

        // If any announced block is unknown, request headers to fill the gap
        let hasUnknown = blockItems.contains { !chain.has(hash: $0.hash) }
        guard hasUnknown else { return }

        if state == .synced {
            // Transition to header sync to catch up with new blocks
            state = .syncingHeaders
            syncPeerId = peer.id
            requestHeaders(peer: peer)
        } else if state == .idle {
            // Start syncing if we're idle and this peer is ahead
            if peer.state.height > UInt32(chain.tip.height) {
                startSync(peer: peer)
            }
        }
    }

    /// Called when we receive a compact block from a peer.
    func onCompactBlock(_ peer: PeerContext, data: CompactBlockData) {
        lock.lock()
        defer { lock.unlock() }
        // Only process compact blocks when fully synced — during IBD we need
        // sequential blocks from the sync peer, not random tip announcements.
        guard state == .synced else {
            logger.debug("Ignoring compact block during sync")
            return
        }

        // Add header (validates PoW via BalloonHash) and get hash from entry.
        // This avoids a separate BalloonHash call — chain.add() computes it once.
        var blockHash: Hash256
        do {
            let entry = try chain.add(header: data.header, proof: data.balloonProof)
            blockHash = entry.hash
            // Track the peer's advertised tip so peer-selection checks work.
            if UInt32(entry.height) > peer.state.height {
                peer.state.height = UInt32(entry.height)
            }
            try chain.flush()
        } catch HeaderError.duplicateHeader(let existing) {
            // Already have this header — use the existing entry's hash
            // directly. Looking up via byHeight would return the wrong
            // entry when the header is for a fork we already know about
            // but that isn't our current best chain.
            blockHash = existing.hash
            if UInt32(existing.height) > peer.state.height {
                peer.state.height = UInt32(existing.height)
            }
        } catch HeaderError.orphanHeader {
            // Peer is on a fork we haven't seen — request headers to
            // discover the fork via locator exchange.
            logger.info("Orphan compact block header, syncing fork from peer", metadata: [
                "peer": "\(peer.id)",
            ])
            state = .syncingHeaders
            syncPeerId = peer.id
            requestHeaders(peer: peer)
            return
        } catch {
            logger.debug("Cannot add compact block header", metadata: [
                "error": "\(error)",
            ])
            return
        }

        // Check if we already have this block connected. Only best-chain
        // blocks are stored, so we must verify the entry is on the best
        // chain — a fork entry at a "stored" height isn't actually stored.
        if let entry = chain.getEntry(hash: blockHash),
           chain.getEntryByHeight(entry.height)?.hash == entry.hash,
           entry.height <= chain.storedHeight {
            logger.debug("Already have compact block \(blockHash.hex)")
            return
        }

        // Determine height
        guard let entry = chain.getEntry(hash: blockHash) else {
            logger.debug("Compact block header not in chain index")
            requestFullBlock(peer: peer, hash: blockHash)
            return
        }

        // Get mempool snapshot for reconstruction
        var mempoolTxs = [Hash256: Transaction]()
        if let mp = mempool {
            for (hash, entry) in mp.map {
                mempoolTxs[hash] = entry.tx
            }
        }

        // Attempt reconstruction (no BalloonHash — blockHash already computed)
        let result = CompactBlockReconstructor.reconstruct(
            data: data, mempoolTxs: mempoolTxs, blockHash: blockHash
        )
        switch result {
        case .success(let block):
            logger.info("Compact block reconstructed", metadata: [
                "height": "\(entry.height)",
                "hash": "\(blockHash.hex)",
                "txs": "\(block.transactions.count)",
            ])
            // Process as a normal block
            previousState = state
            state = .syncingBlocks
            syncPeerId = peer.id
            nextBlockHeight = entry.height + 1
            nextConnectHeight = entry.height
            pendingBlocks.removeAll()
            blockBuffer.removeAll()
            blockBuffer[entry.height] = block
            pendingBlocks[blockHash] = (height: entry.height, time: Date().timeIntervalSinceReferenceDate)
            pendingBlocks.removeValue(forKey: blockHash)
            drainBlockBuffer()

        case .missing(_, let indices):
            logger.info("Compact block missing \(indices.count) txs, requesting", metadata: [
                "height": "\(entry.height)",
                "hash": "\(blockHash.hex)",
            ])
            // Build partial tx array
            let totalTxs = data.shortIds.count + data.prefilledTxs.count
            var txs = [Transaction?](repeating: nil, count: totalTxs)
            // Place prefilled
            var pfIdx: UInt32 = 0
            for (i, pf) in data.prefilledTxs.enumerated() {
                let absIndex = i == 0 ? pf.index : pfIdx + pf.index + 1
                pfIdx = absIndex
                if Int(absIndex) < totalTxs { txs[Int(absIndex)] = pf.tx }
            }
            // Place matched mempool txs
            let (key0, key1) = data.sipHashKeys(headerHash: blockHash)
            var shortIdIdx = 0
            for i in 0..<totalTxs {
                if txs[i] != nil { continue }
                guard shortIdIdx < data.shortIds.count else { break }
                let sid = ShortTxId(data.shortIds[shortIdIdx])
                shortIdIdx += 1
                for (hash, tx) in mempoolTxs {
                    if ShortTxId.compute(txHash: hash, key0: key0, key1: key1) == sid {
                        txs[i] = tx
                        break
                    }
                }
            }

            pendingCompactBlock = PendingCompactBlock(
                header: data.header,
                balloonProof: data.balloonProof,
                blockHash: blockHash,
                height: entry.height,
                txs: txs,
                missingIndices: indices,
                requestTime: Date().timeIntervalSinceReferenceDate
            )
            peer.send(GetBlockTxnPacket(hash: blockHash, indices: indices))
        }
    }

    /// Called when we receive a blocktxn response (missing transactions).
    public func onBlockTxn(_ peer: PeerContext, hash: Hash256, transactions: [Transaction]) {
        lock.lock()
        defer { lock.unlock() }
        guard var pending = pendingCompactBlock, pending.blockHash == hash else {
            logger.debug("Received blocktxn for unknown compact block")
            return
        }

        pendingCompactBlock = nil

        guard let block = CompactBlockReconstructor.fillMissing(
            txs: &pending.txs,
            missingIndices: pending.missingIndices,
            responseTxs: transactions,
            header: pending.header,
            balloonProof: pending.balloonProof
        ) else {
            logger.warning("blocktxn fill failed, falling back to full block")
            requestFullBlock(peer: peer, hash: hash)
            return
        }

        logger.info("Compact block completed via blocktxn", metadata: [
            "height": "\(pending.height)",
            "hash": "\(hash.hex)",
            "txs": "\(block.transactions.count)",
        ])

        // Process as a normal block
        previousState = state
        state = .syncingBlocks
        syncPeerId = peer.id
        nextBlockHeight = pending.height + 1
        nextConnectHeight = pending.height
        pendingBlocks.removeAll()
        blockBuffer.removeAll()
        blockBuffer[pending.height] = block
        drainBlockBuffer()
    }

    /// Check for timed-out compact block requests.
    public func checkCompactBlockTimeout() {
        lock.lock()
        defer { lock.unlock() }
        guard let pending = pendingCompactBlock else { return }
        let elapsed = Date().timeIntervalSinceReferenceDate - pending.requestTime
        if elapsed > Self.blockTxnTimeout {
            logger.info("blocktxn timeout, falling back to full block", metadata: [
                "hash": "\(pending.blockHash.hex)",
            ])
            pendingCompactBlock = nil
            // Request full block from sync peer
            if let peerId = syncPeerId, let peer = delegate?.syncGetPeer(id: peerId) {
                requestFullBlock(peer: peer, hash: pending.blockHash)
            }
        }
    }

    /// Check for timed-out block requests.
    /// Only triggers when no blocks have been received for 60 seconds,
    /// preventing false timeouts during slow but active block processing.
    public func checkBlockTimeout() {
        lock.lock()
        defer { lock.unlock() }
        guard state == .syncingBlocks, !pendingBlocks.isEmpty else { return }
        let now = Date().timeIntervalSinceReferenceDate
        let timeout: Double = 60

        // If we've received a block recently, the peer is still delivering
        if lastBlockReceived > 0 && now - lastBlockReceived < timeout {
            return
        }

        // Also check from first request time if we've never received anything
        if lastBlockReceived == 0 {
            let oldest = pendingBlocks.values.min(by: { $0.time < $1.time })
            if let oldest, now - oldest.time < timeout {
                return
            }
        }

        logger.warning("Block request timeout, switching sync peer", metadata: [
            "pending": "\(pendingBlocks.count)",
        ])

        // Disconnect current sync peer
        if let peerId = syncPeerId, let peer = delegate?.syncGetPeer(id: peerId) {
            peer.close()
        }

        syncPeerId = nil
        pendingBlocks.removeAll()
        blockBuffer.removeAll()
        state = .idle

        // Try to find a new sync peer
        if let peers = delegate?.syncGetHandshakedPeers() {
            let tipHeight = UInt32(chain.tip.height)
            if let newPeer = peers.first(where: { $0.state.height > tipHeight }) {
                startSync(peer: newPeer)
                return
            }

            // No peer is ahead of our tip, but blocks are missing — the
            // entries above storedHeight are orphaned (e.g. miner added
            // headers it couldn't connect). Reset to storedHeight so header
            // sync can rediscover the correct chain from peers.
            if chain.storedHeight < chain.tip.height {
                logger.warning("Resetting chain to stored height (orphaned entries)", metadata: [
                    "stored": "\(chain.storedHeight)",
                    "tip": "\(chain.tip.height)",
                ])
                do {
                    try chain.resetToStoredHeight()
                } catch {
                    logger.error("Failed to reset chain to stored height: \(error)")
                }

                // Re-sync headers from an available peer
                if let peer = peers.first(where: { $0.state.isHandshaked }) {
                    startSync(peer: peer)
                }
            }
        }
        // Final fallback: if we ended up still in .idle, transition to
        // .synced so we keep accepting block announcements via sendheaders.
        // Otherwise the node permanently drops every header it receives.
        if state == .idle {
            state = .synced
        }
    }

    /// Check for timed-out header requests.
    /// If we've been waiting for headers for 30+ seconds, give up and try
    /// another peer. This prevents getting stuck in syncingHeaders when
    /// the sync peer can't serve headers (e.g., block store behind tip).
    public func checkHeaderTimeout() {
        lock.lock()
        defer { lock.unlock() }
        guard state == .syncingHeaders, lastHeaderRequest > 0 else { return }
        let now = Date().timeIntervalSinceReferenceDate
        guard now - lastHeaderRequest >= 30 else { return }

        logger.warning("Header request timeout, switching sync peer", metadata: [
            "peer": "\(syncPeerId ?? 0)",
        ])

        let oldPeerId = syncPeerId
        syncPeerId = nil
        headerTimeoutTask?.cancel()
        lastHeaderRequest = 0
        state = .idle

        // Try to find a new sync peer, or recover orphaned headers
        if let peers = delegate?.syncGetHandshakedPeers() {
            let tipHeight = UInt32(chain.tip.height)
            if let newPeer = peers.first(where: { $0.id != oldPeerId && $0.state.height > tipHeight }) {
                startSync(peer: newPeer)
            } else {
                recoverOrphanedHeaders()
            }
        }
        // If we couldn't find another sync peer or recover, transition to
        // .synced (not .idle) so we keep accepting block announcements.
        // .idle silently drops incoming headers.
        if state == .idle {
            state = .synced
        }
    }

    /// Request a full block as fallback.
    private func requestFullBlock(peer: PeerContext, hash: Hash256) {
        let item = InvItem(type: .block, hash: hash)
        peer.send(GetDataPacket(items: [item]))
    }

    /// If the header tip is ahead of stored blocks and the state is idle,
    /// reset the chain to the stored height so that the next sync cycle
    /// discovers the correct chain from peers. Without this, the node gets
    /// permanently stuck: the miner pauses (storedHeight < tip), no timeout
    /// fires (wrong state), and no peer appears "ahead" of the inflated tip.
    private func recoverOrphanedHeaders() {
        guard state == .idle, chain.hasBlockStore, chain.storedHeight < chain.tip.height else { return }
        logger.warning("Resetting chain to stored height (orphaned entries)", metadata: [
            "stored": "\(chain.storedHeight)",
            "tip": "\(chain.tip.height)",
        ])
        do {
            try chain.resetToStoredHeight()
        } catch {
            logger.error("Failed to reset chain to stored height: \(error)")
            return
        }

        // Re-sync headers from an available peer
        if let peers = delegate?.syncGetHandshakedPeers(),
           let peer = peers.first(where: { $0.state.isHandshaked }) {
            startSync(peer: peer)
        }
    }

    // MARK: - Internal

    private func startSync(peer: PeerContext) {
        previousState = state
        state = .syncingHeaders
        syncPeerId = peer.id
        orphanRetries = 0

        logger.debug("Starting header sync", metadata: [
            "peer": "\(peer.id)",
            "peer_height": "\(peer.state.height)",
            "our_height": "\(chain.tip.height)",
        ])

        requestHeaders(peer: peer)
    }

    private func requestHeaders(peer: PeerContext) {
        lastHeaderRequest = Date().timeIntervalSinceReferenceDate
        let locator = chain.getLocator()
        peer.send(GetHeadersPacket(locator: locator))
        scheduleHeaderTimeout()
    }

    /// Schedule a one-shot timeout that fires after 30s. If no headers
    /// arrive in that window, `checkHeaderTimeout()` switches the sync peer.
    private func scheduleHeaderTimeout() {
        headerTimeoutTask?.cancel()
        headerTimeoutTask = Task { [weak self] in
            try? await Task.sleep(nanoseconds: 30_000_000_000)
            guard !Task.isCancelled else { return }
            self?.checkHeaderTimeout()
        }
    }

    /// Request headers from all connected peers. Called after transitioning to
    /// .synced to catch block announcements dropped during sync.
    private func requestHeadersFromAllPeers() {
        guard let peers = delegate?.syncGetHandshakedPeers() else { return }
        let locator = chain.getLocator()
        for peer in peers {
            peer.send(GetHeadersPacket(locator: locator))
        }
    }

    private func finishHeaderSync(peer: PeerContext) {
        let wasSynced = previousState == .synced

        // Final flush to persist any remaining headers
        do { try chain.flush() } catch {
            logger.error("Failed to persist headers at sync finish", metadata: ["error": "\(error)"])
        }

        if !wasSynced {
            logger.debug("Header sync complete", metadata: [
                "height": "\(chain.tip.height)",
                "hash": "\(chain.tip.hash.hex)",
            ])
        }

        // Check if we need to download blocks
        if chain.hasBlockStore && chain.storedHeight < chain.tip.height {
            state = .syncingBlocks
            nextBlockHeight = chain.storedHeight + 1
            nextConnectHeight = nextBlockHeight
            etaSamples.removeAll()

            if !wasSynced {
                logger.info("Starting block download", metadata: [
                    "from_height": "\(nextBlockHeight)",
                    "to_height": "\(chain.tip.height)",
                ])
            }

            requestBlocks(peer: peer)
        } else {
            state = .synced
            syncPeerId = nil

            // Check other peers for blocks announced while we were syncing.
            requestHeadersFromAllPeers()
        }
    }

    /// Drain the block buffer: connect all consecutive blocks starting from nextConnectHeight.
    /// Used by both normal block sync and compact block reconstruction.
    private func drainBlockBuffer() {
        while let nextBlock = blockBuffer.removeValue(forKey: nextConnectHeight) {
            let h = nextConnectHeight

            do {
                try chain.connectBlock(nextBlock, height: h)
            } catch {
                if case ChainError.invalidTreeRoot = error, !didRepairTree {
                    logger.warning("Tree root mismatch during drain — attempting auto-repair", metadata: ["height": "\(h)"])
                    if let _ = try? chain.repairTreeFromStoredBlocks() {
                        didRepairTree = true
                        logger.info("Tree repair complete, retrying block \(h)")
                        blockBuffer[h] = nextBlock
                        continue
                    }
                }
                logger.warning("Invalid block during drain", metadata: [
                    "height": "\(h)",
                    "error": "\(error)",
                ])
                syncPeerId = nil
                pendingBlocks.removeAll()
                blockBuffer.removeAll()
                state = .idle
                recoverOrphanedHeaders()
                return
            }

            // Announce new block to peers after initial sync
            if initialSyncDone, let entry = chain.getEntryByHeight(h) {
                delegate?.syncDidConnectBlock(hash: entry.hash, header: nextBlock.header, proof: nextBlock.balloonProof, fromPeer: syncPeerId)
            }

            nextConnectHeight += 1
        }

        // Check if we're caught up to the chain tip
        if chain.storedHeight >= chain.tip.height {
            do { try chain.flushBlocks() } catch {
                logger.error("Failed to flush blocks", metadata: ["error": "\(error)"])
            }

            initialSyncDone = true
            state = .synced
            syncPeerId = nil
            pendingBlocks.removeAll()
            blockBuffer.removeAll()

            // Re-request headers from all peers — announcements during
            // syncingBlocks are dropped, so other peers may have forks
            // we haven't seen yet.
            requestHeadersFromAllPeers()
        }
    }

    private func requestBlocks(peer: PeerContext) {
        var items: [InvItem] = []
        let maxHeight = chain.tip.height
        let maxNew = Self.blockWindowSize - pendingBlocks.count - blockBuffer.count

        while items.count < maxNew && nextBlockHeight <= maxHeight {
            guard let entry = chain.getEntryByHeight(nextBlockHeight) else {
                nextBlockHeight += 1
                continue
            }

            let item = InvItem(type: .block, hash: entry.hash)
            items.append(item)
            pendingBlocks[entry.hash] = (height: nextBlockHeight, time: Date().timeIntervalSinceReferenceDate)
            nextBlockHeight += 1
        }

        guard !items.isEmpty else { return }

        peer.send(GetDataPacket(items: items))
    }
}
