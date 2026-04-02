import Foundation
import Logging
import CLevelDB

import Base
import Consensus
import Covenants
import ExtCrypto
import Mempool
import Chain
import Protocol

/// Shared claim container for mining threads.
/// First thread to find valid proof-of-work claims the singleton and
/// other threads discard their work.
private final class MiningResult: Sendable {
    private let lock = NSLock()
    private var _nonce: UInt64 = UInt64.max
    private var _claimed: Bool = false

    func claim(_ nonce: UInt32) -> Bool {
        lock.lock()
        defer { lock.unlock() }
        guard !_claimed else { return false }
        _claimed = true
        _nonce = UInt64(nonce)
        return true
    }

    var shouldStop: Bool {
        lock.lock()
        defer { lock.unlock() }
        return _claimed
    }

    func stop() {
        lock.lock()
        defer { lock.unlock() }
        _claimed = true
    }

    /// The winning nonce, or nil if none found.
    var winningNonce: UInt32? {
        lock.lock()
        defer { lock.unlock() }
        return _nonce == UInt64.max ? nil : UInt32(_nonce)
    }
}

/// Thread-safe mining statistics tracker.
/// Tracks hash counts and block mining metrics across all mining threads.
private final class MiningStats: @unchecked Sendable {
    private let lock = NSLock()
    private var _totalHashes: UInt64 = 0
    private var _blocksMined: UInt64 = 0
    private var _startTime: Date?
    private var _lastBlockTime: Date?
    private var _threadHashes: [Int: UInt64] = [:]

    /// Register a hash completed by any mining thread.
    func addHashes(_ count: UInt64, threadID: Int) {
        lock.lock()
        defer { lock.unlock() }
        if _startTime == nil {
            _startTime = Date()
        }
        _totalHashes += count
        _threadHashes[threadID, default: 0] += count
    }

    /// Register a block mined.
    func registerBlock() {
        lock.lock()
        defer { lock.unlock() }
        _blocksMined += 1
        _lastBlockTime = Date()
    }

    /// Get current statistics.
    func getStats() -> (totalHashes: UInt64, blocksMined: UInt64, elapsedTime: TimeInterval, avgBlockTime: TimeInterval?) {
        lock.lock()
        defer { lock.unlock() }
        return (
            totalHashes: _totalHashes,
            blocksMined: _blocksMined,
            elapsedTime: _startTime.map { Date().timeIntervalSince($0) } ?? 0.0,
            avgBlockTime: calculateAvgBlockTime()
        )
    }

    /// Get per-thread hash counts and calculates hash rates.
    func getPerThreadStats() -> [(threadID: Int, hashes: UInt64, hashRate: Double)] {
        lock.lock()
        defer { lock.unlock() }
        let elapsed = _startTime.map { Date().timeIntervalSince($0) } ?? 0.0
        return _threadHashes.map { (tid, hashes) in
            (tid, hashes, elapsed > 0 ? Double(hashes) / elapsed : 0.0)
        }.sorted { $0.threadID < $1.threadID }
    }

    private func calculateAvgBlockTime() -> TimeInterval? {
        guard _blocksMined > 0, let start = _startTime else { return nil }
        let elapsed = Date().timeIntervalSince(start)
        return elapsed / TimeInterval(_blocksMined)
    }
}
/// A continuous CPU miner that runs as a background task.
///
/// Uses all available CPU cores to mine in parallel. Each core works on a
/// different nonce for the same block template. First core to find a valid
/// proof-of-work wins; the others discard their work and all cores start
/// on the next block.
public final class CPUMiner: Sendable {
    private let chain: Chain
    private let mempool: Mempool
    private let address: Address
    private let logger: Logger
    private let threads: Int
    private let onBlockMined: @Sendable (Block, ChainEntry) -> Void
    private let stats: MiningStats = MiningStats()

    /// Create a CPU miner.
    ///
    /// - Parameters:
    ///   - chain: The blockchain to mine on.
    ///   - mempool: The transaction mempool.
    ///   - address: The coinbase payout address.
    ///   - threads: Number of mining threads (0 = all cores).
    ///   - logger: Logger instance.
    ///   - onBlockMined: Callback invoked after each block is successfully mined and connected.
    public init(
        chain: Chain,
        mempool: Mempool,
        address: Address,
        threads: Int = 0,
        logger: Logger,
        onBlockMined: @escaping @Sendable (Block, ChainEntry) -> Void
    ) {
        self.chain = chain
        self.mempool = mempool
        self.address = address
        self.threads = threads > 0 ? threads : max(1, ProcessInfo.processInfo.activeProcessorCount - 1)
        self.logger = logger
        self.onBlockMined = onBlockMined
    }

    /// Start mining in a background task. Returns the task handle for cancellation.
    public func start() -> Task<Void, Never> {
        Task.detached { [self] in
            self.logger.info("CPU miner started", metadata: [
                "address": "\(self.address)",
                "threads": "\(self.threads)",
            ], source: "Miner")

            while !Task.isCancelled {
                do {
                    try await self.mineNextBlock()
                } catch is CancellationError {
                    break
                } catch HeaderError.headerMismatch, HeaderError.duplicateHeader {
                    // Stale block — tip changed while we were mining, just retry
                    self.logger.debug("Stale mined block, retrying", source: "Miner")
                } catch let error as BlockStoreError {
                    // Height mismatch from block store — block sync likely in progress.
                    // Wait for sync to catch up before retrying.
                    self.logger.debug("Stale mined block (\(error)), waiting for sync", source: "Miner")
                    try? await Task.sleep(nanoseconds: 5_000_000_000)
                } catch {
                    self.logger.error("Mining error: \(error)", source: "Miner")
                    // Evict offending transactions to prevent repeated failures
                    self.evictInvalidTransactions()
                    try? await Task.sleep(nanoseconds: 1_000_000_000)
                }
            }

            self.logger.info("CPU miner stopped", source: "Miner")
        }
    }

    /// Get current mining statistics.
    /// Returns a tuple with (totalHashes, blocksMined, elapsedTime, avgBlockTime).
    public func getStats() -> (totalHashes: UInt64, blocksMined: UInt64, elapsedTime: TimeInterval, avgBlockTime: TimeInterval?) {
        return stats.getStats()
    }

    /// Get per-thread mining statistics.
    /// Returns an array of (threadID, hashes, hashRate).
    public func getPerThreadStats() -> [(threadID: Int, hashes: UInt64, hashRate: Double)] {
        return stats.getPerThreadStats()
    }

    /// Get the actual number of mining threads being used.
    public var activeThreads: Int {
        threads
    }

    /// Register a hash completed by a specific mining thread.
    private func registerHashes(count: UInt64, threadID: Int) {
        stats.addHashes(count, threadID: threadID)
    }

    /// Mine a single block on the current tip using all threads.
    private func mineNextBlock() async throws {
        // Don't mine while block sync is in progress — the block store is behind
        // the header tip, so connectBlock would fail with heightMismatch.
        if chain.storedHeight < chain.tip.height {
            try await Task.sleep(nanoseconds: 5_000_000_000)
            return
        }

        let tip = chain.tip
        let bits = chain.getNextBits()
        let treeRoot = try chain.getCurrentTreeRoot()
        let time = max(UInt64(Date().timeIntervalSince1970), tip.time + 1)
        let params = chain.params

        // Don't mine if the block timestamp would be too far in the future
        let now = UInt64(Date().timeIntervalSince1970)
        if time > now + UInt64(params.maxFutureBlockTime) {
            let wait = time - now - UInt64(params.maxFutureBlockTime)
            logger.info("Block timestamp too far in future, waiting \(wait)s", source: "Miner")
            try await Task.sleep(nanoseconds: UInt64(min(wait, 30)) * 1_000_000_000)
            return
        }

        var template = try BlockAssembler.assemble(
            tip: tip,
            mempool: mempool,
            address: address,
            treeRoot: treeRoot,
            time: time,
            bits: bits
        )

        // Pre-validate: trial-run covenant processing on template transactions.
        // Evict any that would fail connectBlock and re-assemble if needed.
        let invalid = chain.validateTransactions(
            template.transactions, height: tip.height + 1, blockTime: time
        )
        if !invalid.isEmpty {
            for hash in invalid {
                mempool.evictEntry(hash)
            }
            logger.info("Evicted \(invalid.count) invalid transaction(s) before mining", source: "Miner")
            template = try BlockAssembler.assemble(
                tip: tip, mempool: mempool, address: address,
                treeRoot: treeRoot, time: time, bits: bits
            )
        }

        let th = template.header
        let target = Target256.fromCompact(bits)
        let threadCount = self.threads
        let templateTxCount = mempool.count
        let templateTime = Date()

        logger.debug("Mining block \(tip.height + 1)", metadata: [
            "bits": "\(String(format: "0x%08x", bits))",
            "txs": "\(template.transactions.count + 1)",
            "threads": "\(threadCount)",
        ], source: "Miner")

        let result = MiningResult()
        let group = DispatchGroup()

        let logger = self.logger
        for tid in 0..<threadCount {
            group.enter()
            Thread.detachNewThread { [weak self] in
                defer { group.leave() }
                var nonce = UInt32(tid)
                let stride = UInt32(threadCount)
                var threadHashes: UInt64 = 0

                while !result.shouldStop {
                    let h = BlockHeader(
                        nonce: nonce, time: th.time, prevBlock: th.prevBlock,
                        treeRoot: th.treeRoot, extraNonce: th.extraNonce,
                        reservedRoot: th.reservedRoot, witnessRoot: th.witnessRoot,
                        merkleRoot: th.merkleRoot, version: th.version, bits: th.bits
                    )
                    let hash: Hash256
                    do {
                        hash = try ProofOfWork.powHash(for: h, params: params, isCancelled: { result.shouldStop })
                    } catch is BalloonHash.Cancelled {
                        break
                    } catch {
                        logger.error("Mining thread \(tid) error: \(error)", source: "Miner")
                        return
                    }
                    threadHashes += 1
                    self?.registerHashes(count: 1, threadID: tid)
                    if Target256(bigEndian: hash.bytes) <= target {
                        _ = result.claim(nonce)
                        logger.debug("Thread \(tid) found nonce \(nonce) after \(threadHashes) hashes", source: "Miner")
                        return
                    }
                    let (next, overflow) = nonce.addingReportingOverflow(stride)
                    if overflow {
                        logger.debug("Thread \(tid) exhausted nonce space after \(threadHashes) hashes", source: "Miner")
                        return
                    }
                    nonce = next
                }
                logger.debug("Thread \(tid) stopped after \(threadHashes) hashes", source: "Miner")
            }
        }

        // Wait for threads, periodically checking for stale work
        while true {
            let waitResult = group.wait(timeout: .now() + .seconds(5))
            if waitResult == .success { break }
            if Task.isCancelled {
                result.stop()
                group.wait()
                return
            }
            if chain.tip.hash != tip.hash {
                logger.debug("Stale work, restarting", source: "Miner")
                result.stop()
                group.wait()
                return
            }
            // Rebuild template if new mempool txs arrived (after 10s minimum)
            if mempool.count != templateTxCount
                && Date().timeIntervalSince(templateTime) > 10 {
                logger.debug("New mempool txs, rebuilding template", source: "Miner")
                result.stop()
                group.wait()
                return
            }
        }

        guard let winningNonce = result.winningNonce else {
            logger.debug("Nonce space exhausted, updating timestamp", source: "Miner")
            return
        }

        // Check tip hasn't changed before expensive proof generation
        guard chain.tip.hash == tip.hash else {
            logger.debug("Stale block, tip changed before proof generation", source: "Miner")
            return
        }

        let winHeader = BlockHeader(
            nonce: winningNonce, time: th.time, prevBlock: th.prevBlock,
            treeRoot: th.treeRoot, extraNonce: th.extraNonce,
            reservedRoot: th.reservedRoot, witnessRoot: th.witnessRoot,
            merkleRoot: th.merkleRoot, version: th.version, bits: th.bits
        )

        // Generate BalloonProof for the winning header. This recomputes
        // BalloonHash once more but saves the expand-phase buffer to
        // create proof samples for fast verification by peers.
        let chain = self.chain
        let tipHash = tip.hash
        let txs = [template.coinbase] + template.transactions
        let mineResult: (Block, ChainEntry)? = try await withCheckedThrowingContinuation { cont in
            DispatchQueue.global(qos: .userInitiated).async {
                do {
                    // Re-check tip before connecting — a peer block may have arrived
                    // Also verify blocks are fully synced to prevent adding entries
                    // that can't be connected (storedHeight would fall behind tip).
                    guard chain.tip.hash == tipHash,
                          chain.storedHeight >= chain.tip.height else {
                        cont.resume(returning: nil)
                        return
                    }
                    let (_, proof) = try ProofOfWork.powHashWithProof(
                        for: winHeader, params: params
                    )
                    let blk = Block(
                        header: winHeader,
                        transactions: txs,
                        balloonProof: proof
                    )
                    let e = try chain.add(header: blk.header, proof: proof)
                    try chain.connectBlock(blk, height: e.height)
                    try chain.flush()
                    try chain.flushBlocks()
                    cont.resume(returning: (blk, e))
                } catch {
                    cont.resume(throwing: error)
                }
            }
        }

        guard let mineResult else {
            logger.debug("Stale block, tip changed during proof generation", source: "Miner")
            return
        }
        let block = mineResult.0
        let entry = mineResult.1

        logger.info("Block \(entry.height) mined", metadata: [
            "hash": "\(entry.hash.hex)",
            "txs": "\(block.transactions.count)",
            "nonce": "\(winningNonce)",
        ], source: "Miner")

        stats.registerBlock()
        onBlockMined(block, entry)
    }

    /// Remove mempool transactions that would fail block validation.
    private func evictInvalidTransactions() {
        let height = chain.tip.height + 1
        let nameParams = NameParams.params(for: chain.network)
        var evicted = 0
        var toEvict = [Hash256]()

        for (hash, entry) in mempool.map {
            var shouldEvict = false

            // Check minimum bid
            for output in entry.tx.outputs {
                if output.covenant.type == .bid && output.covenant.items.count >= 3 {
                    let rawName = output.covenant.items[2]
                    let minBid = nameParams.minimumBid(atHeight: height, rawName: rawName)
                    if minBid > 0 && Int64(output.value) < minBid {
                        shouldEvict = true
                        break
                    }
                }
            }

            // Check that all inputs exist (in UTXO set or another mempool tx)
            if !shouldEvict {
                for input in entry.tx.inputs {
                    let inMempool = mempool.map[input.prevout.hash] != nil
                    let inChain = chain.getCoin(hash: input.prevout.hash, index: input.prevout.index) != nil
                    if !inMempool && !inChain {
                        shouldEvict = true
                        break
                    }
                }
            }

            // Check covenant validity against current chain state.
            // Load the on-chain name state, apply maybeExpire (as
            // connectBlock would), then verify auction state, covenant
            // height, register deadline, transfer lockup, and renewal
            // block age — all the checks that can go stale while a
            // transaction sits in the mempool.
            if !shouldEvict {
                for output in entry.tx.outputs {
                    guard output.covenant.type.isName, output.covenant.type != .open,
                          output.covenant.items.count >= 2,
                          output.covenant.items[0].count == 32 else { continue }

                    let nameHash = NameHash(unchecked: output.covenant.items[0])
                    guard var ns = try? chain.getNameState(nameHash: nameHash) else {
                        // Name doesn't exist — covenant will fail
                        shouldEvict = true
                        break
                    }

                    ns.maybeExpire(at: height, params: nameParams)
                    let st = ns.state(at: height, params: nameParams)

                    // -- Auction state --
                    switch output.covenant.type {
                    case .bid:
                        if st != .bidding { shouldEvict = true }
                    case .reveal:
                        if st != .reveal { shouldEvict = true }
                    case .redeem:
                        if st != .closed && st != .revoked { shouldEvict = true }
                    case .register:
                        if st != .closed { shouldEvict = true }
                        if height > ns.registerDeadlineHeight(params: nameParams) { shouldEvict = true }
                    case .update, .renew, .transfer, .finalize, .revoke:
                        if st != .closed { shouldEvict = true }
                    default:
                        break
                    }

                    // -- Covenant height must match name state height --
                    // A stale tx from a prior auction round will have
                    // the old open height; after expiry + re-open the
                    // name state height changes.
                    if !shouldEvict && output.covenant.items.count >= 2 && output.covenant.items[1].count == 4 {
                        let covHeight = try? CovenantData.height(from: output.covenant)
                        if let covHeight, output.covenant.type != .open {
                            if covHeight != ns.height { shouldEvict = true }
                        }
                    }

                    // -- FINALIZE: transfer must have been initiated
                    //    and lockup period must have elapsed --
                    if !shouldEvict && output.covenant.type == .finalize {
                        if ns.transfer == 0 || height < ns.transfer + nameParams.transferLockup {
                            shouldEvict = true
                        }
                    }

                    // -- REGISTER / RENEW / FINALIZE: renewal block
                    //    must still be within the valid age window --
                    if !shouldEvict {
                        let renewalItemIndex: Int?
                        switch output.covenant.type {
                        case .register: renewalItemIndex = 3
                        case .renew:    renewalItemIndex = 2
                        case .finalize: renewalItemIndex = 6
                        default:        renewalItemIndex = nil
                        }
                        if let idx = renewalItemIndex,
                           output.covenant.items.count > idx,
                           output.covenant.items[idx].count == 32 {
                            let renewalHash = Hash256(unchecked: output.covenant.items[idx])
                            if !CovenantProcessor.verifyRenewal(
                                hash: renewalHash, height: height,
                                params: nameParams, chain: chain
                            ) {
                                shouldEvict = true
                            }
                        }
                    }

                    if shouldEvict { break }
                }
            }

            // Check covenant validity (delegation conflicts)
            if !shouldEvict {
                for output in entry.tx.outputs {
                    if (output.covenant.type == .update || output.covenant.type == .register) && output.covenant.items.count > 2 {
                        // Check if auctionSubdomains is set in chain state OR in the covenant's flags
                        let nhForFlag = NameHash(unchecked: output.covenant.items[0])
                        let chainFlag = (try? chain.getNameState(nameHash: nhForFlag))?.auctionSubdomains ?? false
                        let covFlag = output.covenant.items.count > 3 && !output.covenant.items[3].isEmpty && (output.covenant.items[3][0] & 1 != 0)
                        if chainFlag || covFlag {
                            let resource = output.covenant.items[2]
                            if !resource.isEmpty && NameRules.containsDelegationRecords(resource) {
                                shouldEvict = true
                                break
                            }
                        }
                    }
                }
            }

            // Check REGISTER has required payment outputs (burn + dev fund)
            if !shouldEvict {
                for output in entry.tx.outputs {
                    guard output.covenant.type == .register,
                          output.covenant.items.count >= 2,
                          output.covenant.items[0].count == 32 else { continue }
                    let regNameHash = NameHash(unchecked: output.covenant.items[0])
                    guard var ns = try? chain.getNameState(nameHash: regNameHash) else { continue }
                    ns.maybeExpire(at: height, params: nameParams)
                    let regMinBid = nameParams.minimumBid(atHeight: height, rawName: ns.name)
                    let regPrice = max(ns.value, regMinBid)
                    if regPrice > 0 {
                        let burnShare = regPrice * Int64(nameParams.registrationBurnPercent) / 100
                        let devShare = regPrice - burnShare
                        // Check that burn and dev fund outputs exist
                        let hasBurn = burnShare == 0 || entry.tx.outputs.contains {
                            $0.covenant.type == .none && $0.address == .null && Int64($0.value) >= burnShare
                        }
                        let hasDevFund = devShare == 0 || entry.tx.outputs.contains {
                            $0.covenant.type == .none && $0.address != .null && Int64($0.value) >= devShare
                        }
                        if !hasBurn || !hasDevFund {
                            shouldEvict = true
                            break
                        }
                    }
                }
            }

            if shouldEvict {
                toEvict.append(hash)
            }
        }
        for hash in toEvict {
            mempool.evictEntry(hash)
            evicted += 1
        }
        if evicted > 0 {
            logger.info("Evicted \(evicted) invalid transaction(s) from mempool", source: "Miner")
        }
    }
}
