import Base
import Chain
import Covenants
import Consensus
import ExtCrypto
import Foundation
import Logging
import Mempool
import Protocol

/// Shared atomic flag for coordinating mining threads.
/// Uses a lock since Swift doesn't have portable atomics in 5.9.
private final class MiningResult: @unchecked Sendable {
    private let lock = NSLock()
    private var _nonce: UInt64 = UInt64.max
    private var _stopped = false

    private var _hashes: UInt64 = 0
    private let stopHook: @Sendable () -> Void

    init(stopHook: @escaping @Sendable () -> Void = {}) {
        self.stopHook = stopHook
    }

    /// Try to claim a winning nonce. Returns true if this thread won.
    func claim(_ nonce: UInt32) -> Bool {
        lock.lock()
        guard _nonce == UInt64.max, !_stopped else {
            lock.unlock()
            return false
        }
        _nonce = UInt64(nonce)
        lock.unlock()
        stopHook()
        return true
    }

    /// Signal all threads to stop (stale work or cancellation).
    func stop() {
        lock.lock()
        let needsHook = !_stopped
        _stopped = true
        lock.unlock()
        if needsHook { stopHook() }
    }

    /// Check if mining should continue.
    var shouldStop: Bool {
        lock.lock()
        defer { lock.unlock() }
        return _stopped || _nonce != UInt64.max
    }

    /// The winning nonce, or nil if none found.
    var winningNonce: UInt32? {
        lock.lock()
        defer { lock.unlock() }
        return _nonce == UInt64.max ? nil : UInt32(_nonce)
    }

    /// Increment the shared hash counter (called by each thread).
    func addHashes(_ count: UInt64) {
        lock.lock()
        _hashes += count
        lock.unlock()
    }

    /// Read the total hash count across all threads.
    var totalHashes: UInt64 {
        lock.lock()
        defer { lock.unlock() }
        return _hashes
    }
}

private final class ActiveBufferRegistry: @unchecked Sendable {
    private let lock = NSLock()
    private var buffers: [MiningBuffer] = []

    func add(_ buffer: MiningBuffer) {
        lock.lock()
        buffers.append(buffer)
        lock.unlock()
    }

    func remove(_ buffer: MiningBuffer) {
        lock.lock()
        buffers.removeAll { $0 === buffer }
        lock.unlock()
    }

    func cancelAll() {
        lock.lock()
        for buffer in buffers {
            buffer.cancelled = 1
        }
        lock.unlock()
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
    private let bufferPool: BufferPool
    private let onBlockMined: @Sendable (Block, ChainEntry) -> Void
    private let onHashRate: @Sendable (_ hashRate: Double, _ hashes: UInt64, _ elapsed: Double) -> Void

    /// Create a CPU miner.
    ///
    /// - Parameters:
    ///   - chain: The blockchain to mine on.
    ///   - mempool: The transaction mempool.
    ///   - address: The coinbase payout address.
    ///   - threads: Number of mining threads (0 = all cores).
    ///   - logger: Logger instance.
    ///   - onBlockMined: Callback invoked after each block is successfully mined and connected.
    ///   - onHashRate: Callback invoked periodically with current hash rate (hashes/sec), total hashes, and elapsed seconds.
    public init(
        chain: Chain,
        mempool: Mempool,
        address: Address,
        threads: Int = 0,
        logger: Logger,
        onBlockMined: @escaping @Sendable (Block, ChainEntry) -> Void,
        onHashRate: @escaping @Sendable (_ hashRate: Double, _ hashes: UInt64, _ elapsed: Double) -> Void = { _, _, _ in }
    ) {
        self.chain = chain
        self.mempool = mempool
        self.address = address
        self.threads = threads > 0 ? threads : max(1, ProcessInfo.processInfo.activeProcessorCount - 1)
        self.logger = logger
        self.bufferPool = BufferPool(slots: chain.params.balloonSlots, maxPooled: self.threads)
        self.onBlockMined = onBlockMined
        self.onHashRate = onHashRate
    }

    /// Start mining in a background task. Returns the task handle for cancellation.
    public func start() -> Task<Void, Never> {
        Task.detached { [self] in
            self.logger.info("CPU miner started", metadata: [
                "address": "\(self.address)",
                "threads": "\(self.threads)",
            ], source: "Miner")

            var lastRate: Double = 0
            while !Task.isCancelled {
                do {
                    lastRate = try await self.mineNextBlock(lastRate: lastRate)
                } catch is CancellationError {
                    break
                } catch HeaderError.headerMismatch {
                    self.logger.debug("Stale mined block, retrying", source: "Miner")
                } catch HeaderError.duplicateHeader {
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

    /// Mine a single block on the current tip using all threads.
    /// Returns the hash rate achieved during this round.
    @discardableResult
    private func mineNextBlock(lastRate: Double = 0) async throws -> Double {
        // Don't mine while block sync is in progress — the block store is behind
        // the header tip, so connectBlock would fail with heightMismatch.
        if chain.storedHeight < chain.tip.height {
            try await Task.sleep(nanoseconds: 5_000_000_000)
            return lastRate
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
            return lastRate
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
        let password = try Self.buildPassword(for: th)
        let saltTemplate = Self.buildSalt(nonce: 0, extraNonce: th.extraNonce)

        var miningMeta: Logger.Metadata = [
            "bits": "\(String(format: "0x%08x", bits))",
            "txs": "\(template.transactions.count + 1)",
            "threads": "\(threadCount)",
        ]
        if lastRate > 0 {
            miningMeta["speed"] = "\(String(format: "%.1f", 1.0 / lastRate)) s/hash"
        }
        logger.debug("Mining block \(tip.height + 1)", metadata: miningMeta, source: "Miner")

        let activeBuffers = ActiveBufferRegistry()
        let result = MiningResult {
            activeBuffers.cancelAll()
        }
        let group = DispatchGroup()

        let logger = self.logger
        let slots = params.balloonSlots
        let rounds = params.balloonRounds
        let delta = params.balloonDelta
        for tid in 0..<threadCount {
            group.enter()
            Thread.detachNewThread {
                defer { group.leave() }
                let buffer = self.bufferPool.checkout()
                activeBuffers.add(buffer)
                defer {
                    activeBuffers.remove(buffer)
                    self.bufferPool.checkin(buffer)
                }

                var salt = saltTemplate
                var nonce = UInt32(tid)
                let stride = UInt32(threadCount)
                var hashes: UInt64 = 0

                while !result.shouldStop {
                    salt[0] = UInt8(truncatingIfNeeded: nonce)
                    salt[1] = UInt8(truncatingIfNeeded: nonce &>> 8)
                    salt[2] = UInt8(truncatingIfNeeded: nonce &>> 16)
                    salt[3] = UInt8(truncatingIfNeeded: nonce &>> 24)

                    let hash: Hash256
                    do {
                        let hashBytes = try FastBalloonHash.hash(
                            password: password,
                            salt: salt,
                            buffer: buffer,
                            slots: slots,
                            rounds: rounds,
                            delta: delta,
                            isCancelled: { result.shouldStop }
                        )
                        hash = Hash256(unchecked: hashBytes)
                    } catch is FastBalloonHash.Cancelled {
                        break
                    } catch {
                        logger.error("Mining thread \(tid) error: \(error)", source: "Miner")
                        return
                    }
                    hashes += 1
                    result.addHashes(1)
                    if Target256(bigEndian: hash.bytes) <= target {
                        _ = result.claim(nonce)
                        logger.debug("Thread \(tid) found nonce \(nonce) after \(hashes) hashes", source: "Miner")
                        return
                    }
                    let (next, overflow) = nonce.addingReportingOverflow(stride)
                    if overflow {
                        logger.debug("Thread \(tid) exhausted nonce space after \(hashes) hashes", source: "Miner")
                        return
                    }
                    nonce = next
                }
                logger.debug("Thread \(tid) stopped after \(hashes) hashes", source: "Miner")
            }
        }

        // Wait for threads, periodically checking for stale work and reporting hash rate
        let onHashRate = self.onHashRate
        while true {
            let waitResult = group.wait(timeout: .now() + .seconds(5))

            let elapsed = Date().timeIntervalSince(templateTime)
            let totalHashes = result.totalHashes
            let hashRate = elapsed > 0 ? Double(totalHashes) / elapsed : 0
            onHashRate(hashRate, totalHashes, elapsed)
            let currentRate = totalHashes > 0 ? hashRate : lastRate

            if waitResult == .success { break }
            if Task.isCancelled {
                result.stop()
                group.wait()
                return currentRate
            }
            if chain.tip.hash != tip.hash {
                logger.debug("Stale work, restarting", source: "Miner")
                result.stop()
                group.wait()
                return currentRate
            }
            // Rebuild template if new mempool txs arrived (after 10s minimum)
            if mempool.count != templateTxCount
                && Date().timeIntervalSince(templateTime) > 10 {
                logger.debug("New mempool txs, rebuilding template", source: "Miner")
                result.stop()
                group.wait()
                return currentRate
            }
        }

        let currentRate = result.totalHashes > 0
            ? (Date().timeIntervalSince(templateTime) > 0 ? Double(result.totalHashes) / Date().timeIntervalSince(templateTime) : lastRate)
            : lastRate

        guard let winningNonce = result.winningNonce else {
            logger.debug("Nonce space exhausted, updating timestamp", source: "Miner")
            return currentRate
        }

        // Check tip hasn't changed before expensive proof generation
        guard chain.tip.hash == tip.hash else {
            logger.debug("Stale block, tip changed before proof generation", source: "Miner")
            return currentRate
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
            return currentRate
        }
        let block = mineResult.0
        let entry = mineResult.1

        logger.info("Block \(entry.height) mined", metadata: [
            "hash": "\(entry.hash.hex)",
            "txs": "\(block.transactions.count)",
            "nonce": "\(winningNonce)",
            "speed": "\(currentRate > 0 ? String(format: "%.1f", 1.0 / currentRate) : "0") s/hash",
        ], source: "Miner")

        onBlockMined(block, entry)
        return currentRate
    }

    private static func buildPassword(for header: BlockHeader) throws -> [UInt8] {
        var rawPassword = [UInt8]()
        rawPassword.reserveCapacity(176)
        rawPassword.append(contentsOf: header.prevBlock.bytes)
        rawPassword.append(contentsOf: header.merkleRoot.bytes)
        rawPassword.append(contentsOf: header.witnessRoot.bytes)
        rawPassword.append(contentsOf: header.treeRoot.bytes)
        rawPassword.append(contentsOf: header.reservedRoot.bytes)

        var time = header.time.littleEndian
        withUnsafeBytes(of: &time) { rawPassword.append(contentsOf: $0) }

        var bits = header.bits.littleEndian
        withUnsafeBytes(of: &bits) { rawPassword.append(contentsOf: $0) }

        var version = header.version.littleEndian
        withUnsafeBytes(of: &version) { rawPassword.append(contentsOf: $0) }

        return try Blake2bHash.hash(rawPassword, size: 32)
    }

    private static func buildSalt(nonce: UInt32, extraNonce: [UInt8]) -> [UInt8] {
        var salt = [UInt8]()
        salt.reserveCapacity(28)

        var nonceLE = nonce.littleEndian
        withUnsafeBytes(of: &nonceLE) { salt.append(contentsOf: $0) }
        salt.append(contentsOf: extraNonce)

        return salt
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
