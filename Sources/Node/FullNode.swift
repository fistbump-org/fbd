#if os(Windows)
import WinSDK
#else
import Dispatch
#endif
#if canImport(Android)
import Android
// SIG_IGN macro isn't importable in Swift on Android.
private let SIG_IGN = unsafeBitCast(1, to: (@convention(c) (Int32) -> Void).self)
#endif
import Foundation
import Base
import Chain
import Consensus
import Covenants
import ExtCrypto
import DNS
import Mempool
import Mining
import Net
import Protocol
import RPC
import Script
@preconcurrency import Wallet
import Logging

/// Module-level continuation for shutdown (signal or RPC stop).
nonisolated(unsafe) private var _signalContinuation: CheckedContinuation<Void, Never>?

#if os(Windows)
private let _consoleCtrlHandler: PHANDLER_ROUTINE = { dwCtrlType in
    if dwCtrlType == DWORD(CTRL_C_EVENT) || dwCtrlType == DWORD(CTRL_BREAK_EVENT) {
        _signalContinuation?.resume()
        _signalContinuation = nil
        return true
    }
    return false
}
#endif

/// The full Fistbump node orchestrator.
///
/// Wires together all subsystems (chain, mempool, network, DNS, RPC, mining)
/// and manages their lifecycle. The node runs as an async task, coordinating
/// startup, sync, and shutdown across all components.
public final class FullNode: Sendable {
    /// The node configuration.
    public let config: NodeConfig

    /// The logger for this node.
    public let logger: Logger

    /// The node's current phase.
    public let phase: NodePhase

    /// The node's version string (semver only, for CLI --version).
    public static let version = Constants.version

    /// Full version with build hash, e.g. "0.1.0 (abc1234)".
    public static let fullVersion = Constants.fullVersion

    /// Build the user agent string, optionally with a custom suffix.
    public static func userAgent(suffix: String? = nil) -> String {
        if let suffix = suffix, !suffix.isEmpty {
            return "/fbd:\(version)/\(suffix)/"
        }
        return "/fbd:\(version)/"
    }

    /// Create a full node with the given configuration.
    public init(config: NodeConfig) {
        self.config = config
        self.phase = .stopped

        var logger = Logger(label: "org.firstbump.fbd")
        logger.logLevel = config.logLevel
        self.logger = logger
    }

    /// Initialize all subsystems and prepare for startup.
    ///
    /// This performs the synchronous initialization phase:
    /// 1. Validate configuration
    /// 2. Initialize mempool
    /// 3. Build RPC config
    public func initialize() throws -> NodeComponents {
        // Validate config
        try validateConfig()

        // Generate a random API key if none was provided and auth isn't disabled
        let effectiveApiKey: String?
        if config.rpcNoAuth {
            effectiveApiKey = nil
        } else if let key = config.rpcApiKey {
            effectiveApiKey = key
        } else {
            var bytes = [UInt8](repeating: 0, count: 32)
            for i in 0..<bytes.count { bytes[i] = UInt8.random(in: 0...255) }
            effectiveApiKey = HexEncoding.encode(bytes)
            logger.info("Generated RPC API key (use --api-key to set your own)",
                        metadata: ["key": "\(effectiveApiKey!)"], source: "RPC")
        }

        let rpcConfig = RPCConfig(
            host: config.rpcHost,
            port: Int(config.effectiveRPCPort),
            apiKey: effectiveApiKey,
            noAuth: config.rpcNoAuth
        )

        return NodeComponents(
            rpcConfig: rpcConfig
        )
    }

    /// Build the initial node state.
    public func initialState() -> NodeState {
        var state = NodeState()
        state.isRunning = false
        state.syncProgress = 0
        return state
    }

    /// Start all network services and run until a shutdown signal is received.
    ///
    /// This starts the RPC HTTP server, DNS UDP server, and P2P TCP listener,
    /// then waits for SIGINT or SIGTERM before performing graceful shutdown.
    public func start(components: NodeComponents) async throws {
        // Ignore SIGPIPE so writing to a closed socket returns an error
        // instead of killing the process.
        #if !os(Windows)
        signal(SIGPIPE, SIG_IGN)
        #endif

        // Create data directory structure
        let dataDir = NSString(string: config.networkDataDir).expandingTildeInPath
        let blocksDir = dataDir + "/blocks"
        let chainDir = dataDir + "/chain"
        let treeDir = dataDir + "/tree"
        let walletsDir = dataDir + "/wallets"

        let fm = FileManager.default
        for dir in [blocksDir, chainDir, treeDir, walletsDir] {
            try fm.createDirectory(atPath: dir, withIntermediateDirectories: true)
        }

        // Write RPC cookie file for fbdctl auto-auth
        let cookiePath = dataDir + "/.cookie"
        if let apiKey = components.rpcConfig.apiKey {
            #if os(Windows)
            fm.createFile(atPath: cookiePath, contents: Data(apiKey.utf8))
            #else
            fm.createFile(atPath: cookiePath, contents: Data(apiKey.utf8), attributes: [.posixPermissions: 0o600])
            #endif
        }

        let chainStore = try ChainStore(
            path: chainDir + "/headers.bin",
            network: config.network
        )

        let blockStore = try BlockStore(
            blocksDir: blocksDir,
            network: config.network
        )

        // Initialize UTXO database — check if reindex is needed before creating Chain.
        // If the coin DB is behind the block store (e.g., chain/ was deleted but blocks/
        // was kept, or a previous reindex was interrupted), reset both coin and tree
        // databases for a clean reindex from block 0.
        let coinsDir = chainDir + "/coins"
        var coinDB = try CoinDatabase(path: coinsDir, network: config.network)
        let storedCount = blockStore.storedCount

        // Detect incomplete block writes via the pending-height sentinel.
        // If present, a block was written to disk but the UTXO batch didn't
        // commit — force reindex regardless of arithmetic.
        let pendingWriteIncomplete = coinDB.pendingHeight != nil
        if pendingWriteIncomplete {
            logger.info("Pending block write detected (crash during write), forcing reindex", metadata: [
                "pending_height": "\(coinDB.pendingHeight!)",
                "coin_height": "\(coinDB.committedHeight)",
                "stored_blocks": "\(storedCount)",
            ], source: "Chain")
        }

        let coinsBehind: Bool
        if coinDB.committedHeight >= 0 {
            coinsBehind = pendingWriteIncomplete
                || (storedCount > 0 && coinDB.committedHeight < storedCount - 1)
        } else {
            coinsBehind = storedCount > 100 && coinDB.coinCount < 100
        }

        // Also detect coin DB ahead of block store (legacy: before write-order
        // swap, connectBlock could commit UTXO before the block was stored).
        let coinsAhead = storedCount > 0 && coinDB.committedHeight >= 0
            && coinDB.committedHeight > storedCount - 1

        if coinsBehind || coinsAhead {
            logger.info("Coin database \(coinsAhead ? "ahead of" : "behind") block store, resetting for reindex...", metadata: [
                "coin_height": "\(coinDB.committedHeight)",
                "stored_blocks": "\(storedCount)",
            ], source: "Chain")
            coinDB.close()
            try? fm.removeItem(atPath: coinsDir)
            coinDB = try CoinDatabase(path: coinsDir, network: config.network)

            // Also reset tree — it must be rebuilt in sync with coins
            let namesPath = treeDir + "/names"
            if fm.fileExists(atPath: namesPath) {
                try fm.removeItem(atPath: namesPath)
            }
        }

        logger.info("UTXO database initialized", metadata: [
            "path": "\(coinsDir)",
            "coins": "\(coinDB.coinCount)",
            "committed_height": "\(coinDB.committedHeight)",
        ], source: "Chain")

        // Validate index flags against existing state.
        // If an index directory exists but the flag is off, the user probably
        // forgot the flag. If the flag is on but no directory exists and the
        // chain already has blocks, the index would be incomplete.
        let txIndexDir = chainDir + "/txindex"
        let addrIndexDir = chainDir + "/addrindex"

        if !config.indexTx && fm.fileExists(atPath: txIndexDir) {
            logger.error("Transaction index exists on disk but --index-tx is not set. Add --index-tx to use the existing index, or delete \(txIndexDir) to discard it.", source: "Chain")
            throw NodeError.indexMismatch("transaction index exists but --index-tx not set")
        }
        if !config.indexAddress && fm.fileExists(atPath: addrIndexDir) {
            logger.error("Address index exists on disk but --index-address is not set. Add --index-address to use the existing index, or delete \(addrIndexDir) to discard it.", source: "Chain")
            throw NodeError.indexMismatch("address index exists but --index-address not set")
        }
        if config.indexTx && !fm.fileExists(atPath: txIndexDir) && storedCount > 1 {
            logger.error("--index-tx enabled but no existing index and chain already has \(storedCount) blocks. The index will be incomplete. Delete the chain data directory to start fresh, or remove --index-tx.", source: "Chain")
            throw NodeError.indexMismatch("--index-tx enabled on existing chain without prior index")
        }
        if config.indexAddress && !fm.fileExists(atPath: addrIndexDir) && storedCount > 1 {
            logger.error("--index-address enabled but no existing index and chain already has \(storedCount) blocks. The index will be incomplete. Delete the chain data directory to start fresh, or remove --index-address.", source: "Chain")
            throw NodeError.indexMismatch("--index-address enabled on existing chain without prior index")
        }

        // Initialize chain (loads persisted headers + block store + coin DB + tree)
        let txIndexPath = config.indexTx ? txIndexDir : nil
        let addrIndexPath = config.indexAddress ? addrIndexDir : nil
        let chain = try Chain(network: config.network, store: chainStore, blockStore: blockStore, coinDB: coinDB, treeDir: treeDir, txIndexPath: txIndexPath, addrIndexPath: addrIndexPath)

        // Connect genesis block on fresh start (stores block data + UTXO)
        if blockStore.storedCount == 0 {
            let genesisBlock = Genesis.block(for: config.network)
            try chain.connectBlock(genesisBlock, height: 0)
            logger.info("Genesis block connected", source: "Chain")
        }

        // If chain tip is ahead of block store (orphaned entries from miner or
        // incomplete sync), reset to stored height so reindex and peer sync
        // start from a consistent state.
        if chain.tip.height > chain.storedHeight && chain.storedHeight >= 0 {
            logger.info("Chain tip ahead of block store, resetting to stored height...", metadata: [
                "tip": "\(chain.tip.height)",
                "stored": "\(chain.storedHeight)",
            ], source: "Chain")
            try chain.resetToStoredHeight()
        }

        // If block store is ahead of header chain (unclean shutdown), replay headers
        // so the chain tip catches up. Full block validation (UTXO, tree) is handled
        // by the reindex/rebuild steps that follow.
        if chain.storedHeight > chain.tip.height {
            logger.info("Block store ahead of chain tip, replaying headers...", metadata: [
                "tip": "\(chain.tip.height)",
                "stored": "\(chain.storedHeight)",
            ], source: "Chain")
            for h in (chain.tip.height + 1)...chain.storedHeight {
                if let block = try chain.getBlock(height: h) {
                    _ = try chain.add(header: block.header, proof: block.balloonProof)
                }
            }
            try chain.flush()
        }

        logger.info("Chain initialized", metadata: [
            "tip": "\(chain.tip.hash.hex)",
            "height": "\(chain.tip.height)",
            "stored_blocks": "\(chain.storedHeight + 1)",
        ], source: "Chain")

        // Initialize mempool
        let mempool = Mempool()
        mempool.nameHasAuctionSubdomains = { [weak chain] nameHashBytes in
            let nameHash = NameHash(unchecked: nameHashBytes)
            guard let ns = try? chain?.getNameState(nameHash: nameHash) else { return false }
            return ns.auctionSubdomains
        }

        let mempoolNetwork = config.network
        mempool.validateCovenants = { [weak chain] tx, coinView, height in
            guard let chain = chain else { return nil }
            let nameParams = NameParams.params(for: mempoolNetwork)
            return chain.trialValidateCovenants(
                tx: tx, coinView: coinView, height: height,
                network: mempoolNetwork, nameParams: nameParams
            )
        }

        // Initialize wallets — scan for existing wallet subdirectories
        let ctx = NodeContext()
        ctx.chain = chain
        ctx.coinDB = coinDB
        ctx.mempool = mempool

        // Set static log broadcast so external log handlers push lines to WS subscribers.
        NodeContext.logBroadcast = { [weak ctx] line in ctx?.emitLog(line) }

        // Parse --miner-address if provided
        if let addrStr = config.minerAddress {
            do {
                let addr = try Address(bech32: addrStr, network: config.network)
                ctx.minerAddress = addr
                logger.info("Mining address set", metadata: [
                    "address": "\(addrStr)",
                ], source: "Node")
            } catch {
                logger.warning("Ignoring invalid miner-address '\(addrStr)': \(error)", source: "Node")
            }
        }

        // Configure miner threads (cap at cpuCount - 1)
        let maxThreads = max(1, ctx.cpuCount - 1)
        let requestedThreads = config.minerThreads
        ctx.minerThreads = requestedThreads > 0 ? min(requestedThreads, maxThreads) : 0
        logger.info("CPU threads: \(ctx.cpuCount), miner threads: \(ctx.minerThreads > 0 ? "\(ctx.minerThreads)" : "auto (\(maxThreads))")", source: "Node")

        // Wire mempool → wallet indexing for unconfirmed transactions
        mempool.onTransactionAccepted = { [ctx, logger] tx in
            let txHash = tx.txHash()
            let mempoolTime = ctx.mempool?.get(txHash)?.time
            logger.info("Added \(txHash.hex)", source: "Mempool")
            for (name, wallet) in ctx.allWallets() {
                do {
                    let relevant = try wallet.indexTransaction(tx, timestamp: mempoolTime)
                    if relevant {
                        logger.info("Transaction \(txHash.hex) (unconfirmed)", metadata: [
                            "wallet": "\(name)",
                        ], source: "Wallet")
                        ctx.notifyWalletBalance(wallet: name, wallet)
                    }
                } catch {
                    logger.error("Failed to index tx \(txHash.hex) for wallet \(name): \(error)", source: "Wallet")
                }
            }
        }

        mempool.onTransactionRemoved = { [ctx, logger] tx in
            let txHash = tx.txHash()
            logger.info("Evicted \(txHash.hex)", source: "Mempool")
            for (name, wallet) in ctx.allWallets() {
                do {
                    let relevant = try wallet.unindexTransaction(tx)
                    if relevant {
                        logger.info("Unindexed evicted tx \(txHash.hex)", metadata: [
                            "wallet": "\(name)",
                        ], source: "Wallet")
                        ctx.notifyWalletBalance(wallet: name, wallet)
                    }
                } catch {
                    logger.error("Failed to unindex tx \(txHash.hex) for wallet \(name): \(error)", source: "Wallet")
                }
            }
        }

        if let entries = try? fm.contentsOfDirectory(atPath: walletsDir) {
            for name in entries.sorted() {
                let walletPath = walletsDir + "/\(name)"
                guard fm.fileExists(atPath: walletPath + "/CURRENT") else { continue }
                let wallet = try WalletDB(path: walletPath, network: config.network)
                ctx.setWallet(name, wallet)
                logger.info("Wallet loaded", metadata: [
                    "name": "\(name)",
                    "addresses": "\(wallet.addressCount)",
                    "scan_height": "\(wallet.scanHeight)",
                ], source: "Wallet")
            }
        }
        logger.debug("Wallets initialized", metadata: [
            "count": "\(ctx.allWallets().count)",
        ], source: "Wallet")

        // Wire wallets and mempool into chain block notifications BEFORE
        // the RPC server starts — otherwise generate/connectBlock could fire
        // before the callback is set, silently skipping wallet indexing.
        chain.onBlockConnected = { [ctx, logger] block, height in
            // Log new blocks only after initial sync is complete.
            let synced = ctx.chainSync?.initialSyncDone == true
            if synced {
                let hash = ctx.chain?.getEntryByHeight(height)?.hash
                logger.info("Block \(height)", metadata: [
                    "hash": "\(hash?.hex ?? "?")",
                    "txs": "\(block.transactions.count)",
                ], source: "Chain")
            }

            // Emit block event to WebSocket/SSE subscribers.
            let headers = ctx.chain?.tip.height ?? height
            let progress = headers > 0 ? min(1.0, Double(height) / Double(headers)) : 1.0
            let peers = ctx.peerManager?.peerCount ?? 0
            ctx.emitEvent("{\"type\":\"block\",\"height\":\(height),\"headers\":\(headers),\"progress\":\(progress),\"peers\":\(peers),\"txs\":\(block.transactions.count)}")

            // Remove confirmed txs from mempool
            ctx.mempool?.removeBlock(block)

            // Update auction index
            ctx.auctionIndex?.indexBlock(block, height: height)

            for (name, wallet) in ctx.allWallets() {
                // Skip wallets that are being rescanned — the rescan loop
                // feeds blocks sequentially and will cover this height.
                guard !wallet.isRescanning else { continue }
                do {
                    let txs = try wallet.indexBlock(block, height: height)
                    if !txs.isEmpty {
                        ctx.notifyWalletBalance(wallet: name, wallet)
                    }
                    for tx in txs {
                        logger.info("Transaction \(tx.hash.hex) (confirmed)", metadata: [
                            "wallet": "\(name)",
                            "height": "\(height)",
                            "sent": "\(tx.sent)",
                            "received": "\(tx.received)",
                        ], source: "Wallet")
                    }
                    // Clean up old-round bids when register deadline passes
                    // (only when auction index is disabled — with it, data is preserved)
                    if ctx.auctionIndex == nil, let chain = ctx.chain {
                        let nameParams = NameParams.params(for: chain.network)
                        if let allBids = try? wallet.getAllBids() {
                            for bid in allBids {
                                guard let ns = try? chain.getNameState(nameHash: bid.nameHash) else { continue }
                                let deadline = ns.registerDeadlineHeight(params: nameParams)
                                if bid.height > 0 && bid.height < ns.height && height >= deadline {
                                    try? wallet.removeBid(nameHash: bid.nameHash, outpoint: bid.outpoint)
                                }
                            }
                        }
                    }
                } catch {
                    logger.error("Failed to index block \(height) for wallet '\(name)': \(error)", source: "Wallet")
                }
            }
        }

        chain.onBlockDisconnected = { [weak self, ctx] block, height in
            self?.logger.info("Block disconnected (reorg)", metadata: [
                "height": "\(height)",
                "txs": "\(block.transactions.count)",
            ], source: "Chain")

            // Re-add block txs to mempool
            if let coinDB = ctx.coinDB, let chain = ctx.chain {
                ctx.mempool?.addBlock(block, coinDB: coinDB, chainHeight: chain.tip.height, params: chain.params)
            }

            // Undo auction index for this block
            ctx.auctionIndex?.unindexBlock(block, height: height)

            for (name, wallet) in ctx.allWallets() {
                do {
                    try wallet.unindexBlock(block, height: height)
                } catch {
                    self?.logger.error("Failed to unindex block \(height) for wallet '\(name)': \(error)", source: "Wallet")
                }
            }
        }

        // Build RPC dispatcher with live state — start server early so
        // queries work during name state rebuild and block sync.
        let dispatcher = buildRPCDispatcher(ctx: ctx)
        logger.debug("RPC dispatcher initialized",
                     metadata: ["methods": "\(dispatcher.methods.count)"], source: "RPC")

        // Start RPC HTTP server
        logger.debug("Binding RPC server...", source: "RPC")
        let rpcServer = RPCNetworkServer(
            config: components.rpcConfig,
            dispatcher: dispatcher,
            logger: logger,
            onWebSocket: { [ctx, logger] stream in
                await Self.handleWebSocket(stream: stream, ctx: ctx, logger: logger)
            },
            onSSE: { [ctx, logger] stream, uri in
                await Self.handleSSE(stream: stream, uri: uri, ctx: ctx, logger: logger)
            }
        )
        do {
            try rpcServer.start()
        } catch {
            logger.error("Cannot bind RPC on \(config.rpcHost):\(config.effectiveRPCPort) — \(Self.describeBindError(error))", source: "RPC")
            coinDB.close()
            for (_, wallet) in ctx.allWallets() { wallet.close() }
            try? fm.removeItem(atPath: cookiePath)
            throw NodeError.startupFailed("bind failed")
        }
        logger.info("RPC listening on \(config.rpcHost):\(config.effectiveRPCPort)", source: "RPC")
        if config.rpcHost != "127.0.0.1" && config.rpcHost != "localhost" {
            logger.warning("RPC is bound to \(config.rpcHost) — wallet API is exposed to the network", source: "RPC")
            if config.rpcNoAuth {
                logger.warning("RPC authentication is disabled (--no-auth) on a non-localhost interface", source: "RPC")
            }
        }

        // Start DNS UDP server with chain-backed name lookup
        let dnsServer = DNSServer(
            host: config.nsHost,
            port: Int(config.effectiveNSPort),
            logger: logger,
            lookup: { [chain, config] name in
                guard let ns = try chain.getNameState(name: name) else { return nil }
                guard ns.registered else { return nil }
                guard ns.revoked == 0 else { return nil }
                let height = chain.tip.height
                let nameParams = NameParams.params(for: config.network)
                guard !ns.isExpired(at: height, params: nameParams) else { return nil }
                return ns.data
            }
        )
        do {
            try dnsServer.start()
        } catch {
            logger.error("Cannot bind DNS on \(config.nsHost):\(config.effectiveNSPort) — \(Self.describeBindError(error))", source: "DNS")
            rpcServer.shutdown()
            coinDB.close()
            for (_, wallet) in ctx.allWallets() { wallet.close() }
            try? fm.removeItem(atPath: cookiePath)
            throw NodeError.startupFailed("bind failed")
        }
        logger.info("DNS listening on \(config.nsHost):\(config.effectiveNSPort)", source: "DNS")

        // Reindex stored blocks if coin database is empty but blocks exist.
        // This happens when chain/ is deleted but blocks/ is kept — rebuilds
        // headers, UTXOs, and name state from the stored block files.
        var didReindex = false
        if chain.needsReindex {
            logger.info("Reindexing blocks (rebuilding UTXO set from stored blocks)...", metadata: [
                "blocks": "\(chain.storedHeight + 1)",
            ], source: "Chain")
            let reindexStart = Date().timeIntervalSinceReferenceDate
            var lastLog = 0
            try chain.reindexBlocks { current, total in
                if current - lastLog >= 100 || current == total - 1 {
                    lastLog = current
                    let pct = total > 0 ? Double(current + 1) / Double(total) * 100 : 0
                    self.logger.info("Reindex: block \(current)/\(total) (\(String(format: "%.3f", pct))%)", source: "Chain")
                }
            }
            let elapsed = Date().timeIntervalSinceReferenceDate - reindexStart
            let mins = Int(elapsed) / 60
            let secs = Int(elapsed) % 60
            logger.info("Block reindex complete", metadata: [
                "elapsed": "\(mins)m\(secs)s",
                "coins": "\(coinDB.coinCount)",
            ], source: "Chain")
            didReindex = true
        }

        // Rebuild name state from stored blocks (needed after restart).
        // Skip if reindex was just done — it already processes covenants via connectBlock.
        // With persisted tree, only replays blocks since the last tree commit.
        if !didReindex && chain.storedHeight >= 0 {
            let fromHeight = chain.nameRebuildStartHeight
            let toHeight = chain.storedHeight
            let replayCount = toHeight - fromHeight + 1
            if fromHeight <= toHeight {
                if replayCount <= 36 {
                    // Normal restart: replay uncommitted blocks since last treeInterval commit
                    logger.debug("Replaying \(replayCount) blocks for name state", metadata: [
                        "from": "\(fromHeight)",
                        "to": "\(toHeight)",
                    ], source: "Chain")
                    try chain.rebuildNameState(progress: nil)
                } else {
                    logger.info("Rebuilding name state...", metadata: [
                        "from": "\(fromHeight)",
                        "to": "\(toHeight)",
                    ], source: "Chain")
                    var lastLog = fromHeight
                    try chain.rebuildNameState { current, total in
                        if current - lastLog >= 100 || current == total - 1 {
                            lastLog = current
                            let pct = total > 0 ? Double(current + 1) / Double(total) * 100 : 0
                            self.logger.info("Name state rebuild: block \(current)/\(total) (\(String(format: "%.3f", pct))%)", source: "Chain")
                        }
                    }
                    logger.info("Name state rebuild complete", source: "Chain")
                }
            } else {
                logger.debug("Name state loaded from disk, no replay needed", source: "Chain")
            }
        }

        // Build auction index (LevelDB-backed with --index-auctions, in-memory otherwise).
        do {
            let auctionStorePath = config.indexAuctions ? (chainDir + "/auctionindex") : nil
            let auctionIndex = try AuctionIndex(network: config.network, storePath: auctionStorePath)
            try auctionIndex.populate(chain: chain)
            ctx.auctionIndex = auctionIndex
            logger.info("Auction index ready", metadata: [
                "auctions": "\(auctionIndex.auctionCount)",
                "persistent": "\(auctionIndex.isPersistent)",
            ], source: "Chain")
        } catch {
            logger.error("Failed to build auction index: \(error)", source: "Chain")
        }

        // Purge stale unconfirmed state from wallets (mempool doesn't persist across restarts)
        for (name, wallet) in ctx.allWallets() {
            guard wallet.initialized else { continue }
            let purged = try wallet.purgeUnconfirmedState()
            if purged > 0 {
                logger.info("Purged \(purged) stale unconfirmed coins", metadata: ["wallet": "\(name)"], source: "Wallet")
            }
            if wallet.scanHeight < chain.storedHeight {
                let behind = chain.storedHeight - wallet.scanHeight
                if wallet.scanHeight == -1 || behind > 1000 {
                    // Large gap or no blocks indexed — user should manually rescan
                    logger.info("Wallet is \(behind) blocks behind, use rescanwallet to sync", metadata: [
                        "name": "\(name)",
                        "scanHeight": "\(wallet.scanHeight)",
                        "chainHeight": "\(chain.storedHeight)",
                    ], source: "Wallet")
                } else {
                    // Small gap — auto catch-up by indexing missed blocks
                    logger.info("Wallet catching up \(behind) blocks", metadata: [
                        "name": "\(name)",
                        "from": "\(wallet.scanHeight + 1)",
                        "to": "\(chain.storedHeight)",
                    ], source: "Wallet")
                    var catchupFailed = false
                    for h in (wallet.scanHeight + 1)...chain.storedHeight {
                        do {
                            if let block = try chain.getBlock(height: h) {
                                try wallet.indexBlock(block, height: h)
                            }
                        } catch {
                            logger.error("Wallet catch-up failed at height \(h): \(error) — use rescanwallet to sync", metadata: [
                                "wallet": "\(name)",
                            ], source: "Wallet")
                            catchupFailed = true
                            break
                        }
                    }
                    if !catchupFailed {
                        logger.info("Wallet caught up to height \(chain.storedHeight)", metadata: [
                            "name": "\(name)",
                        ], source: "Wallet")
                    }
                }
            }
        }

        // Load or generate identity key
        let identityKeyPath = dataDir + "/identity.key"
        let identityKey: PrivateKey
        if let savedKey = try? Data(contentsOf: URL(fileURLWithPath: identityKeyPath)),
           savedKey.count == 32 {
            identityKey = PrivateKey(unchecked: Array(savedKey))
            logger.info("Loaded identity key from disk", source: "Net")
        } else {
            identityKey = try ECDSASigner.generatePrivateKey()
            try Data(identityKey.bytes).write(to: URL(fileURLWithPath: identityKeyPath))
            try fm.setAttributes([.posixPermissions: 0o600], ofItemAtPath: identityKeyPath)
            logger.info("Generated new identity key", source: "Net")
        }
        let identityPub = try ECDSASigner.publicKey(from: identityKey)
        logger.info("Node identity", metadata: [
            "pubkey": "\(identityPub.hex)",
        ], source: "Net")

        let userAgent = FullNode.userAgent(suffix: config.agent)
        let peerManagerConfig = PeerManagerConfig(
            network: config.network,
            maxOutbound: config.maxOutbound,
            maxInbound: config.maxInbound,
            seeds: config.seeds,
            nodes: config.nodes,
            userAgent: userAgent,
            dataDir: dataDir
        )
        let peerManager = try PeerManager(
            config: peerManagerConfig,
            identityKey: identityKey,
            logger: logger
        )

        // Wire chain sync and mempool into peer manager
        peerManager.chain = chain
        peerManager.mempool = mempool
        peerManager.coinDB = coinDB
        let chainSync = ChainSync(chain: chain, delegate: peerManager, logger: logger)
        chainSync.mempool = mempool
        peerManager.chainSync = chainSync
        ctx.chainSync = chainSync
        ctx.peerManager = peerManager
        peerManager.onPeerCountChange = { [ctx] count in
            ctx.emitEvent("{\"type\":\"peers\",\"count\":\(count)}")
        }

        // Start P2P TCP listener
        let p2pListener = P2PListener(
            host: config.host,
            port: Int(config.effectivePort),
            network: config.network,
            peerManager: peerManager,
            logger: logger
        )
        do {
            try p2pListener.start()
        } catch {
            logger.error("Cannot bind P2P on \(config.host):\(config.effectivePort) — \(Self.describeBindError(error))", source: "Net")
            rpcServer.shutdown()
            dnsServer.shutdown()
            ctx.auctionIndex?.close()
            coinDB.close()
            for (_, wallet) in ctx.allWallets() { wallet.close() }
            try? fm.removeItem(atPath: cookiePath)
            throw NodeError.startupFailed("bind failed")
        }
        logger.info("P2P listening on \(config.host):\(config.effectivePort)", source: "Net")

        // Start Brontide (encrypted P2P) listener
        let brontidePort = Int(config.network.brontidePort)
        let brontideListener = P2PListener(
            host: config.host,
            port: brontidePort,
            network: config.network,
            useBrontide: true,
            peerManager: peerManager,
            logger: logger
        )
        do {
            try brontideListener.start()
            logger.info("Brontide listening on \(config.host):\(brontidePort)", source: "Net")
        } catch {
            logger.warning("Cannot bind Brontide on \(config.host):\(brontidePort) — \(Self.describeBindError(error))", source: "Net")
        }

        // Start outbound connections and periodic maintenance
        peerManager.startOutboundConnections()
        peerManager.startPeriodicTasks()

        // Start CPU miner if --miner-address is set
        var minerTask: Task<Void, Never>?
        if let minerAddr = ctx.minerAddress, config.network != .regtest && config.network != .simnet {
            let miner = CPUMiner(
                chain: chain,
                mempool: mempool,
                address: minerAddr,
                threads: ctx.minerThreads,
                logger: logger,
                onBlockMined: { [ctx] block, entry in
                    ctx.peerManager?.syncDidConnectBlock(
                        hash: entry.hash, header: block.header, proof: block.balloonProof, fromPeer: nil
                    )
                    let reward = block.transactions.first.map { $0.outputs.reduce(0) { $0 + $1.value } } ?? 0
                    ctx.emitEvent("{\"type\":\"mined\",\"height\":\(entry.height),\"reward\":\(reward)}")
                }
            )
            ctx.miner = miner
            minerTask = miner.start()
        }

        // Wait for shutdown signal (SIGINT or SIGTERM)
        await waitForSignal()

        // Graceful shutdown
        logger.info("Shutting down...")
        minerTask?.cancel()
        await minerTask?.value
        await peerManager.shutdown()
        rpcServer.shutdown()
        dnsServer.shutdown()
        p2pListener.shutdown()
        brontideListener.shutdown()
        for (_, wallet) in ctx.allWallets() { wallet.close() }
        ctx.auctionIndex?.close()
        chain.close()
        coinDB.close()
        NodeContext.logBroadcast = nil
        try? fm.removeItem(atPath: cookiePath)
        logger.info("Shutdown complete")
    }

    // MARK: - WebSocket Event Stream

    /// Serializes WebSocket frame writes so concurrent events don't interleave bytes.
    private final class WebSocketWriter: @unchecked Sendable {
        private let stream: SocketStream
        private let lock = NSLock()
        private var queue: [[UInt8]] = []
        private var flushing = false
        var isAlive = true

        init(stream: SocketStream) { self.stream = stream }

        func enqueue(_ frame: [UInt8]) {
            lock.lock()
            guard isAlive else { lock.unlock(); return }
            queue.append(frame)
            guard !flushing else { lock.unlock(); return }
            flushing = true
            lock.unlock()
            Task { await flush() }
        }

        private func flush() async {
            while true {
                lock.lock()
                guard !queue.isEmpty else {
                    flushing = false
                    lock.unlock()
                    return
                }
                let frame = queue.removeFirst()
                lock.unlock()
                do {
                    try await stream.write(frame)
                } catch {
                    lock.lock()
                    isAlive = false
                    queue.removeAll()
                    flushing = false
                    lock.unlock()
                    return
                }
            }
        }
    }

    /// Handle a WebSocket connection: subscribe to node events and relay them as JSON text frames.
    private static func handleWebSocket(stream: SocketStream, ctx: NodeContext, logger: Logger) async {
        let writer = WebSocketWriter(stream: stream)

        let subId = ctx.subscribeEvents { json in
            guard writer.isAlive else { return }
            let frame = WebSocket.textFrame(json)
            writer.enqueue(frame)
        }

        defer {
            ctx.unsubscribeEvents(subId)
            writer.isAlive = false
        }

        // Read loop: handle ping/pong/close frames from client
        logger.debug("WebSocket connected", source: "RPC")
        var accumulator = AccumulationBuffer()
        while true {
            do {
                let data = try await stream.read()
                guard !data.isEmpty else {
                    logger.debug("WebSocket EOF", source: "RPC")
                    break
                }
                accumulator.append(data)
            } catch {
                logger.debug("WebSocket read error: \(error)", source: "RPC")
                break
            }

            while let bytes = accumulator.peek(accumulator.readableBytes),
                  let frame = WebSocket.parseFrame(bytes) {
                _ = accumulator.consume(frame.bytesConsumed)
                accumulator.compact()

                switch frame.opcode {
                case 0x08: // Close
                    try? await stream.write(WebSocket.closeFrame())
                    await stream.close()
                    return
                case 0x09: // Ping
                    try? await stream.write(WebSocket.pongFrame(payload: frame.payload))
                default:
                    break // Ignore text/binary from client
                }
            }
        }

        await stream.close()
    }

    /// Handle an SSE connection: subscribe to node events and relay them as `data: {json}\n\n`.
    private static func handleSSE(stream: SocketStream, uri: String, ctx: NodeContext, logger: Logger) async {
        // Parse ?wallet=name from the URI
        var walletFilter: String? = nil
        if let qIdx = uri.firstIndex(of: "?") {
            let query = uri[uri.index(after: qIdx)...]
            for param in query.split(separator: "&") {
                let kv = param.split(separator: "=", maxSplits: 1)
                if kv.count == 2 && kv[0] == "wallet" {
                    walletFilter = String(kv[1])
                }
            }
        }

        // Reuse WebSocketWriter for serialized writes (SSE has no framing, just raw text)
        let writer = WebSocketWriter(stream: stream)

        let subId = ctx.subscribeEvents(wallet: walletFilter) { json in
            guard writer.isAlive else { return }
            writer.enqueue(Array("data: \(json)\n\n".utf8))
        }

        defer {
            ctx.unsubscribeEvents(subId)
            writer.isAlive = false
        }

        // Keep the connection alive by reading until EOF or error.
        // SSE is server→client only; we just need to detect disconnect.
        logger.debug("SSE connected", source: "RPC")
        while true {
            do {
                let data = try await stream.read()
                guard !data.isEmpty else { break }
            } catch {
                break
            }
        }

        await stream.close()
    }

    // MARK: - Internal

    /// Wait for SIGINT, SIGTERM, or RPC stop command.
    private func waitForSignal() async {
        #if os(Windows)
        await withCheckedContinuation { (continuation: CheckedContinuation<Void, Never>) in
            _signalContinuation = continuation
            SetConsoleCtrlHandler(_consoleCtrlHandler, true)
        }
        #elseif os(iOS)
        // On iOS there are no POSIX signals; wait for requestShutdown() from the app.
        await withCheckedContinuation { (continuation: CheckedContinuation<Void, Never>) in
            _signalContinuation = continuation
        }
        #else
        await withCheckedContinuation { (continuation: CheckedContinuation<Void, Never>) in
            _signalContinuation = continuation

            let sigintSource = DispatchSource.makeSignalSource(signal: SIGINT, queue: .main)
            let sigtermSource = DispatchSource.makeSignalSource(signal: SIGTERM, queue: .main)

            // Ignore default signal handling
            signal(SIGINT, SIG_IGN)
            signal(SIGTERM, SIG_IGN)

            var resumed = false
            let resume = {
                guard !resumed else { return }
                resumed = true
                _signalContinuation = nil
                sigintSource.cancel()
                sigtermSource.cancel()
                continuation.resume()
            }

            sigintSource.setEventHandler { resume() }
            sigtermSource.setEventHandler { resume() }

            sigintSource.resume()
            sigtermSource.resume()
        }
        #endif
    }

    /// Trigger a graceful shutdown (called by RPC stop command).
    public func requestShutdown() {
        _signalContinuation?.resume()
        _signalContinuation = nil
    }

    /// Extract a human-readable reason from a bind error.
    private static func describeBindError(_ error: Error) -> String {
        let desc = "\(error)"
        if desc.contains("Address already in use") {
            return "address already in use (is another fbd instance running?)"
        } else if desc.contains("Permission denied") {
            return "permission denied (try a port above 1024)"
        } else {
            return desc
        }
    }

    private func validateConfig() throws {
        // Verify data directory is reasonable
        guard !config.dataDir.isEmpty else {
            throw NodeError.configurationError("Data directory cannot be empty")
        }

        // Verify port ranges
        guard config.maxOutbound >= 0 else {
            throw NodeError.configurationError("maxOutbound must be >= 0")
        }

        // Verify --agent contains only printable ASCII (0x20-0x7E) and fits in
        // the version message (255 bytes max including the /fbd:x.y.z/ prefix).
        if let agent = config.agent {
            let fullAgent = Self.userAgent(suffix: agent)
            for ch in agent.utf8 {
                guard ch >= 0x20, ch <= 0x7E else {
                    throw NodeError.configurationError("--agent contains non-printable character (0x\(String(format: "%02x", ch)))")
                }
            }
            guard fullAgent.utf8.count <= 255 else {
                throw NodeError.configurationError("User agent too long (\(fullAgent.utf8.count) bytes, max 255)")
            }
        }
    }

}

/// The initialized subsystem components.
///
/// Returned by `FullNode.initialize()` for use during the async
/// startup and runtime phases.
public struct NodeComponents: Sendable {
    /// The RPC server configuration.
    public let rpcConfig: RPCConfig
}

extension Double {
    func rounded3() -> Double {
        (self * 1000).rounded() / 1000
    }
}
