import Foundation
import Base
import Chain
import Mempool
import Mining
import Net
import Protocol
import RPC
import Wallet

/// Thread-safe container for live node subsystem references.
///
/// Created before the RPC dispatcher in `FullNode.start()`, then
/// populated as subsystems initialize. RPC handlers capture this
/// object and read state from it.
///
/// Mutable state (`wallets`, `rescanProgress`) is protected by an
/// `NSLock` since it is accessed from NIO event loops, GCD queues
/// (rescan), and the RPC server concurrently.
public final class NodeContext: @unchecked Sendable {
    public var chain: Chain?
    public var peerManager: PeerManager?
    public var chainSync: ChainSync?
    public var coinDB: CoinDatabase?
    public var mempool: Mempool?
    public var auctionIndex: AuctionIndex?

    /// Default miner address from --miner-address (used as fallback in getblocktemplate).
    public var minerAddress: Address?

    /// Total CPU thread count (detected at startup).
    public let cpuCount: Int = ProcessInfo.processInfo.activeProcessorCount

    /// Configured miner thread count (0 = auto).
    public var minerThreads: Int = 0

    /// CPU miner instance (set when mining is enabled).
    public var miner: CPUMiner?

    /// Lock protecting `wallets` and `rescanProgress`.
    private let lock = NSLock()

    private var wallets: [String: WalletDB] = [:]

    /// Per-wallet rescan progress: wallet name → (current block, total blocks).
    /// Non-nil entry means a rescan is in progress.
    private var rescanProgress: [String: (current: Int, total: Int)] = [:]

    // MARK: - Event Stream (WebSocket push)

    /// Connected event stream subscribers: id → (wallet filter, callback).
    /// Callback receives a JSON string to send as an SSE data frame.
    /// If wallet is non-nil, only wallet events matching that name are sent.
    private var eventSubscribers: [UInt64: (wallet: String?, handler: @Sendable (String) -> Void)] = [:]
    private var _nextSubscriberId: UInt64 = 0

    /// Subscribe to node events. Returns an ID for unsubscribing.
    /// If `wallet` is provided, only wallet events for that wallet are delivered.
    @discardableResult
    public func subscribeEvents(wallet: String? = nil, _ handler: @escaping @Sendable (String) -> Void) -> UInt64 {
        lock.lock()
        defer { lock.unlock() }
        _nextSubscriberId += 1
        let id = _nextSubscriberId
        eventSubscribers[id] = (wallet: wallet, handler: handler)
        return id
    }

    /// Unsubscribe from node events.
    public func unsubscribeEvents(_ id: UInt64) {
        lock.lock()
        defer { lock.unlock() }
        eventSubscribers.removeValue(forKey: id)
    }

    /// Broadcast a JSON event string to all subscribers.
    public func emitEvent(_ json: String) {
        let subs: [UInt64: (wallet: String?, handler: @Sendable (String) -> Void)]
        do {
            lock.lock()
            defer { lock.unlock() }
            subs = eventSubscribers
        }
        for (_, sub) in subs {
            sub.handler(json)
        }
    }

    /// Monotonic wallet event counter — bumped on balance-affecting changes.
    private var _walletEventSeq: UInt64 = 0

    /// Static log broadcast hook.  Set by FullNode.start() so that external
    /// log handlers (FBDLogHandler, DirectLogHandler) can push lines to WS
    /// subscribers without holding a reference to a NodeContext instance.
    nonisolated(unsafe) public static var logBroadcast: ((String) -> Void)?

    public init() {}

    // MARK: - Wallet Access (thread-safe)

    /// Look up a wallet by name.
    public func wallet(named name: String) -> WalletDB? {
        lock.lock()
        defer { lock.unlock() }
        return wallets[name]
    }

    /// Get a snapshot of all wallets.
    public func allWallets() -> [String: WalletDB] {
        lock.lock()
        defer { lock.unlock() }
        return wallets
    }

    /// Set or remove a wallet by name.
    public func setWallet(_ name: String, _ wallet: WalletDB?) {
        lock.lock()
        defer { lock.unlock() }
        if let w = wallet {
            wallets[name] = w
        } else {
            wallets.removeValue(forKey: name)
        }
    }

    // MARK: - Rescan Progress (thread-safe)

    /// Get rescan progress for a wallet.
    public func getRescanProgress(_ name: String) -> (current: Int, total: Int)? {
        lock.lock()
        defer { lock.unlock() }
        return rescanProgress[name]
    }

    /// Set or clear rescan progress for a wallet.
    public func setRescanProgress(_ name: String, _ value: (current: Int, total: Int)?) {
        lock.lock()
        defer { lock.unlock() }
        rescanProgress[name] = value
    }

    // MARK: - Wallet Events (WebSocket push)

    /// Signal that a wallet-relevant event occurred (balance change, new tx, etc.).
    public func notifyWalletEvent(wallet: String) {
        let seq: UInt64
        let subs: [UInt64: (wallet: String?, handler: @Sendable (String) -> Void)]
        do {
            lock.lock()
            defer { lock.unlock() }
            _walletEventSeq += 1
            seq = _walletEventSeq
            subs = eventSubscribers
        }
        let json = "{\"type\":\"wallet\",\"seq\":\(seq)}"
        for (_, sub) in subs {
            if sub.wallet == nil || sub.wallet == wallet { sub.handler(json) }
        }
    }

    /// Compute balance and emit a wallet event notification.
    /// Uses the same computeBalance logic as the getbalance RPC handler.
    public func notifyWalletBalance(wallet name: String, _ wallet: WalletDB) {
        guard let balance = try? RPCMethods.computeBalance(wallet: wallet, chain: self.chain) else {
            notifyWalletEvent(wallet: name)
            return
        }
        let balanceJSON = JSONEncoder.encode(balance)
        let seq: UInt64
        let subs: [UInt64: (wallet: String?, handler: @Sendable (String) -> Void)]
        do {
            lock.lock()
            defer { lock.unlock() }
            _walletEventSeq += 1
            seq = _walletEventSeq
            subs = eventSubscribers
        }
        let json = "{\"type\":\"wallet\",\"seq\":\(seq),\"balance\":\(balanceJSON)}"
        for (_, sub) in subs {
            if sub.wallet == nil || sub.wallet == name { sub.handler(json) }
        }
    }

    // MARK: - Log Streaming

    /// Broadcast a log line to WebSocket subscribers.
    public func emitLog(_ line: String) {
        // Escape JSON special characters in the log line
        let escaped = line
            .replacingOccurrences(of: "\\", with: "\\\\")
            .replacingOccurrences(of: "\"", with: "\\\"")
            .replacingOccurrences(of: "\n", with: "\\n")
            .replacingOccurrences(of: "\t", with: "\\t")
        emitEvent("{\"type\":\"log\",\"line\":\"\(escaped)\"}")
    }
}
