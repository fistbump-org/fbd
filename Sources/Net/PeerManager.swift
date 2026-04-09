#if os(Windows)
import WinSDK
#elseif canImport(Android)
import Android
#endif
import Foundation
import Base
import ExtCrypto
import Protocol
import Chain
import Consensus
import Mempool
import Logging

/// Configuration for the peer manager (avoids circular dependency on Node).
public struct PeerManagerConfig: Sendable {
    public let network: NetworkType
    public let maxOutbound: Int
    public let maxInbound: Int
    /// Seed peer addresses — always connect to these, DNS seeds still run.
    public let seeds: [String]
    /// Exclusive peer addresses — connect ONLY to these (no DNS seeds).
    public let nodes: [String]
    /// User agent string for the version message.
    public let userAgent: String
    /// Data directory for persisting peer addresses (nil = no persistence).
    public let dataDir: String?

    public init(network: NetworkType, maxOutbound: Int = 8, maxInbound: Int = 64, seeds: [String] = [], nodes: [String] = [], userAgent: String? = nil, dataDir: String? = nil) {
        self.network = network
        self.maxOutbound = maxOutbound
        self.maxInbound = maxInbound
        self.seeds = seeds
        self.nodes = nodes
        self.userAgent = userAgent ?? NetConstants.userAgent
        self.dataDir = dataDir
    }
}

/// Manages all peer connections, outbound dialing, bans, and periodic tasks.
public final class PeerManager: @unchecked Sendable {

    /// The node's identity private key.
    public let identityKey: PrivateKey

    /// The node's identity public key (compressed).
    public let identityPub: PublicKey

    /// The network type.
    public let network: NetworkType

    /// Peer manager configuration.
    public let config: PeerManagerConfig

    /// Logger.
    let logger: Logger

    /// Connected peers keyed by ID.
    var peers: [UInt64: PeerContext] = [:]

    /// Ban map for misbehaving peers.
    var banMap = BanMap()

    /// The chain index (set after initialization).
    public var chain: Chain?

    /// The chain sync state machine (set after initialization).
    public var chainSync: ChainSync?

    /// Callback invoked when peer count changes (connect or disconnect).
    public var onPeerCountChange: ((Int) -> Void)?

    /// The mempool (set after initialization).
    public var mempool: Mempool?

    /// The UTXO database (set after initialization).
    public var coinDB: CoinDatabase?

    /// Local 8-byte nonce for self-connection detection.
    private let nonce: [UInt8]

    /// Monotonic peer ID counter.
    private var nextPeerId: UInt64 = 1

    /// Lock protecting mutable state (peers, nextPeerId, banMap, dialedAddresses, failedAddresses, etc.).
    let lock = NSLock()

    /// Whether the peer manager is shutting down.
    var isShuttingDown = false

    /// Addresses we've initiated outbound connections to (for dedup).
    var dialedAddresses = Set<String>()

    /// Orphan tx hashes we've already logged (avoid spam from multiple peers).
    private var loggedOrphanTxs = Set<String>()

    /// Addresses that recently failed connection — cooldown until timestamp + failure count.
    var failedAddresses: [String: (until: Double, count: Int)] = [:]

    /// Base cooldown period for failed addresses (seconds). Doubles each failure.
    static let failCooldownBase: Double = 60

    /// After this many consecutive failures, remove the address from the pool entirely.
    static let maxFailCount = 5

    /// Addresses confirmed to be ourselves (via nonce detection). Never connect to these.
    var selfAddresses = Set<String>()

    /// Timestamp of last DNS seed resolution (to avoid tight re-resolve loops).
    var lastDNSResolve: Double = 0

    /// Minimum interval between DNS seed resolutions (seconds).
    static let dnsResolveCooldown: Double = 30

    /// Whether we've already warned about a stale tip in this stale period.
    private var staleTipWarned = false

    /// Periodic task handles.
    private var inactivityTask: Task<Void, Never>?
    private var banCleanupTask: Task<Void, Never>?
    private var mempoolExpiryTask: Task<Void, Never>?
    private var addressSaveTask: Task<Void, Never>?
    private var refillTask: Task<Void, Never>?

    /// Create a PeerManager.
    ///
    /// - Parameters:
    ///   - config: Peer manager configuration.
    ///   - identityKey: The node's identity private key.
    ///   - logger: Logger.
    public init(config: PeerManagerConfig, identityKey: PrivateKey, logger: Logger) throws {
        self.config = config
        self.identityKey = identityKey
        self.identityPub = try ECDSASigner.publicKey(from: identityKey)
        self.network = config.network
        self.logger = logger

        // Generate random nonce
        var nonce = [UInt8](repeating: 0, count: 8)
        for i in 0..<8 { nonce[i] = UInt8.random(in: 0...255) }
        self.nonce = nonce
    }

    // MARK: - Peer Registration

    /// Register a new peer (thread-safe).
    func registerPeer(outbound: Bool, remoteHost: String, remotePort: Int) -> PeerContext? {
        lock.lock()
        defer { lock.unlock() }

        let ip = Self.parseIP(remoteHost)
        let port = UInt16(remotePort)

        // Reject banned IPs
        let now = UInt64(Date().timeIntervalSince1970)
        if banMap.isBanned(ip, now: now) {
            return nil
        }

        // Enforce max inbound limit
        if !outbound {
            let inboundCount = peers.values.filter({ !$0.outbound }).count
            if inboundCount >= config.maxInbound {
                return nil
            }
        }

        let peerId = nextPeerId
        nextPeerId += 1

        let addr = NetAddress(
            time: UInt64(Date().timeIntervalSince1970),
            services: 0,
            ip: ip,
            port: port
        )

        let peerState = PeerState(address: addr, outbound: outbound)
        let peerContext = PeerContext(
            id: peerId,
            state: peerState,
            outbound: outbound
        )
        peers[peerId] = peerContext
        return peerContext
    }

    // MARK: - Connection Creation

    /// Handle an inbound connection from P2PListener.
    public func handleInboundConnection(stream: SocketStream, remoteHost: String, remotePort: Int, useBrontide: Bool = false) {
        guard let peerContext = registerPeer(outbound: false, remoteHost: remoteHost, remotePort: remotePort) else {
            Task { await stream.close() }
            return
        }

        var handshake: BrontideHandshake? = nil
        if useBrontide {
            do {
                handshake = try BrontideHandshake(initiator: false, localStatic: identityKey)
            } catch {
                logger.warning("Failed to create inbound Brontide handshake: \(error)")
                Task { await stream.close() }
                return
            }
        }

        let conn = PeerConnection(
            stream: stream,
            peerContext: peerContext,
            network: network,
            handshake: handshake,
            useBrontide: useBrontide,
            delegate: self,
            userAgent: config.userAgent,
            logger: logger
        )
        peerContext.connection = conn
        conn.start()
    }

    // MARK: - Outbound Connection Management

    /// Resolved seed IPs to try, one at a time.
    var seedAddresses: [(host: String, port: Int)] = []

    /// Parsed configured node addresses for reconnection.
    var configuredNodes: [(host: String, port: Int, key: [UInt8])] = []

    /// Address pool for discovered peers (from addr gossip, enriched with
    /// handshake metadata when we successfully connect).
    var addressPool: [String: AddressPoolEntry] = [:]

    /// Maximum entries in the address pool.
    static let maxAddressPool = 1000

    /// Parse an IP address string into a 16-byte IPv6-mapped address.
    static func parseIP(_ str: String?) -> [UInt8] {
        guard let str = str, !str.isEmpty else {
            return [UInt8](repeating: 0, count: 16)
        }
        // Try dotted IPv4 first
        let parts = str.split(separator: ".")
        if parts.count == 4, let a = UInt8(parts[0]), let b = UInt8(parts[1]),
           let c = UInt8(parts[2]), let d = UInt8(parts[3]) {
            return [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xFF, 0xFF, a, b, c, d]
        }
        // Handle IPv6-mapped IPv4 literals (e.g., "::ffff:1.2.3.4")
        // to produce the same canonical key as a bare "1.2.3.4".
        let lower = str.lowercased()
        if lower.hasPrefix("::ffff:") {
            let v4 = String(str.dropFirst(7))
            let v4Parts = v4.split(separator: ".")
            if v4Parts.count == 4, let a = UInt8(v4Parts[0]), let b = UInt8(v4Parts[1]),
               let c = UInt8(v4Parts[2]), let d = UInt8(v4Parts[3]) {
                return [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xFF, 0xFF, a, b, c, d]
            }
        }
        // Resolve hostname
        var hints = addrinfo()
        hints.ai_family = AF_INET
        #if canImport(Glibc) || canImport(Musl)
        hints.ai_socktype = Int32(SOCK_STREAM.rawValue)
        #else
        hints.ai_socktype = SOCK_STREAM
        #endif
        var result: UnsafeMutablePointer<addrinfo>?
        guard getaddrinfo(str, nil, &hints, &result) == 0, let info = result else {
            return [UInt8](repeating: 0, count: 16)
        }
        defer { freeaddrinfo(info) }
        let sa = info.pointee.ai_addr.withMemoryRebound(to: sockaddr_in.self, capacity: 1) { $0.pointee }
        var inAddr = sa.sin_addr
        let bytes = withUnsafeBytes(of: &inAddr) { Array($0) }
        guard bytes.count >= 4 else { return [UInt8](repeating: 0, count: 16) }
        return [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xFF, 0xFF, bytes[0], bytes[1], bytes[2], bytes[3]]
    }

    // MARK: - Periodic tasks

    /// Start periodic maintenance tasks.
    public func startPeriodicTasks() {
        // Inactivity timeout check every 60 seconds
        inactivityTask = Task { [weak self] in
            while !Task.isCancelled {
                try? await Task.sleep(nanoseconds: 60_000_000_000)
                self?.checkInactivity()
            }
        }

        // Ban map cleanup every 10 minutes
        banCleanupTask = Task { [weak self] in
            while !Task.isCancelled {
                try? await Task.sleep(nanoseconds: 600_000_000_000)
                self?.cleanupBans()
            }
        }

        // Address pool save every 15 minutes
        addressSaveTask = Task { [weak self] in
            while !Task.isCancelled {
                try? await Task.sleep(nanoseconds: 900_000_000_000)
                self?.saveAddressPool()
            }
        }

        // Peer refill every 30 seconds
        refillTask = Task { [weak self] in
            while !Task.isCancelled {
                try? await Task.sleep(nanoseconds: 30_000_000_000)
                self?.refillOutbound()
            }
        }

        // Mempool expiry every 10 minutes
        mempoolExpiryTask = Task { [weak self] in
            while !Task.isCancelled {
                try? await Task.sleep(nanoseconds: 600_000_000_000)
                guard let self = self, let mempool = self.mempool else { continue }
                let evicted = mempool.evictExpired(now: UInt64(Date().timeIntervalSince1970))
                if evicted > 0 {
                    self.logger.info("Evicted \(evicted) expired mempool transactions", source: "Mempool")
                }
            }
        }
    }

    /// Stop periodic tasks.
    public func stopPeriodicTasks() {
        inactivityTask?.cancel()
        inactivityTask = nil
        banCleanupTask?.cancel()
        banCleanupTask = nil
        mempoolExpiryTask?.cancel()
        mempoolExpiryTask = nil
        addressSaveTask?.cancel()
        addressSaveTask = nil
        refillTask?.cancel()
        refillTask = nil
    }

    /// Gracefully shut down the peer manager.
    /// Closes all peers and waits for in-progress operations (e.g. block
    /// processing) to finish so databases can be safely closed afterwards.
    public func shutdown() async {
        lock.lock()
        isShuttingDown = true
        let allPeers = Array(peers.values)
        lock.unlock()

        saveAddressPool()
        stopPeriodicTasks()

        for peer in allPeers {
            peer.close()
        }

        // Wait for all read loops to finish — this ensures any in-progress
        // connectBlock / LevelDB write completes before databases are closed.
        for peer in allPeers {
            await peer.awaitDisconnect()
        }
    }

    private func checkInactivity() {
        lock.lock()
        let peerList = Array(peers.values)
        lock.unlock()

        let now = UInt64(Date().timeIntervalSince1970 * 1000)
        let timeout = NetConstants.inactivityTimeout

        for peer in peerList {
            if peer.state.connectionState != .handshaked {
                // Disconnect peers stuck in pre-handshake state
                let connectedAt = peer.state.connectedAt
                if connectedAt > 0 && (now - connectedAt) > NetConstants.handshakeTimeout {
                    logger.info("Peer \(peer.id) timed out (handshake)")
                    peer.close()
                }
                continue
            }
            let lastActivity = max(peer.state.lastRecv, peer.state.lastSend)
            if lastActivity > 0 && (now - lastActivity) > timeout {
                logger.info("Peer \(peer.id) timed out (inactive)")
                peer.close()
            }
        }

        // Check for compact block timeouts
        chainSync?.checkCompactBlockTimeout()

        // Check for header/block request timeouts
        chainSync?.checkHeaderTimeout()
        chainSync?.checkBlockTimeout()

        // Stale tip detection — request headers once, not every cycle
        if let chain = chain, chainSync?.state == .synced {
            let now = UInt64(Date().timeIntervalSince1970)
            let tipTime = chain.tip.time
            let tipAge = now > tipTime ? now - tipTime : 0
            let handshakedPeers = peerList.filter { $0.state.connectionState == .handshaked }
            if tipAge > 1800 && !handshakedPeers.isEmpty {
                lock.lock()
                let alreadyWarned = staleTipWarned
                staleTipWarned = true
                lock.unlock()
                if !alreadyWarned {
                    logger.warning("Stale tip detected", metadata: [
                        "tip_age": "\(tipAge)s",
                        "height": "\(chain.tip.height)",
                    ])
                    let locator = chain.getLocator()
                    let pkt = GetHeadersPacket(locator: locator)
                    for peer in handshakedPeers {
                        peer.send(pkt)
                    }
                }
            } else if tipAge <= 1800 {
                lock.lock()
                staleTipWarned = false
                lock.unlock()
            }
        }
    }

    private func cleanupBans() {
        lock.lock()
        let now = UInt64(Date().timeIntervalSince1970)
        banMap.cleanup(now: now)
        // Prune expired failed address cooldowns
        let nowD = Date().timeIntervalSinceReferenceDate
        failedAddresses = failedAddresses.filter { $0.value.until > nowD }
        lock.unlock()
    }

    public func clearBans() {
        lock.lock()
        banMap.entries.removeAll()
        lock.unlock()
    }

    /// Immediately check for stale peers and refill outbound connections.
    /// Called when the app returns to foreground after iOS kills networking.
    public func reconnect() {
        checkInactivity()
        refillOutbound()
    }

    // MARK: - Peer access

    /// The number of currently connected peers.
    public var peerCount: Int {
        lock.lock()
        defer { lock.unlock() }
        return peers.count
    }

    /// The number of outbound peers.
    public var outboundCount: Int {
        lock.lock()
        defer { lock.unlock() }
        return peers.values.filter { $0.outbound }.count
    }

    /// Disconnect a peer by ID.
    public func disconnectPeer(id: UInt64) -> Bool {
        lock.lock()
        let peer = peers[id]
        lock.unlock()
        guard let peer = peer else { return false }
        peer.close()
        return true
    }

    /// Disconnect a peer by address string ("host:port").
    public func disconnectPeer(address: String) -> Bool {
        lock.lock()
        let peerList = Array(peers.values)
        lock.unlock()
        for peer in peerList {
            let addr = peer.state.address
            let addrStr = (addr.ipv4String ?? "") + ":\(addr.port)"
            if addrStr == address {
                peer.close()
                return true
            }
        }
        return false
    }

    /// The number of handshaked peers.
    public var handshakedCount: Int {
        lock.lock()
        defer { lock.unlock() }
        return peers.values.filter { $0.state.isHandshaked }.count
    }

    /// The number of entries in the address pool.
    public var addressPoolCount: Int {
        lock.lock()
        defer { lock.unlock() }
        return addressPool.count
    }

    // MARK: - Error formatting

    /// Extract a human-readable message from socket errors.
    public static func cleanError(_ error: Error) -> String {
        let raw = String(describing: error)
        // Check for common socket error patterns
        if raw.contains("Connection refused") { return "Connection refused" }
        if raw.contains("Network is unreachable") { return "Network is unreachable" }
        if raw.contains("Operation timed out") { return "Operation timed out" }
        if raw.contains("Connection reset") { return "Connection reset by peer" }
        return raw
    }
}

// MARK: - PeerMessageDelegate

extension PeerManager: PeerMessageDelegate {

    public func peerDidHandshake(_ peerContext: PeerContext) {
        let addr = peerContext.state.address
        let addrStr = (addr.ipv4String ?? "unknown") + ":\(addr.port)"
        lock.lock()
        failedAddresses.removeValue(forKey: addrStr)
        lock.unlock()
        let count: Int
        lock.lock()
        count = peers.count
        lock.unlock()
        logger.info("Peer \(peerContext.id) connected", metadata: [
            "address": "\(addrStr)",
            "agent": "\(peerContext.state.agent)",
            "height": "\(peerContext.state.height)",
        ])
        onPeerCountChange?(count)
        chainSync?.onPeerHandshake(peerContext)

        // Add peer's routable address to pool (IP from socket + listen port from version)
        let peerListenPort = peerContext.state.listenPort
        if peerListenPort > 0, let ip = addr.ipv4String, !isPrivateIP(ip) {
            let routableAddr = "\(ip):\(peerListenPort)"
            let now = UInt64(Date().timeIntervalSince1970)
            let peerAddr = NetAddress(
                time: now,
                services: peerContext.state.services,
                ip: addr.ip,
                port: peerListenPort
            )
            lock.lock()
            // Always refresh the entry on a successful handshake so the
            // stored agent/version/height/lastSeen reflect the most recent
            // view of this peer. If we're at capacity with no existing
            // entry for this address, skip — we can't evict here.
            let existing = addressPool[routableAddr]
            if existing != nil || addressPool.count < Self.maxAddressPool {
                addressPool[routableAddr] = AddressPoolEntry(
                    host: ip,
                    port: Int(peerListenPort),
                    time: max(now, existing?.time ?? 0),
                    lastSeen: now,
                    agent: peerContext.state.agent,
                    version: peerContext.state.version,
                    services: peerContext.state.services,
                    height: peerContext.state.height
                )
            }
            // Relay the peer's address to up to 2 other peers
            let targets = peers.values
                .filter { $0.state.isHandshaked && $0.id != peerContext.id }
                .shuffled()
                .prefix(2)
            lock.unlock()
            let relayPkt = AddrPacket(items: [peerAddr])
            for target in targets {
                target.send(relayPkt)
            }
        }

        // Request addresses from outbound peers for discovery
        if peerContext.outbound {
            peerContext.send(GetAddrPacket())
        }

        // Request mempool contents so we can repopulate after restart
        peerContext.send(MempoolPacket())

        // Try to fill more outbound slots
        refillOutbound()
    }

    public func peerDidDisconnect(_ peerContext: PeerContext) {
        peerContext.blockServeTask?.cancel()
        peerContext.blockServeTask = nil
        chainSync?.onPeerDisconnect(peerContext)
        let addr = peerContext.state.address
        let addrStr = (addr.ipv4String ?? "") + ":\(addr.port)"
        lock.lock()
        dialedAddresses.remove(addrStr)

        // If the peer was handshaked, snapshot their final state into the
        // address pool so the entry reflects the peer's current (not
        // handshake-time) height/agent and a recent lastSeen. Without this,
        // a peer that ran for hours and then disconnected would still show
        // their handshake-time data forever.
        if peerContext.state.isHandshaked,
           let ip = addr.ipv4String,
           !isPrivateIP(ip),
           peerContext.state.listenPort > 0 {
            let listenPort = Int(peerContext.state.listenPort)
            let routableAddr = "\(ip):\(listenPort)"
            let now = UInt64(Date().timeIntervalSince1970)
            let existing = addressPool[routableAddr]
            addressPool[routableAddr] = AddressPoolEntry(
                host: ip,
                port: listenPort,
                time: max(existing?.time ?? 0, now),
                lastSeen: now,
                agent: peerContext.state.agent,
                version: peerContext.state.version,
                services: peerContext.state.services,
                height: peerContext.state.height
            )
        }

        peers.removeValue(forKey: peerContext.id)
        let remaining = peers.count
        if remaining == 0 {
            nextPeerId = 1
        }
        let shuttingDown = isShuttingDown

        // Re-queue previously handshaked outbound peers for reconnection
        if peerContext.outbound && peerContext.state.isHandshaked,
           let ip = addr.ipv4String {
            let port = peerContext.state.listenPort > 0 ? Int(peerContext.state.listenPort) : Int(addr.port)
            seedAddresses.append((host: ip, port: port))
        }

        // Apply backoff to outbound peers that failed before handshake.
        // After maxFailCount consecutive failures, evict from the pool entirely.
        if peerContext.outbound && !peerContext.state.isHandshaked {
            let prev = failedAddresses[addrStr]?.count ?? 0
            let newCount = prev + 1
            if newCount >= Self.maxFailCount {
                addressPool.removeValue(forKey: addrStr)
                failedAddresses.removeValue(forKey: addrStr)
            } else {
                let backoff = Self.failCooldownBase * pow(2.0, Double(prev))
                failedAddresses[addrStr] = (until: Date().timeIntervalSinceReferenceDate + backoff, count: newCount)
            }
        }

        lock.unlock()
        logger.warning("Peer \(peerContext.id) disconnected", metadata: [
            "remaining": "\(remaining)",
        ])
        onPeerCountChange?(remaining)

        // Retry after a delay
        if !shuttingDown {
            Task { [weak self] in
                try? await Task.sleep(nanoseconds: 5_000_000_000)
                self?.refillOutbound()
            }
        }
    }

    public func peerDidReceiveMessage(_ peerContext: PeerContext, type: PacketType, payload: [UInt8]) {
        switch type {
        case .addr:
            do {
                let pkt = try AddrPacket.decode(from: payload)
                handleAddr(peerContext, addresses: pkt.items)
            } catch {
                logger.debug("Failed to decode addr", metadata: [
                    "peer": "\(peerContext.id)",
                    "error": "\(error)",
                ])
            }
        case .getaddr:
            let now = UInt64(Date().timeIntervalSince1970 * 1000)
            guard now - peerContext.state.lastGetAddrTime >= 30_000 else {
                increasePeerBanScore(peerContext, 5, "getaddr request too frequent")
                break
            }
            peerContext.state.lastGetAddrTime = now
            handleGetAddr(peerContext)
        case .headers:
            do {
                let pkt = try HeadersPacket.decode(from: payload)
                chainSync?.onHeaders(peerContext, headers: pkt.items, proofs: pkt.proofs)
            } catch {
                logger.warning("Failed to decode headers", metadata: [
                    "peer": "\(peerContext.id)",
                    "size": "\(payload.count)",
                    "error": "\(error)",
                ])
                increasePeerBanScore(peerContext, 20, "malformed headers")
            }
        case .inv:
            do {
                let pkt = try InvPacket.decode(from: payload)
                let blockItems = pkt.items.filter { $0.type == .block }
                if !blockItems.isEmpty {
                    chainSync?.onInv(peerContext, items: blockItems)
                }
                let txItems = pkt.items.filter { $0.type == .tx }
                if !txItems.isEmpty {
                    handleTxInv(peerContext, items: txItems)
                }
            } catch {
                logger.warning("Failed to decode inv", metadata: [
                    "peer": "\(peerContext.id)",
                    "error": "\(error)",
                ])
            }
        case .block:
            do {
                var reader = BufferReader(payload)
                let block = try Block.read(from: &reader)
                chainSync?.onBlock(peerContext, block: block)
            } catch {
                logger.warning("Failed to decode block", metadata: [
                    "peer": "\(peerContext.id)",
                    "size": "\(payload.count)",
                    "error": "\(error)",
                ])
                increasePeerBanScore(peerContext, 20, "malformed block")
            }
        case .tx:
            do {
                let pkt = try TxPacket.decode(from: payload)
                handleTx(peerContext, tx: pkt.tx)
            } catch {
                logger.warning("Failed to decode tx", metadata: [
                    "peer": "\(peerContext.id)",
                    "error": "\(error)",
                ])
                increasePeerBanScore(peerContext, 20, "malformed tx")
            }
        case .cmpctblock:
            do {
                let pkt = try CompactBlockPacket.decode(from: payload)
                chainSync?.onCompactBlock(peerContext, data: pkt.data)
            } catch {
                logger.warning("Failed to decode compact block", metadata: [
                    "peer": "\(peerContext.id)",
                    "error": "\(error)",
                ])
            }
        case .getblocktxn:
            do {
                let pkt = try GetBlockTxnPacket.decode(from: payload)
                handleGetBlockTxn(peerContext, hash: pkt.hash, indices: pkt.indices)
            } catch {
                logger.warning("Failed to decode getblocktxn", metadata: [
                    "peer": "\(peerContext.id)",
                    "error": "\(error)",
                ])
            }
        case .blocktxn:
            do {
                let pkt = try BlockTxnPacket.decode(from: payload)
                chainSync?.onBlockTxn(peerContext, hash: pkt.hash, transactions: pkt.transactions)
            } catch {
                logger.warning("Failed to decode blocktxn", metadata: [
                    "peer": "\(peerContext.id)",
                    "error": "\(error)",
                ])
            }
        case .mempool:
            guard let mempool = mempool else { break }
            let now = UInt64(Date().timeIntervalSince1970 * 1000)
            guard now - peerContext.state.lastMempoolTime >= 30_000 else {
                increasePeerBanScore(peerContext, 5, "mempool request too frequent")
                break
            }
            peerContext.state.lastMempoolTime = now
            let items = mempool.map.keys.map { InvItem(type: .tx, hash: $0) }
            let maxInv = NetConstants.maxInv
            for start in stride(from: 0, to: items.count, by: maxInv) {
                let end = min(start + maxInv, items.count)
                let batch = Array(items[start..<end])
                peerContext.send(InvPacket(items: batch))
            }
        case .getdata:
            do {
                let pkt = try GetDataPacket.decode(from: payload)
                handleGetData(peerContext, items: pkt.items)
            } catch {
                logger.warning("Failed to decode getdata", metadata: [
                    "peer": "\(peerContext.id)",
                    "error": "\(error)",
                ])
            }
        case .getheaders:
            // No rate limit on getheaders. Legitimate peers in the middle
            // of fork-convergence across a large mesh send many getheaders
            // in a short window (each orphan announcement from any OTHER
            // peer triggers a getheaders to this one). Both previous
            // strategies were broken:
            //   - Ban-on-exceed → banned legitimate peers during reorgs
            //   - Silent-drop-on-exceed → requester waits forever for a
            //     response that never comes, deadlocking fork discovery
            // Handling a getheaders is cheap (single locator lookup +
            // small response). Just serve every request.
            peerContext.state.lastGetHeadersTime = UInt64(Date().timeIntervalSince1970 * 1000)
            do {
                let pkt = try GetHeadersPacket.decode(from: payload)
                handleGetHeaders(peerContext, locator: pkt.locator, stop: pkt.stop)
            } catch {
                logger.warning("Failed to decode getheaders", metadata: [
                    "peer": "\(peerContext.id)",
                    "error": "\(error)",
                ])
            }
        default:
            break
        }
    }

    public func currentHeight() -> UInt32 {
        guard let chain = chain else { return 0 }
        // Advertise stored block height (not header tip) so peers don't
        // request headers we can't serve with BalloonProofs.
        if chain.hasBlockStore {
            return UInt32(max(0, chain.storedHeight))
        }
        return UInt32(chain.tip.height)
    }

    public func localNonce() -> [UInt8] {
        nonce
    }

    public func localListenPort() -> UInt16 {
        UInt16(config.network.defaultPort)
    }

    public func peerIsSelf(_ peerContext: PeerContext) {
        if let ip = peerContext.state.address.ipv4String {
            let addr = "\(ip):\(config.network.defaultPort)"
            lock.lock()
            selfAddresses.insert(addr)
            lock.unlock()
            logger.debug("Recorded self-address: \(addr)")
        }
    }

    // MARK: - Transaction Handling

    private func handleTx(_ peer: PeerContext, tx: Transaction) {
        guard chainSync?.state == .synced else { return }
        guard let mempool = mempool, let coinDB = coinDB, let chain = chain else { return }

        let txHash = tx.txHash()

        do {
            let entry = try mempool.acceptTransaction(tx, coinDB: coinDB, chainHeight: chain.tip.height, params: chain.params)

            let feeRate = entry.size > 0 ? Int64(entry.fee) * 1000 / Int64(entry.size) : 0
            broadcastTx(txHash: txHash, feeRate: feeRate, from: peer.id)

            logger.debug("Relaying \(txHash.hex)")
        } catch MempoolError.alreadyExists {
            // Silently ignore
        } catch MempoolError.orphanTransaction {
            lock.lock()
            let isNew = loggedOrphanTxs.insert(txHash.hex).inserted
            lock.unlock()
            if isNew {
                logger.debug("Orphan \(txHash.hex)")
            }
        } catch MempoolError.doubleSpend {
            logger.debug("Rejected \(txHash.hex) (double spend)")
            increasePeerBanScore(peer, 100, "double spend tx")
        } catch {
            logger.debug("Rejected \(txHash.hex) error=\(error)")
            increasePeerBanScore(peer, 10, "invalid tx: \(error)")
        }
    }

    private func handleGetData(_ peer: PeerContext, items: [InvItem]) {
        // Serve txs immediately (small).
        var txs = 0
        for item in items where item.type == .tx {
            if let entry = mempool?.get(item.hash) {
                peer.send(TxPacket(tx: entry.tx))
                txs += 1
            }
        }

        // Serialize block serving per peer: queue items and ensure at most one
        // serving Task is running per peer to avoid concurrent disk I/O and
        // duplicate log spam from overlapping getdata requests.
        let blockItems = items.filter { $0.type == .block || $0.type == .compactBlock }
        if !blockItems.isEmpty {
            var shouldSpawn = false
            var queueOverflow = false
            peer.blockServeLock.lock()
            if peer.blockServeQueue.count + blockItems.count > NetConstants.maxBlockRequest {
                queueOverflow = true
            } else {
                peer.blockServeQueue.append(contentsOf: blockItems)
                if !peer.isServingBlocks {
                    peer.isServingBlocks = true
                    shouldSpawn = true
                }
            }
            peer.blockServeLock.unlock()

            if queueOverflow {
                increasePeerBanScore(peer, 20, "getdata block queue overflow")
            }

            if shouldSpawn {
                let chain = self.chain
                let logger = self.logger
                peer.blockServeTask = Task { [weak peer] in
                    defer {
                        peer?.blockServeLock.lock()
                        peer?.isServingBlocks = false
                        peer?.blockServeLock.unlock()
                    }

                    while !Task.isCancelled {
                        guard let peer = peer else { break }

                        // Take the current batch under lock
                        peer.blockServeLock.lock()
                        let batch = peer.blockServeQueue
                        peer.blockServeQueue.removeAll(keepingCapacity: true)
                        peer.blockServeLock.unlock()

                        if batch.isEmpty { break }

                        var blocks = 0
                        var compactBlocks = 0
                        for item in batch {
                            guard !Task.isCancelled else { break }
                            guard let chain = chain else { break }
                            guard let entry = chain.getEntry(hash: item.hash) else { continue }
                            // Only serve blocks on the current best chain.
                            // The block store only holds best-chain blocks, so
                            // loading by height for a fork entry would return
                            // the wrong block (different hash).
                            guard chain.getEntryByHeight(entry.height)?.hash == entry.hash else { continue }
                            guard let block = try? chain.getBlock(height: entry.height) else { continue }

                            switch item.type {
                            case .block:
                                peer.send(BlockPacket(block: block))
                                blocks += 1
                            case .compactBlock:
                                let data = CompactBlockData.fromBlock(block, headerHash: item.hash)
                                peer.send(CompactBlockPacket(data: data))
                                compactBlocks += 1
                            default:
                                break
                            }

                            await Task.yield()
                        }

                        let served = blocks + compactBlocks
                        if served > 0 {
                            var meta: Logger.Metadata = ["peer": "\(peer.id)"]
                            if blocks > 0 { meta["blocks"] = "\(blocks)" }
                            if compactBlocks > 0 { meta["compact"] = "\(compactBlocks)" }
                            logger.debug("Served getdata", metadata: meta)
                        }
                    }
                }
            }
        }

        if txs > 0 {
            logger.debug("Served getdata", metadata: ["peer": "\(peer.id)", "txs": "\(txs)"])
        }
    }

    private func handleGetHeaders(_ peer: PeerContext, locator: [Hash256], stop: Hash256) {
        guard let chain = chain else { return }

        // Find the most recent locator entry that is on OUR best chain.
        // Matching against byHash (any known header, including forks) would
        // pick a fork entry whose height we have, then serve our best-chain
        // header at that height + 1, whose prevBlock the requester doesn't
        // know — producing an orphan loop. Genesis is always on the best
        // chain, so this is guaranteed to find a match.
        var startHeight = 0
        for hash in locator {
            if let entry = chain.getEntry(hash: hash),
               chain.getEntryByHeight(entry.height)?.hash == entry.hash {
                startHeight = entry.height + 1
                break
            }
        }

        var headers = [BlockHeader]()
        var proofs = [BalloonProof]()
        let maxHeaders = NetConstants.maxHeaders
        // Cap the loop at stored height. Headers are serviceable only when
        // we have the full block (for the BalloonProof). During an active
        // reorg or mid-sync, byHeight may be ahead of storedHeight; serving
        // headers we can't prove would either produce a partial response or
        // force the peer to recompute BalloonHash.
        let maxServableHeight = chain.hasBlockStore ? chain.storedHeight : chain.tip.height
        var h = startHeight
        while headers.count < maxHeaders && h <= maxServableHeight {
            guard let entry = chain.getEntryByHeight(h) else { break }
            guard let block = try? chain.getBlock(height: h) else { break }
            headers.append(entry.toHeader())
            proofs.append(block.balloonProof)
            if entry.hash == stop { break }
            h += 1
        }

        if !headers.isEmpty {
            logger.debug("Serving headers to peer", metadata: [
                "peer": "\(peer.id)",
                "count": "\(headers.count)",
                "from": "\(startHeight)",
                "to": "\(startHeight + headers.count - 1)",
            ])
        }
        // Always respond — a silent drop leaves the peer waiting forever
        peer.send(HeadersPacket(items: headers, proofs: proofs))
    }

    private func handleGetBlockTxn(_ peer: PeerContext, hash: Hash256, indices: [UInt32]) {
        guard indices.count <= NetConstants.maxInv else {
            increasePeerBanScore(peer, 20, "getblocktxn too many indices")
            return
        }
        guard let chain = chain else { return }
        guard let entry = chain.getEntry(hash: hash) else {
            logger.debug("getblocktxn for unknown block", metadata: [
                "hash": "\(hash.hex)",
            ])
            return
        }
        // Only serve blocks on the current best chain. Fork entries share
        // heights with best-chain entries but have different hashes; loading
        // by height would return the wrong block.
        guard chain.getEntryByHeight(entry.height)?.hash == entry.hash else {
            logger.debug("getblocktxn for fork block (not on best chain)", metadata: [
                "hash": "\(hash.hex)",
            ])
            return
        }
        guard let block = try? chain.getBlock(height: entry.height) else {
            logger.debug("getblocktxn: block not stored", metadata: [
                "hash": "\(hash.hex)",
            ])
            return
        }

        var txs = [Transaction]()
        for idx in indices {
            if Int(idx) < block.transactions.count {
                txs.append(block.transactions[Int(idx)])
            }
        }

        logger.debug("Serving block txns to peer", metadata: [
            "peer": "\(peer.id)",
            "hash": "\(hash.hex)",
            "count": "\(txs.count)",
        ])
        peer.send(BlockTxnPacket(hash: hash, transactions: txs))
    }

    private func handleTxInv(_ peer: PeerContext, items: [InvItem]) {
        guard chainSync?.state == .synced else { return }
        guard let mempool = mempool else { return }

        let needed = items.filter { !mempool.has($0.hash) }
        guard !needed.isEmpty else { return }

        let request = needed.map { InvItem(type: .tx, hash: $0.hash) }
        peer.send(GetDataPacket(items: request))
    }

    public func broadcastTx(txHash: Hash256, feeRate: Int64 = 0, from senderId: UInt64? = nil) {
        lock.lock()
        let targets = peers.values.filter { $0.state.isHandshaked && $0.id != senderId && $0.state.relay }
        lock.unlock()

        let inv = InvPacket(items: [InvItem(type: .tx, hash: txHash)])
        for peer in targets {
            if peer.state.feeRate > 0 && feeRate < peer.state.feeRate { continue }
            peer.send(inv)
        }
    }

    private func broadcastBlock(hash: Hash256, header: BlockHeader, proof: BalloonProof, fromPeer: UInt64?) {
        lock.lock()
        let targets = peers.values.filter { $0.state.isHandshaked && $0.id != fromPeer }
        lock.unlock()

        var compactData: CompactBlockData?
        let hasCompactPeer = targets.contains { $0.state.compactMode == 1 }
        if hasCompactPeer, let chain = chain,
           let entry = chain.getEntry(hash: hash),
           chain.getEntryByHeight(entry.height)?.hash == entry.hash,
           let block = try? chain.getBlock(height: entry.height) {
            compactData = CompactBlockData.fromBlock(block, headerHash: hash)
        }

        for peer in targets {
            if peer.state.compactMode == 1, let data = compactData {
                peer.send(CompactBlockPacket(data: data))
            } else if peer.state.preferHeaders {
                peer.send(HeadersPacket(items: [header], proofs: [proof]))
            } else {
                peer.send(InvPacket(items: [InvItem(type: .block, hash: hash)]))
            }
        }
    }
}

// MARK: - ChainSyncDelegate

extension PeerManager: ChainSyncDelegate {

    public func syncGetPeer(id: UInt64) -> PeerContext? {
        lock.lock()
        defer { lock.unlock() }
        return peers[id]
    }

    public func syncGetHandshakedPeers() -> [PeerContext] {
        lock.lock()
        defer { lock.unlock() }
        return peers.values.filter { $0.state.isHandshaked }
    }

    /// Return a snapshot of the address pool. Used by the `getaddresspool`
    /// RPC to expose every address we know about along with any handshake
    /// metadata we've collected.
    public func syncGetAddressPool() -> [AddressPoolEntry] {
        lock.lock()
        defer { lock.unlock() }
        return Array(addressPool.values)
    }

    public func syncBanPeer(id: UInt64, reason: String) {
        lock.lock()
        let peer = peers[id]
        lock.unlock()
        guard let peer = peer else { return }
        logger.warning("Banning peer", metadata: [
            "peer": "\(id)",
            "reason": "\(reason)",
        ])
        let now = UInt64(Date().timeIntervalSince1970)
        lock.lock()
        banMap.ban(peer.state.address.ip, now: now)
        lock.unlock()
        peer.close()
    }

    private func increasePeerBanScore(_ peer: PeerContext, _ score: Int, _ reason: String) {
        if peer.state.increaseBanScore(score) {
            logger.warning("Peer banned (score threshold)", metadata: [
                "peer": "\(peer.id)",
                "score": "\(peer.state.banScore)",
                "reason": "\(reason)",
            ])
            let now = UInt64(Date().timeIntervalSince1970)
            lock.lock()
            banMap.ban(peer.state.address.ip, now: now)
            lock.unlock()
            peer.close()
        }
    }

    public func syncDidConnectBlock(hash: Hash256, header: BlockHeader, proof: BalloonProof, fromPeer: UInt64?) {
        lock.lock()
        loggedOrphanTxs.removeAll()
        lock.unlock()
        broadcastBlock(hash: hash, header: header, proof: proof, fromPeer: fromPeer)
    }
}
