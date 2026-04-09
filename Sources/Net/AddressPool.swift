#if os(Windows)
import WinSDK
#elseif canImport(Android)
import Android
#endif
import Foundation
import Base
import ExtCrypto
import Protocol
import Logging

// MARK: - Address Pool Entry

/// A single entry in the address pool.
///
/// Base addressing fields (`host`, `port`, `time`) come from addr-gossip and
/// are always populated. The remaining fields are filled in when we actually
/// handshake with a peer at this address, so they may be zero/empty for
/// addresses we've only heard about but never connected to.
public struct AddressPoolEntry: Codable, Sendable {
    /// IPv4 address as dotted string.
    public var host: String
    /// Listening port.
    public var port: Int
    /// Timestamp (unix seconds) this address was last gossiped to us.
    public var time: UInt64
    /// Timestamp (unix seconds) of our last successful handshake with this
    /// peer. Zero if we've never handshaked with them.
    public var lastSeen: UInt64
    /// User agent string reported at the last handshake. Empty if unknown.
    public var agent: String
    /// Protocol version reported at the last handshake. Zero if unknown.
    public var version: UInt32
    /// Service flags reported at the last handshake.
    public var services: UInt32
    /// Best block height reported at the last handshake.
    public var height: UInt32
}

// MARK: - Address Pool & Outbound Connection Management

extension PeerManager {

    // MARK: - Address Persistence

    /// Load peer addresses from disk.
    ///
    /// New entries are stored as JSON-per-line. A legacy colon-separated
    /// format (`host:port:time`) is still accepted for a one-time upgrade,
    /// with the richer fields defaulted to zero.
    func loadAddressPool() {
        guard let dataDir = config.dataDir else { return }
        let path = dataDir + "/peers.dat"
        guard let data = try? String(contentsOfFile: path, encoding: .utf8) else { return }
        let decoder = JSONDecoder()
        var loaded = 0
        for line in data.split(separator: "\n") {
            guard addressPool.count < Self.maxAddressPool else { break }
            let trimmed = line.trimmingCharacters(in: .whitespaces)
            if trimmed.isEmpty { continue }

            // Preferred: JSON lines.
            if let lineData = trimmed.data(using: .utf8),
               let entry = try? decoder.decode(AddressPoolEntry.self, from: lineData) {
                let key = "\(entry.host):\(entry.port)"
                addressPool[key] = entry
                loaded += 1
                continue
            }

            // Legacy: "host:port:time".
            let parts = trimmed.split(separator: ":")
            guard parts.count >= 3,
                  let port = Int(parts[1]),
                  let time = UInt64(parts[2]) else { continue }
            let host = String(parts[0])
            let key = "\(host):\(port)"
            addressPool[key] = AddressPoolEntry(
                host: host, port: port, time: time,
                lastSeen: 0, agent: "", version: 0, services: 0, height: 0
            )
            loaded += 1
        }
        if loaded > 0 {
            logger.info("Loaded \(loaded) peer addresses from disk", source: "Net")
        }
    }

    /// Save peer addresses to disk atomically as JSON-per-line.
    func saveAddressPool() {
        guard let dataDir = config.dataDir else { return }
        let path = dataDir + "/peers.dat"
        lock.lock()
        let entries = Array(addressPool.values)
        lock.unlock()
        let encoder = JSONEncoder()
        var lines = ""
        for entry in entries {
            guard let data = try? encoder.encode(entry),
                  let json = String(data: data, encoding: .utf8) else { continue }
            lines += json + "\n"
        }
        let tmpPath = path + ".tmp"
        try? lines.write(toFile: tmpPath, atomically: false, encoding: .utf8)
        try? FileManager.default.moveItem(atPath: tmpPath, toPath: path)
    }

    // MARK: - Outbound Connections

    /// Connect to configured outbound nodes and DNS seeds.
    public func startOutboundConnections() {
        loadAddressPool()
        guard config.maxOutbound > 0 else { return }
        let peerList = config.nodes.isEmpty ? config.seeds : config.nodes

        for nodeStr in peerList {
            let parts = nodeStr.split(separator: ":", maxSplits: 2)
            guard parts.count >= 2, let port = Int(parts[1]) else {
                logger.warning("Invalid node address: \(nodeStr)")
                continue
            }
            let host = String(parts[0])

            var remoteKey: [UInt8] = []
            if parts.count >= 3 {
                let hexKey = String(parts[2])
                remoteKey = (try? HexEncoding.decode(hexKey)) ?? []
            }

            // If the host is a hostname (not an IP), resolve all A records
            let hosts: [String]
            if host.first?.isLetter == true {
                let resolved = resolveSeedIPs(host)
                hosts = resolved.isEmpty ? [host] : resolved
            } else {
                hosts = [host]
            }

            for h in hosts {
                configuredNodes.append((host: h, port: port, key: remoteKey))

                if remoteKey.isEmpty {
                    connectPlainOutbound(host: h, port: port)
                } else {
                    connectOutbound(host: h, port: port, remoteKey: remoteKey)
                }
            }
        }

        resolveAndConnectSeeds()
    }

    /// Connect to a specific peer using Brontide encryption.
    public func connectOutbound(host: String, port: Int, remoteKey: [UInt8]) {
        lock.lock()
        dialedAddresses.insert("\(host):\(port)")
        lock.unlock()

        Task {
            do {
                let stream = try await Self.connectTCP(host: host, port: port, timeout: NetConstants.connectTimeout)

                guard let peerContext = self.registerPeer(outbound: true, remoteHost: host, remotePort: port) else {
                    await stream.close()
                    return
                }

                let handshake = try BrontideHandshake(
                    initiator: true,
                    localStatic: self.identityKey,
                    remoteStatic: remoteKey
                )

                let conn = PeerConnection(
                    stream: stream,
                    peerContext: peerContext,
                    network: self.network,
                    handshake: handshake,
                    useBrontide: true,
                    delegate: self,
                    userAgent: self.config.userAgent,
                    logger: self.logger
                )
                peerContext.connection = conn
                conn.start()
            } catch {
                let addr = "\(host):\(port)"
                self.lock.lock()
                self.dialedAddresses.remove(addr)
                let prev = self.failedAddresses[addr]?.count ?? 0
                let newCount = prev + 1
                if newCount >= Self.maxFailCount {
                    self.addressPool.removeValue(forKey: addr)
                    self.failedAddresses.removeValue(forKey: addr)
                } else {
                    let backoff = Self.failCooldownBase * pow(2.0, Double(prev))
                    self.failedAddresses[addr] = (until: Date().timeIntervalSinceReferenceDate + backoff, count: newCount)
                }
                self.lock.unlock()
                self.logger.warning("Connection failed", metadata: [
                    "address": "\(addr)",
                    "error": "\(Self.cleanError(error))",
                ])
            }
        }
    }

    /// Connect to a specific peer using plain TCP (no encryption).
    public func connectPlainOutbound(host: String, port: Int) {
        lock.lock()
        dialedAddresses.insert("\(host):\(port)")
        lock.unlock()

        Task {
            do {
                let stream = try await Self.connectTCP(host: host, port: port, timeout: NetConstants.connectTimeout)

                guard let peerContext = self.registerPeer(outbound: true, remoteHost: host, remotePort: port) else {
                    await stream.close()
                    return
                }

                let conn = PeerConnection(
                    stream: stream,
                    peerContext: peerContext,
                    network: self.network,
                    useBrontide: false,
                    delegate: self,
                    userAgent: self.config.userAgent,
                    logger: self.logger
                )
                peerContext.connection = conn
                conn.start()
            } catch {
                let addr = "\(host):\(port)"
                self.lock.lock()
                self.dialedAddresses.remove(addr)
                let prev = self.failedAddresses[addr]?.count ?? 0
                let newCount = prev + 1
                if newCount >= Self.maxFailCount {
                    self.addressPool.removeValue(forKey: addr)
                    self.failedAddresses.removeValue(forKey: addr)
                } else {
                    let backoff = Self.failCooldownBase * pow(2.0, Double(prev))
                    self.failedAddresses[addr] = (until: Date().timeIntervalSinceReferenceDate + backoff, count: newCount)
                }
                self.lock.unlock()
                self.logger.warning("Connection failed", metadata: [
                    "address": "\(addr)",
                    "error": "\(Self.cleanError(error))",
                ])
            }
        }
    }

    /// GCD queue for blocking connect() calls.
    private static let connectQueue = DispatchQueue.global(qos: .utility)

    /// Connect a TCP socket with a timeout.
    static func connectTCP(host: String, port: Int, timeout: UInt64) async throws -> SocketStream {
        // Use a task group for timeout
        try await withThrowingTaskGroup(of: SocketStream.self) { group in
            group.addTask {
                // Run blocking connect() on GCD to avoid tying up a
                // cooperative thread pool slot.
                try await withCheckedThrowingContinuation { (cont: CheckedContinuation<SocketStream, any Error>) in
                    connectQueue.async {
                        do {
                            let sock = try SocketHandle.tcp()
                            try sock.setNoDelay()
                            try? sock.setKeepalive()
                            try sock.connect(host: host, port: port)
                            cont.resume(returning: SocketStream(handle: sock, remoteAddress: "\(host):\(port)"))
                        } catch {
                            cont.resume(throwing: error)
                        }
                    }
                }
            }
            group.addTask {
                try await Task.sleep(nanoseconds: timeout * 1_000_000)
                throw NetError.timeout("connect timeout")
            }
            let result = try await group.next()!
            group.cancelAll()
            return result
        }
    }

    // MARK: - Outbound Slot Refill

    /// Try to fill outbound peer slots from configured nodes or DNS seeds.
    func refillOutbound() {
        lock.lock()
        let shuttingDown = isShuttingDown
        lock.unlock()
        guard !shuttingDown else { return }
        guard peerCount < config.maxOutbound else { return }

        if !configuredNodes.isEmpty {
            for node in configuredNodes {
                guard peerCount < config.maxOutbound else { return }
                let addr = "\(node.host):\(node.port)"
                lock.lock()
                let alreadyDialed = dialedAddresses.contains(addr)
                let isSelf = selfAddresses.contains(addr)
                lock.unlock()
                guard !alreadyDialed && !isSelf else { continue }
                if node.key.isEmpty {
                    connectPlainOutbound(host: node.host, port: node.port)
                } else {
                    connectOutbound(host: node.host, port: node.port, remoteKey: node.key)
                }
            }
        }

        guard config.nodes.isEmpty else { return }

        let currentOutbound = outboundCount
        guard currentOutbound < config.maxOutbound else { return }
        if !seedAddresses.isEmpty {
            connectNextSeed()
        } else if currentOutbound == 0 {
            // No outbound peers at all — re-resolve DNS seeds
            resolveAndConnectSeeds()
        } else {
            connectFromPool()
        }
    }

    /// Get set of "host:port" strings for currently connected peers.
    func getConnectedAddresses() -> Set<String> {
        lock.lock()
        let peerList = Array(peers.values)
        lock.unlock()
        var addrs = Set<String>()
        for peer in peerList {
            if let ip = peer.state.address.ipv4String {
                addrs.insert("\(ip):\(peer.state.address.port)")
            }
        }
        return addrs
    }

    // MARK: - DNS Seed Resolution

    func resolveAndConnectSeeds() {
        guard config.nodes.isEmpty else { return }
        let seeds = config.network.seeds
        guard !seeds.isEmpty else { return }

        let now = Date().timeIntervalSinceReferenceDate
        guard now - lastDNSResolve >= Self.dnsResolveCooldown else { return }
        lastDNSResolve = now

        let port = config.network.defaultPort
        let configuredAddrs = Set(configuredNodes.map { "\($0.host):\($0.port)" })

        for seed in seeds {
            logger.debug("Resolving DNS seed", metadata: ["seed": "\(seed)"])
            let ips = resolveSeedIPs(seed)
            for ip in ips {
                let addr = "\(ip):\(port)"
                guard !configuredAddrs.contains(addr) else { continue }
                seedAddresses.append((host: ip, port: Int(port)))
            }
        }

        seedAddresses.shuffle()
        refillOutbound()
    }

    func connectNextSeed() {
        lock.lock()
        let shuttingDown = isShuttingDown
        lock.unlock()
        guard !shuttingDown else { return }

        while !seedAddresses.isEmpty {
            guard outboundCount < config.maxOutbound else { return }
            let next = seedAddresses.removeFirst()
            let addr = "\(next.host):\(next.port)"
            lock.lock()
            let alreadyDialed = dialedAddresses.contains(addr)
            let isSelf = selfAddresses.contains(addr)
            let cooldownUntil = failedAddresses[addr]
            lock.unlock()
            guard !alreadyDialed && !isSelf else { continue }
            if let cooldownUntil = cooldownUntil?.until, Date().timeIntervalSinceReferenceDate < cooldownUntil {
                continue
            }
            connectPlainOutbound(host: next.host, port: next.port)
        }
    }

    func connectFromPool() {
        lock.lock()
        let shuttingDown = isShuttingDown
        let poolEntries = Array(addressPool.values)
        lock.unlock()
        guard !shuttingDown else { return }
        guard outboundCount < config.maxOutbound else { return }

        guard !poolEntries.isEmpty else { return }

        for entry in poolEntries.shuffled() {
            guard outboundCount < config.maxOutbound else { break }
            let addr = "\(entry.host):\(entry.port)"
            lock.lock()
            let alreadyDialed = dialedAddresses.contains(addr)
            let isSelf = selfAddresses.contains(addr)
            let cooldownUntil = failedAddresses[addr]
            lock.unlock()
            guard !alreadyDialed && !isSelf else { continue }
            if let cooldownUntil = cooldownUntil?.until, Date().timeIntervalSinceReferenceDate < cooldownUntil {
                continue
            }
            connectPlainOutbound(host: entry.host, port: entry.port)
            break
        }
    }

    /// Resolve a DNS seed hostname to a list of unique IP addresses.
    func resolveSeedIPs(_ hostname: String) -> [String] {
        var hints = addrinfo()
        hints.ai_family = AF_UNSPEC
        #if canImport(Glibc) || canImport(Musl)
        hints.ai_socktype = Int32(SOCK_STREAM.rawValue)
        #else
        hints.ai_socktype = SOCK_STREAM
        #endif
        var result: UnsafeMutablePointer<addrinfo>?

        let status = getaddrinfo(hostname, nil, &hints, &result)
        guard status == 0, let addrList = result else {
            #if os(Windows)
            let errMsg = "getaddrinfo error \(status)"
            #else
            let errMsg = String(cString: gai_strerror(status))
            #endif
            logger.warning("DNS seed resolution failed", metadata: [
                "seed": "\(hostname)",
                "error": "\(errMsg)",
            ])
            return []
        }
        defer { freeaddrinfo(addrList) }

        var seen = Set<String>()
        var ips: [String] = []
        var addr: UnsafeMutablePointer<addrinfo>? = addrList
        while let info = addr {
            defer { addr = info.pointee.ai_next }

            let ip: String
            if info.pointee.ai_family == AF_INET {
                var sa = info.pointee.ai_addr.withMemoryRebound(to: sockaddr_in.self, capacity: 1) { $0.pointee }
                var buf = [CChar](repeating: 0, count: Int(INET_ADDRSTRLEN))
                #if os(Windows)
                inet_ntop(AF_INET, &sa.sin_addr, &buf, Int(INET_ADDRSTRLEN))
                #else
                inet_ntop(AF_INET, &sa.sin_addr, &buf, socklen_t(INET_ADDRSTRLEN))
                #endif
                ip = String(cString: buf)
            } else if info.pointee.ai_family == AF_INET6 {
                var sa = info.pointee.ai_addr.withMemoryRebound(to: sockaddr_in6.self, capacity: 1) { $0.pointee }
                var buf = [CChar](repeating: 0, count: Int(INET6_ADDRSTRLEN))
                #if os(Windows)
                inet_ntop(AF_INET6, &sa.sin6_addr, &buf, Int(INET6_ADDRSTRLEN))
                #else
                inet_ntop(AF_INET6, &sa.sin6_addr, &buf, socklen_t(INET6_ADDRSTRLEN))
                #endif
                ip = String(cString: buf)
            } else {
                continue
            }

            guard !seen.contains(ip) else { continue }
            seen.insert(ip)
            ips.append(ip)
        }

        logger.debug("DNS seed resolved", metadata: [
            "seed": "\(hostname)",
            "addresses": "\(ips.count)",
        ])
        return ips
    }

    // MARK: - Address Gossip

    /// Maximum address pool entries from the same /16 subnet.
    static let maxPerSubnet16 = 10

    /// Extract the /16 subnet prefix from an IPv4 string (e.g., "1.2" from "1.2.3.4").
    static func subnetPrefix16(_ ip: String) -> String {
        let parts = ip.split(separator: ".")
        guard parts.count >= 2 else { return ip }
        return "\(parts[0]).\(parts[1])"
    }

    func handleAddr(_ peer: PeerContext, addresses: [NetAddress]) {
        guard !addresses.isEmpty else { return }

        let connectedAddrs = getConnectedAddresses()
        var added = 0

        lock.lock()
        for addr in addresses {
            guard let ip = addr.ipv4String else { continue }
            let port = addr.port
            guard port > 0 else { continue }
            guard !isPrivateIP(ip) else { continue }
            let addrStr = "\(ip):\(port)"
            guard !connectedAddrs.contains(addrStr) else { continue }
            if addressPool[addrStr] == nil && addressPool.count < Self.maxAddressPool {
                // Enforce /16 subnet diversity to mitigate eclipse attacks
                let subnet = Self.subnetPrefix16(ip)
                let subnetCount = addressPool.values
                    .lazy.filter { Self.subnetPrefix16($0.host) == subnet }.count
                guard subnetCount < Self.maxPerSubnet16 else { continue }
                addressPool[addrStr] = AddressPoolEntry(
                    host: ip, port: Int(port), time: addr.time,
                    lastSeen: 0, agent: "", version: 0, services: 0, height: 0
                )
                added += 1
            }
        }
        let poolSize = addressPool.count
        lock.unlock()

        if added > 0 {
            logger.debug("Added \(added) addresses from peer \(peer.id) (pool: \(poolSize))")
        }

        // Only relay genuinely new addresses (ones we just added to our pool)
        guard added > 0 else { return }
        let toRelay = Array(addresses.prefix(min(added, 10)))
        let relayPkt = AddrPacket(items: toRelay)

        lock.lock()
        let targets = peers.values
            .filter { $0.state.isHandshaked && $0.id != peer.id }
            .shuffled()
            .prefix(2)
        lock.unlock()

        for target in targets {
            target.send(relayPkt)
        }
    }

    func handleGetAddr(_ peer: PeerContext) {
        lock.lock()
        let entries = Array(addressPool.values)
        lock.unlock()

        let toSend = entries.shuffled().prefix(1000)
        let items: [NetAddress] = toSend.map { entry in
            let ipParts = entry.host.split(separator: ".").compactMap { UInt8($0) }
            let ip: [UInt8]
            if ipParts.count == 4 {
                ip = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xFF, 0xFF] + ipParts
            } else {
                ip = [UInt8](repeating: 0, count: 16)
            }
            return NetAddress(time: entry.time, services: entry.services, ip: ip, port: UInt16(entry.port))
        }
        logger.debug("Serving addresses to peer", metadata: [
            "peer": "\(peer.id)",
            "count": "\(items.count)",
        ])
        peer.send(AddrPacket(items: items))
    }

    func isPrivateIP(_ ip: String) -> Bool {
        let parts = ip.split(separator: ".").compactMap { UInt8($0) }
        guard parts.count == 4 else { return true }
        if parts[0] == 10 { return true }
        if parts[0] == 172 && (parts[1] >= 16 && parts[1] <= 31) { return true }
        if parts[0] == 192 && parts[1] == 168 { return true }
        if parts[0] == 127 { return true }
        if parts[0] == 0 { return true }
        return false
    }

}
