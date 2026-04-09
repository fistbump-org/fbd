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

extension FullNode {

    // MARK: - Network RPC Handlers

    func networkRPCHandlers(ctx: NodeContext, network: NetworkType) -> [String: RPCDispatcher.Handler] {
        var handlers: [String: RPCDispatcher.Handler] = [:]

        handlers["getnetworkinfo"] = { [self] _ in
                let connections = ctx.peerManager?.handshakedCount ?? 0
                return RPCMethods.getNetworkInfo(
                    version: Constants.protocolVersion,
                    subversion: FullNode.userAgent(suffix: self.config.agent),
                    protocolversion: Constants.protocolVersion,
                    connections: connections
                )
            }

        handlers["getpeerinfo"] = { _ in
                guard let pm = ctx.peerManager else { return .array([]) }
                let peers = pm.syncGetHandshakedPeers()
                let result: [JSONValue] = peers.map { peer in
                    let state = peer.state
                    let addr = state.address
                    let addrStr = (addr.ipv4String ?? "::") + ":\(addr.port)"
                    // Decode service flags
                    var names: [JSONValue] = []
                    if state.services & 1 != 0 { names.append(.string("NETWORK")) }
                    if state.services & 2 != 0 { names.append(.string("BLOOM")) }

                    return .object([
                        ("id", .int(Int64(peer.id))),
                        ("addr", .string(addrStr)),
                        ("services", .string(String(format: "%08x", state.services))),
                        ("servicenames", .array(names)),
                        ("relaytxes", .bool(state.relay)),
                        ("lastsend", .int(Int64(state.lastSend / 1000))),
                        ("lastrecv", .int(Int64(state.lastRecv / 1000))),
                        ("conntime", .int(Int64(addr.time))),
                        ("pingtime", .double(state.lastPing == UInt64.max ? -1 : (Double(state.lastPing) / 1000.0).rounded3())),
                        ("minping", .double(state.minPing == UInt64.max ? -1 : (Double(state.minPing) / 1000.0).rounded3())),
                        ("version", .int(Int64(state.version))),
                        ("subver", .string(state.agent)),
                        ("inbound", .bool(!peer.outbound)),
                        ("startingheight", .int(Int64(state.height))),
                        ("banscore", .int(Int64(state.banScore))),
                    ])
                }
                return .array(result)
            }

        handlers["getaddresspool"] = { _ in
                guard let pm = ctx.peerManager else { return .array([]) }
                let poolEntries = pm.syncGetAddressPool()
                let handshakedPeers = pm.syncGetHandshakedPeers()
                let now = UInt64(Date().timeIntervalSince1970)

                // Start from the stored pool (historical + gossip) keyed by
                // routable address.
                var merged: [String: AddressPoolEntry] = [:]
                for entry in poolEntries {
                    merged["\(entry.host):\(entry.port)"] = entry
                }

                // Overlay live state for currently-connected peers. Their
                // state.height is kept fresh by ChainSync as headers/blocks
                // arrive, so this reflects the peer's actual current tip
                // instead of whatever they reported at handshake time.
                // Also re-stamps lastSeen to now for connected peers.
                for peer in handshakedPeers {
                    let s = peer.state
                    guard let ip = s.address.ipv4String, s.listenPort > 0 else { continue }
                    let key = "\(ip):\(Int(s.listenPort))"
                    let existing = merged[key]
                    merged[key] = AddressPoolEntry(
                        host: ip,
                        port: Int(s.listenPort),
                        time: max(existing?.time ?? 0, now),
                        lastSeen: now,
                        agent: s.agent,
                        version: s.version,
                        services: s.services,
                        height: s.height
                    )
                }

                let result: [JSONValue] = merged.values.map { entry in
                    return .object([
                        ("host", .string(entry.host)),
                        ("port", .int(Int64(entry.port))),
                        ("addr", .string("\(entry.host):\(entry.port)")),
                        ("time", .int(Int64(entry.time))),
                        ("lastSeen", .int(Int64(entry.lastSeen))),
                        ("agent", .string(entry.agent)),
                        ("version", .int(Int64(entry.version))),
                        ("services", .string(String(format: "%08x", entry.services))),
                        ("height", .int(Int64(entry.height))),
                    ])
                }
                return .array(result)
            }

        handlers["addnode"] = { req in
                let params = req.params
                guard let pm = ctx.peerManager else {
                    throw RPCError.internalError("node not ready")
                }
                guard let addrStr = params.first?.stringValue, !addrStr.isEmpty else {
                    throw RPCError.invalidParams("expected host:port")
                }
                let parts = addrStr.split(separator: ":")
                guard parts.count >= 2, let port = Int(parts[1]) else {
                    throw RPCError.invalidParams("expected host:port format")
                }
                let host = String(parts[0])
                pm.connectPlainOutbound(host: host, port: port)
                return .bool(true)
            }

        handlers["disconnectnode"] = { req in
                let params = req.params
                guard let pm = ctx.peerManager else {
                    throw RPCError.internalError("node not ready")
                }
                guard let param = params.first else {
                    throw RPCError.invalidParams("expected peer id or host:port")
                }

                // Try as numeric peer ID first
                if let peerId = param.intValue {
                    guard pm.disconnectPeer(id: UInt64(peerId)) else {
                        throw RPCError.invalidParams("peer not found: \(peerId)")
                    }
                    return .bool(true)
                }

                // Try as host:port string
                if let addrStr = param.stringValue, addrStr.contains(":") {
                    guard pm.disconnectPeer(address: addrStr) else {
                        throw RPCError.invalidParams("peer not found: \(addrStr)")
                    }
                    return .bool(true)
                }

                throw RPCError.invalidParams("expected peer id or host:port")
            }

        handlers["clearbans"] = { _ in
                guard let pm = ctx.peerManager else {
                    throw RPCError.internalError("node not ready")
                }
                pm.clearBans()
                return .bool(true)
            }

        handlers["reconnect"] = { _ in
                guard let pm = ctx.peerManager else {
                    throw RPCError.internalError("peer manager not ready")
                }
                pm.reconnect()
                return .bool(true)
            }

        return handlers
    }
}
