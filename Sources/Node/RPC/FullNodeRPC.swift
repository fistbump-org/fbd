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

    // MARK: - RPC Dispatcher

    /// Build the RPC method dispatcher with live state access.
    func buildRPCDispatcher(ctx: NodeContext) -> RPCDispatcher {
        let network = config.network
        let walletsDir = NSString(string: config.networkDataDir).expandingTildeInPath + "/wallets"

        var handlers: [String: RPCDispatcher.Handler] = [:]
        handlers.merge(blockchainRPCHandlers(ctx: ctx, network: network)) { _, new in new }
        handlers.merge(mempoolRPCHandlers(ctx: ctx, network: network)) { _, new in new }
        handlers.merge(miningRPCHandlers(ctx: ctx, network: network)) { _, new in new }
        handlers.merge(networkRPCHandlers(ctx: ctx, network: network)) { _, new in new }
        handlers.merge(nameRPCHandlers(ctx: ctx, network: network, walletsDir: walletsDir)) { _, new in new }
        handlers.merge(walletRPCHandlers(ctx: ctx, network: network, walletsDir: walletsDir)) { _, new in new }
        handlers.merge(htlcRPCHandlers(ctx: ctx, network: network)) { _, new in new }
        handlers.merge(miscRPCHandlers(ctx: ctx, network: network, walletsDir: walletsDir)) { _, new in new }

        return RPCDispatcher(handlers: handlers)
    }
}
