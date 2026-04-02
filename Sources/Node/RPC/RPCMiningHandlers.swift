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

    // MARK: - Mining RPC Handlers

    func miningRPCHandlers(ctx: NodeContext, network: NetworkType) -> [String: RPCDispatcher.Handler] {
        var handlers: [String: RPCDispatcher.Handler] = [:]

        handlers["getmininginfo"] = { _ in
                guard let chain = ctx.chain else {
                    return RPCMethods.getMiningInfo(height: 0, bits: 0, pooledtx: 0, cpuCount: ctx.cpuCount, minerThreads: ctx.minerThreads)
                }

                var totalHashes: UInt64 = 0
                var blocksMined: UInt64 = 0
                var elapsedTime: TimeInterval = 0
                var avgBlockTime: Double? = nil
                var hashRate: Double = 0
                var memoryBandwidth: Double = 0
                var perThreadStats: [(threadID: Int, hashes: UInt64, hashRate: Double)] = []
                var avgHashRatePerThread: Double = 0

                var activeThreads = ctx.minerThreads
                if let miner = ctx.miner {
                    // Use the actual thread count being used by the miner
                    activeThreads = miner.activeThreads

                    let stats = miner.getStats()
                    totalHashes = stats.totalHashes
                    blocksMined = stats.blocksMined
                    elapsedTime = stats.elapsedTime
                    avgBlockTime = stats.avgBlockTime

                    // Get per-thread statistics
                    perThreadStats = miner.getPerThreadStats()

                    // Calculate average hash rate per thread
                    if !perThreadStats.isEmpty {
                        let totalThreadHashRate = perThreadStats.reduce(0.0) { $0 + $1.hashRate }
                        avgHashRatePerThread = totalThreadHashRate / Double(perThreadStats.count)
                    }

                    if elapsedTime > 0 {
                        // Hash rate = hashes per second
                        hashRate = Double(totalHashes) / elapsedTime

                        // Memory bandwidth estimate = (totalHashes * 0.5GB) / elapsedTime
                        // BalloonHash uses 512MB per hash as per specification
                        let totalGBProcessed = Double(totalHashes) * 0.5 // 0.5GB per hash
                        memoryBandwidth = totalGBProcessed / elapsedTime // GB per second
                    }
                }

                return RPCMethods.getMiningInfo(
                    height: chain.height,
                    bits: chain.tip.bits,
                    pooledtx: ctx.mempool?.count ?? 0,
                    cpuCount: ctx.cpuCount,
                    minerThreads: activeThreads,
                    totalHashes: totalHashes,
                    blocksMined: blocksMined,
                    elapsedTime: elapsedTime,
                    hashRate: hashRate,
                    avgBlockTime: avgBlockTime,
                    memoryBandwidth: memoryBandwidth,
                    perThreadStats: perThreadStats,
                    avgHashRatePerThread: avgHashRatePerThread
                )
            }

        handlers["estimatefee"] = { _ in
                return .int(MempoolPolicy.minRelay)
            }

        handlers["getblocktemplate"] = { req in
                let params = req.params
                let (chain, mempool, _) = try Self.requireNode(ctx)

                let address: Address
                if let addrStr = params.first?.stringValue, !addrStr.isEmpty {
                    address = try Address(bech32: addrStr, network: network)
                } else if let minerAddr = ctx.minerAddress {
                    address = minerAddr
                } else {
                    throw RPCError.invalidParams("no address provided and --miner-address not set")
                }

                let tip = chain.tip
                let bits = chain.getNextBits()
                let treeRoot = try chain.getCurrentTreeRoot()
                let time = UInt64(Date().timeIntervalSince1970)

                let template = try BlockAssembler.assemble(
                    tip: tip,
                    mempool: mempool,
                    address: address,
                    treeRoot: treeRoot,
                    time: time,
                    bits: bits
                )

                // Encode coinbase
                var cbWriter = BufferWriter()
                template.coinbase.write(to: &cbWriter)

                // Encode transactions
                let txsJSON: [JSONValue] = template.transactions.map { tx in
                    var writer = BufferWriter()
                    tx.write(to: &writer)
                    let txHash = tx.txHash()
                    let fee = mempool.get(txHash)?.fee ?? 0
                    return .object([
                        ("data", .string(HexEncoding.encode(writer.data))),
                        ("txid", .string(txHash.hex)),
                        ("fee", .int(Int64(fee))),
                    ])
                }

                // Compute target from bits
                let target = Target256.fromCompact(bits)
                let targetHex = HexEncoding.encode(target.bigEndianBytes())

                let cp = ConsensusParams.params(for: network)
                return .object([
                    ("height", .int(Int64(template.height))),
                    ("bits", .int(Int64(bits))),
                    ("prevblockhash", .string(tip.hash.hex)),
                    ("curtime", .int(Int64(time))),
                    ("coinbase", .string(HexEncoding.encode(cbWriter.data))),
                    ("transactions", .array(txsJSON)),
                    ("merkleroot", .string(template.header.merkleRoot.hex)),
                    ("witnessroot", .string(template.header.witnessRoot.hex)),
                    ("treeroot", .string(treeRoot.hex)),
                    ("target", .string(targetHex)),
                    ("fees", .int(template.fees)),
                    ("pow", .object([
                        ("algorithm", .string("balloon")),
                        ("hash", .string("blake2b-256")),
                        ("slots", .int(Int64(cp.balloonSlots))),
                        ("rounds", .int(Int64(cp.balloonRounds))),
                        ("delta", .int(Int64(cp.balloonDelta))),
                        ("proofsamples", .int(Int64(BalloonProof.numSamples))),
                        ("proofsize", .int(Int64(BalloonProof.serializedSize))),
                    ])),
                ])
            }

        handlers["submitblock"] = { req in
                let params = req.params
                let chain = try Self.requireChain(ctx)
                guard let hexStr = params.first?.stringValue, !hexStr.isEmpty else {
                    throw RPCError.invalidParams("expected hex block data")
                }

                let rawBytes = try HexEncoding.decode(hexStr)
                var reader = BufferReader(rawBytes)
                let block = try Block.read(from: &reader)

                let entry = try chain.add(header: block.header, proof: block.balloonProof)
                try chain.connectBlock(block, height: entry.height)
                try chain.flush()
                try chain.flushBlocks()

                // Announce to peers
                ctx.peerManager?.syncDidConnectBlock(
                    hash: entry.hash, header: block.header, proof: block.balloonProof, fromPeer: nil
                )

                return .object([
                    ("hash", .string(entry.hash.hex)),
                    ("height", .int(Int64(entry.height))),
                ])
            }

        // MARK: Generate (regtest/simnet only)

        handlers["generate"] = { [self] req in
                let params = req.params
                let (chain, mempool, _) = try Self.requireNode(ctx)
                guard network == .regtest || network == .simnet else {
                    throw RPCError.invalidParams("generate is only available on regtest/simnet")
                }

                let count = params.first?.intValue.flatMap({ Int($0) }) ?? 1
                guard count > 0, count <= 1000 else {
                    throw RPCError.invalidParams("count must be 1-1000")
                }

                let address: Address
                if let addrStr = params.dropFirst().first?.stringValue, !addrStr.isEmpty {
                    address = try Address(bech32: addrStr, network: network)
                } else if let minerAddr = ctx.minerAddress {
                    address = minerAddr
                } else {
                    throw RPCError.invalidParams("pass address or set --miner-address")
                }

                let consensusParams = ConsensusParams.params(for: network)
                var hashes: [String] = []

                for _ in 0..<count {
                    let tip = chain.tip
                    let bits = chain.getNextBits()
                    let treeRoot = try chain.getCurrentTreeRoot()
                    let time = max(UInt64(Date().timeIntervalSince1970), tip.time + 1)

                    let template = try BlockAssembler.assemble(
                        tip: tip,
                        mempool: mempool,
                        address: address,
                        treeRoot: treeRoot,
                        time: time,
                        bits: bits
                    )

                    // Mine: iterate nonce until PoW passes, then generate proof
                    let th = template.header
                    let target = Target256.fromCompact(bits)
                    var minedHeader: BlockHeader?
                    for nonce in UInt32(0)...UInt32.max {
                        let h = BlockHeader(
                            nonce: nonce, time: th.time, prevBlock: th.prevBlock,
                            treeRoot: th.treeRoot, extraNonce: th.extraNonce,
                            reservedRoot: th.reservedRoot, witnessRoot: th.witnessRoot,
                            merkleRoot: th.merkleRoot, version: th.version, bits: th.bits
                        )
                        let hash = try ProofOfWork.powHash(for: h, params: consensusParams)
                        if Target256(bigEndian: hash.bytes) <= target {
                            minedHeader = h
                            break
                        }
                    }
                    guard let header = minedHeader else {
                        throw RPCError.internalError("failed to mine block")
                    }

                    let (_, proof) = try ProofOfWork.powHashWithProof(
                        for: header, params: consensusParams
                    )
                    let txs = [template.coinbase] + template.transactions
                    let block = Block(header: header, transactions: txs, balloonProof: proof)
                    let entry: ChainEntry
                    do {
                        entry = try chain.add(header: block.header, proof: proof)
                    } catch {
                        throw RPCError.internalError("add header failed: \(error)")
                    }
                    do {
                        try chain.connectBlock(block, height: entry.height)
                    } catch {
                        throw RPCError.internalError("connect block failed at height \(entry.height): \(error)")
                    }

                    ctx.peerManager?.syncDidConnectBlock(
                        hash: entry.hash, header: block.header, proof: proof, fromPeer: nil
                    )

                    self.logger.info("Block \(entry.height) mined", metadata: [
                        "hash": "\(entry.hash.hex)",
                        "txs": "\(block.transactions.count)",
                    ], source: "Mining")

                    hashes.append(entry.hash.hex)
                }

                return .array(hashes.map { .string($0) })
            }

        return handlers
    }
}
