import Foundation
import Base
import Covenants
import Protocol
import Chain
import Consensus
import Wallet

/// Standard RPC method implementations.
///
/// Each method is a static function that takes parameters and node state,
/// returning a `JSONValue`. These are registered with the `RPCDispatcher`.
public enum RPCMethods {

    // MARK: - Blockchain

    /// Get blockchain state info.
    ///
    /// Returns: chain name, block count, best hash, difficulty, etc.
    public static func getBlockchainInfo(
        chain: String,
        blocks: Int,
        headers: Int,
        bestHash: Hash256,
        treeRoot: Hash256,
        bits: UInt32,
        medianTime: UInt64,
        chainwork: String,
        progress: Double,
        softforks: [(String, JSONValue)] = [],
        version: String? = nil
    ) -> JSONValue {
        var fields: [(String, JSONValue)] = [
            ("chain", .string(chain)),
            ("blocks", .int(Int64(blocks))),
            ("headers", .int(Int64(headers))),
            ("bestblockhash", .string(bestHash.hex)),
            ("treeroot", .string(treeRoot.hex)),
            ("difficulty", .double(difficultyFromBits(bits))),
            ("mediantime", .int(Int64(medianTime))),
            ("chainwork", .string(chainwork)),
            ("pruned", .bool(false)),
            ("softforks", .object(softforks)),
            ("verificationprogress", .double(progress)),
        ]
        if let version = version {
            fields.append(("version", .string(version)))
        }
        return .object(fields)
    }

    /// Format a deployment as a softfork JSON entry.
    public static func formatDeployment(_ deployment: Deployment, status: ThresholdState) -> JSONValue {
        .object([
            ("status", .string(status.statusString)),
            ("bit", .int(Int64(deployment.bit))),
            ("startTime", .int(Int64(deployment.startTime))),
            ("timeout", .int(Int64(deployment.timeout))),
        ])
    }

    /// Get the best block hash.
    public static func getBestBlockHash(_ hash: Hash256) -> JSONValue {
        .string(hash.hex)
    }

    /// Get the current block count.
    public static func getBlockCount(_ height: Int) -> JSONValue {
        .int(Int64(height))
    }

    /// Get a block hash by height.
    public static func getBlockHash(_ hash: Hash256) -> JSONValue {
        .string(hash.hex)
    }

    /// Format a block header as JSON.
    public static func formatBlockHeader(entry: ChainEntry) -> JSONValue {
        .object([
            ("hash", .string(entry.hash.hex)),
            ("height", .int(Int64(entry.height))),
            ("version", .int(Int64(entry.version))),
            ("previousblockhash", .string(entry.prevBlock.hex)),
            ("merkleroot", .string(entry.merkleRoot.hex)),
            ("witnessroot", .string(entry.witnessRoot.hex)),
            ("treeroot", .string(entry.treeRoot.hex)),
            ("reservedroot", .string(entry.reservedRoot.hex)),
            ("time", .int(Int64(entry.time))),
            ("bits", .int(Int64(entry.bits))),
            ("nonce", .int(Int64(entry.nonce))),
            ("difficulty", .double(difficultyFromBits(entry.bits))),
        ])
    }

    /// Format a transaction as JSON.
    public static func formatTransaction(_ tx: Transaction, confirmations: Int = 0, network: NetworkType = .main) -> JSONValue {
        let hash = tx.txHash()
        var inputs = [JSONValue]()
        for (i, input) in tx.inputs.enumerated() {
            inputs.append(.object([
                ("prevout", .object([
                    ("hash", .string(input.prevout.hash.hex)),
                    ("index", .int(Int64(input.prevout.index))),
                ])),
                ("sequence", .int(Int64(input.sequence))),
                ("witness", formatWitness(tx.witnesses.count > i ? tx.witnesses[i] : .empty)),
            ]))
        }

        var outputs = [JSONValue]()
        for (i, output) in tx.outputs.enumerated() {
            outputs.append(.object([
                ("value", .int(Int64(output.value))),
                ("n", .int(Int64(i))),
                ("address", .object([
                    ("version", .int(Int64(output.address.version))),
                    ("hash", .string(HexEncoding.encode(output.address.hash))),
                    ("string", .string(output.address.toBech32(network: network))),
                ])),
                ("covenant", .object([
                    ("type", .int(Int64(output.covenant.type.rawValue))),
                    ("action", .string(covenantName(output.covenant.type))),
                    ("items", .array(output.covenant.items.map { .string(HexEncoding.encode($0)) })),
                ])),
            ]))
        }

        return .object([
            ("hash", .string(hash.hex)),
            ("witnessHash", .string(hash.hex)),
            ("size", .int(Int64(tx.serializedSize))),
            ("vsize", .int(Int64(tx.virtualSize))),
            ("version", .int(Int64(tx.version))),
            ("locktime", .int(Int64(tx.locktime))),
            ("inputs", .array(inputs)),
            ("outputs", .array(outputs)),
            ("confirmations", .int(Int64(confirmations))),
        ])
    }

    // MARK: - Mempool

    /// Format mempool info as JSON.
    public static func getMempoolInfo(
        size: Int,
        bytes: Int,
        orphans: Int
    ) -> JSONValue {
        .object([
            ("size", .int(Int64(size))),
            ("bytes", .int(Int64(bytes))),
            ("usage", .int(Int64(bytes))),
            ("orphans", .int(Int64(orphans))),
        ])
    }

    // MARK: - Mining

    /// Format mining info as JSON.
    public static func getMiningInfo(
        height: Int,
        bits: UInt32,
        pooledtx: Int,
        cpuCount: Int = 0,
        minerThreads: Int = 0,
        totalHashes: UInt64 = 0,
        blocksMined: UInt64 = 0,
        elapsedTime: TimeInterval = 0,
        hashRate: Double = 0,
        avgBlockTime: Double? = nil,
        memoryBandwidth: Double = 0,
        perThreadStats: [(threadID: Int, hashes: UInt64, hashRate: Double)] = [],
        avgHashRatePerThread: Double = 0
    ) -> JSONValue {
        var result: [(String, JSONValue)] = [
            ("blocks", .int(Int64(height))),
            ("difficulty", .double(difficultyFromBits(bits))),
            ("pooledtx", .int(Int64(pooledtx))),
            ("cpus", .int(Int64(cpuCount))),
            ("minerThreads", .int(Int64(minerThreads))),
        ]

        // Add mining stats if mining is active (elapsedTime > 0)
        if elapsedTime > 0 {
            result.append(("totalHashes", .int(Int64(totalHashes))))
            result.append(("blocksMined", .int(Int64(blocksMined))))
            result.append(("elapsedTime", .double(elapsedTime))) // seconds
            result.append(("hashRate", .double(hashRate))) // hashes per second (H/s)
            if let avgTime = avgBlockTime {
                result.append(("avgBlockTime", .double(avgTime))) // seconds
            }
            result.append(("memoryBandwidth", .double(memoryBandwidth))) // Effective memory bandwidth: gigabytes of BalloonHash memory processed per second (upper bound estimate based on 512MB per hash)
            // Example: convert to user-friendly display string:
            //   let bw = String(format: "%.2f GB/s", memoryBandwidth)  // "0.50 GB/s", "1.25 GB/s", "4.00 GB/s"
            // Pseudo-code for formatting with appropriate units:
            //   IF memoryBandwidth >= 1.0:        display as "X.XX GB/s"
            //   ELSE IF memoryBandwidth >= 0.001: display as "X.XX MB/s" (multiply by 1024)
            //   ELSE:                             display as "X.XX KB/s" (multiply by 1024*1024)

            // Add per-thread statistics
            if !perThreadStats.isEmpty {
                let threadsArray: [JSONValue] = perThreadStats.map { stat in
                    .object([
                        ("threadID", .int(Int64(stat.threadID))),
                        ("hashes", .int(Int64(stat.hashes))),
                        ("hashRate", .double(stat.hashRate)) // hashes per second (H/s)
                    ])
                }
                result.append(("threads", .array(threadsArray)))

                // Add average hash rate per thread (helps identify thread contention/imbalance)
                result.append(("avgHashRatePerThread", .double(avgHashRatePerThread))) // hashes per second (H/s)
            }
        }

        return .object(result)
    }

    // MARK: - Network

    /// Format network info as JSON.
    public static func getNetworkInfo(
        version: UInt32,
        subversion: String,
        protocolversion: UInt32,
        connections: Int
    ) -> JSONValue {
        .object([
            ("version", .int(Int64(version))),
            ("subversion", .string(subversion)),
            ("protocolversion", .int(Int64(protocolversion))),
            ("localservices", .string("00000001")),
            ("localrelay", .bool(true)),
            ("connections", .int(Int64(connections))),
        ])
    }

    // MARK: - Names

    /// Format name info as JSON.
    public static func formatNameInfo(
        name: String,
        nameHash: NameHash,
        state: String,
        height: Int,
        renewal: Int,
        owner: JSONValue,
        value: Int64,
        highest: Int64
    ) -> JSONValue {
        .object([
            ("name", .string(name)),
            ("nameHash", .string(nameHash.hex)),
            ("state", .string(state)),
            ("height", .int(Int64(height))),
            ("renewal", .int(Int64(renewal))),
            ("owner", owner),
            ("value", .int(value)),
            ("highest", .int(highest)),
        ])
    }

    // MARK: - Balance

    /// Compute the full wallet balance including forfeited coins.
    /// Used by both the getbalance RPC handler and SSE wallet events.
    public static func computeBalance(wallet: WalletDB, chain: Chain?) throws -> JSONValue {
        let bal = try wallet.getDetailedBalance()
        let spendable = bal.unconfirmed - bal.lockedUnconfirmed - bal.immatureCoinbase
        let pending = Int64(bal.unconfirmed) - Int64(bal.confirmed)
        let locked = Int64(bal.lockedUnconfirmed)
        var result: [(String, JSONValue)] = [
            ("spendable", .int(Int64(spendable))),
            ("confirmed", .int(Int64(bal.confirmed))),
        ]
        if pending != 0 {
            result.append(("pending", .int(pending)))
        }
        if bal.immatureCoinbase > 0 {
            result.append(("immature", .int(Int64(bal.immatureCoinbase))))
        }
        // Calculate forfeited coins (unrevealed BIDs and winning REVEALs stuck in expired auctions)
        if let chain = chain {
            let nameParams = NameParams.params(for: chain.network)
            let coins = try wallet.listUnspent()
            var forfeited: UInt64 = 0
            let height = chain.storedHeight
            for coin in coins {
                guard (coin.covenant.type == .bid || coin.covenant.type == .reveal),
                      coin.covenant.items.count >= 1, coin.covenant.items[0].count == 32 else { continue }
                let nh = NameHash(unchecked: coin.covenant.items[0])
                guard let ns = try? chain.getNameState(nameHash: nh) else { continue }

                let isCurrentRound = coin.height >= ns.height
                let isOldRound = coin.height > 0 && coin.height < ns.height
                let expired = ns.isExpired(at: height + 1, params: nameParams)
                let st = ns.state(at: height, params: nameParams)
                let pastReveal = st == .closed || expired

                if coin.covenant.type == .bid {
                    // Unrevealed bid: forfeited if auction is past reveal phase
                    if isCurrentRound && pastReveal {
                        forfeited += coin.value
                    }
                } else if coin.covenant.type == .reveal {
                    if isOldRound {
                        // Stale reveal from a previous auction round
                        forfeited += coin.value
                    } else if expired {
                        // Name expired — all reveals are forfeited
                        forfeited += coin.value
                    } else if st == .closed && !ns.registered && height >= ns.registerDeadlineHeight(params: nameParams) {
                        // Register deadline passed without registration — all reveals forfeited
                        forfeited += coin.value
                    }
                }
            }
            let activeLocked = locked - Int64(forfeited)
            if activeLocked > 0 {
                result.append(("locked", .int(activeLocked)))
            }
            if forfeited > 0 {
                result.append(("forfeited", .int(Int64(forfeited))))
            }
        } else {
            if locked > 0 {
                result.append(("locked", .int(locked)))
            }
        }
        return .object(result)
    }

    // MARK: - Helpers

    /// Convert compact bits to a floating-point difficulty.
    ///
    /// Uses the Bitcoin/hsd convention: difficulty = 0xFFFF / mantissa,
    /// scaled by 256^(29 - exponent). This matches hsd's getDifficulty().
    public static func difficultyFromBits(_ bits: UInt32) -> Double {
        var shift = Int((bits >> 24) & 0xFF)
        let mantissa = bits & 0x00FFFFFF
        guard mantissa > 0 else { return 0 }

        var diff = Double(0x0000FFFF) / Double(mantissa)

        while shift < 29 {
            diff *= 256.0
            shift += 1
        }
        while shift > 29 {
            diff /= 256.0
            shift -= 1
        }

        return diff
    }

    /// Format witness items as JSON.
    private static func formatWitness(_ witness: Witness) -> JSONValue {
        .array(witness.items.map { .string(HexEncoding.encode($0)) })
    }

    /// Get the string name for a covenant type.
    private static func covenantName(_ type: CovenantType) -> String {
        type.name
    }
}
