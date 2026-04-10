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

    // MARK: - Wallet RPC Handlers

    func walletRPCHandlers(ctx: NodeContext, network: NetworkType, walletsDir: String) -> [String: RPCDispatcher.Handler] {
        let logger = self.logger
        var handlers: [String: RPCDispatcher.Handler] = [:]

        handlers["listwallets"] = { _ in
                let names = ctx.allWallets().keys.sorted()
                return .array(names.map { .string($0) })
            }

        handlers["createwallet"] = { req in
                let params = req.params
                guard let name = params.first?.stringValue, !name.isEmpty else {
                    throw RPCError.invalidParams("expected wallet name")
                }
                try Self.rpcValidateWalletName(name)
                guard ctx.wallet(named: name) == nil else {
                    throw RPCError.invalidParams("wallet already exists: \(name)")
                }
                let walletPath = walletsDir + "/\(name)"
                let wallet = try WalletDB(path: walletPath, network: network)

                let importKey = params.count > 1 ? params[1].stringValue : nil

                // Detect xpriv import vs mnemonic
                let isXpriv = importKey?.hasPrefix("xprv") == true
                if isXpriv {
                    try wallet.importXpriv(importKey!)
                } else {
                    _ = try wallet.create(mnemonic: importKey)
                }

                // Set scan height to current tip so startup doesn't auto-rescan.
                // User can manually rescanwallet if they need historical txs.
                if let chain = ctx.chain, chain.storedHeight >= 0 {
                    try wallet.setScanHeight(chain.storedHeight)
                }

                ctx.setWallet(name, wallet)

                var result: [(String, JSONValue)] = [
                    ("name", .string(name)),
                    ("addresses", .int(Int64(wallet.addressCount))),
                ]
                if isXpriv {
                    result.insert(("imported", .string("xpriv")), at: 1)
                } else if importKey != nil {
                    result.insert(("imported", .string("mnemonic")), at: 1)
                } else {
                    result.insert(("mnemonic", .string(wallet.mnemonic ?? "")), at: 1)
                }
                return .object(result)
            }

        handlers["getwalletinfo"] = { req in
                let (name, wallet, _) = try Self.rpcResolveWallet(req, ctx: ctx)
                guard wallet.initialized else {
                    return .object([("name", .string(name)), ("initialized", .bool(false))])
                }
                let bal = try wallet.getDetailedBalance()
                let spendable = bal.unconfirmed - bal.lockedUnconfirmed - bal.immatureCoinbase
                let primary = wallet.primaryAddress?.toBech32(network: network)
                var result: [(String, JSONValue)] = [
                    ("name", .string(name)),
                    ("initialized", .bool(true)),
                    ("type", .string(wallet.walletType == .multisig ? "multisig" : "regular")),
                    ("address", primary.map { .string($0) } ?? .null),
                    ("xpub", wallet.xpub.map { .string($0) } ?? .null),
                    ("addresses", .int(Int64(wallet.addressCount))),
                    ("scanHeight", .int(Int64(wallet.scanHeight))),
                    ("balance", .int(Int64(bal.unconfirmed))),
                    ("spendable", .int(Int64(spendable))),
                ]
                if wallet.walletType == .multisig {
                    result.append(("m", .int(Int64(wallet.multisigM))))
                    result.append(("n", .int(Int64(wallet.cosignerXpubs.count + 1))))
                    result.append(("cosignerXpubs", .array(wallet.cosignerXpubs.map { .string($0) })))
                }
                result.append(("encrypted", .bool(wallet.isEncrypted)))
                result.append(("unlocked", .bool(wallet.isUnlocked)))
                return .object(result)
            }

        // Dedicated RPC for retrieving the seed phrase.
        // Requires the wallet to be unlocked (or unencrypted).
        handlers["getwalletsecret"] = { req in
                let (_, wallet, _) = try Self.rpcResolveWallet(req, ctx: ctx)
                guard wallet.initialized else {
                    throw RPCError.internalError("wallet not initialized")
                }
                wallet.checkAutoLock()
                guard wallet.isUnlocked else {
                    throw RPCError.internalError("wallet is locked; call walletpassphrase first")
                }
                var result: [(String, JSONValue)] = []
                if let mnemonic = wallet.mnemonic {
                    result.append(("mnemonic", .string(mnemonic)))
                }
                if let xpriv = wallet.xpriv {
                    result.append(("xpriv", .string(xpriv)))
                }
                return .object(result)
            }

        handlers["encryptwallet"] = { req in
                let (_, wallet, rest) = try Self.rpcResolveWallet(req, ctx: ctx)
                guard wallet.initialized else {
                    throw RPCError.internalError("wallet not initialized")
                }
                guard let passphrase = rest.first?.stringValue, !passphrase.isEmpty else {
                    throw RPCError.invalidParams("encryptwallet <passphrase>")
                }
                try wallet.encryptWallet(passphrase: passphrase)
                return .string("wallet encrypted successfully")
            }

        handlers["walletpassphrase"] = { req in
                let (name, wallet, rest) = try Self.rpcResolveWallet(req, ctx: ctx)
                guard wallet.initialized else {
                    throw RPCError.internalError("wallet not initialized")
                }
                guard let passphrase = rest.first?.stringValue, !passphrase.isEmpty else {
                    throw RPCError.invalidParams("walletpassphrase <passphrase> [timeout=300]")
                }
                let timeout: Int
                if rest.count >= 2, let t = rest[1].intValue {
                    timeout = Int(t)
                } else {
                    timeout = 300
                }
                do {
                    try wallet.unlockWallet(passphrase: passphrase, timeout: timeout)
                    logger.info("Wallet unlocked", metadata: ["wallet": "\(name)", "timeout": "\(timeout)"], source: "Wallet")
                    return .string("wallet unlocked for \(timeout) seconds")
                } catch {
                    logger.warning("Unlock failed", metadata: [
                        "wallet": "\(name)",
                        "error": "\(error)",
                    ], source: "Wallet")
                    throw error
                }
            }

        handlers["walletlock"] = { req in
                let (_, wallet, _) = try Self.rpcResolveWallet(req, ctx: ctx)
                guard wallet.initialized else {
                    throw RPCError.internalError("wallet not initialized")
                }
                try wallet.lockWallet()
                return .string("wallet locked")
            }

        handlers["getbalance"] = { req in
                let (_, wallet, rest) = try Self.rpcResolveWallet(req, ctx: ctx)
                guard wallet.initialized else {
                    throw RPCError.internalError("wallet not initialized (call createwallet first)")
                }
                if let addrStr = rest.first?.stringValue, !addrStr.isEmpty {
                    let addr = try Address(bech32: addrStr, network: network)
                    let balance = try wallet.getBalance(address: addr)
                    return .int(Int64(balance))
                }
                return try RPCMethods.computeBalance(wallet: wallet, chain: ctx.chain)
            }

        handlers["getnewaddress"] = { req in
                let (_, wallet, _) = try Self.rpcResolveWallet(req, ctx: ctx)
                guard wallet.initialized else {
                    throw RPCError.internalError("wallet not initialized (call createwallet first)")
                }
                let addr = try wallet.advanceReceiveAddress()
                return .string(addr.toBech32(network: network))
            }

        handlers["getchangeaddress"] = { req in
                let (_, wallet, _) = try Self.rpcResolveWallet(req, ctx: ctx)
                guard wallet.initialized else {
                    throw RPCError.internalError("wallet not initialized (call createwallet first)")
                }
                let addr = try wallet.advanceChangeAddress()
                return .string(addr.toBech32(network: network))
            }

        handlers["listunspent"] = { req in
                let (_, wallet, _) = try Self.rpcResolveWallet(req, ctx: ctx)
                guard wallet.initialized else { throw RPCError.internalError("wallet not initialized (call createwallet first)") }
                let chain = try Self.requireChain(ctx)
                let currentHeight = chain.height
                let coins = try wallet.listUnspent()
                let result: [JSONValue] = coins.map { coin in
                    let confirmations = coin.height < 0 ? 0 : currentHeight - coin.height + 1
                    return .object([
                        ("txid", .string(coin.outpoint.hash.hex)),
                        ("vout", .int(Int64(coin.outpoint.index))),
                        ("address", .string(coin.address.toBech32(network: network))),
                        ("value", .int(Int64(coin.value))),
                        ("confirmations", .int(Int64(confirmations))),
                        ("coinbase", .bool(coin.coinbase)),
                        ("height", .int(Int64(coin.height))),
                    ])
                }
                return .array(result)
            }

        handlers["listaddresses"] = { req in
                let (_, wallet, _) = try Self.rpcResolveWallet(req, ctx: ctx)
                guard wallet.initialized else {
                    throw RPCError.internalError("wallet not initialized (call createwallet first)")
                }
                let addrs = try wallet.listAddresses()
                let result: [JSONValue] = addrs.map { entry in
                    .object([
                        ("address", .string(entry.address.toBech32(network: network))),
                        ("path", .string(entry.path)),
                        ("balance", .int(Int64(entry.balance))),
                        ("used", .bool(entry.balance > 0)),
                    ])
                }
                return .array(result)
            }

        handlers["listtransactions"] = { req in
                let (_, wallet, rest) = try Self.rpcResolveWallet(req, ctx: ctx)
                guard wallet.initialized else { throw RPCError.internalError("wallet not initialized (call createwallet first)") }
                let chain = try Self.requireChain(ctx)
                let count = max(0, min(rest.first?.intValue.map { Int($0) } ?? 10, 10_000))
                let offset = max(0, rest.count >= 2 ? (rest[1].intValue.map { Int($0) } ?? 0) : 0)
                let currentHeight = chain.height
                var records = try wallet.listTransactions(count: count, offset: offset)
                // Mempool txs (height < 0) sort by txHash in DB; re-sort by timestamp (newest first)
                let mempoolStart = records.firstIndex { $0.height < 0 } ?? records.count
                let mempoolEnd = records.count
                if mempoolStart < mempoolEnd {
                    records[mempoolStart..<mempoolEnd].sort { $0.timestamp > $1.timestamp }
                }
                let result: [JSONValue] = records.map { record in
                    let confirmations: Int
                    if record.height < 0 {
                        confirmations = 0
                    } else {
                        confirmations = currentHeight - Int(record.height) + 1
                    }
                    let net = Int64(record.received) - Int64(record.sent)

                    // Determine tx type by checking output ownership
                    let hasNameCov = record.covenantTypes & ~(1 << CovenantType.none.rawValue) != 0
                    let txType: String
                    if hasNameCov && record.sent > 0 {
                        txType = "covenant"
                    } else if record.sent > 0 {
                        // Check if all outputs go to our wallet (self-send vs send)
                        var allOutputsOurs = true
                        // Find the tx: mempool or confirmed block
                        let tx: Transaction? = {
                            if record.height < 0 {
                                return ctx.mempool?.get(record.txHash)?.tx
                            } else if let block = try? chain.getBlock(height: Int(record.height)) {
                                return block.transactions.first { $0.txHash() == record.txHash }
                            }
                            return nil
                        }()
                        if let tx = tx {
                            for output in tx.outputs {
                                if !wallet.ismine(output.address) {
                                    allOutputsOurs = false
                                    break
                                }
                            }
                        }
                        txType = allOutputsOurs && tx != nil ? "self" : "send"
                    } else {
                        txType = "receive"
                    }

                    // Decode covenant bitmask to type+name pairs
                    var covEntries = [JSONValue]()
                    let hasNameCovs = record.covenantTypes & ~(1 << CovenantType.none.rawValue) != 0

                    if hasNameCovs {
                        // Look up the actual transaction to get covenant names
                        let lookupTx: Transaction? = {
                            if record.height >= 0 {
                                if let block = try? chain.getBlock(height: Int(record.height)) {
                                    return block.transactions.first { $0.txHash() == record.txHash }
                                }
                            } else {
                                return ctx.mempool?.get(record.txHash)?.tx
                            }
                            return nil
                        }()
                        if let tx = lookupTx {
                            for output in tx.outputs {
                                let ct = output.covenant.type
                                if ct == .none { continue }
                                let action = "\(ct)".uppercased()
                                var name: String? = nil
                                if !output.covenant.items.isEmpty {
                                    if (ct == .open || ct == .bid) && output.covenant.items.count >= 3 {
                                        name = String(bytes: output.covenant.items[2], encoding: .utf8)
                                    } else {
                                        let nhBytes = output.covenant.items[0]
                                        if nhBytes.count == 32 {
                                            if let ns = try? chain.getNameState(nameHash: NameHash(unchecked: nhBytes)) {
                                                name = String(bytes: ns.name, encoding: .utf8)
                                            }
                                        }
                                    }
                                }
                                let label = name != nil ? "\(action) \(name!)" : action
                                let entry: JSONValue = .string(label)
                                if !covEntries.contains(entry) {
                                    covEntries.append(entry)
                                }
                            }
                        }
                    }

                    // Fallback: just type names if block lookup failed
                    if covEntries.isEmpty {
                        for ct in CovenantType.allCases {
                            if record.covenantTypes & (1 << ct.rawValue) != 0 && ct != .none {
                                covEntries.append(.string("\(ct)".uppercased()))
                            }
                        }
                    }

                    return .object([
                        ("txid", .string(record.txHash.hex)),
                        ("type", .string(txType)),
                        ("height", .int(Int64(record.height))),
                        ("confirmations", .int(Int64(confirmations))),
                        ("sent", .int(Int64(record.sent))),
                        ("received", .int(Int64(record.received))),
                        ("net", .int(net)),
                        ("fee", .int(Int64(record.fee))),
                        ("timestamp", .int(Int64(record.timestamp))),
                        ("covenants", .array(covEntries)),
                        ("coinbase", .bool(record.coinbase)),
                    ])
                }
                return .array(result)
            }

        handlers["sendnone"] = { req in
                let (_, wallet, rest, chain, mempool, coinDB) = try Self.requireWalletAndNode(req, ctx: ctx)

                guard let addrStr = rest.first?.stringValue, !addrStr.isEmpty else {
                    throw RPCError.invalidParams("expected destination address")
                }
                let destination = try Address(bech32: addrStr, network: network)

                guard rest.count >= 2, let amountFBD = rest[1].doubleValue, amountFBD > 0 else {
                    throw RPCError.invalidParams("expected positive amount (FBC)")
                }
                let amount = UInt64(amountFBD * 1_000_000)

                let subtractFee = rest.count >= 3 && rest[2].boolValue == true

                let tx = try wallet.createTransaction(
                    destination: destination,
                    amount: amount,
                    currentHeight: chain.height,
                    subtractFee: subtractFee
                )
                let txHash = tx.txHash()

                try mempool.acceptTransaction(tx, coinDB: coinDB, chainHeight: chain.tip.height, params: chain.params)

                ctx.peerManager?.broadcastTx(txHash: txHash)

                return .object([("txid", .string(txHash.hex))])
            }

        handlers["deletewallet"] = { req in
                let (name, _, _) = try Self.rpcResolveWallet(req, ctx: ctx)
                // Remove from ctx -- stops rescan loop and prevents onBlockConnected access.
                // Don't call wallet.close() here; deinit handles it once all
                // references (rescan loop, onBlockConnected) are released.
                ctx.setWallet(name, nil)
                ctx.setRescanProgress(name, nil)
                let walletPath = walletsDir + "/\(name)"
                try? FileManager.default.removeItem(atPath: walletPath)
                return .bool(true)
            }

        handlers["rescanwallet"] = { req in
                let (name, wallet, rest) = try Self.rpcResolveWallet(req, ctx: ctx)
                guard wallet.initialized else { throw RPCError.internalError("wallet not initialized") }
                let chain = try Self.requireChain(ctx)
                guard ctx.getRescanProgress(name) == nil else {
                    throw RPCError.internalError("rescan already in progress for wallet '\(name)'")
                }

                let fromHeight: Int
                if let h = rest.first?.intValue {
                    fromHeight = max(Int(h), 0)
                } else {
                    fromHeight = 0
                }
                let toHeight = chain.storedHeight
                guard toHeight >= fromHeight else {
                    return .object([
                        ("started", .bool(false)),
                        ("reason", .string("no blocks to scan")),
                    ])
                }

                if fromHeight == 0 {
                    try wallet.resetForRescan()
                } else {
                    try wallet.setScanHeight(fromHeight - 1)
                }

                let total = toHeight - fromHeight + 1
                ctx.setRescanProgress(name, (current: 0, total: total))

                logger.info("Wallet rescan starting from=\(fromHeight) to=\(toHeight) wallet=\(name)", source: "wallet")

                wallet.isRescanning = true
                Task.detached {
                    defer { wallet.isRescanning = false }
                    var lastLog = 0
                    for h in fromHeight...toHeight {
                        guard ctx.wallet(named: name) != nil else {
                            logger.warning("Wallet '\(name)' removed during rescan, aborting", source: "Wallet")
                            break
                        }
                        do {
                            if let block = try chain.getBlock(height: h) {
                                try wallet.indexBlock(block, height: h)
                            }
                        } catch {
                            logger.error("Wallet rescan error at height \(h): \(error)", source: "Wallet")
                            break
                        }

                        let done = h - fromHeight + 1
                        ctx.setRescanProgress(name, (current: done, total: total))

                        if done - lastLog >= 1000 || h == toHeight {
                            lastLog = done
                            let pct = Double(done) / Double(total) * 100
                            logger.info("Wallet rescan: \(done)/\(total) (\(String(format: "%.3f", pct))%)",
                                        metadata: ["wallet": "\(name)"], source: "Wallet")
                        }
                    }

                    // Catch up with blocks that arrived during the rescan.
                    // isRescanning blocked onBlockConnected, so we must index
                    // from toHeight+1 to current tip before clearing the flag.
                    // Loop until stable -- new blocks may arrive during catch-up.
                    while let currentTip = ctx.chain?.storedHeight,
                          currentTip > wallet.scanHeight {
                        let from = wallet.scanHeight + 1
                        var failed = false
                        for h in from...currentTip {
                            guard ctx.wallet(named: name) != nil else { failed = true; break }
                            do {
                                if let block = try chain.getBlock(height: h) {
                                    try wallet.indexBlock(block, height: h)
                                }
                            } catch {
                                logger.error("Wallet rescan catch-up error at height \(h): \(error)", source: "Wallet")
                                failed = true
                                break
                            }
                        }
                        if failed { break }
                    }

                    ctx.setRescanProgress(name, nil)
                    if let balance = try? wallet.getDetailedBalance() {
                        logger.info("Wallet rescan complete", metadata: [
                            "wallet": "\(name)",
                            "confirmed": "\(balance.confirmed)",
                            "unconfirmed": "\(balance.unconfirmed)",
                        ], source: "Wallet")
                    } else {
                        logger.info("Wallet rescan complete", metadata: ["wallet": "\(name)"], source: "Wallet")
                    }
                }

                return .object([
                    ("started", .bool(true)),
                    ("name", .string(name)),
                    ("from", .int(Int64(fromHeight))),
                    ("to", .int(Int64(toHeight))),
                    ("blocks", .int(Int64(total))),
                ])
            }

        handlers["getrescanprogress"] = { req in
                let (name, _, _) = try Self.rpcResolveWallet(req, ctx: ctx)
                guard let progress = ctx.getRescanProgress(name) else {
                    return .null
                }
                let pct = progress.total > 0
                    ? Double(progress.current) / Double(progress.total) * 100
                    : 0.0
                let pctRounded = (pct * 1000).rounded() / 1000
                return .object([
                    ("name", .string(name)),
                    ("current", .int(Int64(progress.current))),
                    ("total", .int(Int64(progress.total))),
                    ("percent", .double(pctRounded)),
                ])
            }

        // MARK: Batch

        handlers["sendmany"] = { req in
                let (_, wallet, rest, chain, mempool, coinDB) = try Self.requireWalletAndNode(req, ctx: ctx)

                let nameParams = NameParams.params(for: network)

                // Flatten params into a single string the segment-by-comma /
                // arg-by-space parser below can chew on. Anything that
                // arrives as a JSON array gets joined back with commas and
                // suffixed with a trailing comma so the array boundary is
                // preserved in the flattened raw string.
                //
                // This matters because `fbdctl`'s `autoDetect` will turn
                // any shell token containing a comma (e.g. `10.5,` from a
                // command like `sendmany none <addr> 10.5, none <addr2>
                // 20.0`) into a single-element JSON array `["10.5"]` on
                // the wire — that's intended for the xpub/pstx-list cases
                // but it breaks `sendmany`'s `<value>,` segment-boundary
                // syntax. Without the trailing-comma re-emission here, the
                // array case would lose the comma, the join-then-split
                // would treat all four payments as one segment, and only
                // the first would be processed.
                func paramToString(_ v: JSONValue) -> String {
                    switch v {
                    case .string(let s): return s
                    case .int(let n): return String(n)
                    case .double(let d): return String(d)
                    case .bool(let b): return b ? "true" : "false"
                    case .array(let xs):
                        return xs.map(paramToString).joined(separator: ",") + ","
                    default: return ""
                    }
                }
                let raw = rest.map(paramToString).joined(separator: " ")

                guard !raw.trimmingCharacters(in: .whitespaces).isEmpty else {
                    throw RPCError.invalidParams("expected: sendmany <action> <args>, <action> <args>, ...")
                }

                let segments = raw.split(separator: ",").map { $0.trimmingCharacters(in: .whitespaces) }
                var ops = [WalletDB.CovenantOp]()

                // Track pending bid nonces to save after tx is built
                struct PendingBid {
                    let opIndex: Int
                    let nameHash: NameHash
                    let nonce: BidNonce
                    let value: UInt64
                    let lockup: UInt64
                }
                var pendingBids = [PendingBid]()

                for segment in segments {
                    let parts = segment.split(separator: " ", omittingEmptySubsequences: true).map(String.init)
                    guard let action = parts.first?.lowercased(), !action.isEmpty else { continue }
                    let args = Array(parts.dropFirst())

                    switch action {
                    case "open":
                        guard let name = args.first, !name.isEmpty else {
                            throw RPCError.invalidParams("open: expected name")
                        }
                        guard NameRules.verifyName(name) else {
                            throw RPCError.invalidParams("open: invalid name: \(name)")
                        }
                        let nameHash = NameRules.hashName(name)
                        guard NameRules.isAvailable(nameHash: nameHash, height: chain.storedHeight, params: nameParams, rawName: Array(name.utf8)) else {
                            throw RPCError.invalidParams("open: name not yet available: \(name)")
                        }
                        if let ns = try chain.getNameState(name: name) {
                            let st = ns.state(at: chain.storedHeight, params: nameParams)
                            guard st == .closed && ns.isExpired(at: chain.storedHeight, params: nameParams) else {
                                throw RPCError.invalidParams("open: name already in auction or registered: \(name) (state: \(st))")
                            }
                        }
                        let covenant: Covenant
                        let addr: Address
                        if NameRules.requiresDNSSEC(name) {
                            guard args.count >= 2, !args[1].isEmpty else {
                                throw RPCError.invalidParams("open: \(NameRules.dnssecReason(name)) (\(name)) requires domain (e.g., open fbd fbd.dev)")
                            }
                            let domain = args[1]
                            let proofBytes: [UInt8]
                            do {
                                proofBytes = try DNSSECProber.buildProof(name: name, domain: domain)
                            } catch {
                                let recvAddr = try wallet.getReceiveAddress()
                                let bech32 = recvAddr.toBech32(network: network)
                                throw RPCError.internalError(
                                    "\(error)\n\nTo fix: add a TXT record at _fbd.\(domain) with value:\n  fbd=\(name):\(bech32)\n\nThen enable DNSSEC on \(domain) and retry."
                                )
                            }
                            let binding = try DNSSECProofValidator.validateProof(
                                proofBytes, claimedName: name,
                                blockTime: UInt64(Date().timeIntervalSince1970), gracePeriod: 86_400
                            )
                            let bindingAddr = Address(unchecked: binding.version, hash: binding.hash)
                            guard wallet.ismine(bindingAddr) else {
                                throw RPCError.invalidParams("open: DNSSEC proof binds to address \(bindingAddr.toBech32(network: network)) which is not in this wallet")
                            }
                            addr = bindingAddr
                            covenant = CovenantData.makePremiumOpen(nameHash: nameHash, name: Array(name.utf8), dnssecProof: proofBytes)
                        } else {
                            addr = try wallet.getReceiveAddress()
                            covenant = CovenantData.makeOpen(nameHash: nameHash, name: Array(name.utf8))
                        }
                        ops.append(WalletDB.CovenantOp(covenant: covenant, value: 0, address: addr))

                    case "bid":
                        guard let name = args.first, !name.isEmpty else {
                            throw RPCError.invalidParams("bid: expected name")
                        }
                        guard args.count >= 2, let bidFBD = Double(args[1]), bidFBD > 0 else {
                            throw RPCError.invalidParams("bid: expected positive bid amount (FBC)")
                        }
                        guard args.count >= 3, let lockupFBD = Double(args[2]), lockupFBD > 0 else {
                            throw RPCError.invalidParams("bid: expected positive lockup amount (FBC)")
                        }
                        let bid = UInt64(bidFBD * 1_000_000)
                        let lockup = UInt64(lockupFBD * 1_000_000)
                        guard lockup >= bid else {
                            throw RPCError.invalidParams("bid: lockup must be >= bid")
                        }
                        let nameHash = NameRules.hashName(name)
                        guard let ns = try chain.getNameState(name: name) else {
                            throw RPCError.invalidParams("bid: name not found: \(name) (send open first)")
                        }
                        let st = ns.state(at: chain.storedHeight, params: nameParams)
                        guard st == .bidding else {
                            throw RPCError.invalidParams("bid: name not in bidding state: \(name) (state: \(st))")
                        }
                        let addr: Address
                        var bidDnssecProof: [UInt8]?
                        if NameRules.requiresDNSSEC(name) {
                            guard args.count >= 4, !args[3].isEmpty else {
                                throw RPCError.invalidParams("bid: \(NameRules.dnssecReason(name)) (\(name)) requires domain (e.g., bid fbd 100 200 fbd.dev)")
                            }
                            let domain = args[3]
                            let proofBytes: [UInt8]
                            do {
                                proofBytes = try DNSSECProber.buildProof(name: name, domain: domain)
                            } catch {
                                let recvAddr = try wallet.getReceiveAddress()
                                let bech32 = recvAddr.toBech32(network: network)
                                throw RPCError.internalError(
                                    "\(error)\n\nTo fix: add a TXT record at _fbd.\(domain) with value:\n  fbd=\(name):\(bech32)\n\nThen enable DNSSEC on \(domain) and retry."
                                )
                            }
                            let binding = try DNSSECProofValidator.validateProof(
                                proofBytes, claimedName: name,
                                blockTime: UInt64(Date().timeIntervalSince1970), gracePeriod: 86_400,
                                expectedAddressHRP: network.addressHRP
                            )
                            let bindingAddr = Address(unchecked: binding.version, hash: binding.hash)
                            guard wallet.ismine(bindingAddr) else {
                                throw RPCError.invalidParams("bid: DNSSEC proof binds to address \(bindingAddr.toBech32(network: network)) which is not in this wallet")
                            }
                            addr = bindingAddr
                            bidDnssecProof = proofBytes
                        } else {
                            addr = try wallet.getReceiveAddress()
                        }
                        guard let nonce = try wallet.deriveNonce(address: addr, nameHash: nameHash) else {
                            throw RPCError.internalError("failed to derive bid nonce")
                        }
                        let blind = try BlindBid.blind(value: bid, nonce: nonce)
                        let covenant: Covenant
                        if let proof = bidDnssecProof {
                            covenant = CovenantData.makePremiumBid(
                                nameHash: nameHash, startHeight: ns.height,
                                name: Array(name.utf8), blind: blind, dnssecProof: proof
                            )
                        } else {
                            covenant = CovenantData.makeBid(
                                nameHash: nameHash, startHeight: ns.height,
                                name: Array(name.utf8), blind: blind
                            )
                        }
                        pendingBids.append(PendingBid(
                            opIndex: ops.count, nameHash: nameHash,
                            nonce: nonce, value: bid, lockup: lockup
                        ))
                        ops.append(WalletDB.CovenantOp(covenant: covenant, value: lockup, address: addr))

                    case "reveal":
                        if let name = args.first, !name.isEmpty {
                            // Single-name reveal
                            let nh = NameRules.hashName(name)
                            guard let ns = try chain.getNameState(name: name) else {
                                throw RPCError.invalidParams("reveal: name not found: \(name)")
                            }
                            let st = ns.state(at: chain.storedHeight, params: nameParams)
                            guard st == .reveal else {
                                throw RPCError.invalidParams("reveal: name not in reveal state: \(name) (state: \(st))")
                            }
                            let bids = try wallet.getBidsForName(nameHash: nh)
                            guard !bids.isEmpty else {
                                throw RPCError.invalidParams("reveal: no bids found for \(name)")
                            }
                            let bidCoins = try wallet.findNameCoins(nameHash: nh, covenantType: .bid)
                            for bid in bids {
                                guard let bidCoin = bidCoins.first(where: { $0.outpoint == bid.outpoint }) else { continue }
                                let covenant = CovenantData.makeReveal(
                                    nameHash: nh, startHeight: ns.height, nonce: bid.nonce
                                )
                                let addr = try wallet.getReceiveAddress()
                                ops.append(WalletDB.CovenantOp(covenant: covenant, value: bid.value, address: addr, linkedCoin: bidCoin))
                            }
                        } else {
                            // Bulk reveal: reveal ALL pending bids in reveal state
                            let allBids = try wallet.getAllBids()
                            let allCoins = try wallet.listUnspent()
                            let bidCoins = allCoins.filter { $0.covenant.type == .bid }
                            var seenNames = Set<NameHash>()
                            for bid in allBids {
                                if seenNames.contains(bid.nameHash) { /* already checked */ }
                                else { seenNames.insert(bid.nameHash) }

                                guard let ns = try chain.getNameState(nameHash: bid.nameHash) else { continue }
                                let st = ns.state(at: chain.storedHeight, params: nameParams)
                                guard st == .reveal else { continue }

                                guard let bidCoin = bidCoins.first(where: { $0.outpoint == bid.outpoint }) else { continue }
                                let covenant = CovenantData.makeReveal(
                                    nameHash: bid.nameHash, startHeight: ns.height, nonce: bid.nonce
                                )
                                let addr = try wallet.getReceiveAddress()
                                ops.append(WalletDB.CovenantOp(covenant: covenant, value: bid.value, address: addr, linkedCoin: bidCoin))
                            }
                        }

                    case "redeem":
                        if let name = args.first, !name.isEmpty {
                            // Single-name redeem
                            let nh = NameRules.hashName(name)
                            guard let ns = try chain.getNameState(name: name) else {
                                throw RPCError.invalidParams("redeem: name not found: \(name)")
                            }
                            let st = ns.state(at: chain.storedHeight, params: nameParams)
                            guard st == .closed else {
                                throw RPCError.invalidParams("redeem: name auction not closed: \(name) (state: \(st))")
                            }
                            let coins = try wallet.findNameCoins(nameHash: nh, covenantType: .reveal)
                            var found = false
                            for coin in coins {
                                if let owner = ns.owner, coin.outpoint.hash.bytes == owner.hash && coin.outpoint.index == UInt32(owner.index) {
                                    continue // Skip winner
                                }
                                guard let nhBytes = coin.covenant.items.first, nhBytes.count == 32 else { continue }
                                guard coin.covenant.items.count >= 2 else { continue }
                                let heightBytes = coin.covenant.items[1]
                                guard heightBytes.count == 4 else { continue }
                                let startHeight = Int(UInt32(heightBytes[0]) | UInt32(heightBytes[1]) << 8
                                    | UInt32(heightBytes[2]) << 16 | UInt32(heightBytes[3]) << 24)
                                let covenant = CovenantData.makeRedeem(nameHash: NameHash(unchecked: nhBytes), startHeight: startHeight)
                                let addr = try wallet.getReceiveAddress()
                                ops.append(WalletDB.CovenantOp(covenant: covenant, value: 0, address: addr, linkedCoin: coin))
                                found = true
                            }
                            if !found {
                                throw RPCError.invalidParams("redeem: no redeemable reveals found for \(name)")
                            }
                        } else {
                            // Bulk redeem: redeem ALL losing reveals
                            let allCoins = try wallet.listUnspent()
                            let revealCoins = allCoins.filter { $0.covenant.type == .reveal }
                            for coin in revealCoins {
                                guard let nhBytes = coin.covenant.items.first, nhBytes.count == 32 else { continue }
                                guard let ns = try chain.getNameState(nameHash: NameHash(unchecked: nhBytes)) else { continue }
                                let st = ns.state(at: chain.storedHeight, params: nameParams)
                                guard st == .closed else { continue }
                                // Skip winner
                                if let owner = ns.owner, coin.outpoint.hash.bytes == owner.hash && coin.outpoint.index == UInt32(owner.index) {
                                    continue
                                }
                                guard coin.covenant.items.count >= 2 else { continue }
                                let heightBytes = coin.covenant.items[1]
                                guard heightBytes.count == 4 else { continue }
                                let startHeight = Int(UInt32(heightBytes[0]) | UInt32(heightBytes[1]) << 8
                                    | UInt32(heightBytes[2]) << 16 | UInt32(heightBytes[3]) << 24)
                                let covenant = CovenantData.makeRedeem(nameHash: NameHash(unchecked: nhBytes), startHeight: startHeight)
                                let addr = try wallet.getReceiveAddress()
                                ops.append(WalletDB.CovenantOp(covenant: covenant, value: 0, address: addr, linkedCoin: coin))
                            }
                        }

                    case "register":
                        let cp = chain.params
                        let regDevFundAddr = CovenantProcessor.resolveDevFundAddress(nameDB: chain.nameDBRef, network: network, consensusParams: cp)
                        let regRenewalHeight = max(chain.storedHeight - nameParams.renewalMaturity, 0)
                        guard let regRenewalEntry = chain.getEntryByHeight(regRenewalHeight) else {
                            throw RPCError.internalError("cannot find block for renewal proof")
                        }

                        // Helper: add register ops for a single name
                        func addRegisterOps(_ name: String) throws -> Bool {
                            let regNameHash = NameRules.hashName(name)
                            guard var regNS = try chain.getNameState(name: name) else { return false }
                            regNS.maybeExpire(at: chain.storedHeight + 1, params: nameParams)
                            let regSt = regNS.state(at: chain.storedHeight, params: nameParams)
                            guard regSt == .closed else { return false }
                            guard !regNS.isExpired(at: chain.storedHeight + 1, params: nameParams) else { return false }
                            guard !regNS.registered else { return false }
                            // Must have a bid record for this name (proves we participated in this round)
                            let bids = try wallet.getBidsForName(nameHash: regNameHash)
                            guard !bids.isEmpty else { return false }
                            let regRevealCoins = try wallet.findNameCoins(nameHash: regNameHash, covenantType: .reveal)
                            guard let regRevealCoin = regRevealCoins.first(where: { coin in
                                guard let owner = regNS.owner else { return false }
                                guard coin.outpoint.hash.bytes == owner.hash && coin.outpoint.index == UInt32(owner.index) else { return false }
                                guard coin.height >= regNS.height else { return false }
                                return true
                            }) else { return false }

                            let regCovenant = CovenantData.makeRegister(
                                nameHash: regNameHash, startHeight: regNS.height,
                                resource: [], blockHash: regRenewalEntry.hash.bytes
                            )
                            let regAddr = try wallet.getReceiveAddress()
                            let regMinBid = nameParams.minimumBid(atHeight: chain.storedHeight, name: name)
                            let regPrice = max(regNS.value, regMinBid)
                            let regBurnShare = regPrice * Int64(nameParams.registrationBurnPercent) / 100
                            let regTotalNonBurn = regPrice - regBurnShare

                            ops.append(WalletDB.CovenantOp(covenant: regCovenant, value: 0, address: regAddr, linkedCoin: regRevealCoin))
                            if regBurnShare > 0 {
                                ops.append(WalletDB.CovenantOp(covenant: Covenant.none, value: UInt64(regBurnShare), address: .null))
                            }
                            if regNS.parentHash != .zero {
                                let parentShare = regTotalNonBurn / 2
                                var devExtra: Int64 = 0
                                let ancestorHashes = NameRules.ancestorHashes(name)
                                if !ancestorHashes.isEmpty && parentShare > 0 {
                                    let perAncestor = parentShare / Int64(ancestorHashes.count)
                                    var unclaimed = parentShare
                                    for aHash in ancestorHashes {
                                        guard perAncestor > 0 else { continue }
                                        if let aNS = try chain.getNameState(nameHash: aHash),
                                           let ownerOP = aNS.owner,
                                           !aNS.isExpired(at: chain.storedHeight, params: nameParams),
                                           let ownerCoin = chain.getCoin(hash: Hash256(unchecked: ownerOP.hash), index: UInt32(ownerOP.index)) {
                                            ops.append(WalletDB.CovenantOp(covenant: Covenant.none, value: UInt64(perAncestor), address: ownerCoin.output.address))
                                            unclaimed -= perAncestor
                                        }
                                    }
                                    devExtra = unclaimed
                                } else {
                                    devExtra = parentShare
                                }
                                let devShare = regTotalNonBurn - parentShare + devExtra
                                if devShare > 0 {
                                    ops.append(WalletDB.CovenantOp(covenant: Covenant.none, value: UInt64(devShare), address: regDevFundAddr))
                                }
                            } else {
                                if regTotalNonBurn > 0 {
                                    ops.append(WalletDB.CovenantOp(covenant: Covenant.none, value: UInt64(regTotalNonBurn), address: regDevFundAddr))
                                }
                            }
                            return true
                        }

                        if let name = args.first, !name.isEmpty {
                            // Single name register
                            guard try addRegisterOps(name) else {
                                throw RPCError.invalidParams("register: cannot register \(name)")
                            }
                        } else {
                            // Bulk register: all revealed names in closed auctions where we won
                            let allCoins = try wallet.listUnspent()
                            let revealCoins = allCoins.filter { $0.covenant.type == .reveal }
                            var registered = Set<String>()
                            for coin in revealCoins {
                                guard let nhBytes = coin.covenant.items.first, nhBytes.count == 32 else { continue }
                                let nh = NameHash(unchecked: nhBytes)
                                guard let ns = try chain.getNameState(nameHash: nh) else { continue }
                                let nameStr = String(decoding: ns.name, as: UTF8.self)
                                guard !nameStr.isEmpty, !registered.contains(nameStr) else { continue }
                                if try addRegisterOps(nameStr) {
                                    registered.insert(nameStr)
                                }
                            }
                        }

                    case "update":
                        guard let name = args.first, !name.isEmpty else {
                            throw RPCError.invalidParams("update: expected name")
                        }
                        guard args.count >= 2 else {
                            throw RPCError.invalidParams("update: expected resource JSON")
                        }
                        let nameHash = NameRules.hashName(name)
                        guard let ns = try chain.getNameState(name: name) else {
                            throw RPCError.invalidParams("update: name not found: \(name)")
                        }
                        let st = ns.state(at: chain.storedHeight, params: nameParams)
                        guard st == .closed else {
                            throw RPCError.invalidParams("update: name not in closed state: \(name) (state: \(st))")
                        }
                        guard let nameCoin = try wallet.findCurrentNameCoin(nameHash: nameHash) else {
                            throw RPCError.invalidParams("update: no name UTXO found for \(name)")
                        }
                        let jsonStr = args.dropFirst().joined(separator: " ")
                        let jsonVal = try JSONParser.parse(jsonStr)
                        let resource = Self.parseResourceJSON(jsonVal)
                        try Self.validateResource(resource, network: network)
                        let resourceData = try resource.encode()
                        let covenant = CovenantData.makeUpdate(
                            nameHash: nameHash, startHeight: ns.height,
                            resource: resourceData
                        )
                        ops.append(WalletDB.CovenantOp(covenant: covenant, value: nameCoin.value, address: nameCoin.address, linkedCoin: nameCoin))

                    case "renew":
                        let batchCP = ConsensusParams.params(for: network)
                        let devFundAddr = CovenantProcessor.resolveDevFundAddress(nameDB: chain.nameDBRef, network: network, consensusParams: batchCP)

                        // Helper: add renewal fee ops for a name (dev fund + ancestors for subdomains)
                        func addRenewalFeeOps(_ ns: NameState, name: String) throws {
                            let pctFee = ns.value * Int64(nameParams.renewalFeePercent) / 100
                            let minFee = nameParams.minimumBid(atHeight: chain.storedHeight, rawName: ns.name)
                            let fee = max(pctFee, minFee)
                            guard fee > 0 else { return }
                            if ns.parentHash != .zero {
                                let ancestorShare = fee / 2
                                let devShare = fee - ancestorShare
                                let ancestorHashes = NameRules.ancestorHashes(name)
                                var devExtra: Int64 = 0
                                if !ancestorHashes.isEmpty && ancestorShare > 0 {
                                    let perAncestor = ancestorShare / Int64(ancestorHashes.count)
                                    var unclaimed = ancestorShare
                                    for aHash in ancestorHashes {
                                        guard perAncestor > 0 else { continue }
                                        if let aNS = try chain.getNameState(nameHash: aHash),
                                           let ownerOP = aNS.owner,
                                           !aNS.isExpired(at: chain.storedHeight, params: nameParams),
                                           let ownerCoin = chain.getCoin(hash: Hash256(unchecked: ownerOP.hash), index: UInt32(ownerOP.index)) {
                                            ops.append(WalletDB.CovenantOp(covenant: Covenant.none, value: UInt64(perAncestor), address: ownerCoin.output.address))
                                            unclaimed -= perAncestor
                                        }
                                    }
                                    devExtra = unclaimed
                                } else {
                                    devExtra = ancestorShare
                                }
                                ops.append(WalletDB.CovenantOp(covenant: Covenant.none, value: UInt64(devShare + devExtra), address: devFundAddr))
                            } else {
                                ops.append(WalletDB.CovenantOp(covenant: Covenant.none, value: UInt64(fee), address: devFundAddr))
                            }
                        }

                        if let name = args.first, !name.isEmpty {
                            let nameHash = NameRules.hashName(name)
                            guard let ns = try chain.getNameState(name: name) else {
                                throw RPCError.invalidParams("renew: name not found: \(name)")
                            }
                            let st = ns.state(at: chain.storedHeight, params: nameParams)
                            guard st == .closed else {
                                throw RPCError.invalidParams("renew: name not in closed state: \(name) (state: \(st))")
                            }
                            guard let nameCoin = try wallet.findCurrentNameCoin(nameHash: nameHash) else {
                                throw RPCError.invalidParams("renew: no name UTXO found for \(name)")
                            }
                            let renewalHeight = max(chain.storedHeight - nameParams.renewalMaturity, 0)
                            guard let renewalEntry = chain.getEntryByHeight(renewalHeight) else {
                                throw RPCError.internalError("cannot find block for renewal proof")
                            }
                            let covenant = CovenantData.makeRenew(nameHash: nameHash, startHeight: ns.height, blockHash: renewalEntry.hash.bytes)
                            ops.append(WalletDB.CovenantOp(covenant: covenant, value: nameCoin.value, address: nameCoin.address, linkedCoin: nameCoin))
                            try addRenewalFeeOps(ns, name: name)
                        } else {
                            let owned = try wallet.getOwnedNames()
                            let renewalHeight = max(chain.storedHeight - nameParams.renewalMaturity, 0)
                            guard let renewalEntry = chain.getEntryByHeight(renewalHeight) else {
                                throw RPCError.internalError("cannot find block for renewal proof")
                            }
                            for (nameHash, coin) in owned {
                                guard coin.covenant.type != .transfer else { continue }
                                guard let ns = try chain.getNameState(nameHash: nameHash) else { continue }
                                let st = ns.state(at: chain.storedHeight, params: nameParams)
                                guard st == .closed else { continue }
                                let covenant = CovenantData.makeRenew(nameHash: nameHash, startHeight: ns.height, blockHash: renewalEntry.hash.bytes)
                                ops.append(WalletDB.CovenantOp(covenant: covenant, value: coin.value, address: coin.address, linkedCoin: coin))
                                let renewName = String(decoding: ns.name, as: UTF8.self)
                                try addRenewalFeeOps(ns, name: renewName)
                            }
                        }

                    case "transfer":
                        guard let name = args.first, !name.isEmpty else {
                            throw RPCError.invalidParams("transfer: expected name")
                        }
                        guard args.count >= 2, !args[1].isEmpty else {
                            throw RPCError.invalidParams("transfer: expected destination address")
                        }
                        let destination = try Address(bech32: args[1], network: network)
                        let nameHash = NameRules.hashName(name)
                        guard let ns = try chain.getNameState(name: name) else {
                            throw RPCError.invalidParams("transfer: name not found: \(name)")
                        }
                        let st = ns.state(at: chain.storedHeight, params: nameParams)
                        guard st == .closed else {
                            throw RPCError.invalidParams("transfer: name not in closed state: \(name) (state: \(st))")
                        }
                        guard let nameCoin = try wallet.findCurrentNameCoin(nameHash: nameHash) else {
                            throw RPCError.invalidParams("transfer: no name UTXO found for \(name)")
                        }
                        let covenant = CovenantData.makeTransfer(
                            nameHash: nameHash, startHeight: ns.height,
                            version: destination.version, addressHash: destination.hash
                        )
                        let addr = try wallet.getReceiveAddress()
                        ops.append(WalletDB.CovenantOp(covenant: covenant, value: nameCoin.value, address: addr, linkedCoin: nameCoin))

                    case "finalize":
                        if let name = args.first, !name.isEmpty {
                            // Single-name finalize
                            let nameHash = NameRules.hashName(name)
                            guard let ns = try chain.getNameState(name: name) else {
                                throw RPCError.invalidParams("finalize: name not found: \(name)")
                            }
                            guard ns.transfer != 0 else {
                                throw RPCError.invalidParams("finalize: no pending transfer for \(name)")
                            }
                            guard chain.storedHeight >= ns.transfer + nameParams.transferLockup else {
                                let remaining = ns.transfer + nameParams.transferLockup - chain.storedHeight
                                throw RPCError.invalidParams("finalize: transfer lockup not met (\(remaining) blocks remaining)")
                            }
                            let transferCoins = try wallet.findNameCoins(nameHash: nameHash, covenantType: .transfer)
                            guard let transferCoin = transferCoins.first else {
                                throw RPCError.invalidParams("finalize: no TRANSFER UTXO found for \(name)")
                            }
                            guard transferCoin.covenant.items.count >= 4 else {
                                throw RPCError.internalError("finalize: malformed TRANSFER covenant")
                            }
                            let destVersion = transferCoin.covenant.items[2]
                            let destHash = transferCoin.covenant.items[3]
                            guard destVersion.count == 1 else {
                                throw RPCError.internalError("finalize: invalid TRANSFER address version")
                            }
                            let destAddr = Address(unchecked: destVersion[0], hash: destHash)
                            let renewalHeight = max(chain.storedHeight - nameParams.renewalMaturity, 0)
                            guard let renewalEntry = chain.getEntryByHeight(renewalHeight) else {
                                throw RPCError.internalError("cannot find block for renewal proof")
                            }
                            let flags: UInt8 = ns.flags
                            let covenant = CovenantData.makeFinalize(
                                nameHash: nameHash, startHeight: ns.height,
                                name: Array(name.utf8), flags: flags,
                                claimed: 0, renewals: ns.renewals,
                                blockHash: renewalEntry.hash.bytes
                            )
                            ops.append(WalletDB.CovenantOp(covenant: covenant, value: transferCoin.value, address: destAddr, linkedCoin: transferCoin))
                        } else {
                            // Bulk finalize: finalize ALL pending transfers past lockup
                            let allCoins = try wallet.listUnspent()
                            let transferCoins = allCoins.filter { $0.covenant.type == .transfer }
                            let renewalHeight = max(chain.storedHeight - nameParams.renewalMaturity, 0)
                            guard let renewalEntry = chain.getEntryByHeight(renewalHeight) else {
                                throw RPCError.internalError("cannot find block for renewal proof")
                            }
                            for coin in transferCoins {
                                guard let nhBytes = coin.covenant.items.first, nhBytes.count == 32 else { continue }
                                guard let ns = try chain.getNameState(nameHash: NameHash(unchecked: nhBytes)) else { continue }
                                guard ns.transfer != 0 else { continue }
                                guard chain.storedHeight >= ns.transfer + nameParams.transferLockup else { continue }
                                guard coin.covenant.items.count >= 4 else { continue }
                                let destVersion = coin.covenant.items[2]
                                let destHash = coin.covenant.items[3]
                                guard destVersion.count == 1 else { continue }
                                let destAddr = Address(unchecked: destVersion[0], hash: destHash)
                                let flags: UInt8 = ns.flags
                                let covenant = CovenantData.makeFinalize(
                                    nameHash: NameHash(unchecked: nhBytes), startHeight: ns.height,
                                    name: ns.name, flags: flags,
                                    claimed: 0, renewals: ns.renewals,
                                    blockHash: renewalEntry.hash.bytes
                                )
                                ops.append(WalletDB.CovenantOp(covenant: covenant, value: coin.value, address: destAddr, linkedCoin: coin))
                            }
                        }

                    case "revoke":
                        guard let name = args.first, !name.isEmpty else {
                            throw RPCError.invalidParams("revoke: expected name")
                        }
                        let nameHash = NameRules.hashName(name)
                        guard let ns = try chain.getNameState(name: name) else {
                            throw RPCError.invalidParams("revoke: name not found: \(name)")
                        }
                        let st = ns.state(at: chain.storedHeight, params: nameParams)
                        guard st == .closed else {
                            throw RPCError.invalidParams("revoke: name not in closed state: \(name) (state: \(st))")
                        }
                        guard let nameCoin = try wallet.findCurrentNameCoin(nameHash: nameHash) else {
                            throw RPCError.invalidParams("revoke: no name UTXO found for \(name)")
                        }
                        let covenant = CovenantData.makeRevoke(
                            nameHash: nameHash, startHeight: ns.height
                        )
                        ops.append(WalletDB.CovenantOp(covenant: covenant, value: nameCoin.value, address: nameCoin.address, linkedCoin: nameCoin))

                    case "none":
                        guard let addrStr = args.first, !addrStr.isEmpty else {
                            throw RPCError.invalidParams("none: expected destination address")
                        }
                        guard args.count >= 2, let amountFBD = Double(args[1]), amountFBD > 0 else {
                            throw RPCError.invalidParams("none: expected positive amount (FBC)")
                        }
                        let destination = try Address(bech32: addrStr, network: network)
                        let amount = UInt64(amountFBD * 1_000_000)
                        ops.append(WalletDB.CovenantOp(covenant: Covenant(type: .none, items: []), value: amount, address: destination))

                    default:
                        throw RPCError.invalidParams("unknown action: \(action)")
                    }
                }

                guard !ops.isEmpty else {
                    throw RPCError.invalidParams("nothing to do — no eligible names found")
                }

                let tx = try wallet.createBatchCovenantTransaction(
                    ops: ops, currentHeight: chain.storedHeight
                )
                let txHash = tx.txHash()

                // Save bid nonces BEFORE broadcasting (lost nonce = lost funds).
                for pending in pendingBids {
                    let bidOutpoint = Outpoint(hash: txHash, index: UInt32(pending.opIndex))
                    try wallet.saveBid(BidRecord(
                        nameHash: pending.nameHash, outpoint: bidOutpoint,
                        nonce: pending.nonce, value: pending.value, lockup: pending.lockup
                    ))
                }

                try mempool.acceptTransaction(tx, coinDB: coinDB, chainHeight: chain.tip.height, params: chain.params)
                ctx.peerManager?.broadcastTx(txHash: txHash)

                return .object([("txid", .string(txHash.hex))])
            }

        // MARK: Sign / Verify Message

        handlers["signmessage"] = { req in
                let (_, wallet, rest) = try Self.rpcResolveWallet(req, ctx: ctx)
                guard wallet.initialized else {
                    throw RPCError.internalError("wallet not initialized")
                }
                guard rest.count >= 2,
                      let addrStr = rest[0].stringValue,
                      let message = rest[1].stringValue else {
                    throw RPCError.invalidParams("expected: signmessage <address> <message>")
                }
                let address = try Address(bech32: addrStr, network: network)
                guard let privKey = try wallet.getPrivateKey(for: address) else {
                    throw RPCError.invalidParams("private key not found for address (watch-only?)")
                }

                let prefix = "fistbump signed message:\n"
                let msgBytes = Array((prefix + message).utf8)
                let hash = try Blake2bHash.hash256(msgBytes)
                let sig = try ECDSASigner.signRecoverable(hash: hash, privateKey: PrivateKey(unchecked: privKey))
                return .string(Base64.encode(sig))
            }

        handlers["signmessagewithname"] = { req in
                let (_, wallet, rest) = try Self.rpcResolveWallet(req, ctx: ctx)
                guard wallet.initialized else { throw RPCError.internalError("wallet not initialized") }
                guard rest.count >= 2,
                      let name = rest[0].stringValue,
                      let message = rest[1].stringValue else {
                    throw RPCError.invalidParams("expected: signmessagewithname <name> <message>")
                }
                let chain = try Self.requireChain(ctx)
                guard let ns = try chain.getNameState(name: name) else {
                    throw RPCError.invalidParams("name not found: \(name)")
                }
                let nameParams = NameParams.params(for: network)
                guard ns.state(at: chain.storedHeight, params: nameParams) == .closed else {
                    throw RPCError.invalidParams("name is not in CLOSED state")
                }
                let nameHash = NameRules.hashName(name)
                guard let coin = try wallet.findCurrentNameCoin(nameHash: nameHash) else {
                    throw RPCError.invalidParams("name owner coin not found in wallet")
                }
                guard let privKey = try wallet.getPrivateKey(for: coin.address) else {
                    throw RPCError.invalidParams("private key not found for name owner address")
                }

                let prefix = "fistbump signed message:\n"
                let msgBytes = Array((prefix + message).utf8)
                let hash = try Blake2bHash.hash256(msgBytes)
                let sig = try ECDSASigner.signRecoverable(hash: hash, privateKey: PrivateKey(unchecked: privKey))

                // For P2WSH (multisig), embed the pubkeys so verify can work without a wallet
                if coin.address.hash.count == 32 {
                    guard let config = try wallet.getMultisigConfig(addressHash: coin.address.hash) else {
                        throw RPCError.internalError("multisig config not found for name owner")
                    }
                    // Extended format: sig(65) + m(1) + n(1) + pubkeys(n*33)
                    var extended = sig
                    extended.append(UInt8(config.m))
                    extended.append(UInt8(config.n))
                    for pk in config.publicKeys {
                        extended.append(contentsOf: pk)
                    }
                    return .string(Base64.encode(extended))
                }

                return .string(Base64.encode(sig))
            }

        handlers["verifymessage"] = { req in
                let rest = req.params
                guard rest.count >= 3,
                      let addrStr = rest[0].stringValue,
                      let sigB64 = rest[1].stringValue,
                      let message = rest[2].stringValue else {
                    throw RPCError.invalidParams("expected: verifymessage <address> <signature> <message>")
                }
                let address = try Address(bech32: addrStr, network: network)

                guard let sigBytes = Base64.decode(sigB64), sigBytes.count == 65 else {
                    throw RPCError.invalidParams("invalid signature (expected 65-byte base64)")
                }

                let prefix = "fistbump signed message:\n"
                let msgBytes = Array((prefix + message).utf8)
                let hash = try Blake2bHash.hash256(msgBytes)

                guard let recoveredPub = ECDSASigner.recoverPublicKey(signature: sigBytes, hash: hash) else {
                    return .bool(false)
                }

                guard let pubHash = try? Blake2bHash.hash(recoveredPub.bytes, size: 20) else {
                    return .bool(false)
                }

                return .bool(pubHash == address.hash)
            }

        handlers["verifymessagewithname"] = { req in
                let rest = req.params
                guard rest.count >= 3,
                      let name = rest[0].stringValue,
                      let sigB64 = rest[1].stringValue,
                      let message = rest[2].stringValue else {
                    throw RPCError.invalidParams("expected: verifymessagewithname <name> <signature> <message>")
                }
                let chain = try Self.requireChain(ctx)
                guard let ns = try chain.getNameState(name: name) else {
                    throw RPCError.invalidParams("name not found: \(name)")
                }
                let nameParams = NameParams.params(for: network)
                guard ns.state(at: chain.storedHeight, params: nameParams) == .closed else {
                    throw RPCError.invalidParams("name is not in CLOSED state")
                }
                guard let owner = ns.owner else {
                    throw RPCError.invalidParams("name has no owner")
                }

                // Look up the owner coin from chain UTXO set to get the address
                guard let coinEntry = chain.getCoin(hash: try Hash256(owner.hash), index: UInt32(owner.index)) else {
                    throw RPCError.invalidParams("owner coin not found on chain")
                }

                guard let decoded = Base64.decode(sigB64), decoded.count >= 65 else {
                    throw RPCError.invalidParams("invalid signature")
                }

                let sig = Array(decoded[0..<65])
                let prefix = "fistbump signed message:\n"
                let msgBytes = Array((prefix + message).utf8)
                let hash = try Blake2bHash.hash256(msgBytes)

                guard let recoveredPub = ECDSASigner.recoverPublicKey(signature: sig, hash: hash) else {
                    return .bool(false)
                }

                let ownerAddr = coinEntry.output.address
                if ownerAddr.hash.count == 20 {
                    // P2WPKH: BLAKE2b-160 of recovered pubkey must match owner
                    guard let pubHash = try? Blake2bHash.hash(recoveredPub.bytes, size: 20) else {
                        return .bool(false)
                    }
                    return .bool(pubHash == ownerAddr.hash)
                } else {
                    // P2WSH: extended signature embeds m + n + pubkeys
                    // Reconstruct redeem script, hash it, compare to owner address
                    guard decoded.count > 67 else {
                        throw RPCError.invalidParams("P2WSH name requires extended signature from signmessagewithname")
                    }
                    let m = Int(decoded[65])
                    let n = Int(decoded[66])
                    let keyData = Array(decoded[67...])
                    guard keyData.count == n * 33, m >= 1, m <= 15, n >= m, n <= 15 else {
                        throw RPCError.invalidParams("malformed extended signature")
                    }
                    var pubkeys = [[UInt8]]()
                    for i in 0..<n {
                        pubkeys.append(Array(keyData[i*33..<(i+1)*33]))
                    }

                    // Rebuild redeem script and verify hash matches on-chain owner
                    let redeemScript = Script.multisig(m: m, publicKeys: pubkeys)
                    let scriptHash = SHA3Hash.sha3_256(redeemScript.raw)
                    guard scriptHash.bytes == ownerAddr.hash else {
                        return .bool(false) // embedded keys don't match the name's owner
                    }

                    // Check the signer is one of the multisig participants
                    return .bool(pubkeys.contains(recoveredPub.bytes))
                }
            }

        // MARK: Address Validation

        handlers["validateaddress"] = { req in
                let rest = req.params
                guard let addrStr = rest.first?.stringValue, !addrStr.isEmpty else {
                    throw RPCError.invalidParams("expected: validateaddress <address>")
                }
                do {
                    let address = try Address(bech32: addrStr, network: network)
                    var result: [(String, JSONValue)] = [
                        ("isvalid", .bool(true)),
                        ("address", .string(addrStr)),
                        ("version", .int(Int64(address.version))),
                        ("hash", .string(HexEncoding.encode(address.hash))),
                    ]
                    // Only check ownership if a specific wallet is selected
                    if let walletName = req.wallet, let wallet = ctx.wallet(named: walletName) {
                        result.append(("ismine", .bool(wallet.ismine(address))))
                    }
                    return .object(result)
                } catch {
                    return .object([
                        ("isvalid", .bool(false)),
                        ("address", .string(addrStr)),
                    ])
                }
            }

        // MARK: Backup / Import

        handlers["backupwallet"] = { req in
                guard let path = req.params.first?.stringValue, !path.isEmpty else {
                    throw RPCError.invalidParams("expected: backupwallet <path>")
                }
                guard !path.contains("..") else {
                    throw RPCError.invalidParams("path must not contain '..'")
                }
                let (name, wallet, _) = try Self.rpcResolveWallet(req, ctx: ctx)
                guard wallet.initialized else {
                    throw RPCError.internalError("wallet not initialized")
                }
                var result: [(String, JSONValue)] = [
                    ("name", .string(name)),
                ]
                if let mnemonic = wallet.mnemonic {
                    result.append(("mnemonic", .string(mnemonic)))
                }
                if let xpriv = wallet.xpriv {
                    result.append(("xpriv", .string(xpriv)))
                }
                result.append(("birthHeight", .int(Int64(wallet.birthHeight))))

                // Include derivation indices
                let indices = wallet.walletIndices
                result.append(("receiveIndex", .int(Int64(indices.receive))))
                result.append(("changeIndex", .int(Int64(indices.change))))
                result.append(("nextReceiveIndex", .int(Int64(indices.nextReceive))))
                result.append(("nextChangeIndex", .int(Int64(indices.nextChange))))

                // Include bids
                let allBids = (try? wallet.getAllBids()) ?? []
                let bidsJSON: [JSONValue] = allBids.map { bid in
                    .object([
                        ("nameHash", .string(bid.nameHash.hex)),
                        ("txHash", .string(bid.outpoint.hash.hex)),
                        ("index", .int(Int64(bid.outpoint.index))),
                        ("nonce", .string(bid.nonce.hex)),
                        ("value", .int(Int64(bid.value))),
                        ("lockup", .int(Int64(bid.lockup))),
                    ])
                }
                result.append(("bids", .array(bidsJSON)))

                // Include imported addresses
                let imported = wallet.getImportedAddresses()
                let importedJSON: [JSONValue] = imported.map { addr in
                    .string(addr.toBech32(network: network))
                }
                result.append(("importedAddresses", .array(importedJSON)))

                // Write pretty JSON to file
                let backupJSON: JSONValue = .object(result)
                let prettyStr = JSONEncoder.prettyEncode(backupJSON)
                let expandedPath = NSString(string: path).expandingTildeInPath
                let fm = FileManager.default
                #if os(Windows)
                fm.createFile(atPath: expandedPath, contents: Data(prettyStr.utf8))
                #else
                fm.createFile(atPath: expandedPath, contents: Data(prettyStr.utf8), attributes: [.posixPermissions: 0o600])
                #endif

                return .object([
                    ("path", .string(expandedPath)),
                    ("message", .string("wallet backed up to \(expandedPath)")),
                ])
            }

        handlers["restorewallet"] = { req in
                let params = req.params
                guard let name = params.first?.stringValue, !name.isEmpty else {
                    throw RPCError.invalidParams("expected: restorewallet <name> <path>")
                }
                try Self.rpcValidateWalletName(name)
                guard ctx.wallet(named: name) == nil else {
                    throw RPCError.invalidParams("wallet already exists: \(name)")
                }
                guard params.count >= 2, let filePath = params[1].stringValue, !filePath.isEmpty else {
                    throw RPCError.invalidParams("expected backup file path as second argument")
                }

                // Read and parse backup file
                let expandedPath = NSString(string: filePath).expandingTildeInPath
                let fm = FileManager.default
                guard let fileData = fm.contents(atPath: expandedPath),
                      let fileStr = String(data: fileData, encoding: .utf8) else {
                    throw RPCError.invalidParams("cannot read backup file: \(expandedPath)")
                }
                let parsed = try JSONParser.parse(fileStr)
                guard case .object(let backupPairs) = parsed else {
                    throw RPCError.invalidParams("backup file is not a JSON object")
                }
                let bk = Dictionary(backupPairs, uniquingKeysWith: { _, b in b })

                // Extract secret (mnemonic or xpriv required)
                let secret: String
                if let m = bk["mnemonic"]?.stringValue, !m.isEmpty {
                    secret = m
                } else if let x = bk["xpriv"]?.stringValue, !x.isEmpty {
                    secret = x
                } else {
                    throw RPCError.invalidParams("backup file missing mnemonic or xpriv")
                }

                let walletPath = walletsDir + "/\(name)"
                let wallet = try WalletDB(path: walletPath, network: network)

                let isXpriv = secret.hasPrefix("xprv")
                if isXpriv {
                    try wallet.importXpriv(secret)
                } else {
                    _ = try wallet.create(mnemonic: secret)
                }

                // Set scan height from backup birthHeight, default to full rescan
                let birthHeight: Int
                if let h = bk["birthHeight"]?.intValue {
                    birthHeight = max(Int(h) - 1, -1)
                } else {
                    birthHeight = -1
                }
                try wallet.setScanHeight(birthHeight)

                // Restore derivation indices
                if let ri = bk["receiveIndex"]?.intValue,
                   let ci = bk["changeIndex"]?.intValue,
                   let nri = bk["nextReceiveIndex"]?.intValue,
                   let nci = bk["nextChangeIndex"]?.intValue {
                    try wallet.setIndices(
                        receive: Int(ri), change: Int(ci),
                        nextReceive: Int(nri), nextChange: Int(nci)
                    )
                    try wallet.ensureAddresses(receive: Int(nri), change: Int(nci))
                }

                // Restore bids
                if case .array(let bidsArr) = bk["bids"] {
                    for bidJSON in bidsArr {
                        guard case .object(let bidFields) = bidJSON else { continue }
                        let bd = Dictionary(bidFields, uniquingKeysWith: { _, b in b })
                        guard let nhHex = bd["nameHash"]?.stringValue,
                              let txHex = bd["txHash"]?.stringValue,
                              let idx = bd["index"]?.intValue,
                              let nonceHex = bd["nonce"]?.stringValue,
                              let value = bd["value"]?.intValue,
                              let lockup = bd["lockup"]?.intValue else { continue }
                        let nhBytes = (try? HexEncoding.decode(nhHex)) ?? []
                        let txHash = try Hash256.fromHex(txHex)
                        let nonceBytes = (try? HexEncoding.decode(nonceHex)) ?? []
                        guard nhBytes.count == 32, nonceBytes.count == 32 else { continue }
                        try wallet.saveBid(BidRecord(
                            nameHash: NameHash(unchecked: nhBytes), outpoint: Outpoint(hash: txHash, index: UInt32(idx)),
                            nonce: BidNonce(unchecked: nonceBytes), value: UInt64(value), lockup: UInt64(lockup)
                        ))
                    }
                }

                // Restore imported addresses
                if case .array(let addrsArr) = bk["importedAddresses"] {
                    for addrJSON in addrsArr {
                        guard let addrStr = addrJSON.stringValue else { continue }
                        if let addr = try? Address(bech32: addrStr, network: network) {
                            try wallet.importAddress(addr)
                        }
                    }
                }

                ctx.setWallet(name, wallet)

                // Auto-trigger rescan (same pattern as rescanwallet handler)
                let fromHeight = max(birthHeight + 1, 0)
                if let chain = ctx.chain, chain.storedHeight >= fromHeight {
                    let toHeight = chain.storedHeight
                    let total = toHeight - fromHeight + 1

                    if fromHeight == 0 {
                        try wallet.resetForRescan()
                    } else {
                        try wallet.setScanHeight(fromHeight - 1)
                    }

                    ctx.setRescanProgress(name, (current: 0, total: total))
                    logger.info("Wallet rescan starting from=\(fromHeight) to=\(toHeight) wallet=\(name)", source: "Wallet")

                    wallet.isRescanning = true
                    Task.detached {
                        defer { wallet.isRescanning = false }
                        var lastLog = 0
                        for h in fromHeight...toHeight {
                            guard ctx.wallet(named: name) != nil else {
                                logger.warning("Wallet '\(name)' removed during rescan, aborting", source: "Wallet")
                                break
                            }
                            do {
                                if let block = try chain.getBlock(height: h) {
                                    try wallet.indexBlock(block, height: h)
                                }
                            } catch {
                                logger.error("Wallet rescan error at height \(h): \(error)", source: "Wallet")
                                break
                            }

                            let done = h - fromHeight + 1
                            ctx.setRescanProgress(name, (current: done, total: total))

                            if done - lastLog >= 1000 || h == toHeight {
                                lastLog = done
                                let pct = Double(done) / Double(total) * 100
                                logger.info("Wallet rescan: \(done)/\(total) (\(String(format: "%.3f", pct))%)",
                                            metadata: ["wallet": "\(name)"], source: "Wallet")
                            }
                        }

                        // Catch up with blocks that arrived during the rescan
                        while let currentTip = ctx.chain?.storedHeight,
                              currentTip > wallet.scanHeight {
                            let from = wallet.scanHeight + 1
                            var failed = false
                            for h in from...currentTip {
                                guard ctx.wallet(named: name) != nil else { failed = true; break }
                                do {
                                    if let block = try chain.getBlock(height: h) {
                                        try wallet.indexBlock(block, height: h)
                                    }
                                } catch {
                                    logger.error("Wallet rescan catch-up error at height \(h): \(error)", source: "Wallet")
                                    failed = true
                                    break
                                }
                            }
                            if failed { break }
                        }

                        ctx.setRescanProgress(name, nil)
                        if let balance = try? wallet.getDetailedBalance() {
                            logger.info("Wallet rescan complete", metadata: [
                                "wallet": "\(name)",
                                "confirmed": "\(balance.confirmed)",
                                "unconfirmed": "\(balance.unconfirmed)",
                            ], source: "Wallet")
                        } else {
                            logger.info("Wallet rescan complete", metadata: ["wallet": "\(name)"], source: "Wallet")
                        }
                    }

                    return .object([
                        ("name", .string(name)),
                        ("birthHeight", .int(Int64(fromHeight))),
                        ("message", .string("wallet restored, rescan started from height \(fromHeight)")),
                    ])
                } else {
                    // Birth height is ahead of sync -- rescan will happen
                    // automatically as new blocks connect.
                    return .object([
                        ("name", .string(name)),
                        ("birthHeight", .int(Int64(fromHeight))),
                        ("message", .string("wallet restored, will index from height \(fromHeight) as sync progresses")),
                    ])
                }
            }

        // MARK: Multisig Wallet

        handlers["createmultisigwallet"] = { req in
                let params = req.params
                guard let name = params.first?.stringValue, !name.isEmpty else {
                    throw RPCError.invalidParams("expected: createmultisigwallet <name> <m> [mnemonic|xpriv] <xpub1,xpub2,...>")
                }
                try Self.rpcValidateWalletName(name)
                guard ctx.wallet(named: name) == nil else {
                    throw RPCError.invalidParams("wallet already exists: \(name)")
                }
                guard params.count >= 3 else {
                    throw RPCError.invalidParams("expected: createmultisigwallet <name> <m> [mnemonic|xpriv] <xpub1,xpub2,...>")
                }
                guard let m = params[1].intValue.map({ Int($0) }), m >= 1 else {
                    throw RPCError.invalidParams("m must be a positive integer")
                }

                // Determine if a key material or xpubs come next
                let xpubsParam: [String]
                let providedSecret: String?
                if params.count >= 4,
                   let maybeSecret = params[2].stringValue,
                   !maybeSecret.hasPrefix("xpub") {
                    // params[2] is mnemonic or xpriv, params[3] is xpubs
                    providedSecret = maybeSecret
                    if let arr = params[3].arrayValue {
                        xpubsParam = arr.compactMap { $0.stringValue }
                    } else if let s = params[3].stringValue {
                        xpubsParam = s.split(separator: ",").map(String.init)
                    } else {
                        throw RPCError.invalidParams("expected cosigner xpubs")
                    }
                } else {
                    // params[2] is xpubs (no secret provided)
                    providedSecret = nil
                    if let arr = params[2].arrayValue {
                        xpubsParam = arr.compactMap { $0.stringValue }
                    } else if let s = params[2].stringValue {
                        xpubsParam = s.split(separator: ",").map(String.init)
                    } else {
                        throw RPCError.invalidParams("expected cosigner xpubs")
                    }
                }

                let walletPath = walletsDir + "/\(name)"
                let wallet = try WalletDB(path: walletPath, network: network)

                // Determine key source
                var accountKeyFromSource: ExtendedPrivateKey?
                if let sourceWalletName = req.wallet {
                    // Mode 3: --wallet mode, copy key from source
                    guard let sourceWallet = ctx.wallet(named: sourceWalletName) else {
                        throw RPCError.invalidParams("source wallet not found: \(sourceWalletName)")
                    }
                    guard sourceWallet.initialized else {
                        throw RPCError.internalError("source wallet not initialized")
                    }
                    guard let xpriv = sourceWallet.xpriv else {
                        throw RPCError.invalidParams("source wallet has no account key")
                    }
                    accountKeyFromSource = try ExtendedPrivateKey.deserialize(xpriv)
                }

                let generatedMnemonic: String?
                if let accountKey = accountKeyFromSource {
                    generatedMnemonic = try wallet.createMultisigWallet(
                        m: m, accountKey: accountKey,
                        cosignerXpubs: xpubsParam
                    )
                } else if let secret = providedSecret {
                    if secret.hasPrefix("xprv") {
                        generatedMnemonic = try wallet.createMultisigWallet(
                            m: m, xpriv: secret,
                            cosignerXpubs: xpubsParam
                        )
                    } else {
                        generatedMnemonic = try wallet.createMultisigWallet(
                            m: m, mnemonic: secret,
                            cosignerXpubs: xpubsParam
                        )
                    }
                } else {
                    generatedMnemonic = try wallet.createMultisigWallet(
                        m: m, cosignerXpubs: xpubsParam
                    )
                }

                ctx.setWallet(name, wallet)

                var result: [(String, JSONValue)] = [
                    ("name", .string(name)),
                    ("type", .string("multisig")),
                    ("m", .int(Int64(m))),
                    ("n", .int(Int64(xpubsParam.count + 1))),
                ]
                if let mnemonic = generatedMnemonic {
                    result.append(("mnemonic", .string(mnemonic)))
                }
                if let xpub = wallet.xpub {
                    result.append(("xpub", .string(xpub)))
                }
                return .object(result)
            }

        // MARK: Transaction Lifecycle

        handlers["createtx"] = { req in
                let (_, wallet, rest) = try Self.rpcResolveWallet(req, ctx: ctx)
                guard wallet.initialized else { throw RPCError.internalError("wallet not initialized") }
                let chain = try Self.requireChain(ctx)

                guard let action = rest.first?.stringValue?.lowercased(), !action.isEmpty else {
                    throw RPCError.invalidParams("expected: createtx <action> [params...]")
                }
                let args = Array(rest.dropFirst())
                let nameParams = NameParams.params(for: network)

                let pstx: PartiallySignedTx
                var pendingBids = [(opIndex: Int, nameHash: NameHash, nonce: BidNonce, value: UInt64, lockup: UInt64)]()

                switch action {
                case "none":
                    guard let addrStr = args.first?.stringValue, !addrStr.isEmpty else {
                        throw RPCError.invalidParams("createtx none: expected destination address")
                    }
                    guard args.count >= 2, let amountFBD = args[1].doubleValue, amountFBD > 0 else {
                        throw RPCError.invalidParams("createtx none: expected positive amount (FBC)")
                    }
                    let destination = try Address(bech32: addrStr, network: network)
                    let amount = UInt64(amountFBD * 1_000_000)
                    let subtractFee = args.count >= 3 && args[2].boolValue == true
                    pstx = try wallet.buildUnsignedTransaction(
                        destination: destination, amount: amount,
                        currentHeight: chain.storedHeight, subtractFee: subtractFee
                    )

                case "open":
                    guard let name = args.first?.stringValue, !name.isEmpty else {
                        throw RPCError.invalidParams("createtx open: expected name")
                    }
                    guard NameRules.verifyName(name) else {
                        throw RPCError.invalidParams("createtx open: invalid name: \(name)")
                    }
                    let nameHash = NameRules.hashName(name)
                    guard NameRules.isAvailable(nameHash: nameHash, height: chain.storedHeight, params: nameParams, rawName: Array(name.utf8)) else {
                        throw RPCError.invalidParams("createtx open: name not yet available")
                    }
                    if let ns = try chain.getNameState(name: name) {
                        let st = ns.state(at: chain.storedHeight, params: nameParams)
                        guard st == .closed && ns.isExpired(at: chain.storedHeight, params: nameParams) else {
                            throw RPCError.invalidParams("createtx open: name already in auction (state: \(st))")
                        }
                    }
                    let covenant = CovenantData.makeOpen(nameHash: nameHash, name: Array(name.utf8))
                    let addr = try wallet.getReceiveAddress()
                    pstx = try wallet.buildUnsignedCovenantTransaction(
                        covenant: covenant, value: 0, address: addr,
                        currentHeight: chain.storedHeight
                    )

                case "bid":
                    guard let name = args.first?.stringValue, !name.isEmpty else {
                        throw RPCError.invalidParams("createtx bid: expected name")
                    }
                    guard args.count >= 2, let bidFBD = args[1].doubleValue, bidFBD >= 0 else {
                        throw RPCError.invalidParams("createtx bid: expected bid amount (FBC)")
                    }
                    guard args.count >= 3, let lockupFBD = args[2].doubleValue, lockupFBD > 0 else {
                        throw RPCError.invalidParams("createtx bid: expected positive lockup amount (FBC)")
                    }
                    let bid = UInt64(bidFBD * 1_000_000)
                    let lockup = UInt64(lockupFBD * 1_000_000)
                    guard lockup >= bid else {
                        throw RPCError.invalidParams("createtx bid: lockup must be >= bid")
                    }
                    let nameHash = NameRules.hashName(name)
                    guard let ns = try chain.getNameState(name: name) else {
                        throw RPCError.invalidParams("createtx bid: name not found (send open first)")
                    }
                    let st = ns.state(at: chain.storedHeight, params: nameParams)
                    guard st == .bidding else {
                        throw RPCError.invalidParams("createtx bid: name not in bidding state (state: \(st))")
                    }
                    let createAddr = try wallet.getReceiveAddress()
                    guard let nonce = try wallet.deriveNonce(address: createAddr, nameHash: nameHash) else {
                        throw RPCError.internalError("failed to derive bid nonce")
                    }
                    let blind = try BlindBid.blind(value: bid, nonce: nonce)
                    let covenant = CovenantData.makeBid(
                        nameHash: nameHash, startHeight: ns.height,
                        name: Array(name.utf8), blind: blind
                    )
                    let addr = try wallet.getReceiveAddress()
                    pstx = try wallet.buildUnsignedCovenantTransaction(
                        covenant: covenant, value: lockup, address: addr,
                        currentHeight: chain.storedHeight
                    )
                    // Save nonce at creation time (txHash stable without witnesses)
                    pendingBids.append((opIndex: 0, nameHash: nameHash, nonce: nonce, value: bid, lockup: lockup))

                case "reveal":
                    let name = args.first?.stringValue ?? ""
                    if !name.isEmpty {
                        let nh = NameRules.hashName(name)
                        guard let ns = try chain.getNameState(name: name) else {
                            throw RPCError.invalidParams("createtx reveal: name not found: \(name)")
                        }
                        let st = ns.state(at: chain.storedHeight, params: nameParams)
                        guard st == .reveal else {
                            throw RPCError.invalidParams("createtx reveal: name not in reveal state (state: \(st))")
                        }
                        let bids = try wallet.getBidsForName(nameHash: nh)
                        guard !bids.isEmpty else {
                            throw RPCError.invalidParams("createtx reveal: no bids found for \(name)")
                        }
                        let bidCoins = try wallet.findNameCoins(nameHash: nh, covenantType: .bid)
                        var ops = [WalletDB.CovenantOp]()
                        for bid in bids {
                            guard let bidCoin = bidCoins.first(where: { $0.outpoint == bid.outpoint }) else { continue }
                            let covenant = CovenantData.makeReveal(nameHash: nh, startHeight: ns.height, nonce: bid.nonce)
                            let addr = try wallet.getReceiveAddress()
                            ops.append(WalletDB.CovenantOp(covenant: covenant, value: bid.value, address: addr, linkedCoin: bidCoin))
                        }
                        guard !ops.isEmpty else {
                            throw RPCError.invalidParams("createtx reveal: no matching bid coins found")
                        }
                        pstx = try wallet.buildUnsignedBatchTransaction(ops: ops, currentHeight: chain.storedHeight)
                    } else {
                        // Bulk reveal all
                        let allBids = try wallet.getAllBids()
                        let allCoins = try wallet.listUnspent()
                        let bidCoins = allCoins.filter { $0.covenant.type == .bid }
                        var ops = [WalletDB.CovenantOp]()
                        for bid in allBids {
                            guard let ns = try chain.getNameState(nameHash: bid.nameHash) else { continue }
                            let st = ns.state(at: chain.storedHeight, params: nameParams)
                            guard st == .reveal else { continue }
                            guard let bidCoin = bidCoins.first(where: { $0.outpoint == bid.outpoint }) else { continue }
                            let covenant = CovenantData.makeReveal(nameHash: bid.nameHash, startHeight: ns.height, nonce: bid.nonce)
                            let addr = try wallet.getReceiveAddress()
                            ops.append(WalletDB.CovenantOp(covenant: covenant, value: bid.value, address: addr, linkedCoin: bidCoin))
                        }
                        guard !ops.isEmpty else {
                            throw RPCError.invalidParams("createtx reveal: no bids found to reveal")
                        }
                        pstx = try wallet.buildUnsignedBatchTransaction(ops: ops, currentHeight: chain.storedHeight)
                    }

                case "redeem":
                    let name = args.first?.stringValue ?? ""
                    if !name.isEmpty {
                        let nh = NameRules.hashName(name)
                        guard let ns = try chain.getNameState(name: name) else {
                            throw RPCError.invalidParams("createtx redeem: name not found: \(name)")
                        }
                        let st = ns.state(at: chain.storedHeight, params: nameParams)
                        guard st == .closed else {
                            throw RPCError.invalidParams("createtx redeem: name auction not closed (state: \(st))")
                        }
                        let coins = try wallet.findNameCoins(nameHash: nh, covenantType: .reveal)
                        var ops = [WalletDB.CovenantOp]()
                        for coin in coins {
                            if let owner = ns.owner, coin.outpoint.hash.bytes == owner.hash && coin.outpoint.index == UInt32(owner.index) { continue }
                            guard let nhBytes = coin.covenant.items.first, nhBytes.count == 32,
                                  coin.covenant.items.count >= 2 else { continue }
                            let heightBytes = coin.covenant.items[1]
                            guard heightBytes.count == 4 else { continue }
                            let startHeight = Int(UInt32(heightBytes[0]) | UInt32(heightBytes[1]) << 8
                                | UInt32(heightBytes[2]) << 16 | UInt32(heightBytes[3]) << 24)
                            let covenant = CovenantData.makeRedeem(nameHash: NameHash(unchecked: nhBytes), startHeight: startHeight)
                            let addr = try wallet.getReceiveAddress()
                            ops.append(WalletDB.CovenantOp(covenant: covenant, value: 0, address: addr, linkedCoin: coin))
                        }
                        guard !ops.isEmpty else {
                            throw RPCError.invalidParams("createtx redeem: no redeemable reveals found")
                        }
                        pstx = try wallet.buildUnsignedBatchTransaction(ops: ops, currentHeight: chain.storedHeight)
                    } else {
                        let allCoins = try wallet.listUnspent()
                        let revealCoins = allCoins.filter { $0.covenant.type == .reveal }
                        var ops = [WalletDB.CovenantOp]()
                        for coin in revealCoins {
                            guard let nhBytes = coin.covenant.items.first, nhBytes.count == 32 else { continue }
                            guard let ns = try chain.getNameState(nameHash: NameHash(unchecked: nhBytes)) else { continue }
                            let st = ns.state(at: chain.storedHeight, params: nameParams)
                            guard st == .closed else { continue }
                            if let owner = ns.owner, coin.outpoint.hash.bytes == owner.hash && coin.outpoint.index == UInt32(owner.index) { continue }
                            guard coin.covenant.items.count >= 2 else { continue }
                            let heightBytes = coin.covenant.items[1]
                            guard heightBytes.count == 4 else { continue }
                            let startHeight = Int(UInt32(heightBytes[0]) | UInt32(heightBytes[1]) << 8
                                | UInt32(heightBytes[2]) << 16 | UInt32(heightBytes[3]) << 24)
                            let covenant = CovenantData.makeRedeem(nameHash: NameHash(unchecked: nhBytes), startHeight: startHeight)
                            let addr = try wallet.getReceiveAddress()
                            ops.append(WalletDB.CovenantOp(covenant: covenant, value: 0, address: addr, linkedCoin: coin))
                        }
                        guard !ops.isEmpty else {
                            throw RPCError.invalidParams("createtx redeem: no redeemable reveals found")
                        }
                        pstx = try wallet.buildUnsignedBatchTransaction(ops: ops, currentHeight: chain.storedHeight)
                    }

                case "register":
                    guard let name = args.first?.stringValue, !name.isEmpty else {
                        throw RPCError.invalidParams("createtx register: expected name")
                    }
                    let nameHash = NameRules.hashName(name)
                    guard let ns = try chain.getNameState(name: name) else {
                        throw RPCError.invalidParams("createtx register: name not found")
                    }
                    let st = ns.state(at: chain.storedHeight, params: nameParams)
                    guard st == .closed else {
                        throw RPCError.invalidParams("createtx register: name auction not closed (state: \(st))")
                    }
                    let revealCoins = try wallet.findNameCoins(nameHash: nameHash, covenantType: .reveal)
                    guard let revealCoin = revealCoins.first(where: { coin in
                        if let owner = ns.owner {
                            return coin.outpoint.hash.bytes == owner.hash && coin.outpoint.index == UInt32(owner.index)
                        }
                        return false
                    }) else {
                        throw RPCError.invalidParams("createtx register: no winning reveal found")
                    }
                    var resourceData = [UInt8]()
                    if args.count >= 2 {
                        let resource = Self.parseResourceJSON(args[1])
                        try Self.validateResource(resource, network: network)
                        resourceData = try resource.encode()
                    }
                    let renewalHeight = max(chain.storedHeight - nameParams.renewalMaturity, 0)
                    guard let renewalEntry = chain.getEntryByHeight(renewalHeight) else {
                        throw RPCError.internalError("cannot find block for renewal proof")
                    }
                    let covenant = CovenantData.makeRegister(
                        nameHash: nameHash, startHeight: ns.height,
                        resource: resourceData, blockHash: renewalEntry.hash.bytes
                    )
                    let addr = try wallet.getReceiveAddress()
                    pstx = try wallet.buildUnsignedCovenantTransaction(
                        covenant: covenant, value: revealCoin.value, address: addr,
                        linkedCoin: revealCoin, currentHeight: chain.storedHeight
                    )

                case "update":
                    guard let name = args.first?.stringValue, !name.isEmpty else {
                        throw RPCError.invalidParams("createtx update: expected name")
                    }
                    guard args.count >= 2 else {
                        throw RPCError.invalidParams("createtx update: expected resource JSON")
                    }
                    let nameHash = NameRules.hashName(name)
                    guard let ns = try chain.getNameState(name: name) else {
                        throw RPCError.invalidParams("createtx update: name not found")
                    }
                    let st = ns.state(at: chain.storedHeight, params: nameParams)
                    guard st == .closed else {
                        throw RPCError.invalidParams("createtx update: name not in closed state (state: \(st))")
                    }
                    guard let nameCoin = try wallet.findCurrentNameCoin(nameHash: nameHash) else {
                        throw RPCError.invalidParams("createtx update: no name UTXO found")
                    }
                    let resource = Self.parseResourceJSON(args[1])
                    try Self.validateResource(resource, network: network)
                    let resourceData = try resource.encode()
                    let covenant = CovenantData.makeUpdate(
                        nameHash: nameHash, startHeight: ns.height, resource: resourceData
                    )
                    pstx = try wallet.buildUnsignedCovenantTransaction(
                        covenant: covenant, value: nameCoin.value, address: nameCoin.address,
                        linkedCoin: nameCoin, currentHeight: chain.storedHeight
                    )

                case "renew":
                    let ctxCP = ConsensusParams.params(for: network)
                    let devFundAddr = CovenantProcessor.resolveDevFundAddress(nameDB: chain.nameDBRef, network: network, consensusParams: ctxCP)
                    let name = args.first?.stringValue ?? ""
                    if !name.isEmpty {
                        let nameHash = NameRules.hashName(name)
                        guard let ns = try chain.getNameState(name: name) else {
                            throw RPCError.invalidParams("createtx renew: name not found")
                        }
                        let st = ns.state(at: chain.storedHeight, params: nameParams)
                        guard st == .closed else {
                            throw RPCError.invalidParams("createtx renew: name not in closed state (state: \(st))")
                        }
                        guard let nameCoin = try wallet.findCurrentNameCoin(nameHash: nameHash) else {
                            throw RPCError.invalidParams("createtx renew: no name UTXO found")
                        }
                        let renewalHeight = max(chain.storedHeight - nameParams.renewalMaturity, 0)
                        guard let renewalEntry = chain.getEntryByHeight(renewalHeight) else {
                            throw RPCError.internalError("cannot find block for renewal proof")
                        }
                        let covenant = CovenantData.makeRenew(
                            nameHash: nameHash, startHeight: ns.height, blockHash: renewalEntry.hash.bytes
                        )
                        // Build batch tx with renewal fee output
                        var ops = [WalletDB.CovenantOp]()
                        ops.append(WalletDB.CovenantOp(covenant: covenant, value: nameCoin.value, address: nameCoin.address, linkedCoin: nameCoin))
                        let pctFee = ns.value * Int64(nameParams.renewalFeePercent) / 100
                        let minFee = nameParams.minimumBid(atHeight: chain.storedHeight, name: name)
                        let fee = max(pctFee, minFee)
                        if fee > 0 {
                            ops.append(WalletDB.CovenantOp(covenant: Covenant.none, value: UInt64(fee), address: devFundAddr))
                        }
                        pstx = try wallet.buildUnsignedBatchTransaction(ops: ops, currentHeight: chain.storedHeight)
                    } else {
                        let owned = try wallet.getOwnedNames()
                        let renewalHeight = max(chain.storedHeight - nameParams.renewalMaturity, 0)
                        guard let renewalEntry = chain.getEntryByHeight(renewalHeight) else {
                            throw RPCError.internalError("cannot find block for renewal proof")
                        }
                        var ops = [WalletDB.CovenantOp]()
                        var totalRenewalFee: Int64 = 0
                        for (nameHash, coin) in owned {
                            guard coin.covenant.type != .transfer else { continue }
                            guard let ns = try chain.getNameState(nameHash: nameHash) else { continue }
                            let st = ns.state(at: chain.storedHeight, params: nameParams)
                            guard st == .closed else { continue }
                            let covenant = CovenantData.makeRenew(
                                nameHash: nameHash, startHeight: ns.height, blockHash: renewalEntry.hash.bytes
                            )
                            ops.append(WalletDB.CovenantOp(covenant: covenant, value: coin.value, address: coin.address, linkedCoin: coin))
                            let pctFee = ns.value * Int64(nameParams.renewalFeePercent) / 100
                            let minFee = nameParams.minimumBid(atHeight: chain.storedHeight, rawName: ns.name)
                            totalRenewalFee += max(pctFee, minFee)
                        }
                        if totalRenewalFee > 0 {
                            ops.append(WalletDB.CovenantOp(covenant: Covenant.none, value: UInt64(totalRenewalFee), address: devFundAddr))
                        }
                        guard !ops.isEmpty else {
                            throw RPCError.invalidParams("createtx renew: no names to renew")
                        }
                        pstx = try wallet.buildUnsignedBatchTransaction(ops: ops, currentHeight: chain.storedHeight)
                    }

                case "transfer":
                    guard let name = args.first?.stringValue, !name.isEmpty else {
                        throw RPCError.invalidParams("createtx transfer: expected name")
                    }
                    guard args.count >= 2, let addrStr = args[1].stringValue, !addrStr.isEmpty else {
                        throw RPCError.invalidParams("createtx transfer: expected destination address")
                    }
                    let destination = try Address(bech32: addrStr, network: network)
                    let nameHash = NameRules.hashName(name)
                    guard let ns = try chain.getNameState(name: name) else {
                        throw RPCError.invalidParams("createtx transfer: name not found")
                    }
                    let st = ns.state(at: chain.storedHeight, params: nameParams)
                    guard st == .closed else {
                        throw RPCError.invalidParams("createtx transfer: name not in closed state (state: \(st))")
                    }
                    guard let nameCoin = try wallet.findCurrentNameCoin(nameHash: nameHash) else {
                        throw RPCError.invalidParams("createtx transfer: no name UTXO found")
                    }
                    let covenant = CovenantData.makeTransfer(
                        nameHash: nameHash, startHeight: ns.height,
                        version: destination.version, addressHash: destination.hash
                    )
                    let addr = try wallet.getReceiveAddress()
                    pstx = try wallet.buildUnsignedCovenantTransaction(
                        covenant: covenant, value: nameCoin.value, address: addr,
                        linkedCoin: nameCoin, currentHeight: chain.storedHeight
                    )

                case "finalize":
                    let name = args.first?.stringValue ?? ""
                    if !name.isEmpty {
                        let nameHash = NameRules.hashName(name)
                        guard let ns = try chain.getNameState(name: name) else {
                            throw RPCError.invalidParams("createtx finalize: name not found")
                        }
                        guard ns.transfer != 0 else {
                            throw RPCError.invalidParams("createtx finalize: no pending transfer")
                        }
                        guard chain.storedHeight >= ns.transfer + nameParams.transferLockup else {
                            let remaining = ns.transfer + nameParams.transferLockup - chain.storedHeight
                            throw RPCError.invalidParams("createtx finalize: transfer lockup not met (\(remaining) blocks remaining)")
                        }
                        let transferCoins = try wallet.findNameCoins(nameHash: nameHash, covenantType: .transfer)
                        guard let transferCoin = transferCoins.first else {
                            throw RPCError.invalidParams("createtx finalize: no TRANSFER UTXO found")
                        }
                        guard transferCoin.covenant.items.count >= 4 else {
                            throw RPCError.internalError("malformed TRANSFER covenant")
                        }
                        let destVersion = transferCoin.covenant.items[2]
                        let destHash = transferCoin.covenant.items[3]
                        guard destVersion.count == 1 else {
                            throw RPCError.internalError("invalid TRANSFER address version")
                        }
                        let destAddr = Address(unchecked: destVersion[0], hash: destHash)
                        let renewalHeight = max(chain.storedHeight - nameParams.renewalMaturity, 0)
                        guard let renewalEntry = chain.getEntryByHeight(renewalHeight) else {
                            throw RPCError.internalError("cannot find block for renewal proof")
                        }
                        let flags: UInt8 = ns.flags
                        let covenant = CovenantData.makeFinalize(
                            nameHash: nameHash, startHeight: ns.height,
                            name: Array(name.utf8), flags: flags,
                            claimed: 0, renewals: ns.renewals,
                            blockHash: renewalEntry.hash.bytes
                        )
                        pstx = try wallet.buildUnsignedCovenantTransaction(
                            covenant: covenant, value: transferCoin.value, address: destAddr,
                            linkedCoin: transferCoin, currentHeight: chain.storedHeight
                        )
                    } else {
                        let allCoins = try wallet.listUnspent()
                        let transferCoins = allCoins.filter { $0.covenant.type == .transfer }
                        let renewalHeight = max(chain.storedHeight - nameParams.renewalMaturity, 0)
                        guard let renewalEntry = chain.getEntryByHeight(renewalHeight) else {
                            throw RPCError.internalError("cannot find block for renewal proof")
                        }
                        var ops = [WalletDB.CovenantOp]()
                        for coin in transferCoins {
                            guard let nhBytes = coin.covenant.items.first, nhBytes.count == 32 else { continue }
                            guard let ns = try chain.getNameState(nameHash: NameHash(unchecked: nhBytes)) else { continue }
                            guard ns.transfer != 0, chain.storedHeight >= ns.transfer + nameParams.transferLockup else { continue }
                            guard coin.covenant.items.count >= 4 else { continue }
                            let destVersion = coin.covenant.items[2]
                            let destHash = coin.covenant.items[3]
                            guard destVersion.count == 1 else { continue }
                            let destAddr = Address(unchecked: destVersion[0], hash: destHash)
                            let flags: UInt8 = ns.flags
                            let covenant = CovenantData.makeFinalize(
                                nameHash: NameHash(unchecked: nhBytes), startHeight: ns.height,
                                name: ns.name, flags: flags,
                                claimed: 0, renewals: ns.renewals,
                                blockHash: renewalEntry.hash.bytes
                            )
                            ops.append(WalletDB.CovenantOp(covenant: covenant, value: coin.value, address: destAddr, linkedCoin: coin))
                        }
                        guard !ops.isEmpty else {
                            throw RPCError.invalidParams("createtx finalize: no transfers ready to finalize")
                        }
                        pstx = try wallet.buildUnsignedBatchTransaction(ops: ops, currentHeight: chain.storedHeight)
                    }

                case "revoke":
                    guard let name = args.first?.stringValue, !name.isEmpty else {
                        throw RPCError.invalidParams("createtx revoke: expected name")
                    }
                    let nameHash = NameRules.hashName(name)
                    guard let ns = try chain.getNameState(name: name) else {
                        throw RPCError.invalidParams("createtx revoke: name not found")
                    }
                    let st = ns.state(at: chain.storedHeight, params: nameParams)
                    guard st == .closed else {
                        throw RPCError.invalidParams("createtx revoke: name not in closed state (state: \(st))")
                    }
                    guard let nameCoin = try wallet.findCurrentNameCoin(nameHash: nameHash) else {
                        throw RPCError.invalidParams("createtx revoke: no name UTXO found")
                    }
                    let covenant = CovenantData.makeRevoke(nameHash: nameHash, startHeight: ns.height)
                    pstx = try wallet.buildUnsignedCovenantTransaction(
                        covenant: covenant, value: nameCoin.value, address: nameCoin.address,
                        linkedCoin: nameCoin, currentHeight: chain.storedHeight
                    )

                default:
                    throw RPCError.invalidParams("createtx: unknown action '\(action)'")
                }

                // Save pending bid nonces (txHash is stable without witnesses in FBD)
                let txHash = pstx.tx.txHash()
                for pending in pendingBids {
                    let bidOutpoint = Outpoint(hash: txHash, index: UInt32(pending.opIndex))
                    try wallet.saveBid(BidRecord(
                        nameHash: pending.nameHash, outpoint: bidOutpoint,
                        nonce: pending.nonce, value: pending.value, lockup: pending.lockup
                    ))
                }

                let hex = HexEncoding.encode(pstx.serialize())
                return .object([
                    ("pstx", .string(hex)),
                    ("inputs", .int(Int64(pstx.tx.inputs.count))),
                    ("outputs", .int(Int64(pstx.tx.outputs.count))),
                ])
            }

        handlers["signtx"] = { req in
                let (_, wallet, rest) = try Self.rpcResolveWallet(req, ctx: ctx)
                guard wallet.initialized else {
                    throw RPCError.internalError("wallet not initialized")
                }
                guard let hexStr = rest.first?.stringValue else {
                    throw RPCError.invalidParams("expected pstx hex string")
                }
                let rawBytes = try HexEncoding.decode(hexStr)
                guard let pstx = PartiallySignedTx.deserialize(rawBytes) else {
                    throw RPCError.invalidParams("invalid pstx data")
                }

                let signed = try wallet.signTransaction(pstx)

                var sigCount = 0
                for inputSigs in signed.signatures {
                    sigCount += inputSigs.filter({ !$0.isEmpty }).count
                }

                let hex = HexEncoding.encode(signed.serialize())
                return .object([
                    ("pstx", .string(hex)),
                    ("signatures", .int(Int64(sigCount))),
                ])
            }

        handlers["broadcasttx"] = { req in
                let rest = req.params
                guard let hexStr = rest.first?.stringValue else {
                    throw RPCError.invalidParams("expected pstx hex string")
                }
                let rawBytes = try HexEncoding.decode(hexStr)
                guard let pstx = PartiallySignedTx.deserialize(rawBytes) else {
                    throw RPCError.invalidParams("invalid pstx data")
                }

                let tx = try WalletDB.finalizeTransaction(pstx)
                let txHash = tx.txHash()

                if let mempool = ctx.mempool,
                   let coinDB = ctx.coinDB,
                   let chain = ctx.chain {
                    try mempool.acceptTransaction(tx, coinDB: coinDB, chainHeight: chain.tip.height, params: chain.params)
                    ctx.peerManager?.broadcastTx(txHash: txHash)
                }

                return .object([("txid", .string(txHash.hex))])
            }

        handlers["combinetx"] = { req in
                let rest = req.params
                guard let hexArray = rest.first?.arrayValue, hexArray.count >= 2 else {
                    throw RPCError.invalidParams("expected array of 2+ pstx hex strings")
                }
                let hexStrings = hexArray.compactMap { $0.stringValue }
                guard hexStrings.count == hexArray.count else {
                    throw RPCError.invalidParams("all pstx values must be hex strings")
                }

                var pstxs = [PartiallySignedTx]()
                for hex in hexStrings {
                    let rawBytes = try HexEncoding.decode(hex)
                    guard let pstx = PartiallySignedTx.deserialize(rawBytes) else {
                        throw RPCError.invalidParams("invalid pstx data")
                    }
                    pstxs.append(pstx)
                }

                let combined = try WalletDB.combineTransactions(pstxs)

                var sigCount = 0
                for inputSigs in combined.signatures {
                    sigCount += inputSigs.filter({ !$0.isEmpty }).count
                }

                let hex = HexEncoding.encode(combined.serialize())
                return .object([
                    ("pstx", .string(hex)),
                    ("signatures", .int(Int64(sigCount))),
                ])
            }

        // MARK: Wallet Actions

        handlers["getwalletactions"] = { req in
                let (_, wallet, _) = try Self.rpcResolveWallet(req, ctx: ctx)
                guard wallet.initialized else { throw RPCError.internalError("wallet not initialized") }
                let chain = try Self.requireChain(ctx)
                let nameParams = NameParams.params(for: network)
                let currentHeight = chain.storedHeight
                let renewalWarning = 4320 // ~6 days warning (same as wallet UI)

                var revealActions = [JSONValue]()
                var registerActions = [JSONValue]()
                var redeemActions = [JSONValue]()
                var renewActions = [JSONValue]()
                var finalizeActions = [JSONValue]()
                var repairActions = [JSONValue]()

                // --- Bid-based actions ---
                let allBids = try wallet.getAllBids()
                let allCoins = try wallet.listUnspent()
                let bidCoins = allCoins.filter { $0.covenant.type == .bid }
                let revealCoins = allCoins.filter { $0.covenant.type == .reveal }
                let mp = ctx.mempool

                // Track names already processed (dedup across multiple bids for same name)
                var registerNameHashes = Set<NameHash>()
                var repairNameHashes = Set<NameHash>()

                for bid in allBids {
                    let hasBidCoin = bidCoins.contains { $0.outpoint == bid.outpoint }
                    let inMempool = mp?.has(bid.outpoint.hash) ?? false
                    let hasRevealCoin = revealCoins.contains { coin in
                        guard let nh = coin.covenant.items.first else { return false }
                        return nh == bid.nameHash.bytes
                    }
                    let bidActive = hasBidCoin || inMempool
                    let isRevealed = hasRevealCoin && !bidActive
                    let needsRepair = bid.nonce == .zero && bid.value == 0

                    guard let ns = try? chain.getNameState(nameHash: bid.nameHash) else { continue }
                    let st = ns.state(at: currentHeight, params: nameParams)
                    let nameStr = String(bytes: ns.name, encoding: .utf8) ?? ""

                    // Skip bids from previous auction rounds
                    let bidCoin = bidCoins.first { $0.outpoint == bid.outpoint }
                    let coinHeight: Int
                    if let h = bidCoin?.height, h > 0 {
                        coinHeight = h
                    } else if chain.hasTxIndex, let loc = chain.getTxLocation(txHash: bid.outpoint.hash) {
                        coinHeight = loc.height
                    } else {
                        coinHeight = -1
                    }
                    if coinHeight > 0 && coinHeight < ns.height { continue }

                    // Detect forfeited bids
                    var isForfeited = false
                    if isRevealed {
                        let revealCoin = revealCoins.first { coin in
                            guard let nh = coin.covenant.items.first else { return false }
                            return nh == bid.nameHash.bytes
                        }
                        if let rc = revealCoin {
                            if rc.height > 0 && rc.height < ns.height {
                                isForfeited = true
                            } else if !ns.registered && ns.isExpired(at: currentHeight, params: nameParams) {
                                if let owner = ns.owner,
                                   rc.outpoint.hash.bytes == owner.hash &&
                                   rc.outpoint.index == UInt32(owner.index) {
                                    isForfeited = true
                                }
                            }
                        }
                    } else if hasBidCoin && coinHeight > 0 && st == .closed {
                        isForfeited = true
                    }

                    // Repair: broken bid nonce (one per name)
                    if needsRepair && !isRevealed && (st == .bidding || st == .reveal)
                        && !repairNameHashes.contains(bid.nameHash) {
                        repairNameHashes.insert(bid.nameHash)
                        repairActions.append(.object([
                            ("name", .string(nameStr)),
                            ("nameHash", .string(bid.nameHash.hex)),
                            ("lockup", .int(Int64(bid.lockup))),
                        ]))
                        continue
                    }

                    // Reveal: name in reveal state, bid not yet revealed (one per bid)
                    if st == .reveal && !isRevealed && !needsRepair && (hasBidCoin || inMempool) {
                        let deadline = ns.height + nameParams.openPeriod + nameParams.biddingPeriod + nameParams.revealPeriod
                        revealActions.append(.object([
                            ("name", .string(nameStr)),
                            ("nameHash", .string(bid.nameHash.hex)),
                            ("txid", .string(bid.outpoint.hash.hex)),
                            ("index", .int(Int64(bid.outpoint.index))),
                            ("deadline", .int(Int64(deadline))),
                        ]))
                        continue
                    }

                    // Register: auction closed, bid revealed, not registered, not expired (one per name)
                    if st == .closed && isRevealed && !isForfeited && !ns.registered
                        && !ns.isExpired(at: currentHeight, params: nameParams) && ns.owner != nil
                        && !registerNameHashes.contains(bid.nameHash) {
                        registerNameHashes.insert(bid.nameHash)
                        let deadline = ns.registerDeadlineHeight(params: nameParams)
                        registerActions.append(.object([
                            ("name", .string(nameStr)),
                            ("nameHash", .string(bid.nameHash.hex)),
                            ("deadline", .int(Int64(deadline))),
                        ]))
                        continue
                    }

                    // Redeem: auction closed, revealed, not forfeited, not expired, not a register candidate (one per bid)
                    let isRedeemed = !hasBidCoin && !isRevealed && !isForfeited && !inMempool
                    if st == .closed && isRevealed && !isForfeited && !isRedeemed
                        && !ns.isExpired(at: currentHeight + 1, params: nameParams)
                        && !registerNameHashes.contains(bid.nameHash) {
                        redeemActions.append(.object([
                            ("name", .string(nameStr)),
                            ("nameHash", .string(bid.nameHash.hex)),
                            ("value", .int(Int64(bid.lockup))),
                        ]))
                    }
                }

                // --- Owned name actions ---
                let ownedNames = try wallet.getOwnedNames()
                for (nameHash, _) in ownedNames {
                    guard let ns = try? chain.getNameState(nameHash: nameHash) else { continue }
                    let st = ns.state(at: currentHeight, params: nameParams)
                    let nameStr = String(bytes: ns.name, encoding: .utf8) ?? ""

                    // Finalize: transfer initiated
                    if ns.transfer != 0 && st == .closed {
                        let finalizeHeight = ns.transfer + nameParams.transferLockup
                        if currentHeight >= finalizeHeight {
                            finalizeActions.append(.object([
                                ("name", .string(nameStr)),
                                ("nameHash", .string(nameHash.hex)),
                            ]))
                        }
                    }

                    // Renew: approaching expiration within warning window
                    if st == .closed && ns.registered {
                        let expiresAt = ns.renewal + nameParams.renewalWindow
                        let blocksRemaining = expiresAt - currentHeight
                        if blocksRemaining > 0 && blocksRemaining <= renewalWarning {
                            renewActions.append(.object([
                                ("name", .string(nameStr)),
                                ("nameHash", .string(nameHash.hex)),
                                ("expiresAt", .int(Int64(expiresAt))),
                                ("blocksRemaining", .int(Int64(blocksRemaining))),
                            ]))
                        }
                    }
                }

                return .object([
                    ("reveal", .array(revealActions)),
                    ("register", .array(registerActions)),
                    ("redeem", .array(redeemActions)),
                    ("renew", .array(renewActions)),
                    ("finalize", .array(finalizeActions)),
                    ("repair", .array(repairActions)),
                ])
            }

        return handlers
    }
}
