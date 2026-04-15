import Foundation
import Base
import Chain
import ExtCrypto
import Protocol
import RPC
import Script
@preconcurrency import Wallet

extension FullNode {

    // MARK: - HTLC RPC Handlers
    //
    // RPC surface for the FBC ↔ BTC atomic swap protocol (see swap/SPEC.md).
    //
    // These four methods together allow a dApp to:
    //   1. read the wallet's swap pubkey                   (getswappubkey)
    //   2. build the HTLC witness script deterministically (buildhtlcscript)
    //   3. fund an HTLC output                             (createhtlcfund)
    //   4. spend an HTLC via claim or refund               (signhtlcspend)

    func htlcRPCHandlers(ctx: NodeContext, network: NetworkType) -> [String: RPCDispatcher.Handler] {
        var handlers: [String: RPCDispatcher.Handler] = [:]

        // getswappubkey → returns { pubkey, address }
        //
        // Params: (none beyond optional -rpcwallet=<name> resolution)
        handlers["getswappubkey"] = { req in
            let (_, wallet, _) = try Self.rpcResolveWallet(req, ctx: ctx)
            guard wallet.initialized else {
                throw RPCError.internalError("wallet not initialized")
            }
            let (pub, addr) = try wallet.publicKeyForSwaps()
            return .object([
                ("pubkey", .string(HexEncoding.encode(pub))),
                ("address", .string(addr.toBech32(network: network))),
            ])
        }

        // parsehtlcscript <script_hex>
        //   → { hashlock, claim_pubkey, refund_pubkey, locktime, p2wsh_address }
        //   or null if the script is not a canonical HTLC.
        //
        // Useful for wallet UIs that need to render HTLC parameters in a
        // confirmation modal without re-implementing the script parser.
        handlers["parsehtlcscript"] = { req in
            guard let scriptHex = req.params.first?.stringValue else {
                throw RPCError.invalidParams("expected: parsehtlcscript <script_hex>")
            }
            let bytes = try HexEncoding.decode(scriptHex)
            let script = Script(bytes)
            guard let p = script.htlcParams else {
                return .null
            }
            let commitment = SHA3Hash.sha3_256(bytes)
            let addr = try Address(version: 0, hash: commitment.bytes)
            return .object([
                ("hashlock", .string(HexEncoding.encode(p.hashlock))),
                ("claim_pubkey", .string(HexEncoding.encode(p.claimPubkey))),
                ("refund_pubkey", .string(HexEncoding.encode(p.refundPubkey))),
                ("locktime", .int(Int64(p.locktime))),
                ("p2wsh_address", .string(addr.toBech32(network: network))),
            ])
        }

        // buildhtlcscript <hashlock> <claim_pubkey> <refund_pubkey> <locktime>
        //   → { script_hex, p2wsh_address }
        //
        // Pure helper — does not touch wallet state. Useful for callers that
        // want the canonical script bytes without reimplementing the encoder.
        handlers["buildhtlcscript"] = { req in
            let args = req.params
            guard args.count >= 4 else {
                throw RPCError.invalidParams(
                    "expected: buildhtlcscript <hashlock> <claim_pubkey> <refund_pubkey> <locktime>"
                )
            }
            guard let hashHex = args[0].stringValue,
                  let claimHex = args[1].stringValue,
                  let refundHex = args[2].stringValue else {
                throw RPCError.invalidParams("pubkeys and hashlock must be hex strings")
            }
            guard let locktimeInt = args[3].intValue, locktimeInt >= 1, locktimeInt < 500_000_000 else {
                throw RPCError.invalidParams("locktime must be a block height (1..499_999_999)")
            }
            let locktime = UInt32(locktimeInt)
            let hashlock = try HexEncoding.decode(hashHex)
            let claimPubkey = try HexEncoding.decode(claimHex)
            let refundPubkey = try HexEncoding.decode(refundHex)
            guard hashlock.count == 32 else {
                throw RPCError.invalidParams("hashlock must be 32 bytes (64 hex chars)")
            }
            guard claimPubkey.count == 33 else {
                throw RPCError.invalidParams("claim pubkey must be 33 bytes (66 hex chars, compressed)")
            }
            guard refundPubkey.count == 33 else {
                throw RPCError.invalidParams("refund pubkey must be 33 bytes (66 hex chars, compressed)")
            }

            let script = Script.htlc(
                hashlock: hashlock,
                claimPubkey: claimPubkey,
                refundPubkey: refundPubkey,
                locktime: locktime
            )
            let commitment = SHA3Hash.sha3_256(script.raw)
            let address = try Address(version: 0, hash: commitment.bytes)

            return .object([
                ("script_hex", .string(HexEncoding.encode(script.raw))),
                ("p2wsh_address", .string(address.toBech32(network: network))),
            ])
        }

        // createhtlcfund <script_hex> <amount_fbc>
        //   → { pstx, address, amount_bumps }
        //
        // Returns an unsigned PSTX that pays `amount_fbc` into the P2WSH
        // address derived from the given HTLC script. The caller should sign
        // via `signtx` and broadcast via `broadcasttx` as for a normal send.
        handlers["createhtlcfund"] = { req in
            let (_, wallet, rest) = try Self.rpcResolveWallet(req, ctx: ctx)
            guard wallet.initialized else {
                throw RPCError.internalError("wallet not initialized")
            }
            let chain = try Self.requireChain(ctx)

            guard rest.count >= 2 else {
                throw RPCError.invalidParams("expected: createhtlcfund <script_hex> <amount_fbc>")
            }
            guard let scriptHex = rest[0].stringValue else {
                throw RPCError.invalidParams("script_hex must be a hex string")
            }
            guard let amountFBC = rest[1].doubleValue, amountFBC > 0 else {
                throw RPCError.invalidParams("amount must be a positive number of FBC")
            }
            let witnessScript = try HexEncoding.decode(scriptHex)
            guard Script(witnessScript).htlcParams != nil else {
                throw RPCError.invalidParams(
                    "script_hex does not match the canonical HTLC template — refusing to fund"
                )
            }
            let amount = UInt64(amountFBC * 1_000_000)

            let pstx = try wallet.buildUnsignedHTLCFund(
                witnessScript: witnessScript,
                amount: amount,
                currentHeight: chain.storedHeight
            )

            let commitment = SHA3Hash.sha3_256(witnessScript)
            let htlcAddr = try Address(version: 0, hash: commitment.bytes)

            return .object([
                ("pstx", .string(HexEncoding.encode(pstx.serialize()))),
                ("address", .string(htlcAddr.toBech32(network: network))),
                ("amount_bumps", .int(Int64(amount))),
            ])
        }

        // signhtlcspend <funding_txid> <funding_vout> <funding_amount_bumps>
        //               <script_hex> <branch> <destination> <fee_rate>
        //               [preimage_hex]
        //   → { tx_hex, txid }
        //
        // `branch` is "claim" or "refund".
        // `preimage_hex` is required when branch == "claim".
        // The returned tx is fully signed. Caller broadcasts via `sendrawtransaction`.
        handlers["signhtlcspend"] = { req in
            let (_, wallet, rest) = try Self.rpcResolveWallet(req, ctx: ctx)
            guard wallet.initialized else {
                throw RPCError.internalError("wallet not initialized")
            }

            guard rest.count >= 7 else {
                throw RPCError.invalidParams(
                    "expected: signhtlcspend <funding_txid> <funding_vout> <funding_amount_bumps> <script_hex> <branch> <destination> <fee_rate> [preimage_hex]"
                )
            }
            guard let txidHex = rest[0].stringValue else {
                throw RPCError.invalidParams("funding_txid must be hex")
            }
            guard let voutInt = rest[1].intValue, voutInt >= 0, voutInt <= Int64(UInt32.max) else {
                throw RPCError.invalidParams("funding_vout must be a non-negative integer")
            }
            guard let amountBumps = rest[2].intValue, amountBumps > 0 else {
                throw RPCError.invalidParams("funding_amount_bumps must be a positive integer")
            }
            guard let scriptHex = rest[3].stringValue else {
                throw RPCError.invalidParams("script_hex must be hex")
            }
            guard let branchStr = rest[4].stringValue?.lowercased() else {
                throw RPCError.invalidParams("branch must be \"claim\" or \"refund\"")
            }
            guard let destStr = rest[5].stringValue else {
                throw RPCError.invalidParams("destination must be a bech32 address")
            }
            guard let feeRateInt = rest[6].intValue, feeRateInt > 0 else {
                throw RPCError.invalidParams("fee_rate must be a positive integer (bumps per kvB)")
            }

            let txidBytes = try HexEncoding.decode(txidHex)
            guard txidBytes.count == 32 else {
                throw RPCError.invalidParams("funding_txid must be 32 bytes (64 hex chars)")
            }
            let outpoint = Outpoint(hash: Hash256(unchecked: txidBytes), index: UInt32(voutInt))
            let witnessScript = try HexEncoding.decode(scriptHex)
            let destination = try Address(bech32: destStr, network: network)

            let branch: HTLCSpendBranch
            switch branchStr {
            case "claim":
                guard rest.count >= 8, let preimageHex = rest[7].stringValue else {
                    throw RPCError.invalidParams("claim branch requires preimage_hex")
                }
                let preimage = try HexEncoding.decode(preimageHex)
                guard preimage.count == 32 else {
                    throw RPCError.invalidParams("preimage must be 32 bytes (64 hex chars)")
                }
                branch = .claim(preimage: preimage)
            case "refund":
                branch = .refund
            default:
                throw RPCError.invalidParams("branch must be \"claim\" or \"refund\"")
            }

            let signedTx = try wallet.signHTLCSpend(
                fundingOutpoint: outpoint,
                fundingValue: UInt64(amountBumps),
                witnessScript: witnessScript,
                branch: branch,
                destination: destination,
                feeRate: UInt64(feeRateInt)
            )

            return .object([
                ("tx_hex", .string(HexEncoding.encode(signedTx.serializedData()))),
                ("txid", .string(signedTx.txHash().hex)),
            ])
        }

        return handlers
    }
}
