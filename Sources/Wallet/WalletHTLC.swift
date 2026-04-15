import Foundation
import Base
import ExtCrypto
import Protocol
import Script

// MARK: - HTLC (Hash Time-Locked Contract) Operations
//
// Used by the FBC ↔ BTC atomic swap protocol. See swap/SPEC.md for the full protocol.
//
// The wallet provides three primitives:
//   1. publicKeyForSwaps()   — expose a pubkey so a dApp can build an HTLC script.
//   2. buildUnsignedHTLCFund — send to the P2WSH address derived from the HTLC script.
//   3. signHTLCSpend         — sign a claim or refund spend against an existing HTLC output.

extension WalletDB {

    /// The secp256k1 compressed public key used for atomic swaps.
    ///
    /// Returns the wallet's primary pubkey (receive chain, index 0) in all cases.
    /// The paired private key is recoverable on-demand during signing.
    ///
    /// For multisig wallets, swaps are not supported and this throws — multisig
    /// HTLCs need a different script template (not in v1).
    public func publicKeyForSwaps() throws -> (pubkey: [UInt8], address: Address) {
        guard initialized else { throw WalletError.notInitialized }
        guard walletType == .regular else {
            throw WalletError.invalidMultisigParams
        }

        guard let pub = getAccountPublicKey() else {
            throw WalletError.notInitialized
        }
        let derived = try pub.derive(0).derive(0)
        let hash = try Blake2bHash.hash(derived.key, size: 20)
        let addr = try Address(version: 0, hash: hash)
        return (pubkey: derived.key, address: addr)
    }

    /// Build an unsigned funding transaction that pays into an HTLC P2WSH output.
    ///
    /// The P2WSH address is computed as `SHA3-256(witnessScript)`.
    ///
    /// Callers (typically the wallet extension proxying a `fundHtlc` dApp call)
    /// are responsible for verifying that `witnessScript` matches a valid
    /// `Script.htlc(...)` instance before invoking this. This function does NOT
    /// inspect the script — it just pays into whatever P2WSH commitment you give it.
    ///
    /// - Parameters:
    ///   - witnessScript: The HTLC witness script bytes (typically 97–103 bytes).
    ///   - amount: Output value in bumps.
    ///   - feeRate: Fee rate in bumps per kvB.
    ///   - currentHeight: Current chain tip height (for coinbase maturity checks).
    /// - Returns: An unsigned `PartiallySignedTx` ready for `signTransaction`.
    public func buildUnsignedHTLCFund(
        witnessScript: [UInt8],
        amount: UInt64,
        feeRate: UInt64 = 1000,
        currentHeight: Int
    ) throws -> PartiallySignedTx {
        guard witnessScript.count <= 10_000 else {
            throw WalletError.amountTooSmall  // reuse: script too large
        }
        let scriptHash = SHA3Hash.sha3_256(witnessScript)
        let htlcAddr = try Address(version: 0, hash: scriptHash.bytes)
        return try buildUnsignedTransaction(
            destination: htlcAddr,
            amount: amount,
            feeRate: feeRate,
            currentHeight: currentHeight
        )
    }

    /// Build and sign a transaction spending an HTLC output via the claim or refund branch.
    ///
    /// Produces a fully-signed `Transaction` ready for broadcast. The wallet
    /// finds the matching private key by scanning its derivation chain for the
    /// pubkey embedded in the HTLC script for the chosen branch.
    ///
    /// For the **claim** branch: the caller supplies `preimage`. The witness is
    /// `[sig, preimage, 0x01, witnessScript]` and the spending tx's `nLockTime` is 0.
    ///
    /// For the **refund** branch: the spending tx's `nLockTime` is set to the
    /// HTLC's locktime value and the input's sequence is `0xFFFFFFFE` to satisfy
    /// `OP_CHECKLOCKTIMEVERIFY`. The witness is `[sig, empty, witnessScript]`.
    ///
    /// - Parameters:
    ///   - fundingOutpoint: The HTLC output being spent.
    ///   - fundingValue: The value of that output in bumps (needed for sighash).
    ///   - witnessScript: The HTLC witness script bytes.
    ///   - branch: `.claim(preimage:)` or `.refund`.
    ///   - destination: Address receiving the swept value (minus fee).
    ///   - feeRate: Fee rate in bumps per kvB.
    /// - Returns: A fully-signed transaction.
    public func signHTLCSpend(
        fundingOutpoint: Outpoint,
        fundingValue: UInt64,
        witnessScript: [UInt8],
        branch: HTLCSpendBranch,
        destination: Address,
        feeRate: UInt64 = 1000
    ) throws -> Transaction {
        guard initialized else { throw WalletError.notInitialized }
        checkAutoLock()
        guard isUnlocked else { throw WalletError.walletLocked }

        let script = Script(witnessScript)
        guard let params = script.htlcParams else {
            throw WalletError.invalidSignature("script is not a well-formed HTLC")
        }

        // Select signing pubkey and locktime/sequence per branch.
        let targetPubkey: [UInt8]
        let txLocktime: UInt32
        let inputSequence: UInt32
        switch branch {
        case .claim:
            targetPubkey = params.claimPubkey
            txLocktime = 0
            inputSequence = 0xFFFF_FFFF
        case .refund:
            targetPubkey = params.refundPubkey
            txLocktime = params.locktime
            inputSequence = 0xFFFF_FFFE  // < 0xFFFFFFFF required for CLTV evaluation
        }

        // Find our private key for the target pubkey.
        guard let account = getAccountKey() else {
            throw WalletError.notInitialized
        }
        let privKey = try findPrivateKey(for: targetPubkey, account: account)

        // Estimate spend size for fee calculation.
        //   base tx: ~41 bytes (version + 1 input outpoint + sequence + locktime + 1 output)
        //   witness:  claim  ≈ 72 sig + 32 preimage + 1 flag + 100 script ≈ 210
        //            refund  ≈ 72 sig + 0          + 1 flag + 100 script ≈ 180
        let witnessSize: Int
        switch branch {
        case .claim:  witnessSize = 210
        case .refund: witnessSize = 180
        }
        let baseSize = 11 + 41 + (8 + 2 + 34) // version+locktime+inputs_count+outputs_count + input + output
        let weight = baseSize * 4 + witnessSize
        let vsize = (weight + 3) / 4
        let fee = UInt64(vsize) * feeRate / 1000 + 1

        guard fundingValue > fee + 500 else {
            // Leave a small buffer so we don't strand dust.
            throw WalletError.amountTooSmall
        }
        let sendValue = fundingValue - fee

        let input = Input(prevout: fundingOutpoint, sequence: inputSequence)
        let output = Output(value: sendValue, address: destination)
        let unsignedTx = Transaction(
            version: 0,
            inputs: [input],
            outputs: [output],
            locktime: txLocktime
        )

        // Sighash is computed against the witness script (the "prevScript" for P2WSH).
        let sigHash = try SigHash.compute(
            tx: unsignedTx,
            index: 0,
            prevScript: script,
            value: fundingValue,
            type: .all
        )
        let rawSig = try ECDSASigner.sign(hash: sigHash, privateKey: PrivateKey(unchecked: privKey))
        var sig = rawSig
        sig.append(0x01) // SIGHASH_ALL

        // Assemble witness stack.
        let witnessItems: [[UInt8]]
        switch branch {
        case .claim(let preimage):
            guard preimage.count == 32 else {
                throw WalletError.invalidSignature("preimage must be 32 bytes")
            }
            witnessItems = [sig, preimage, [0x01], witnessScript]
        case .refund:
            witnessItems = [sig, [], witnessScript]
        }

        return Transaction(
            version: 0,
            inputs: [input],
            outputs: [output],
            locktime: txLocktime,
            witnesses: [Witness(items: witnessItems)]
        )
    }

    // MARK: - Internal

    /// Search the account's receive and change chains for the private key whose
    /// compressed public key matches `targetPubkey`. Throws `keyNotFound` if no
    /// derivation path within the current gap produces a match.
    private func findPrivateKey(for targetPubkey: [UInt8], account: ExtendedPrivateKey) throws -> [UInt8] {
        // Scan generously past the currently used indices so we catch freshly
        // minted HTLC pubkeys the wallet hasn't advanced through yet.
        let scanLimit = max(nextReceiveIndex, nextChangeIndex) + lookahead + 1
        for chain: UInt32 in [0, 1] {
            for i in 0..<scanLimit {
                guard let key = try? account.derive(chain).derive(UInt32(i)),
                      let pub = try? key.compressedPublicKey else { continue }
                if pub.bytes == targetPubkey {
                    return key.key
                }
            }
        }
        // Represent the key's pubkey hash for the error (no Address here since
        // the script uses the pubkey, not a hashed witness-program address).
        let hash = (try? Blake2bHash.hash(targetPubkey, size: 20)) ?? [UInt8](repeating: 0, count: 20)
        throw WalletError.keyNotFound(Address(unchecked: 0, hash: hash))
    }
}

/// Which branch of the HTLC script to exercise when spending.
public enum HTLCSpendBranch: Sendable {
    /// Claim the HTLC by revealing the preimage of its hashlock.
    case claim(preimage: [UInt8])

    /// Refund the HTLC after its absolute-height timelock has passed.
    case refund
}
