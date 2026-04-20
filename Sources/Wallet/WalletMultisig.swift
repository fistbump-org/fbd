import Storage
import Foundation
import Base
import Consensus
import ExtCrypto
import Protocol
import Script
import Crypto

// MARK: - Multisig Operations

extension WalletDB {
    /// Create a multisig address from local and cosigner keys.
    ///
    /// Derives the local public key at `0/<derivationIndex>` (receive chain),
    /// combines with cosigner xpubs derived at the same path, sorts keys (BIP67),
    /// builds the redeem script, and stores the configuration.
    ///
    /// - Parameters:
    ///   - m: Required number of signatures.
    ///   - cosignerXpubs: Base58Check-encoded xpub strings from cosigners.
    ///   - derivationIndex: The receive chain index to derive (e.g. 0).
    /// - Returns: The multisig address and redeem script.
    public func createMultisig(
        m: Int,
        cosignerXpubs: [String],
        derivationIndex: Int
    ) throws -> (address: Address, redeemScript: [UInt8]) {
        guard initialized, let account = getAccountKey() else {
            throw WalletError.notInitialized
        }

        // Derive local pubkey at receive chain 0/<index>
        let localPriv = try account.derive(0).derive(UInt32(derivationIndex))
        let localPub = try localPriv.compressedPublicKey.bytes

        // Parse cosigner xpubs and derive at 0/<index>
        var allPubkeys = [localPub]
        for xpubStr in cosignerXpubs {
            let xpub = try ExtendedPublicKey.deserialize(xpubStr)
            let derived = try xpub.derivePath("0/\(derivationIndex)")
            allPubkeys.append(derived.key)
        }

        let n = allPubkeys.count
        guard m >= 1, m <= n, n <= 15 else {
            throw WalletError.invalidMultisigParams
        }

        // Build redeem script (sorts keys via BIP67 internally)
        let redeemScript = Script.multisig(m: m, publicKeys: allPubkeys)

        // Compute address: SHA3-256 of redeemScript -> 32-byte P2WSH hash
        let scriptHash = SHA3Hash.sha3_256(redeemScript.raw)
        let address = try Address(version: 0, hash: scriptHash.bytes)

        // Sort pubkeys for storage (match script order)
        let sortedPubkeys = allPubkeys.sorted { a, b in
            for i in 0..<min(a.count, b.count) {
                if a[i] != b[i] { return a[i] < b[i] }
            }
            return a.count < b.count
        }

        // Determine which sorted indices are ours
        var localIndices = [Int]()
        for (i, pk) in sortedPubkeys.enumerated() {
            if pk == localPub { localIndices.append(i) }
        }

        let config = MultisigConfig(
            m: m, n: n, publicKeys: sortedPubkeys,
            redeemScript: redeemScript.raw,
            localKeyIndices: localIndices
        )

        // Store config keyed by script hash
        try put(db: scriptsDB, key: scriptHash.bytes, value: config.serialize())

        // Register address so block scanning picks up coins
        let addrKey = addressKeyBytes(address)
        try put(db: addressesDB, key: addrKey, value: Array("multisig".utf8))
        addressSet.insert(AddressKey(address))

        return (address: address, redeemScript: redeemScript.raw)
    }

    /// List all stored multisig configurations.
    public func listMultisig() throws -> [(address: Address, config: MultisigConfig)] {
        var results = [(address: Address, config: MultisigConfig)]()
        try forEachEntry(db: scriptsDB) { key, value in
            guard key.count == 32 else { return }
            guard let config = MultisigConfig.deserialize(value) else { return }
            let addr = Address(unchecked: 0, hash: key)
            results.append((address: addr, config: config))
        }
        return results
    }

    /// Look up a MultisigConfig by its P2WSH address hash (32 bytes).
    public func getMultisigConfig(addressHash: [UInt8]) throws -> MultisigConfig? {
        guard addressHash.count == 32 else { return nil }
        guard let data = try get(db: scriptsDB, key: addressHash) else { return nil }
        return MultisigConfig.deserialize(data)
    }

    /// Select spendable P2WSH (multisig) coins to cover the target amount plus fees.
    func selectMultisigCoins(target: UInt64, feeRate: UInt64, currentHeight: Int, witnessSize: Int) throws -> (coins: [WalletCoin], totalInput: UInt64) {
        let allCoins = try listUnspent()

        let spendable = allCoins.filter { coin in
            guard !coin.covenant.type.isNonspendable else { return false }
            if coin.coinbase {
                guard coin.height >= 0 else { return false }
                let confirmations = currentHeight - coin.height
                guard confirmations >= ConsensusParams.params(for: network).coinbaseMaturity else { return false }
            }
            // P2WSH only: version 0, 32-byte hash
            guard coin.address.version == 0, coin.address.hash.count == 32 else { return false }
            return true
        }

        guard !spendable.isEmpty else {
            if allCoins.isEmpty {
                throw WalletError.insufficientFunds(have: 0, need: target)
            }
            throw WalletError.noSpendableCoins
        }

        let sorted = spendable.sorted { $0.value > $1.value }
        var selected = [WalletCoin]()
        var total: UInt64 = 0

        for coin in sorted {
            selected.append(coin)
            total += coin.value

            let fee = estimateMultisigFee(inputCount: selected.count, outputCount: 2, feeRate: feeRate, witnessPerInput: witnessSize)
            if total >= target + fee {
                return (coins: selected, totalInput: total)
            }
        }

        let fee = estimateMultisigFee(inputCount: selected.count, outputCount: 2, feeRate: feeRate, witnessPerInput: witnessSize)
        throw WalletError.insufficientFunds(have: total, need: target + fee)
    }

    /// Estimate fee for a multisig transaction with custom witness size per input.
    func estimateMultisigFee(inputCount: Int, outputCount: Int, feeRate: UInt64, witnessPerInput: Int) -> UInt64 {
        let baseOverhead = 10
        let inputBase = 40 * inputCount
        let outputBase = 32 * outputCount
        let witnessSize = witnessPerInput * inputCount
        let baseSize = baseOverhead + inputBase + outputBase
        let weight = baseSize * 4 + witnessSize
        let vsize = (weight + 3) / 4
        return UInt64(vsize) * feeRate / 1000 + 1
    }

    /// Estimate multisig witness size for this wallet's configuration.
    ///
    /// Uses the first available multisig config, or a conservative default.
    func estimateMultisigWitnessSizeForWallet() -> Int {
        if let configs = try? listMultisig(), let first = configs.first {
            return estimateMultisigWitnessSize(config: first.config)
        }
        // Conservative default for 2-of-3
        return 256
    }

    /// Estimate the witness size for a multisig input.
    ///
    /// Witness: [OP_0_dummy(1), sig1(73), sig2(73), redeemScript(~105)]
    /// Plus varint lengths for each item.
    func estimateMultisigWitnessSize(config: MultisigConfig) -> Int {
        // item count varint(1) + OP_0 dummy(1+1) + m signatures(1+73 each) + redeemScript(varint + len)
        let itemCount = 1 + config.m + 1  // dummy + m sigs + script
        var size = compactSizeLen(UInt64(itemCount))
        size += 1 + 1  // varint(1) + empty dummy byte(1)
        size += config.m * (1 + 73)  // varint(1) + DER sig + sighash byte (max 73)
        size += compactSizeLen(UInt64(config.redeemScript.count)) + config.redeemScript.count
        return size
    }

    /// Create a partially-signed multisig transaction.
    ///
    /// Selects P2WSH coins, builds the transaction, signs with local keys only,
    /// and returns a `PartiallySignedTx` for cosigner exchange.
    public func createMultisigTransaction(
        destination: Address,
        amount: UInt64,
        feeRate: UInt64 = 1000,
        currentHeight: Int
    ) throws -> PartiallySignedTx {
        guard initialized, let account = getAccountKey() else {
            throw WalletError.notInitialized
        }
        guard amount > 0 else { throw WalletError.amountTooSmall }

        // We need to find a config to estimate witness size; use the first available
        let allMultisig = try listMultisig()
        guard let firstConfig = allMultisig.first?.config else {
            throw WalletError.noMultisigConfigs
        }

        let witnessSize = estimateMultisigWitnessSize(config: firstConfig)
        let (coins, totalInput) = try selectMultisigCoins(
            target: amount, feeRate: feeRate,
            currentHeight: currentHeight, witnessSize: witnessSize
        )

        // Look up config for each input
        var configs = [MultisigConfig]()
        for coin in coins {
            guard let config = try getMultisigConfig(addressHash: coin.address.hash) else {
                throw WalletError.noMultisigConfigs
            }
            configs.append(config)
        }

        // Build inputs
        let inputs = coins.map { Input(prevout: $0.outpoint) }

        // Compute fee with actual configs
        let actualWitnessSize = configs.map { estimateMultisigWitnessSize(config: $0) }.max() ?? witnessSize
        let fee = estimateMultisigFee(inputCount: coins.count, outputCount: 2, feeRate: feeRate, witnessPerInput: actualWitnessSize)

        // Build outputs
        var outputs = [Output]()
        outputs.append(Output(value: amount, address: destination))

        guard totalInput >= amount + fee else {
            throw WalletError.insufficientFunds(have: totalInput, need: amount + fee)
        }
        let change = totalInput - amount - fee
        if change > 500 {
            // Send change back to multisig address (first input's address)
            outputs.append(Output(value: change, address: coins[0].address))
        }

        // Build unsigned transaction (empty witnesses)
        let unsignedTx = Transaction(
            version: 0,
            inputs: inputs,
            outputs: outputs,
            locktime: 0,
            witnesses: inputs.map { _ in Witness.empty }
        )

        // Initialize empty signature slots
        var signatures = [[[UInt8]]]()
        for config in configs {
            signatures.append([[UInt8]](repeating: [], count: config.n))
        }

        let optConfigs: [MultisigConfig?] = configs.map { $0 }
        var pstx = PartiallySignedTx(
            tx: unsignedTx, coins: coins,
            configs: optConfigs, signatures: signatures,
            pubkeys: [[UInt8]?](repeating: nil, count: coins.count)
        )

        // Sign with local keys
        pstx = try signMultisigTransaction(pstx, account: account)

        return pstx
    }

    /// Sign a partially-signed multisig transaction with this wallet's local keys.
    ///
    /// For each input, finds local key indices and produces signatures.
    public func signMultisigTransaction(_ pstx: PartiallySignedTx) throws -> PartiallySignedTx {
        guard initialized, let account = getAccountKey() else {
            throw WalletError.notInitialized
        }
        checkAutoLock()
        guard isUnlocked else { throw WalletError.walletLocked }
        return try signMultisigTransaction(pstx, account: account)
    }

    /// Internal signing with a known account key (P2WSH inputs only).
    func signMultisigTransaction(_ pstx: PartiallySignedTx, account: ExtendedPrivateKey) throws -> PartiallySignedTx {
        var updatedSigs = pstx.signatures

        for (inputIdx, optConfig) in pstx.configs.enumerated() {
            guard let config = optConfig else { continue } // skip P2WPKH inputs
            let coin = pstx.coins[inputIdx]
            let prevScript = Script(config.redeemScript)

            let sigHash = try SigHash.compute(
                tx: pstx.tx,
                index: inputIdx,
                prevScript: prevScript,
                value: coin.value,
                type: .all
            )

            // Try to sign with each key position
            for keyIdx in 0..<config.n {
                // Skip if already signed at this position
                guard updatedSigs[inputIdx][keyIdx].isEmpty else { continue }

                let targetPubkey = config.publicKeys[keyIdx]

                // Try all derivation paths to find a matching key
                // Check receive chain indices 0..nextReceiveIndex
                var privKey: [UInt8]?
                for i in 0..<nextReceiveIndex {
                    if let key = try? account.derive(0).derive(UInt32(i)),
                       let pub = try? key.compressedPublicKey,
                       pub.bytes == targetPubkey {
                        privKey = key.key
                        break
                    }
                }
                // Check change chain indices
                if privKey == nil {
                    for i in 0..<nextChangeIndex {
                        if let key = try? account.derive(1).derive(UInt32(i)),
                           let pub = try? key.compressedPublicKey,
                           pub.bytes == targetPubkey {
                            privKey = key.key
                            break
                        }
                    }
                }

                if let privKey = privKey {
                    let sig = try ECDSASigner.sign(hash: sigHash, privateKey: PrivateKey(unchecked: privKey))
                    var sigWithType = sig
                    sigWithType.append(0x01) // SIGHASH_ALL
                    updatedSigs[inputIdx][keyIdx] = sigWithType
                }
            }
        }

        return PartiallySignedTx(
            tx: pstx.tx, coins: pstx.coins,
            configs: pstx.configs, signatures: updatedSigs,
            pubkeys: pstx.pubkeys
        )
    }

    /// Combine signatures from two or more partially-signed transactions.
    ///
    /// Merges non-empty sigs and pubkeys across all PSTXs.
    public static func combineTransactions(_ pstxs: [PartiallySignedTx]) throws -> PartiallySignedTx {
        guard let first = pstxs.first else { throw WalletError.invalidMultisigParams }
        var combined = first.signatures
        var combinedPubkeys = first.pubkeys
        for p in pstxs.dropFirst() {
            for i in 0..<min(combined.count, p.signatures.count) {
                for j in 0..<min(combined[i].count, p.signatures[i].count) {
                    if combined[i][j].isEmpty && !p.signatures[i][j].isEmpty {
                        combined[i][j] = p.signatures[i][j]
                    }
                }
            }
            for i in 0..<min(combinedPubkeys.count, p.pubkeys.count) {
                if combinedPubkeys[i] == nil && p.pubkeys[i] != nil {
                    combinedPubkeys[i] = p.pubkeys[i]
                }
            }
        }
        return PartiallySignedTx(
            tx: first.tx, coins: first.coins,
            configs: first.configs, signatures: combined,
            pubkeys: combinedPubkeys
        )
    }

    /// Legacy combine for backwards compatibility (instance method, 2 args).
    public func combineMultisigSignatures(_ a: PartiallySignedTx, _ b: PartiallySignedTx) throws -> PartiallySignedTx {
        try Self.combineTransactions([a, b])
    }

    /// Finalize a partially-signed transaction by assembling complete witnesses.
    ///
    /// - P2WPKH inputs: witness = `[sig, pubkey]`
    /// - P2WSH inputs: witness = `[OP_0_dummy, sig1, ..., sigM, redeemScript]`
    ///
    /// Static method -- no wallet access needed (pubkeys embedded in PSTX).
    public static func finalizeTransaction(_ pstx: PartiallySignedTx) throws -> Transaction {
        var witnesses = [Witness]()

        for (inputIdx, optConfig) in pstx.configs.enumerated() {
            if let config = optConfig {
                // P2WSH: collect m signatures, verifying each against its pubkey
                let coin = pstx.coins[inputIdx]
                let prevScript = Script(config.redeemScript)

                var validSigs = [[UInt8]]()
                for (keyIdx, sig) in pstx.signatures[inputIdx].enumerated() {
                    if !sig.isEmpty {
                        // Verify signature against the corresponding pubkey
                        let rawSig = Array(sig.dropLast())
                        let sigType = SigHashType(UInt32(sig.last!))
                        let sigHash = try SigHash.compute(
                            tx: pstx.tx, index: inputIdx,
                            prevScript: prevScript, value: coin.value, type: sigType
                        )
                        let pubkey = config.publicKeys[keyIdx]
                        let valid = (try? ECDSASigner.verify(
                            signature: rawSig, hash: sigHash,
                            publicKey: PublicKey(pubkey)
                        )) ?? false
                        guard valid else {
                            throw WalletError.invalidSignature(
                                "key \(keyIdx) input \(inputIdx): signature does not match pubkey"
                            )
                        }
                        validSigs.append(sig)
                    }
                    if validSigs.count == config.m { break }
                }

                guard validSigs.count >= config.m else {
                    throw WalletError.insufficientSignatures(
                        have: validSigs.count, need: config.m, input: inputIdx
                    )
                }

                var items = [[UInt8]]()
                items.append([])  // OP_0 dummy for CHECKMULTISIG off-by-one
                for sig in validSigs {
                    items.append(sig)
                }
                items.append(config.redeemScript)
                witnesses.append(Witness(items: items))
            } else {
                // P2WPKH: need sig + pubkey
                let sig = pstx.signatures[inputIdx].first ?? []
                guard !sig.isEmpty else {
                    throw WalletError.insufficientSignatures(have: 0, need: 1, input: inputIdx)
                }
                guard let pubkey = pstx.pubkeys[inputIdx], pubkey.count == 33 else {
                    throw WalletError.insufficientSignatures(have: 1, need: 1, input: inputIdx)
                }
                witnesses.append(Witness(items: [sig, pubkey]))
            }
        }

        return Transaction(
            version: pstx.tx.version,
            inputs: pstx.tx.inputs,
            outputs: pstx.tx.outputs,
            locktime: pstx.tx.locktime,
            witnesses: witnesses
        )
    }

    /// Legacy finalize for backwards compatibility (instance method).
    public func finalizeMultisigTransaction(_ pstx: PartiallySignedTx) throws -> Transaction {
        try Self.finalizeTransaction(pstx)
    }

    // MARK: - Unsigned Transaction Builders

    /// Build an unsigned transaction sending FBC to a destination address.
    ///
    /// Returns a `PartiallySignedTx` with empty signatures and pubkeys ready for signing.
    public func buildUnsignedTransaction(
        destination: Address,
        amount: UInt64,
        feeRate: UInt64 = 1000,
        currentHeight: Int,
        subtractFee: Bool = false
    ) throws -> PartiallySignedTx {
        guard initialized else { throw WalletError.notInitialized }
        guard amount > 0 else { throw WalletError.amountTooSmall }

        let isMultisig = walletType == .multisig

        // Select coins based on wallet type
        let coins: [WalletCoin]
        let totalInput: UInt64
        if isMultisig {
            let witnessSize = estimateMultisigWitnessSizeForWallet()
            (coins, totalInput) = try selectMultisigCoins(
                target: amount, feeRate: feeRate,
                currentHeight: currentHeight, witnessSize: witnessSize
            )
        } else {
            (coins, totalInput) = try selectCoins(target: amount, feeRate: feeRate, currentHeight: currentHeight, subtractFee: subtractFee)
        }

        let inputs = coins.map { Input(prevout: $0.outpoint) }

        // Compute fee from actual transaction size
        let changeAddr = try getChangeAddress()
        let fee = computeFee(
            inputs: inputs,
            covenantOutput: Output(value: amount, address: destination),
            changeAddr: changeAddr, totalInput: totalInput,
            value: amount, feeRate: feeRate, isMultisig: isMultisig
        )

        let sendAmount: UInt64
        if subtractFee {
            guard amount > fee else { throw WalletError.amountTooSmall }
            sendAmount = amount - fee
        } else {
            sendAmount = amount
        }

        var outputs = [Output]()
        outputs.append(Output(value: sendAmount, address: destination))

        guard totalInput >= sendAmount + fee else {
            throw WalletError.insufficientFunds(have: totalInput, need: sendAmount + fee)
        }
        let change = totalInput - sendAmount - fee
        if change > 500 {
            outputs.append(Output(value: change, address: changeAddr))
        }

        let unsignedTx = Transaction(
            version: 0,
            inputs: inputs,
            outputs: outputs,
            locktime: 0
        )

        return try makePSTX(tx: unsignedTx, coins: coins)
    }

    /// Build an unsigned covenant transaction.
    public func buildUnsignedCovenantTransaction(
        covenant: Covenant,
        value: UInt64,
        address: Address,
        linkedCoin: WalletCoin? = nil,
        feeRate: UInt64 = 1000,
        currentHeight: Int
    ) throws -> PartiallySignedTx {
        guard initialized else { throw WalletError.notInitialized }

        let isMultisig = walletType == .multisig

        var selectedCoins = [WalletCoin]()
        var totalInput: UInt64 = 0
        if let linked = linkedCoin {
            selectedCoins.append(linked)
            totalInput += linked.value
        }

        let extraBytes = max(covenantSize(covenant) - 2, 0)

        if isMultisig {
            let witnessSize = estimateMultisigWitnessSizeForWallet()
            let baseFee = estimateMultisigFee(inputCount: selectedCoins.count + 1, outputCount: 2, feeRate: feeRate, witnessPerInput: witnessSize)
            let needed = value + baseFee
            if totalInput < needed {
                let shortfall = needed - totalInput
                let (fundingCoins, fundingTotal) = try selectMultisigCoins(
                    target: shortfall, feeRate: feeRate,
                    currentHeight: currentHeight, witnessSize: witnessSize
                )
                selectedCoins.append(contentsOf: fundingCoins)
                totalInput += fundingTotal
            }
        } else {
            let baseFee = estimateFee(inputCount: selectedCoins.count + 1, outputCount: 2, feeRate: feeRate, extraOutputBytes: extraBytes)
            let needed = value + baseFee
            if totalInput < needed {
                let shortfall = needed - totalInput
                let (fundingCoins, fundingTotal) = try selectCoins(target: shortfall, feeRate: feeRate, currentHeight: currentHeight)
                selectedCoins.append(contentsOf: fundingCoins)
                totalInput += fundingTotal
            }
        }

        let inputs = selectedCoins.map { Input(prevout: $0.outpoint) }

        // Build outputs with estimated fee, then recompute from actual tx size
        let changeAddr = try getChangeAddress()
        let fee = computeFee(inputs: inputs, covenantOutput: Output(value: value, address: address, covenant: covenant), changeAddr: changeAddr, totalInput: totalInput, value: value, feeRate: feeRate, isMultisig: isMultisig)

        var outputs = [Output]()
        outputs.append(Output(value: value, address: address, covenant: covenant))

        guard totalInput >= value + fee else {
            throw WalletError.insufficientFunds(have: totalInput, need: value + fee)
        }
        let change = totalInput - value - fee
        if change > 500 {
            outputs.append(Output(value: change, address: changeAddr))
        }

        let unsignedTx = Transaction(
            version: 0,
            inputs: inputs,
            outputs: outputs,
            locktime: 0
        )

        return try makePSTX(tx: unsignedTx, coins: selectedCoins)
    }

    /// Build an unsigned batch covenant transaction.
    public func buildUnsignedBatchTransaction(
        ops: [CovenantOp],
        feeRate: UInt64 = 1000,
        currentHeight: Int
    ) throws -> PartiallySignedTx {
        guard initialized else { throw WalletError.notInitialized }
        guard !ops.isEmpty else { throw WalletError.amountTooSmall }

        let isMultisig = walletType == .multisig

        var selectedCoins = [WalletCoin]()
        var totalInput: UInt64 = 0
        var linkedOutpoints = Set<String>()
        for op in ops {
            if let linked = op.linkedCoin {
                selectedCoins.append(linked)
                totalInput += linked.value
                linkedOutpoints.insert("\(linked.outpoint.hash.hex):\(linked.outpoint.index)")
            }
        }

        let totalOutputValue = ops.reduce(UInt64(0)) { $0 + $1.value }
        let outputCount = ops.count + 1
        var extraBytes = 0
        for op in ops {
            extraBytes += max(covenantSize(op.covenant) - 2, 0)
        }

        if isMultisig {
            let witnessSize = estimateMultisigWitnessSizeForWallet()
            let baseFee = estimateMultisigFee(inputCount: selectedCoins.count + 1, outputCount: outputCount, feeRate: feeRate, witnessPerInput: witnessSize)
            let needed = totalOutputValue + baseFee
            if totalInput < needed {
                let shortfall = needed - totalInput
                let (fundingCoins, fundingTotal) = try selectMultisigCoins(
                    target: shortfall, feeRate: feeRate,
                    currentHeight: currentHeight, witnessSize: witnessSize
                )
                selectedCoins.append(contentsOf: fundingCoins)
                totalInput += fundingTotal
            }
        } else {
            let baseFee = estimateFee(inputCount: selectedCoins.count + 1, outputCount: outputCount, feeRate: feeRate, extraOutputBytes: extraBytes)
            let needed = totalOutputValue + baseFee
            if totalInput < needed {
                let shortfall = needed - totalInput
                let (fundingCoins, fundingTotal) = try selectCoins(target: shortfall, feeRate: feeRate, currentHeight: currentHeight, excluding: linkedOutpoints)
                selectedCoins.append(contentsOf: fundingCoins)
                totalInput += fundingTotal
            }
        }

        let inputs = selectedCoins.map { Input(prevout: $0.outpoint) }

        // Build outputs: covenant ops stay individual, plain payments (burn/fee)
        // are consolidated per address to reduce output count in batch txs.
        let changeAddr = try getChangeAddress()
        var covenantOutputs = [Output]()
        var paymentTotals: [(address: Address, value: UInt64)] = []
        for op in ops {
            if op.covenant.type != .none {
                // Covenant output — must be its own output
                covenantOutputs.append(Output(value: op.value, address: op.address, covenant: op.covenant))
            } else if op.value > 0 {
                // Plain payment (burn, dev fund, ancestor) — consolidate by address
                if let idx = paymentTotals.firstIndex(where: { $0.address == op.address }) {
                    paymentTotals[idx].value += op.value
                } else {
                    paymentTotals.append((address: op.address, value: op.value))
                }
            }
        }
        for payment in paymentTotals {
            covenantOutputs.append(Output(value: payment.value, address: payment.address))
        }
        let dummyChange = Output(value: 0, address: changeAddr)
        let tx2 = Transaction(version: 0, inputs: inputs,
                              outputs: covenantOutputs + [dummyChange], locktime: 0)
        let witnessPerInput = isMultisig ? estimateMultisigWitnessSizeForWallet() : 101
        let witnessTotal = witnessPerInput * inputs.count
        let weight2 = tx2.baseSize * 4 + witnessTotal
        let vsize2 = (weight2 + 3) / 4
        var fee = UInt64(vsize2) * feeRate / 1000 + 1

        // Check if change would be dust -- if so, recompute without change output
        guard totalInput >= totalOutputValue + fee else {
            throw WalletError.insufficientFunds(have: totalInput, need: totalOutputValue + fee)
        }
        let change = totalInput - totalOutputValue - fee
        if change <= 500 {
            let tx1 = Transaction(version: 0, inputs: inputs, outputs: covenantOutputs, locktime: 0)
            let weight1 = tx1.baseSize * 4 + witnessTotal
            let vsize1 = (weight1 + 3) / 4
            fee = UInt64(vsize1) * feeRate / 1000 + 1
        }

        var outputs = covenantOutputs
        guard totalInput >= totalOutputValue + fee else {
            throw WalletError.insufficientFunds(have: totalInput, need: totalOutputValue + fee)
        }
        let finalChange = totalInput - totalOutputValue - fee
        if finalChange > 500 {
            outputs.append(Output(value: finalChange, address: changeAddr))
        }

        let unsignedTx = Transaction(
            version: 0,
            inputs: inputs,
            outputs: outputs,
            locktime: 0
        )

        return try makePSTX(tx: unsignedTx, coins: selectedCoins)
    }

    /// Build a PartiallySignedTx from an unsigned transaction and its input coins.
    ///
    /// For multisig wallets: populates configs from scriptsDB for P2WSH coins.
    /// For regular wallets: configs are nil (P2WPKH).
    func makePSTX(tx: Transaction, coins: [WalletCoin]) throws -> PartiallySignedTx {
        var configs = [MultisigConfig?]()
        var signatures = [[[UInt8]]]()
        var pubkeys = [[UInt8]?]()

        for coin in coins {
            if coin.address.hash.count == 32,
               let config = try getMultisigConfig(addressHash: coin.address.hash) {
                // P2WSH input
                configs.append(config)
                signatures.append([[UInt8]](repeating: [], count: config.n))
                pubkeys.append(nil)
            } else {
                // P2WPKH input
                configs.append(nil)
                signatures.append([[]])
                pubkeys.append(nil)
            }
        }

        return PartiallySignedTx(
            tx: tx, coins: coins, configs: configs,
            signatures: signatures, pubkeys: pubkeys
        )
    }

    // MARK: - Unified Signing

    /// Sign a partially-signed transaction with this wallet's keys.
    ///
    /// - P2WPKH inputs: look up private key by address, sign, store sig + pubkey.
    /// - P2WSH inputs: find local keys by matching pubkeys, sign at correct positions.
    public func signTransaction(_ pstx: PartiallySignedTx) throws -> PartiallySignedTx {
        guard initialized else { throw WalletError.notInitialized }
        guard walletType != .watchOnly else { throw WalletError.watchOnly }
        checkAutoLock()
        guard isUnlocked else { throw WalletError.walletLocked }

        var updatedSigs = pstx.signatures
        var updatedPubkeys = pstx.pubkeys

        for (inputIdx, optConfig) in pstx.configs.enumerated() {
            let coin = pstx.coins[inputIdx]

            if let config = optConfig {
                // P2WSH: sign with account key (same as signMultisigTransaction)
                guard let account = getAccountKey() else { continue }
                let prevScript = Script(config.redeemScript)
                let sigHash = try SigHash.compute(
                    tx: pstx.tx, index: inputIdx,
                    prevScript: prevScript, value: coin.value, type: .all
                )

                for keyIdx in 0..<config.n {
                    guard updatedSigs[inputIdx][keyIdx].isEmpty else { continue }
                    let targetPubkey = config.publicKeys[keyIdx]

                    var privKey: [UInt8]?
                    for i in 0..<nextReceiveIndex {
                        if let key = try? account.derive(0).derive(UInt32(i)),
                           let pub = try? key.compressedPublicKey,
                           pub.bytes == targetPubkey {
                            privKey = key.key
                            break
                        }
                    }
                    if privKey == nil {
                        for i in 0..<nextChangeIndex {
                            if let key = try? account.derive(1).derive(UInt32(i)),
                               let pub = try? key.compressedPublicKey,
                               pub.bytes == targetPubkey {
                                privKey = key.key
                                break
                            }
                        }
                    }

                    if let privKey = privKey {
                        let sig = try ECDSASigner.sign(hash: sigHash, privateKey: PrivateKey(unchecked: privKey))
                        var sigWithType = sig
                        sigWithType.append(0x01)
                        updatedSigs[inputIdx][keyIdx] = sigWithType
                    }
                }
            } else {
                // P2WPKH: look up private key by address
                guard let privKey = try getPrivateKey(for: coin.address) else { continue }
                let pubKey = try ECDSASigner.publicKey(from: privKey)
                let prevScript = Script.p2pkh(coin.address.hash)
                let sigHash = try SigHash.compute(
                    tx: pstx.tx, index: inputIdx,
                    prevScript: prevScript, value: coin.value, type: .all
                )
                let sig = try ECDSASigner.sign(hash: sigHash, privateKey: PrivateKey(unchecked: privKey))
                var sigWithType = sig
                sigWithType.append(0x01)
                updatedSigs[inputIdx] = [sigWithType]
                updatedPubkeys[inputIdx] = pubKey.bytes
            }
        }

        return PartiallySignedTx(
            tx: pstx.tx, coins: pstx.coins,
            configs: pstx.configs, signatures: updatedSigs,
            pubkeys: updatedPubkeys
        )
    }

    // MARK: - Transaction Building Convenience

    /// Create a signed transaction sending FBC to a destination address.
    ///
    /// Convenience method: builds unsigned -> signs -> finalizes in one call.
    public func createTransaction(
        destination: Address,
        amount: UInt64,
        feeRate: UInt64 = 1000,
        currentHeight: Int,
        subtractFee: Bool = false
    ) throws -> Transaction {
        let pstx = try buildUnsignedTransaction(
            destination: destination, amount: amount,
            feeRate: feeRate, currentHeight: currentHeight,
            subtractFee: subtractFee
        )
        let signed = try signTransaction(pstx)
        return try Self.finalizeTransaction(signed)
    }

    /// Create a signed covenant transaction.
    ///
    /// Convenience method: builds unsigned -> signs -> finalizes in one call.
    public func createCovenantTransaction(
        covenant: Covenant,
        value: UInt64,
        address: Address,
        linkedCoin: WalletCoin? = nil,
        feeRate: UInt64 = 1000,
        currentHeight: Int
    ) throws -> Transaction {
        let pstx = try buildUnsignedCovenantTransaction(
            covenant: covenant, value: value, address: address,
            linkedCoin: linkedCoin, feeRate: feeRate,
            currentHeight: currentHeight
        )
        let signed = try signTransaction(pstx)
        return try Self.finalizeTransaction(signed)
    }

    /// A single operation within a batch covenant transaction.
    public struct CovenantOp: Sendable {
        /// The covenant for this output.
        public let covenant: Covenant
        /// The output value in bumps.
        public let value: UInt64
        /// The output address.
        public let address: Address
        /// Required input for linked covenants (e.g. REVEAL must spend BID).
        public let linkedCoin: WalletCoin?

        public init(covenant: Covenant, value: UInt64, address: Address, linkedCoin: WalletCoin? = nil) {
            self.covenant = covenant
            self.value = value
            self.address = address
            self.linkedCoin = linkedCoin
        }
    }

    /// Create a signed batch covenant transaction.
    ///
    /// Convenience method: builds unsigned -> signs -> finalizes in one call.
    public func createBatchCovenantTransaction(
        ops: [CovenantOp],
        feeRate: UInt64 = 1000,
        currentHeight: Int
    ) throws -> Transaction {
        let pstx = try buildUnsignedBatchTransaction(
            ops: ops, feeRate: feeRate, currentHeight: currentHeight
        )
        let signed = try signTransaction(pstx)
        return try Self.finalizeTransaction(signed)
    }

    // MARK: - Multisig Wallet Creation

    /// Create a multisig wallet.
    ///
    /// The local wallet's key is always included as a signer. Cosigner xpubs are the OTHER parties.
    /// Total n = cosignerXpubs.count + 1.
    ///
    /// Three key derivation modes:
    /// 1. `accountKey` provided (from existing wallet)
    /// 2. `mnemonic` or `xpriv` provided explicitly
    /// 3. Neither -> auto-generates a fresh 24-word mnemonic (returned for backup)
    ///
    /// - Returns: The mnemonic if one was generated, nil otherwise.
    @discardableResult
    public func createMultisigWallet(
        m: Int,
        mnemonic: String? = nil,
        xpriv: String? = nil,
        accountKey: ExtendedPrivateKey? = nil,
        cosignerXpubs xpubs: [String],
        passphrase: String = ""
    ) throws -> String? {
        guard !initialized else {
            throw WalletError.alreadyInitialized
        }

        let n = xpubs.count + 1
        guard m >= 1, m <= n, n <= 15 else {
            throw WalletError.invalidMultisigParams
        }

        // Validate cosigner xpubs
        for xpubStr in xpubs {
            _ = try ExtendedPublicKey.deserialize(xpubStr)
        }

        var generatedMnemonic: String?

        if let accountKey = accountKey {
            // Mode 1: copy from existing wallet
            storedAccountKey = accountKey
            try put(db: metaDB, key: Array("accountKey".utf8), value: serializeAccountKey(accountKey))
        } else if let xpriv = xpriv {
            // Mode 2a: explicit xpriv
            try importXprivInternal(xpriv)
        } else if let mnemonic = mnemonic {
            // Mode 2b: explicit mnemonic
            guard BIP39.validateMnemonic(mnemonic) else {
                throw WalletError.invalidMnemonic
            }
            let seed = BIP39.toSeed(mnemonic: mnemonic, passphrase: passphrase)
            masterSeed = seed
            storedMnemonic = mnemonic
            try put(db: metaDB, key: Array("seed".utf8), value: seed)
            try put(db: metaDB, key: Array("mnemonic".utf8), value: Array(mnemonic.utf8))
        } else {
            // Mode 3: auto-generate
            let phrase = BIP39.generateMnemonic(strength: 256)
            let seed = BIP39.toSeed(mnemonic: phrase, passphrase: passphrase)
            masterSeed = seed
            storedMnemonic = phrase
            try put(db: metaDB, key: Array("seed".utf8), value: seed)
            try put(db: metaDB, key: Array("mnemonic".utf8), value: Array(phrase.utf8))
            generatedMnemonic = phrase
        }

        // Store wallet type metadata
        walletType = .multisig
        multisigM = m
        cosignerXpubs = xpubs

        try put(db: metaDB, key: Array("walletType".utf8), value: [WalletType.multisig.rawValue])
        try put(db: metaDB, key: Array("multisigM".utf8), value: intToBytes(m))
        try put(db: metaDB, key: Array("cosignerXpubs".utf8), value: Array(xpubs.joined(separator: "\n").utf8))
        try put(db: metaDB, key: Array("height".utf8), value: intToBytes(-1))

        // Store account xpub for public-key-only address derivation
        if let account = getAccountKey(), let pub = try? account.publicKey() {
            storedAccountXpub = pub
            try put(db: metaDB, key: Array("accountXpub".utf8), value: Array(pub.serialized().utf8))
        }

        // Derive initial multisig addresses
        try deriveMultisigAddresses(receive: lookahead, change: lookahead)

        initialized = true
        try put(db: metaDB, key: Array("initialized".utf8), value: [1])

        return generatedMnemonic
    }

    /// Internal xpriv import (shared between importXpriv and createMultisigWallet).
    func importXprivInternal(_ xpriv: String) throws {
        let accountKey = try ExtendedPrivateKey.deserialize(xpriv)
        storedAccountKey = accountKey
        try put(db: metaDB, key: Array("accountKey".utf8), value: serializeAccountKey(accountKey))
    }
}
