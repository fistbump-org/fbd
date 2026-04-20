import Storage
import Foundation
import Base
import Covenants
import ExtCrypto
import Protocol
import Script
import Crypto

// MARK: - Address Derivation & Management

extension WalletDB {
    /// Get the stored mnemonic phrase for backup display.
    /// Returns nil when the wallet is encrypted and locked.
    public var mnemonic: String? {
        guard isUnlocked else { return nil }
        return storedMnemonic
    }

    /// Get the account-level extended private key (m/44'/14159'/0').
    ///
    /// Returns from cache, derives from master seed, or nil if unavailable.
    func getAccountKey() -> ExtendedPrivateKey? {
        if let key = storedAccountKey { return key }
        guard let seed = masterSeed else { return nil }
        let master = ExtendedPrivateKey.fromSeed(seed)
        guard let account = try? master.derivePath("m/44'/14159'/0'") else { return nil }
        storedAccountKey = account
        return account
    }

    /// Get the account-level extended public key (xpub at m/44'/14159'/0').
    /// Works while locked (uses stored xpub if available).
    public var xpub: String? {
        if let xpub = storedAccountXpub { return xpub.serialized() }
        guard let account = getAccountKey(),
              let pub = try? account.publicKey() else { return nil }
        return pub.serialized()
    }

    /// Get the account-level extended private key (xpriv at m/44'/14159'/0').
    /// Returns nil when the wallet is encrypted and locked.
    public var xpriv: String? {
        guard isUnlocked else { return nil }
        guard let account = getAccountKey() else { return nil }
        return account.serialized()
    }

    /// Get the account-level public key for address derivation.
    /// Works while locked (uses stored xpub).
    func getAccountPublicKey() -> ExtendedPublicKey? {
        if let xpub = storedAccountXpub { return xpub }
        guard let account = getAccountKey(),
              let pub = try? account.publicKey() else { return nil }
        return pub
    }

    /// Get the next unused receive address.
    ///
    /// Returns P2WPKH (20-byte hash) for regular wallets, P2WSH (32-byte hash) for multisig.
    /// Works while locked using xpub derivation.
    public func getReceiveAddress() throws -> Address {
        guard initialized else { throw WalletError.notInitialized }
        let idx = receiveIndex + 1
        if walletType == .multisig {
            if let account = getAccountKey() {
                return try deriveMultisigAddress(chain: 0, index: idx, account: account)
            }
            guard let pub = getAccountPublicKey() else { throw WalletError.notInitialized }
            return try deriveMultisigAddress(chain: 0, index: idx, accountPub: pub)
        }
        guard let pub = getAccountPublicKey() else { throw WalletError.notInitialized }
        let derived = try pub.derive(0).derive(UInt32(idx))
        let hash = try Blake2bHash.hash(derived.key, size: 20)
        return try Address(version: 0, hash: hash)
    }

    /// Get the next unused change address.
    ///
    /// Returns P2WPKH (20-byte hash) for regular wallets, P2WSH (32-byte hash) for multisig.
    /// Works while locked using xpub derivation.
    public func getChangeAddress() throws -> Address {
        guard initialized else { throw WalletError.notInitialized }
        let idx = changeIndex + 1
        if walletType == .multisig {
            if let account = getAccountKey() {
                return try deriveMultisigAddress(chain: 1, index: idx, account: account)
            }
            guard let pub = getAccountPublicKey() else { throw WalletError.notInitialized }
            return try deriveMultisigAddress(chain: 1, index: idx, accountPub: pub)
        }
        guard let pub = getAccountPublicKey() else { throw WalletError.notInitialized }
        let derived = try pub.derive(1).derive(UInt32(idx))
        let hash = try Blake2bHash.hash(derived.key, size: 20)
        return try Address(version: 0, hash: hash)
    }

    /// Advance the receive index and return a genuinely new receive address.
    public func advanceReceiveAddress() throws -> Address {
        guard initialized else { throw WalletError.notInitialized }
        receiveIndex += 1
        try put(db: metaDB, key: Array("usedReceive".utf8), value: intToBytes(receiveIndex))
        try ensureGap()
        if walletType == .multisig {
            if let account = getAccountKey() {
                return try deriveMultisigAddress(chain: 0, index: receiveIndex, account: account)
            }
            guard let pub = getAccountPublicKey() else { throw WalletError.notInitialized }
            return try deriveMultisigAddress(chain: 0, index: receiveIndex, accountPub: pub)
        }
        guard let pub = getAccountPublicKey() else { throw WalletError.notInitialized }
        let derived = try pub.derive(0).derive(UInt32(receiveIndex))
        let hash = try Blake2bHash.hash(derived.key, size: 20)
        return try Address(version: 0, hash: hash)
    }

    /// Advance the change index and return a genuinely new change address.
    public func advanceChangeAddress() throws -> Address {
        guard initialized else { throw WalletError.notInitialized }
        changeIndex += 1
        try put(db: metaDB, key: Array("usedChange".utf8), value: intToBytes(changeIndex))
        try ensureGap()
        if walletType == .multisig {
            if let account = getAccountKey() {
                return try deriveMultisigAddress(chain: 1, index: changeIndex, account: account)
            }
            guard let pub = getAccountPublicKey() else { throw WalletError.notInitialized }
            return try deriveMultisigAddress(chain: 1, index: changeIndex, accountPub: pub)
        }
        guard let pub = getAccountPublicKey() else { throw WalletError.notInitialized }
        let derived = try pub.derive(1).derive(UInt32(changeIndex))
        let hash = try Blake2bHash.hash(derived.key, size: 20)
        return try Address(version: 0, hash: hash)
    }

    /// Derive a single multisig address at the given chain/index (private key version).
    func deriveMultisigAddress(chain: UInt32, index: Int, account: ExtendedPrivateKey) throws -> Address {
        let localPub = try account.derive(chain).derive(UInt32(index)).compressedPublicKey.bytes
        return try deriveMultisigAddressFromPubkeys(chain: chain, index: index, localPub: localPub)
    }

    /// Derive a single multisig address at the given chain/index (public key version).
    func deriveMultisigAddress(chain: UInt32, index: Int, accountPub: ExtendedPublicKey) throws -> Address {
        let derived = try accountPub.derivePath("\(chain)/\(index)")
        return try deriveMultisigAddressFromPubkeys(chain: chain, index: index, localPub: derived.key)
    }

    /// Build a multisig address from the local pubkey and cosigner xpubs.
    private func deriveMultisigAddressFromPubkeys(chain: UInt32, index: Int, localPub: [UInt8]) throws -> Address {
        var allPubkeys = [localPub]
        for xpubStr in cosignerXpubs {
            let xpub = try ExtendedPublicKey.deserialize(xpubStr)
            let derived = try xpub.derivePath("\(chain)/\(index)")
            allPubkeys.append(derived.key)
        }
        let redeemScript = Script.multisig(m: multisigM, publicKeys: allPubkeys)
        let scriptHash = SHA3Hash.sha3_256(redeemScript.raw)
        return try Address(version: 0, hash: scriptHash.bytes)
    }

    /// The primary address (first receive address at index 0).
    public var primaryAddress: Address? {
        if walletType == .multisig {
            var found: Address?
            try? forEachEntry(db: addressesDB) { key, value in
                let path = String(bytes: value, encoding: .utf8) ?? ""
                // Multisig paths are full BIP44: m/44'/14159'/0'/0/0
                if path.hasSuffix("/0/0") {
                    guard key.count >= 2 else { return }
                    found = Address(unchecked: key[0], hash: Array(key[1...]))
                }
            }
            return found
        }
        guard initialized, let pub = getAccountPublicKey(),
              let child = try? pub.derive(0).derive(0),
              let hash = try? Blake2bHash.hash(child.key, size: 20) else {
            return nil
        }
        return Address(unchecked: 0, hash: hash)
    }

    /// List all derived addresses with their path and balance.
    public func listAddresses() throws -> [(address: Address, path: String, balance: UInt64)] {
        var result = [(address: Address, path: String, balance: UInt64)]()
        try forEachEntry(db: addressesDB) { key, value in
            guard key.count >= 2 else { return }
            let ver = key[0]
            let hash = Array(key[1...])
            let addr = Address(unchecked: ver, hash: hash)
            let path = String(bytes: value, encoding: .utf8) ?? ""
            let balance = (try? getBalance(address: addr)) ?? 0
            result.append((address: addr, path: path, balance: balance))
        }
        return result
    }

    /// Import a standalone watch address (no private key).
    public func importAddress(_ address: Address) throws {
        let addrKey = addressKeyBytes(address)
        try put(db: addressesDB, key: addrKey, value: Array("imported".utf8))
        addressSet.insert(AddressKey(address))
    }

    /// The number of tracked addresses.
    public var addressCount: Int { addressSet.count }

    /// The wallet's key derivation indices.
    public var walletIndices: (receive: Int, change: Int, nextReceive: Int, nextChange: Int) {
        (receive: receiveIndex, change: changeIndex,
         nextReceive: nextReceiveIndex, nextChange: nextChangeIndex)
    }

    /// Set wallet derivation indices and persist to metaDB.
    public func setIndices(receive: Int, change: Int, nextReceive: Int, nextChange: Int) throws {
        receiveIndex = receive
        changeIndex = change
        nextReceiveIndex = nextReceive
        nextChangeIndex = nextChange
        try put(db: metaDB, key: Array("usedReceive".utf8), value: intToBytes(receiveIndex))
        try put(db: metaDB, key: Array("usedChange".utf8), value: intToBytes(changeIndex))
        try put(db: metaDB, key: Array("nextReceive".utf8), value: intToBytes(nextReceiveIndex))
        try put(db: metaDB, key: Array("nextChange".utf8), value: intToBytes(nextChangeIndex))
    }

    /// Get all imported (non-derived) addresses.
    public func getImportedAddresses() -> [Address] {
        var result = [Address]()
        do {
            try forEachEntry(db: addressesDB) { key, value in
                let path = String(bytes: value, encoding: .utf8) ?? ""
                guard path == "imported" else { return }
                guard key.count >= 2 else { return }
                let ver = key[0]
                let hash = Array(key[1...])
                result.append(Address(unchecked: ver, hash: hash))
            }
        } catch {
            // Non-fatal: imported address scan failure doesn't block wallet operation
        }
        return result
    }

    /// Check whether an address belongs to this wallet.
    public func ismine(_ address: Address) -> Bool {
        addressSet.contains(AddressKey(address))
    }

    /// The height of the earliest wallet transaction (for backup/restore).
    ///
    /// Scans the history database for the first confirmed entry.
    /// Returns `scanHeight` if no transactions found (wallet is synced but
    /// has no on-chain activity, so no rescan needed on restore).
    public var birthHeight: Int {
        var earliest = Int.max
        do {
            try forEachEntry(db: historyDB) { key, _ in
                guard key.count == 38 else { return }
                // Key: [height:4 BE][txIndex:2 BE][txHash:32]
                let h = Int(UInt32(key[0]) << 24 | UInt32(key[1]) << 16
                    | UInt32(key[2]) << 8 | UInt32(key[3]))
                // Skip mempool entries (height == Int32.max)
                if h < earliest && h != Int(Int32.max) {
                    earliest = h
                }
            }
        } catch {
            return max(scanHeight, 0)
        }
        return earliest == Int.max ? max(scanHeight, 0) : earliest
    }

    /// Ensure addresses are derived up to the given indices.
    /// If nextReceiveIndex or nextChangeIndex is already >= the target, this is a no-op.
    public func ensureAddresses(receive targetReceive: Int, change targetChange: Int) throws {
        let neededReceive = max(targetReceive - nextReceiveIndex, 0)
        let neededChange = max(targetChange - nextChangeIndex, 0)
        if neededReceive > 0 || neededChange > 0 {
            if walletType == .multisig {
                try deriveMultisigAddresses(receive: neededReceive, change: neededChange)
            } else {
                try deriveAddresses(receive: neededReceive, change: neededChange)
            }
        }
    }

    func deriveAddresses(receive: Int, change: Int) throws {
        // Use xpub for address derivation (works while locked, and is the only
        // option for watch-only wallets).
        let useXpub = isEncrypted || walletType == .watchOnly
        var accountPriv: ExtendedPrivateKey?
        var accountPub: ExtendedPublicKey?

        if useXpub {
            guard let pub = getAccountPublicKey() else { return }
            accountPub = pub
        } else {
            guard let priv = getAccountKey() else { return }
            accountPriv = priv
        }

        var ops = [(db: UInt8, op: LevelDBStore.BatchOp)]()

        // Derive receive addresses
        for i in 0..<receive {
            let idx = nextReceiveIndex + i
            let path = "m/44'/14159'/0'/0/\(idx)"
            let pubKey: [UInt8]
            if useXpub {
                guard let pub = accountPub else { return }
                pubKey = try pub.derive(0).derive(UInt32(idx)).key
            } else {
                guard let priv = accountPriv else { return }
                let key = try priv.derive(0).derive(UInt32(idx))
                pubKey = try key.compressedPublicKey.bytes
                // Store private key (only for unencrypted wallets)
                ops.append((keysDB, .put(key: Array(path.utf8), value: key.key)))
            }
            let hash = try Blake2bHash.hash(pubKey, size: 20)
            let addr = Address(unchecked: 0, hash: hash)

            let addrKey = addressKeyBytes(addr)
            ops.append((addressesDB, .put(key: addrKey, value: Array(path.utf8))))

            addressSet.insert(AddressKey(addr))
        }
        nextReceiveIndex += receive

        // Derive change addresses
        for i in 0..<change {
            let idx = nextChangeIndex + i
            let path = "m/44'/14159'/0'/1/\(idx)"
            let pubKey: [UInt8]
            if useXpub {
                guard let pub = accountPub else { return }
                pubKey = try pub.derive(1).derive(UInt32(idx)).key
            } else {
                guard let priv = accountPriv else { return }
                let key = try priv.derive(1).derive(UInt32(idx))
                pubKey = try key.compressedPublicKey.bytes
                // Store private key (only for unencrypted wallets)
                ops.append((keysDB, .put(key: Array(path.utf8), value: key.key)))
            }
            let hash = try Blake2bHash.hash(pubKey, size: 20)
            let addr = Address(unchecked: 0, hash: hash)

            let addrKey = addressKeyBytes(addr)
            ops.append((addressesDB, .put(key: addrKey, value: Array(path.utf8))))

            addressSet.insert(AddressKey(addr))
        }
        nextChangeIndex += change

        // Persist address indices
        ops.append((metaDB, .put(key: Array("nextReceive".utf8),
                                 value: intToBytes(nextReceiveIndex))))
        ops.append((metaDB, .put(key: Array("nextChange".utf8),
                                 value: intToBytes(nextChangeIndex))))

        if !ops.isEmpty {
            try writeBatch(ops)
        }
    }

    /// Derive multisig addresses for both receive and change chains.
    ///
    /// For each index: derives local pubkey + all cosigner pubkeys, sorts BIP67,
    /// builds redeemScript, computes SHA3-256 hash, stores MultisigConfig, registers address.
    func deriveMultisigAddresses(receive: Int, change: Int) throws {
        let account = getAccountKey()
        let accountPub: ExtendedPublicKey?
        if account == nil {
            accountPub = getAccountPublicKey()
            guard accountPub != nil else { return }
        } else {
            accountPub = nil
        }

        var ops = [(db: UInt8, op: LevelDBStore.BatchOp)]()

        // Helper to derive a single multisig address at chain/idx
        func deriveOne(chainIdx: UInt32, idx: Int, path: String) throws {
            let localPub: [UInt8]
            var localPrivKey: [UInt8]?
            if let account = account {
                let localKey = try account.derive(chainIdx).derive(UInt32(idx))
                localPub = try localKey.compressedPublicKey.bytes
                localPrivKey = localKey.key
            } else {
                guard let pub = accountPub else { return }
                let derived = try pub.derivePath("\(chainIdx)/\(idx)")
                localPub = derived.key
            }
            var allPubkeys = [localPub]
            for xpubStr in cosignerXpubs {
                let xpub = try ExtendedPublicKey.deserialize(xpubStr)
                let derived = try xpub.derivePath("\(chainIdx)/\(idx)")
                allPubkeys.append(derived.key)
            }

            let n = allPubkeys.count
            let redeemScript = Script.multisig(m: multisigM, publicKeys: allPubkeys)
            let scriptHash = SHA3Hash.sha3_256(redeemScript.raw)
            let addr = try Address(version: 0, hash: scriptHash.bytes)

            // Sort pubkeys for config (match BIP67 order in script)
            let sortedPubkeys = allPubkeys.sorted { a, b in
                for i in 0..<min(a.count, b.count) {
                    if a[i] != b[i] { return a[i] < b[i] }
                }
                return a.count < b.count
            }

            var localIndices = [Int]()
            for (i, pk) in sortedPubkeys.enumerated() {
                if pk == localPub { localIndices.append(i) }
            }

            let config = MultisigConfig(
                m: multisigM, n: n, publicKeys: sortedPubkeys,
                redeemScript: redeemScript.raw, localKeyIndices: localIndices
            )

            // Store config keyed by script hash
            ops.append((scriptsDB, .put(key: scriptHash.bytes, value: config.serialize())))

            // Register address
            let addrKey = addressKeyBytes(addr)
            ops.append((addressesDB, .put(key: addrKey, value: Array(path.utf8))))

            // Store private key for the local derivation (only when available)
            if let privKey = localPrivKey {
                ops.append((keysDB, .put(key: Array(path.utf8), value: privKey)))
            }

            addressSet.insert(AddressKey(addr))
        }

        for i in 0..<receive {
            let idx = nextReceiveIndex + i
            let path = "m/44'/14159'/0'/0/\(idx)"
            try deriveOne(chainIdx: 0, idx: idx, path: path)
        }
        nextReceiveIndex += receive

        for i in 0..<change {
            let idx = nextChangeIndex + i
            let path = "m/44'/14159'/0'/1/\(idx)"
            try deriveOne(chainIdx: 1, idx: idx, path: path)
        }
        nextChangeIndex += change

        ops.append((metaDB, .put(key: Array("nextReceive".utf8),
                                 value: intToBytes(nextReceiveIndex))))
        ops.append((metaDB, .put(key: Array("nextChange".utf8),
                                 value: intToBytes(nextChangeIndex))))

        if !ops.isEmpty {
            try writeBatch(ops)
        }
    }

    func updateGapTracking(path: String) {
        // Parse path like "m/44'/14159'/0'/0/5" or "m/44'/14159'/0'/1/3"
        let parts = path.split(separator: "/")
        guard parts.count == 6 else { return }
        let chain = parts[4] // "0" or "1"
        guard let idx = Int(parts[5]) else { return }

        if chain == "0" {
            if idx > receiveIndex { receiveIndex = idx }
        } else if chain == "1" {
            if idx > changeIndex { changeIndex = idx }
        }
    }

    func ensureGap() throws {
        // Ensure we always have `lookahead` addresses ahead of the highest used index
        let targetReceive = receiveIndex + 1 + lookahead
        let receiveNeeded = targetReceive - nextReceiveIndex
        if receiveNeeded > 0 {
            if walletType == .multisig {
                try deriveMultisigAddresses(receive: receiveNeeded, change: 0)
            } else {
                try deriveAddresses(receive: receiveNeeded, change: 0)
            }
        }

        let targetChange = changeIndex + 1 + lookahead
        let changeNeeded = targetChange - nextChangeIndex
        if changeNeeded > 0 {
            if walletType == .multisig {
                try deriveMultisigAddresses(receive: 0, change: changeNeeded)
            } else {
                try deriveAddresses(receive: 0, change: changeNeeded)
            }
        }
    }

    /// Look up the private key for an address we own.
    ///
    /// - Returns: The 32-byte private key, or nil if the address is imported/watch-only.
    public func getPrivateKey(for address: Address) throws -> [UInt8]? {
        checkAutoLock()
        guard isUnlocked else { throw WalletError.walletLocked }
        let addrKey = addressKeyBytes(address)
        guard let pathData = try get(db: addressesDB, key: addrKey) else { return nil }
        guard let path = String(bytes: pathData, encoding: .utf8) else { return nil }
        if path == "imported" { return nil }
        // When encrypted+unlocked, keys are derived on-the-fly from the in-memory account key
        if isEncrypted {
            guard let account = getAccountKey() else { return nil }
            let parts = path.split(separator: "/")
            guard parts.count == 6,
                  let chain = UInt32(parts[4]),
                  let idx = UInt32(parts[5]) else { return nil }
            return try account.derive(chain).derive(idx).key
        }
        guard let keyData = try get(db: keysDB, key: Array(path.utf8)) else { return nil }
        guard keyData.count == 32 else { return nil }
        return keyData
    }

    /// Derive a deterministic bid nonce from the wallet's private key and name hash.
    /// nonce = BLAKE2b-256(privateKey || nameHash)
    /// This makes nonces recoverable after wallet reimport.
    public func deriveNonce(address: Address, nameHash: NameHash) throws -> BidNonce? {
        guard let privKey = try getPrivateKey(for: address) else { return nil }
        let bytes = try Blake2bHash.hash(privKey + nameHash.bytes, size: 32)
        return BidNonce(unchecked: bytes)
    }
}
