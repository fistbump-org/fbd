import Storage
import Foundation
import Base
import Covenants
import Protocol

// MARK: - Name & Bid Operations

extension WalletDB {
    /// Save a bid record (nonce) before broadcasting the BID transaction.
    ///
    /// If a record already exists with a non-zero nonce and the new record
    /// has a zero nonce, the write is skipped to prevent overwriting good
    /// data with a placeholder.
    public func saveBid(_ bid: BidRecord) throws {
        // Key: nameHash(32) + txHash(32) + vout(4) = 68 bytes
        var kw = BufferWriter(capacity: 68)
        kw.writeBytes(bid.nameHash.bytes)
        kw.writeBytes(bid.outpoint.hash.bytes)
        kw.writeUInt32LE(bid.outpoint.index)

        // Never overwrite a real nonce with zeros
        if bid.nonce == .zero {
            if let existing = try get(db: bidsDB, key: kw.data) {
                if let old = parseBidEntry(key: kw.data, value: existing), old.nonce != .zero {
                    return
                }
            }
        }

        // Value: nonce(32) + value(8) + lockup(8) + height(4) = 52 bytes
        var vw = BufferWriter(capacity: 52)
        vw.writeBytes(bid.nonce.bytes)
        vw.writeUInt64LE(bid.value)
        vw.writeUInt64LE(bid.lockup)
        vw.writeUInt32LE(UInt32(bitPattern: Int32(bid.height)))

        try put(db: bidsDB, key: kw.data, value: vw.data)
    }

    /// Parse a bid record from a raw 68-byte key and 48 or 52-byte value.
    private func parseBidEntry(key: [UInt8], value: [UInt8]) -> BidRecord? {
        guard key.count == 68, (value.count == 48 || value.count == 52) else { return nil }
        var kr = BufferReader(key)
        guard let nameHashBytes = try? kr.readBytes(32),
              let txHash = try? kr.readBytes(32),
              let idx = try? kr.readUInt32LE() else { return nil }
        var vr = BufferReader(value)
        guard let nonce = try? vr.readBytes(32),
              let bidVal = try? vr.readUInt64LE(),
              let lockup = try? vr.readUInt64LE() else { return nil }
        let height: Int = value.count >= 52 ? Int(Int32(bitPattern: (try? vr.readUInt32LE()) ?? 0)) : 0
        return BidRecord(
            nameHash: NameHash(unchecked: nameHashBytes),
            outpoint: Outpoint(hash: Hash256(unchecked: txHash), index: idx),
            nonce: BidNonce(unchecked: nonce), value: bidVal, lockup: lockup, height: height
        )
    }

    /// Get all bid records for a given name hash.
    public func getBidsForName(nameHash: NameHash) throws -> [BidRecord] {
        var results = [BidRecord]()
        try forEachEntry(db: bidsDB) { key, value in
            guard let bid = parseBidEntry(key: key, value: value),
                  bid.nameHash == nameHash else { return }
            results.append(bid)
        }
        return results
    }

    /// Remove a bid record by name hash and outpoint.
    public func removeBid(nameHash: NameHash, outpoint: Outpoint) throws {
        var kw = BufferWriter(capacity: 68)
        kw.writeBytes(nameHash.bytes)
        kw.writeBytes(outpoint.hash.bytes)
        kw.writeUInt32LE(outpoint.index)
        try store.delete(db: bidsDB, key: kw.data)
    }

    /// Get all bid records across all names.
    public func getAllBids() throws -> [BidRecord] {
        var results = [BidRecord]()
        try forEachEntry(db: bidsDB) { key, value in
            guard let bid = parseBidEntry(key: key, value: value) else { return }
            results.append(bid)
        }
        return results
    }

    /// Get wallet UTXOs grouped by name -- one coin per unique nameHash for ownership types.
    ///
    /// Returns the most advanced covenant per name (highest rawValue wins),
    /// since earlier covenant outputs (e.g. OPEN) can remain unspent.
    public func getOwnedNames() throws -> [(nameHash: NameHash, coin: WalletCoin)] {
        let nameTypes: Set<CovenantType> = [.register, .update, .renew, .transfer, .finalize]
        let all = try listUnspent()
        var best: [NameHash: WalletCoin] = [:]
        for coin in all {
            guard nameTypes.contains(coin.covenant.type) else { continue }
            guard let nhBytes = coin.covenant.items.first, nhBytes.count == 32 else { continue }
            let nameHash = NameHash(unchecked: nhBytes)
            if let existing = best[nameHash] {
                if coin.covenant.type.rawValue > existing.covenant.type.rawValue {
                    best[nameHash] = coin
                }
            } else {
                best[nameHash] = coin
            }
        }
        return best.map { (nameHash: $0.key, coin: $0.value) }
    }

    /// Find wallet coins matching a specific covenant type and name hash.
    ///
    /// Scans all wallet UTXOs, returning those whose covenant type matches
    /// and whose first item (nameHash) matches the given hash.
    public func findNameCoins(nameHash: NameHash, covenantType: CovenantType) throws -> [WalletCoin] {
        let all = try listUnspent()
        return all.filter { coin in
            guard coin.covenant.type == covenantType else { return false }
            guard let item0 = coin.covenant.items.first else { return false }
            return item0 == nameHash.bytes
        }
    }

    /// Find the current name UTXO -- the most recent coin for this name
    /// from the set of covenant types that represent "ownership".
    public func findCurrentNameCoin(nameHash: NameHash) throws -> WalletCoin? {
        // FINALIZE is the incoming side of a transfer: after the old owner
        // broadcasts sendfinalize, the new owner's UTXO is type FINALIZE
        // until they do their first UPDATE/RENEW/TRANSFER, so it must count
        // as ownership here.
        let ownerTypes: Set<CovenantType> = [.register, .update, .renew, .transfer, .finalize]
        let all = try listUnspent()
        return all.first { coin in
            guard ownerTypes.contains(coin.covenant.type) else { return false }
            guard let item0 = coin.covenant.items.first else { return false }
            return item0 == nameHash.bytes
        }
    }
}
