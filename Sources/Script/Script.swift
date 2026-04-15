import Base

/// A parsed Bitcoin-style script (sequence of opcodes and data pushes).
public struct Script: Equatable, Sendable {
    /// The raw script bytes.
    public let raw: [UInt8]

    /// Create a script from raw bytes.
    public init(_ raw: [UInt8] = []) {
        self.raw = raw
    }

    /// Create a script from individual instructions.
    public init(building instructions: [Instruction]) {
        var bytes: [UInt8] = []
        for inst in instructions {
            switch inst {
            case .opcode(let op):
                bytes.append(op.rawValue)
            case .unknownOpcode(let byte):
                bytes.append(byte)
            case .pushData(let data):
                let count = data.count
                if count == 0 {
                    bytes.append(Opcode.OP_0.rawValue)
                } else if count <= 0x4b {
                    bytes.append(UInt8(count))
                    bytes.append(contentsOf: data)
                } else if count <= 0xFF {
                    bytes.append(Opcode.OP_PUSHDATA1.rawValue)
                    bytes.append(UInt8(count))
                    bytes.append(contentsOf: data)
                } else if count <= 0xFFFF {
                    bytes.append(Opcode.OP_PUSHDATA2.rawValue)
                    bytes.append(UInt8(count & 0xFF))
                    bytes.append(UInt8(count >> 8))
                    bytes.append(contentsOf: data)
                } else {
                    bytes.append(Opcode.OP_PUSHDATA4.rawValue)
                    bytes.append(UInt8(count & 0xFF))
                    bytes.append(UInt8((count >> 8) & 0xFF))
                    bytes.append(UInt8((count >> 16) & 0xFF))
                    bytes.append(UInt8((count >> 24) & 0xFF))
                    bytes.append(contentsOf: data)
                }
            }
        }
        self.raw = bytes
    }

    /// The number of bytes in the raw script.
    public var size: Int { raw.count }

    /// Whether the script is empty.
    public var isEmpty: Bool { raw.isEmpty }

    /// Iterate over the instructions in this script.
    public func instructions() throws -> [Instruction] {
        var result: [Instruction] = []
        var offset = 0
        while offset < raw.count {
            let byte = raw[offset]
            offset += 1

            if isDirectPush(byte) {
                let count = Int(byte)
                guard offset + count <= raw.count else {
                    throw ScriptError.invalidPushData
                }
                result.append(.pushData(Array(raw[offset..<(offset + count)])))
                offset += count
            } else if let opcode = Opcode(rawValue: byte) {
                switch opcode {
                case .OP_PUSHDATA1:
                    guard offset < raw.count else {
                        throw ScriptError.unexpectedEndOfScript
                    }
                    let count = Int(raw[offset])
                    offset += 1
                    guard offset + count <= raw.count else {
                        throw ScriptError.invalidPushData
                    }
                    result.append(.pushData(Array(raw[offset..<(offset + count)])))
                    offset += count

                case .OP_PUSHDATA2:
                    guard offset + 2 <= raw.count else {
                        throw ScriptError.unexpectedEndOfScript
                    }
                    let count = Int(raw[offset]) | (Int(raw[offset + 1]) << 8)
                    offset += 2
                    guard offset + count <= raw.count else {
                        throw ScriptError.invalidPushData
                    }
                    result.append(.pushData(Array(raw[offset..<(offset + count)])))
                    offset += count

                case .OP_PUSHDATA4:
                    guard offset + 4 <= raw.count else {
                        throw ScriptError.unexpectedEndOfScript
                    }
                    let count = Int(raw[offset])
                        | (Int(raw[offset + 1]) << 8)
                        | (Int(raw[offset + 2]) << 16)
                        | (Int(raw[offset + 3]) << 24)
                    offset += 4
                    guard offset + count <= raw.count else {
                        throw ScriptError.invalidPushData
                    }
                    result.append(.pushData(Array(raw[offset..<(offset + count)])))
                    offset += count

                default:
                    result.append(.opcode(opcode))
                }
            } else {
                // Unknown opcode byte — parseable but will fail on execution
                result.append(.unknownOpcode(byte))
            }
        }
        return result
    }

    // MARK: - Common script templates

    /// Create a P2PKH script: OP_DUP OP_BLAKE160 <hash> OP_EQUALVERIFY OP_CHECKSIG
    ///
    /// Handshake uses OP_BLAKE160 (0xc0) instead of Bitcoin's OP_HASH160 (0xa9).
    public static func p2pkh(_ hash: [UInt8]) -> Script {
        Script(building: [
            .opcode(.OP_DUP),
            .opcode(.OP_BLAKE160),
            .pushData(hash),
            .opcode(.OP_EQUALVERIFY),
            .opcode(.OP_CHECKSIG),
        ])
    }

    /// Build a standard m-of-n multisig script.
    ///
    /// Format: `OP_m <pk1> <pk2> ... <pkn> OP_n OP_CHECKMULTISIG`
    ///
    /// Public keys are sorted lexicographically (BIP67) for deterministic addresses.
    /// - Parameters:
    ///   - m: Required number of signatures (1...15).
    ///   - publicKeys: Array of 33-byte compressed public keys.
    /// - Returns: The multisig script.
    public static func multisig(m: Int, publicKeys: [[UInt8]]) -> Script {
        precondition(m >= 1 && m <= 15, "m must be 1...15")
        precondition(publicKeys.count >= m && publicKeys.count <= 15, "n must be m...15")
        for pk in publicKeys {
            precondition(pk.count == 33, "public keys must be 33 bytes (compressed)")
        }

        // BIP67: sort pubkeys lexicographically
        let sorted = publicKeys.sorted { a, b in
            for i in 0..<min(a.count, b.count) {
                if a[i] != b[i] { return a[i] < b[i] }
            }
            return a.count < b.count
        }

        var instructions: [Instruction] = []
        // OP_m (OP_1 = 0x51, so OP_m = 0x50 + m)
        instructions.append(.opcode(Opcode(rawValue: UInt8(0x50 + m))!))
        for pk in sorted {
            instructions.append(.pushData(pk))
        }
        // OP_n
        instructions.append(.opcode(Opcode(rawValue: UInt8(0x50 + sorted.count))!))
        instructions.append(.opcode(.OP_CHECKMULTISIG))
        return Script(building: instructions)
    }

    /// Parse a multisig script and extract its parameters.
    ///
    /// Returns `(m, publicKeys)` if this is a valid `OP_m <pk1>...<pkn> OP_n OP_CHECKMULTISIG`
    /// script, or nil otherwise. The returned public keys are in script order (sorted if BIP67).
    public var multisigParams: (m: Int, publicKeys: [[UInt8]])? {
        guard let insts = try? instructions() else { return nil }
        // Minimum: OP_m, pk1, OP_n, OP_CHECKMULTISIG = 4 instructions
        guard insts.count >= 4 else { return nil }

        // Last instruction must be OP_CHECKMULTISIG
        guard case .opcode(.OP_CHECKMULTISIG) = insts.last else { return nil }

        // First instruction: OP_m
        guard case .opcode(let mOp) = insts[0],
              let m = mOp.smallIntValue, m >= 1 else { return nil }

        // Second-to-last: OP_n
        guard case .opcode(let nOp) = insts[insts.count - 2],
              let n = nOp.smallIntValue, n >= 1, n <= 15 else { return nil }

        guard m <= n else { return nil }

        // Between first and second-to-last should be exactly n data pushes
        let keyInsts = insts[1..<(insts.count - 2)]
        guard keyInsts.count == n else { return nil }

        var keys = [[UInt8]]()
        for inst in keyInsts {
            guard case .pushData(let pk) = inst, pk.count == 33 else { return nil }
            keys.append(pk)
        }

        return (m: m, publicKeys: keys)
    }

    /// Whether this script matches the P2PKH template.
    public var isP2PKH: Bool {
        raw.count == 25
            && raw[0] == Opcode.OP_DUP.rawValue
            && raw[1] == Opcode.OP_BLAKE160.rawValue
            && raw[2] == 0x14  // push 20 bytes
            && raw[23] == Opcode.OP_EQUALVERIFY.rawValue
            && raw[24] == Opcode.OP_CHECKSIG.rawValue
    }

    /// Build an HTLC (hash time-locked contract) witness script for atomic swaps.
    ///
    /// Two spend paths:
    ///   - **Claim**: counterparty provides preimage `s` such that `SHA256(s) == hashlock`,
    ///     plus a signature under `claimPubkey`.
    ///   - **Refund**: originator waits until block height `locktime`, then signs under `refundPubkey`.
    ///
    /// Script layout:
    /// ```
    /// OP_IF
    ///   OP_SHA256 <hashlock> OP_EQUALVERIFY <claimPubkey> OP_CHECKSIG
    /// OP_ELSE
    ///   <locktime> OP_CLTV OP_DROP <refundPubkey> OP_CHECKSIG
    /// OP_ENDIF
    /// ```
    ///
    /// The resulting script is suitable for a P2WSH output (commitment via SHA3-256).
    /// See `swap/SPEC.md` for the full protocol.
    ///
    /// - Parameters:
    ///   - hashlock: 32-byte SHA-256 of the preimage.
    ///   - claimPubkey: 33-byte compressed secp256k1 pubkey for the claim path.
    ///   - refundPubkey: 33-byte compressed secp256k1 pubkey for the refund path.
    ///   - locktime: Absolute block height after which refund becomes valid (1...499_999_999).
    public static func htlc(
        hashlock: [UInt8],
        claimPubkey: [UInt8],
        refundPubkey: [UInt8],
        locktime: UInt32
    ) -> Script {
        precondition(hashlock.count == 32, "hashlock must be 32 bytes")
        precondition(claimPubkey.count == 33, "claim pubkey must be 33 bytes (compressed)")
        precondition(refundPubkey.count == 33, "refund pubkey must be 33 bytes (compressed)")
        precondition(locktime >= 1 && locktime < 500_000_000,
                     "locktime must be a block height (< 500,000,000)")

        return Script(building: [
            .opcode(.OP_IF),
                .opcode(.OP_SHA256),
                .pushData(hashlock),
                .opcode(.OP_EQUALVERIFY),
                .pushData(claimPubkey),
                .opcode(.OP_CHECKSIG),
            .opcode(.OP_ELSE),
                .pushData(ScriptNum.encode(Int64(locktime))),
                .opcode(.OP_CHECKLOCKTIMEVERIFY),
                .opcode(.OP_DROP),
                .pushData(refundPubkey),
                .opcode(.OP_CHECKSIG),
            .opcode(.OP_ENDIF),
        ])
    }

    /// Parse an HTLC script produced by `Script.htlc(...)` back into its parameters.
    ///
    /// Returns nil if the script does not match the exact template. Callers verifying
    /// a counterparty-provided script MUST re-build from parameters and compare bytes,
    /// rather than trusting this parser alone.
    public var htlcParams: (hashlock: [UInt8], claimPubkey: [UInt8], refundPubkey: [UInt8], locktime: UInt32)? {
        guard let insts = try? instructions(), insts.count == 13 else { return nil }

        guard case .opcode(.OP_IF) = insts[0] else { return nil }
        guard case .opcode(.OP_SHA256) = insts[1] else { return nil }
        guard case .pushData(let h) = insts[2], h.count == 32 else { return nil }
        guard case .opcode(.OP_EQUALVERIFY) = insts[3] else { return nil }
        guard case .pushData(let claimPk) = insts[4], claimPk.count == 33 else { return nil }
        guard case .opcode(.OP_CHECKSIG) = insts[5] else { return nil }
        guard case .opcode(.OP_ELSE) = insts[6] else { return nil }
        guard case .pushData(let ltBytes) = insts[7] else { return nil }
        guard case .opcode(.OP_CHECKLOCKTIMEVERIFY) = insts[8] else { return nil }
        guard case .opcode(.OP_DROP) = insts[9] else { return nil }
        guard case .pushData(let refundPk) = insts[10], refundPk.count == 33 else { return nil }
        guard case .opcode(.OP_CHECKSIG) = insts[11] else { return nil }
        guard case .opcode(.OP_ENDIF) = insts[12] else { return nil }

        guard let lt = try? ScriptNum.decode(ltBytes), lt >= 1, lt < 500_000_000 else { return nil }

        return (hashlock: h, claimPubkey: claimPk, refundPubkey: refundPk, locktime: UInt32(lt))
    }

    /// Count the number of signature operations in this script.
    public var sigops: Int {
        guard let insts = try? instructions() else { return 0 }
        var count = 0
        for (i, inst) in insts.enumerated() {
            switch inst {
            case .opcode(.OP_CHECKSIG), .opcode(.OP_CHECKSIGVERIFY):
                count += 1
            case .opcode(.OP_CHECKMULTISIG), .opcode(.OP_CHECKMULTISIGVERIFY):
                if i > 0, case .opcode(let prev) = insts[i - 1],
                   let n = prev.smallIntValue {
                    count += n
                } else {
                    count += ScriptInterpreter.maxMultisigKeys
                }
            default:
                break
            }
        }
        return count
    }
}

// MARK: - Instruction

/// A single decoded instruction from a script.
public enum Instruction: Equatable, Sendable {
    /// A standard opcode.
    case opcode(Opcode)

    /// A data push (from direct push, PUSHDATA1/2/4).
    case pushData([UInt8])

    /// An unrecognized opcode byte (parsed but fails on execution).
    case unknownOpcode(UInt8)
}

// MARK: - WireSerializable

extension Script: WireSerializable {
    public var serializedSize: Int {
        CompactSize.encodedSize(of: UInt64(raw.count)) + raw.count
    }

    public func write(to writer: inout BufferWriter) {
        writer.writeVarBytes(raw)
    }

    public static func read(from reader: inout BufferReader) throws -> Script {
        let bytes = try reader.readVarBytes()
        return Script(bytes)
    }
}
