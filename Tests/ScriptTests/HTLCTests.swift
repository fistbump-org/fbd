import XCTest
@testable import Script
import Base
import ExtCrypto
import Protocol

final class HTLCScriptTests: XCTestCase {

    private let sampleHashlock: [UInt8] = Array(repeating: 0xab, count: 32)
    private let sampleClaimPubkey: [UInt8] = {
        var bytes = [UInt8]()
        bytes.append(0x02)
        bytes.append(contentsOf: [UInt8](repeating: 0x11, count: 32))
        return bytes
    }()
    private let sampleRefundPubkey: [UInt8] = {
        var bytes = [UInt8]()
        bytes.append(0x03)
        bytes.append(contentsOf: [UInt8](repeating: 0x22, count: 32))
        return bytes
    }()
    private let sampleLocktime: UInt32 = 860_144

    func testHTLCScriptStructure() throws {
        let script = Script.htlc(
            hashlock: sampleHashlock,
            claimPubkey: sampleClaimPubkey,
            refundPubkey: sampleRefundPubkey,
            locktime: sampleLocktime
        )

        let insts = try script.instructions()
        XCTAssertEqual(insts.count, 13, "HTLC script must have exactly 13 instructions")

        XCTAssertEqual(insts[0], .opcode(.OP_IF))
        XCTAssertEqual(insts[1], .opcode(.OP_SHA256))
        if case .pushData(let h) = insts[2] {
            XCTAssertEqual(h, sampleHashlock)
        } else {
            XCTFail("insts[2] must be pushData(hashlock)")
        }
        XCTAssertEqual(insts[3], .opcode(.OP_EQUALVERIFY))
        if case .pushData(let pk) = insts[4] {
            XCTAssertEqual(pk, sampleClaimPubkey)
        } else {
            XCTFail("insts[4] must be pushData(claimPubkey)")
        }
        XCTAssertEqual(insts[5], .opcode(.OP_CHECKSIG))
        XCTAssertEqual(insts[6], .opcode(.OP_ELSE))
        if case .pushData(let lt) = insts[7] {
            let decoded = try ScriptNum.decode(lt)
            XCTAssertEqual(decoded, Int64(sampleLocktime))
        } else {
            XCTFail("insts[7] must be pushData(locktime)")
        }
        XCTAssertEqual(insts[8], .opcode(.OP_CHECKLOCKTIMEVERIFY))
        XCTAssertEqual(insts[9], .opcode(.OP_DROP))
        if case .pushData(let pk) = insts[10] {
            XCTAssertEqual(pk, sampleRefundPubkey)
        } else {
            XCTFail("insts[10] must be pushData(refundPubkey)")
        }
        XCTAssertEqual(insts[11], .opcode(.OP_CHECKSIG))
        XCTAssertEqual(insts[12], .opcode(.OP_ENDIF))
    }

    func testHTLCScriptRoundTrip() {
        let script = Script.htlc(
            hashlock: sampleHashlock,
            claimPubkey: sampleClaimPubkey,
            refundPubkey: sampleRefundPubkey,
            locktime: sampleLocktime
        )

        guard let params = script.htlcParams else {
            XCTFail("htlcParams must parse a well-formed HTLC script")
            return
        }
        XCTAssertEqual(params.hashlock, sampleHashlock)
        XCTAssertEqual(params.claimPubkey, sampleClaimPubkey)
        XCTAssertEqual(params.refundPubkey, sampleRefundPubkey)
        XCTAssertEqual(params.locktime, sampleLocktime)
    }

    func testHTLCScriptBytesDeterministic() {
        // Two builds with the same inputs must produce byte-identical scripts.
        // This is important because counterparties independently reconstruct
        // scripts from offer parameters and compare byte-for-byte.
        let a = Script.htlc(
            hashlock: sampleHashlock,
            claimPubkey: sampleClaimPubkey,
            refundPubkey: sampleRefundPubkey,
            locktime: sampleLocktime
        )
        let b = Script.htlc(
            hashlock: sampleHashlock,
            claimPubkey: sampleClaimPubkey,
            refundPubkey: sampleRefundPubkey,
            locktime: sampleLocktime
        )
        XCTAssertEqual(a.raw, b.raw)
    }

    func testHTLCScriptByteLayout() {
        // Lock in the exact byte layout. The expected sequence below is the
        // same one asserted by the TS `buildHTLCScript` test in
        // swap/web/core/test/script.test.ts — changing one requires
        // changing the other in the same commit.
        let script = Script.htlc(
            hashlock: sampleHashlock,
            claimPubkey: sampleClaimPubkey,
            refundPubkey: sampleRefundPubkey,
            locktime: sampleLocktime
        )

        var expected: [UInt8] = []
        expected.append(0x63)               // OP_IF
        expected.append(0xa8)               // OP_SHA256
        expected.append(0x20)               // push 32
        expected.append(contentsOf: sampleHashlock)
        expected.append(0x88)               // OP_EQUALVERIFY
        expected.append(0x21)               // push 33
        expected.append(contentsOf: sampleClaimPubkey)
        expected.append(0xac)               // OP_CHECKSIG
        expected.append(0x67)               // OP_ELSE
        // locktime = 860_144 = 0x0D_1F_F0, little-endian 3 bytes
        expected.append(contentsOf: [0x03, 0xf0, 0x1f, 0x0d])
        expected.append(0xb1)               // OP_CHECKLOCKTIMEVERIFY
        expected.append(0x75)               // OP_DROP
        expected.append(0x21)               // push 33
        expected.append(contentsOf: sampleRefundPubkey)
        expected.append(0xac)               // OP_CHECKSIG
        expected.append(0x68)               // OP_ENDIF

        XCTAssertEqual(script.raw, expected)
    }

    func testHTLCParamsRejectsNonHTLCScripts() {
        // p2pkh is not an HTLC
        let p2pkh = Script.p2pkh([UInt8](repeating: 0x00, count: 20))
        XCTAssertNil(p2pkh.htlcParams)

        // empty script is not an HTLC
        let empty = Script()
        XCTAssertNil(empty.htlcParams)

        // multisig is not an HTLC
        let ms = Script.multisig(m: 1, publicKeys: [sampleClaimPubkey])
        XCTAssertNil(ms.htlcParams)

        // Script with correct opcodes but wrong pubkey length
        let bad = Script(building: [
            .opcode(.OP_IF),
                .opcode(.OP_SHA256),
                .pushData(sampleHashlock),
                .opcode(.OP_EQUALVERIFY),
                .pushData([0xff]),          // too short
                .opcode(.OP_CHECKSIG),
            .opcode(.OP_ELSE),
                .pushData(ScriptNum.encode(1)),
                .opcode(.OP_CHECKLOCKTIMEVERIFY),
                .opcode(.OP_DROP),
                .pushData(sampleRefundPubkey),
                .opcode(.OP_CHECKSIG),
            .opcode(.OP_ENDIF),
        ])
        XCTAssertNil(bad.htlcParams)
    }

    func testP2WSHCommitmentIs32Bytes() {
        // The P2WSH address committed to by the HTLC script must be exactly 32 bytes
        // (SHA3-256), which is the P2WSH witness-program length on FBC.
        let script = Script.htlc(
            hashlock: sampleHashlock,
            claimPubkey: sampleClaimPubkey,
            refundPubkey: sampleRefundPubkey,
            locktime: sampleLocktime
        )
        let commitment = SHA3Hash.sha3_256(script.raw)
        XCTAssertEqual(commitment.bytes.count, 32)

        // And it round-trips through the Address constructor as a valid v0 P2WSH.
        XCTAssertNoThrow(try Address(version: 0, hash: commitment.bytes))
    }
}
