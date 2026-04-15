import XCTest
@testable import Net
import Base
import ExtCrypto
import Protocol

// MARK: - PacketType Tests

final class PacketTypeTests: XCTestCase {

    func testAllTypes() {
        XCTAssertEqual(PacketType.version.rawValue, 0)
        XCTAssertEqual(PacketType.verack.rawValue, 1)
        XCTAssertEqual(PacketType.ping.rawValue, 2)
        XCTAssertEqual(PacketType.pong.rawValue, 3)
        XCTAssertEqual(PacketType.getaddr.rawValue, 4)
        XCTAssertEqual(PacketType.addr.rawValue, 5)
        XCTAssertEqual(PacketType.inv.rawValue, 6)
        XCTAssertEqual(PacketType.getdata.rawValue, 7)
        XCTAssertEqual(PacketType.notfound.rawValue, 8)
        XCTAssertEqual(PacketType.getblocks.rawValue, 9)
        XCTAssertEqual(PacketType.getheaders.rawValue, 10)
        XCTAssertEqual(PacketType.headers.rawValue, 11)
        XCTAssertEqual(PacketType.sendheaders.rawValue, 12)
        XCTAssertEqual(PacketType.block.rawValue, 13)
        XCTAssertEqual(PacketType.tx.rawValue, 14)
        XCTAssertEqual(PacketType.reject.rawValue, 15)
        XCTAssertEqual(PacketType.mempool.rawValue, 16)
        XCTAssertEqual(PacketType.getproof.rawValue, 26)
        XCTAssertEqual(PacketType.proof.rawValue, 27)
    }

    func testTotalTypeCount() {
        XCTAssertEqual(PacketType.allCases.count, 31)
    }
}

// MARK: - ServiceFlags Tests

final class ServiceFlagsTests: XCTestCase {

    func testNetworkFlag() {
        let flags: ServiceFlags = .network
        XCTAssertEqual(flags.rawValue, 1)
        XCTAssertTrue(flags.contains(.network))
        XCTAssertFalse(flags.contains(.bloom))
    }

    func testBloomFlag() {
        let flags: ServiceFlags = .bloom
        XCTAssertEqual(flags.rawValue, 2)
    }

    func testCombinedFlags() {
        let flags: ServiceFlags = [.network, .bloom]
        XCTAssertEqual(flags.rawValue, 3)
        XCTAssertTrue(flags.contains(.network))
        XCTAssertTrue(flags.contains(.bloom))
    }

    func testLocalServices() {
        XCTAssertTrue(ServiceFlags.localServices.contains(.network))
    }
}

// MARK: - PacketFramer Tests

final class PacketFramerTests: XCTestCase {

    func testEncodeDecodeHeader() throws {
        let payload: [UInt8] = [1, 2, 3, 4, 5]
        let frame = PacketFramer.encode(
            type: .ping,
            payload: payload,
            network: .main
        )

        // Header = 9 bytes + 5 bytes payload
        XCTAssertEqual(frame.count, 14)

        let header = try PacketFramer.decodeHeader(frame, network: .main)
        XCTAssertEqual(header.type, .ping)
        XCTAssertEqual(header.payloadSize, 5)
    }

    func testBadMagic() {
        let frame = PacketFramer.encode(type: .ping, payload: [], network: .main)
        XCTAssertThrowsError(try PacketFramer.decodeHeader(frame, network: .testnet)) { error in
            if case NetError.badMagic = error {} else {
                XCTFail("Expected badMagic error")
            }
        }
    }

    func testEmptyPayload() throws {
        let frame = PacketFramer.encode(type: .verack, payload: [], network: .regtest)
        XCTAssertEqual(frame.count, 9)

        let header = try PacketFramer.decodeHeader(frame, network: .regtest)
        XCTAssertEqual(header.type, .verack)
        XCTAssertEqual(header.payloadSize, 0)
    }

    func testMagicValues() throws {
        // Verify the FBD magic bytes are correct
        for network in NetworkType.allCases {
            let frame = PacketFramer.encode(type: .version, payload: [], network: network)
            let header = try PacketFramer.decodeHeader(frame, network: network)
            XCTAssertEqual(header.type, .version)
        }
    }
}

// MARK: - Packet Serialization Tests

final class PacketTests: XCTestCase {

    func testPingPongRoundTrip() throws {
        let nonce: [UInt8] = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]
        let ping = PingPacket(nonce: nonce)
        let encoded = ping.encode()
        XCTAssertEqual(encoded.count, 8)

        let decoded = try PingPacket.decode(from: encoded)
        XCTAssertEqual(decoded.nonce, nonce)

        // Same data works as pong
        let pong = try PongPacket.decode(from: encoded)
        XCTAssertEqual(pong.nonce, nonce)
    }

    func testVersionRoundTrip() throws {
        let ver = VersionPacket(
            version: 3,
            services: 1,
            time: 1000,
            remote: NetAddress(time: 500, services: 1, port: 32867),
            nonce: [UInt8](repeating: 0xAA, count: 8),
            agent: "/fbd:test/",
            height: 100,
            noRelay: true
        )

        let encoded = ver.encode()
        let decoded = try VersionPacket.decode(from: encoded)

        XCTAssertEqual(decoded.version, 3)
        XCTAssertEqual(decoded.services, 1)
        XCTAssertEqual(decoded.time, 1000)
        XCTAssertEqual(decoded.nonce, [UInt8](repeating: 0xAA, count: 8))
        XCTAssertEqual(decoded.agent, "/fbd:test/")
        XCTAssertEqual(decoded.height, 100)
        XCTAssertTrue(decoded.noRelay)
    }

    func testInvRoundTrip() throws {
        let items = [
            InvItem(type: .tx, hash: Hash256(unchecked: [UInt8](repeating: 0x11, count: 32))),
            InvItem(type: .block, hash: Hash256(unchecked: [UInt8](repeating: 0x22, count: 32))),
        ]
        let inv = InvPacket(items: items)
        let encoded = inv.encode()
        let decoded = try InvPacket.decode(from: encoded)

        XCTAssertEqual(decoded.items.count, 2)
        XCTAssertEqual(decoded.items[0].type, .tx)
        XCTAssertEqual(decoded.items[1].type, .block)
    }

    func testGetDataSharesInvFormat() throws {
        let items = [InvItem(type: .tx, hash: .zero)]
        let getData = GetDataPacket(items: items)
        let encoded = getData.encode()
        let decoded = try GetDataPacket.decode(from: encoded)
        XCTAssertEqual(decoded.items.count, 1)
    }

    func testGetBlocksRoundTrip() throws {
        let locator = [
            Hash256(unchecked: [UInt8](repeating: 0xAA, count: 32)),
            Hash256(unchecked: [UInt8](repeating: 0xBB, count: 32)),
        ]
        let stop = Hash256(unchecked: [UInt8](repeating: 0xCC, count: 32))
        let pkt = GetBlocksPacket(locator: locator, stop: stop)
        let encoded = pkt.encode()
        let decoded = try GetBlocksPacket.decode(from: encoded)

        XCTAssertEqual(decoded.locator.count, 2)
        XCTAssertEqual(decoded.locator[0], locator[0])
        XCTAssertEqual(decoded.stop, stop)
    }

    func testRejectRoundTrip() throws {
        let reject = RejectPacket(
            message: PacketType.tx.rawValue,
            code: RejectCode.dust.rawValue,
            reason: "output too small",
            hash: Hash256(unchecked: [UInt8](repeating: 0xDD, count: 32))
        )
        let encoded = reject.encode()
        let decoded = try RejectPacket.decode(from: encoded)

        XCTAssertEqual(decoded.message, PacketType.tx.rawValue)
        XCTAssertEqual(decoded.code, RejectCode.dust.rawValue)
        XCTAssertEqual(decoded.reason, "output too small")
        XCTAssertEqual(decoded.hash, reject.hash)
    }

    func testFeeFilterRoundTrip() throws {
        let pkt = FeeFilterPacket(rate: 5000)
        let encoded = pkt.encode()
        XCTAssertEqual(encoded.count, 8)

        let decoded = try FeeFilterPacket.decode(from: encoded)
        XCTAssertEqual(decoded.rate, 5000)
    }

    func testSendCmpctRoundTrip() throws {
        let pkt = SendCmpctPacket(mode: 1, version: 1)
        let encoded = pkt.encode()
        XCTAssertEqual(encoded.count, 9)

        let decoded = try SendCmpctPacket.decode(from: encoded)
        XCTAssertEqual(decoded.mode, 1)
        XCTAssertEqual(decoded.version, 1)
    }

    func testGetProofRoundTrip() throws {
        let root = Hash256(unchecked: [UInt8](repeating: 0xAA, count: 32))
        let key = Hash256(unchecked: [UInt8](repeating: 0xBB, count: 32))
        let pkt = GetProofPacket(root: root, key: key)
        let encoded = pkt.encode()
        XCTAssertEqual(encoded.count, 64)

        let decoded = try GetProofPacket.decode(from: encoded)
        XCTAssertEqual(decoded.root, root)
        XCTAssertEqual(decoded.key, key)
    }

    func testEmptyPackets() throws {
        // Verack, GetAddr, SendHeaders, Mempool should all have empty payloads
        XCTAssertEqual(VerackPacket().encode().count, 0)
        XCTAssertEqual(GetAddrPacket().encode().count, 0)
        XCTAssertEqual(SendHeadersPacket().encode().count, 0)
        XCTAssertEqual(MempoolPacket().encode().count, 0)
    }
}

// MARK: - HKDF Tests

final class HKDFTests: XCTestCase {

    func testExpand() {
        let secret = [UInt8](repeating: 0x01, count: 32)
        let salt = [UInt8](repeating: 0x02, count: 32)
        let (k1, k2) = HKDF256.expand(secret: secret, salt: salt)
        XCTAssertEqual(k1.count, 32)
        XCTAssertEqual(k2.count, 32)
        XCTAssertNotEqual(k1, k2)
    }

    func testExpandDeterministic() {
        let secret = [UInt8](repeating: 0xAA, count: 32)
        let salt = [UInt8](repeating: 0xBB, count: 32)
        let (k1a, k2a) = HKDF256.expand(secret: secret, salt: salt)
        let (k1b, k2b) = HKDF256.expand(secret: secret, salt: salt)
        XCTAssertEqual(k1a, k1b)
        XCTAssertEqual(k2a, k2b)
    }

    func testExpandDifferentInputs() {
        let (k1a, _) = HKDF256.expand(secret: [UInt8](repeating: 1, count: 32), salt: [UInt8](repeating: 0, count: 32))
        let (k1b, _) = HKDF256.expand(secret: [UInt8](repeating: 2, count: 32), salt: [UInt8](repeating: 0, count: 32))
        XCTAssertNotEqual(k1a, k1b)
    }
}

// MARK: - CipherState Tests

final class CipherStateTests: XCTestCase {

    func testEncryptDecrypt() throws {
        var sender = CipherState()
        var receiver = CipherState()
        let key = [UInt8](repeating: 0x42, count: 32)
        sender.initKey(key)
        receiver.initKey(key)

        var plaintext: [UInt8] = [1, 2, 3, 4, 5]
        let original = plaintext
        let tag = try sender.encrypt(&plaintext)

        XCTAssertNotEqual(plaintext, original)
        XCTAssertEqual(tag.count, 16)

        let ok = receiver.decrypt(&plaintext, tag: tag)
        XCTAssertTrue(ok)
        XCTAssertEqual(plaintext, original)
    }

    func testBadTagFails() throws {
        var sender = CipherState()
        var receiver = CipherState()
        let key = [UInt8](repeating: 0x42, count: 32)
        sender.initKey(key)
        receiver.initKey(key)

        var plaintext: [UInt8] = [1, 2, 3]
        let tag = try sender.encrypt(&plaintext)

        var badTag = tag
        badTag[0] ^= 0xFF
        let ok = receiver.decrypt(&plaintext, tag: badTag)
        XCTAssertFalse(ok)
    }

    func testNonceIncrements() throws {
        var cipher = CipherState()
        cipher.initKey([UInt8](repeating: 0x01, count: 32))

        XCTAssertEqual(cipher.nonce, 0)

        var data: [UInt8] = [0]
        _ = try cipher.encrypt(&data)
        XCTAssertEqual(cipher.nonce, 1)

        _ = try cipher.encrypt(&data)
        XCTAssertEqual(cipher.nonce, 2)
    }

    func testKeyRotation() throws {
        var cipher = CipherState()
        cipher.initKey([UInt8](repeating: 0x01, count: 32))
        cipher.salt = [UInt8](repeating: 0x02, count: 32)

        let keyBefore = cipher.key

        // Encrypt 999 times — no rotation yet
        for _ in 0..<999 {
            var d: [UInt8] = [0]
            _ = try cipher.encrypt(&d)
        }
        XCTAssertEqual(cipher.nonce, 999)

        // 1000th encryption triggers rotation: nonce becomes 1000, then rotateKey resets to 0
        var d: [UInt8] = [0]
        _ = try cipher.encrypt(&d)

        XCTAssertEqual(cipher.nonce, 0)
        XCTAssertNotEqual(cipher.key, keyBefore)
    }

    func testEncryptWithAD() throws {
        var sender = CipherState()
        var receiver = CipherState()
        let key = [UInt8](repeating: 0x42, count: 32)
        sender.initKey(key)
        receiver.initKey(key)

        let ad: [UInt8] = [0xAA, 0xBB, 0xCC]
        var plaintext: [UInt8] = [1, 2, 3]
        let original = plaintext
        let tag = try sender.encrypt(&plaintext, ad: ad)

        // Decrypt with correct AD
        let ok = receiver.decrypt(&plaintext, tag: tag, ad: ad)
        XCTAssertTrue(ok)
        XCTAssertEqual(plaintext, original)
    }
}

// MARK: - BrontideHandshake Tests

final class BrontideHandshakeTests: XCTestCase {

    func testFullHandshake() throws {
        // Generate static keypairs for both sides
        let initiatorKey = try ECDSASigner.generatePrivateKey()
        let responderKey = try ECDSASigner.generatePrivateKey()
        let responderPub = try ECDSASigner.publicKey(from: responderKey)

        // Create handshake instances
        var initiator = try BrontideHandshake(
            initiator: true,
            localStatic: initiatorKey,
            remoteStatic: responderPub.bytes
        )
        var responder = try BrontideHandshake(
            initiator: false,
            localStatic: responderKey
        )

        // Act 1: Initiator → Responder
        let act1 = try initiator.genActOne()
        XCTAssertEqual(act1.count, BrontideHandshake.actOneSize)
        try responder.recvActOne(act1)

        // Act 2: Responder → Initiator
        let act2 = try responder.genActTwo()
        XCTAssertEqual(act2.count, BrontideHandshake.actTwoSize)
        try initiator.recvActTwo(act2)

        // Act 3: Initiator → Responder
        let act3 = try initiator.genActThree()
        XCTAssertEqual(act3.count, BrontideHandshake.actThreeSize)
        try responder.recvActThree(act3)

        // Both should be in done state
        XCTAssertEqual(initiator.phase, .done)
        XCTAssertEqual(responder.phase, .done)

        // Responder should now know initiator's static key
        XCTAssertEqual(responder.remoteStatic, initiator.localStaticPub.bytes)
    }

    func testEncryptedTransport() throws {
        // Full handshake
        let initiatorKey = try ECDSASigner.generatePrivateKey()
        let responderKey = try ECDSASigner.generatePrivateKey()
        let responderPub = try ECDSASigner.publicKey(from: responderKey)

        var initiator = try BrontideHandshake(
            initiator: true,
            localStatic: initiatorKey,
            remoteStatic: responderPub.bytes
        )
        var responder = try BrontideHandshake(
            initiator: false,
            localStatic: responderKey
        )

        let act1 = try initiator.genActOne()
        try responder.recvActOne(act1)
        let act2 = try responder.genActTwo()
        try initiator.recvActTwo(act2)
        let act3 = try initiator.genActThree()
        try responder.recvActThree(act3)

        // Now test transport: initiator sends a message to responder
        let message: [UInt8] = Array("Hello, Fistbump!".utf8)
        let encrypted = try initiator.write(message)

        // Responder reads the header (first 20 bytes)
        let payloadLen = try responder.readHeader(Array(encrypted[0..<20]))
        XCTAssertEqual(payloadLen, message.count)

        // Responder reads the body
        let decrypted = try responder.readBody(
            Array(encrypted[20...]),
            length: payloadLen
        )
        XCTAssertEqual(decrypted, message)
    }

    func testBidirectionalTransport() throws {
        let initiatorKey = try ECDSASigner.generatePrivateKey()
        let responderKey = try ECDSASigner.generatePrivateKey()
        let responderPub = try ECDSASigner.publicKey(from: responderKey)

        var initiator = try BrontideHandshake(
            initiator: true,
            localStatic: initiatorKey,
            remoteStatic: responderPub.bytes
        )
        var responder = try BrontideHandshake(
            initiator: false,
            localStatic: responderKey
        )

        let act1 = try initiator.genActOne()
        try responder.recvActOne(act1)
        let act2 = try responder.genActTwo()
        try initiator.recvActTwo(act2)
        let act3 = try initiator.genActThree()
        try responder.recvActThree(act3)

        // Initiator → Responder
        let msg1: [UInt8] = [1, 2, 3]
        let enc1 = try initiator.write(msg1)
        let len1 = try responder.readHeader(Array(enc1[0..<20]))
        let dec1 = try responder.readBody(Array(enc1[20...]), length: len1)
        XCTAssertEqual(dec1, msg1)

        // Responder → Initiator
        let msg2: [UInt8] = [4, 5, 6]
        let enc2 = try responder.write(msg2)
        let len2 = try initiator.readHeader(Array(enc2[0..<20]))
        let dec2 = try initiator.readBody(Array(enc2[20...]), length: len2)
        XCTAssertEqual(dec2, msg2)
    }

    func testMultipleMessages() throws {
        let initiatorKey = try ECDSASigner.generatePrivateKey()
        let responderKey = try ECDSASigner.generatePrivateKey()
        let responderPub = try ECDSASigner.publicKey(from: responderKey)

        var initiator = try BrontideHandshake(
            initiator: true,
            localStatic: initiatorKey,
            remoteStatic: responderPub.bytes
        )
        var responder = try BrontideHandshake(
            initiator: false,
            localStatic: responderKey
        )

        let act1 = try initiator.genActOne()
        try responder.recvActOne(act1)
        let act2 = try responder.genActTwo()
        try initiator.recvActTwo(act2)
        let act3 = try initiator.genActThree()
        try responder.recvActThree(act3)

        // Send multiple messages to verify nonce progression
        for i in 0..<10 {
            let msg = [UInt8](repeating: UInt8(i), count: 100)
            let enc = try initiator.write(msg)
            let len = try responder.readHeader(Array(enc[0..<20]))
            let dec = try responder.readBody(Array(enc[20...]), length: len)
            XCTAssertEqual(dec, msg, "Message \(i) mismatch")
        }
    }

    func testBadActOneSize() throws {
        let responderKey = try ECDSASigner.generatePrivateKey()
        var responder = try BrontideHandshake(
            initiator: false,
            localStatic: responderKey
        )

        XCTAssertThrowsError(try responder.recvActOne([0, 1, 2])) { error in
            if case NetError.handshakeFailed = error {} else {
                XCTFail("Expected handshakeFailed error")
            }
        }
    }
}

// MARK: - PeerState Tests

final class PeerStateTests: XCTestCase {

    func testInitialState() {
        let state = PeerState(
            address: NetAddress(port: 32867),
            outbound: true
        )
        XCTAssertEqual(state.connectionState, .disconnected)
        XCTAssertTrue(state.outbound)
        XCTAssertFalse(state.isHandshaked)
        XCTAssertFalse(state.isBanned)
        XCTAssertEqual(state.banScore, 0)
    }

    func testBanScoring() {
        var state = PeerState(address: NetAddress(), outbound: false)
        XCTAssertFalse(state.isBanned)

        state.increaseBanScore(50)
        XCTAssertFalse(state.isBanned)

        state.increaseBanScore(50)
        XCTAssertTrue(state.isBanned)
    }

    func testApplyVersion() {
        var state = PeerState(address: NetAddress(), outbound: true)
        let ver = VersionPacket(
            version: 3,
            services: 3,
            agent: "/hsd:6.0.0/",
            height: 12345,
            noRelay: true
        )
        state.applyVersion(ver)
        XCTAssertEqual(state.version, 3)
        XCTAssertEqual(state.services, 3)
        XCTAssertEqual(state.agent, "/hsd:6.0.0/")
        XCTAssertEqual(state.height, 12345)
        XCTAssertFalse(state.relay)
    }

    func testRecordPing() {
        var state = PeerState(address: NetAddress(), outbound: true)
        XCTAssertEqual(state.minPing, UInt64.max)

        state.recordPing(rtt: 100)
        XCTAssertEqual(state.minPing, 100)

        state.recordPing(rtt: 50)
        XCTAssertEqual(state.minPing, 50)

        state.recordPing(rtt: 200) // higher, should not replace
        XCTAssertEqual(state.minPing, 50)
    }
}

// MARK: - BanMap Tests

final class BanMapTests: XCTestCase {

    func testBanAndCheck() {
        var bans = BanMap()
        let ip: [UInt8] = [127, 0, 0, 1]

        XCTAssertFalse(bans.isBanned(ip, now: 1000))

        bans.ban(ip, now: 1000)
        XCTAssertTrue(bans.isBanned(ip, now: 1000))
        XCTAssertTrue(bans.isBanned(ip, now: 1000 + NetConstants.banTime - 1))
        XCTAssertFalse(bans.isBanned(ip, now: 1000 + NetConstants.banTime))
    }

    func testCleanup() {
        var bans = BanMap()
        bans.ban([1, 2, 3, 4], now: 1000)
        bans.ban([5, 6, 7, 8], now: 2000)

        // Cleanup at a time that expires the first ban but not the second
        bans.cleanup(now: 1000 + NetConstants.banTime)
        XCTAssertEqual(bans.entries.count, 1)
    }
}

// MARK: - NetAddress Updated Format Tests

final class NetAddressTests: XCTestCase {

    func testSerializedSize() throws {
        let addr = NetAddress(time: 1000, services: 1, port: 32867)
        var writer = BufferWriter()
        addr.write(to: &writer)
        XCTAssertEqual(writer.count, 88)
    }

    func testRoundTrip() throws {
        let ip: [UInt8] = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xFF, 0xFF, 192, 168, 1, 1]
        let key = [UInt8](repeating: 0x02, count: 33)
        let addr = NetAddress(time: 1234, services: 3, ip: ip, port: 32868, key: key)

        var writer = BufferWriter()
        addr.write(to: &writer)

        var reader = BufferReader(writer.data)
        let decoded = try NetAddress.read(from: &reader)
        XCTAssertEqual(decoded.time, 1234)
        XCTAssertEqual(decoded.services, 3)
        XCTAssertEqual(decoded.ip, ip)
        XCTAssertEqual(decoded.port, 32868)
        XCTAssertEqual(decoded.key, key)
    }

    func testHasKey() {
        let withKey = NetAddress(key: [UInt8](repeating: 0x02, count: 33))
        XCTAssertTrue(withKey.hasKey)

        let withoutKey = NetAddress()
        XCTAssertFalse(withoutKey.hasKey)
    }

    func testIPv4String() {
        let ip: [UInt8] = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xFF, 0xFF, 127, 0, 0, 1]
        let addr = NetAddress(ip: ip)
        XCTAssertEqual(addr.ipv4String, "127.0.0.1")
    }
}
