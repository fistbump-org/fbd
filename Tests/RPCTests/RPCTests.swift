import XCTest
@testable import RPC
@testable import Base
@testable import Protocol
@testable import Chain

// MARK: - JSON Parser Tests

final class JSONParserTests: XCTestCase {

    func testParseNull() throws {
        let result = try JSONParser.parse("null")
        XCTAssertEqual(result, .null)
    }

    func testParseBool() throws {
        XCTAssertEqual(try JSONParser.parse("true"), .bool(true))
        XCTAssertEqual(try JSONParser.parse("false"), .bool(false))
    }

    func testParseInt() throws {
        XCTAssertEqual(try JSONParser.parse("42"), .int(42))
        XCTAssertEqual(try JSONParser.parse("-1"), .int(-1))
        XCTAssertEqual(try JSONParser.parse("0"), .int(0))
    }

    func testParseDouble() throws {
        let result = try JSONParser.parse("3.14")
        if case .double(let d) = result {
            XCTAssertEqual(d, 3.14, accuracy: 0.001)
        } else {
            XCTFail("Expected double")
        }
    }

    func testParseString() throws {
        XCTAssertEqual(try JSONParser.parse("\"hello\""), .string("hello"))
        XCTAssertEqual(try JSONParser.parse("\"\""), .string(""))
    }

    func testParseStringWithEscapes() throws {
        XCTAssertEqual(try JSONParser.parse("\"line1\\nline2\""), .string("line1\nline2"))
        XCTAssertEqual(try JSONParser.parse("\"tab\\there\""), .string("tab\there"))
        XCTAssertEqual(try JSONParser.parse("\"quote\\\"end\""), .string("quote\"end"))
    }

    func testParseEmptyArray() throws {
        XCTAssertEqual(try JSONParser.parse("[]"), .array([]))
    }

    func testParseArray() throws {
        let result = try JSONParser.parse("[1, 2, 3]")
        XCTAssertEqual(result, .array([.int(1), .int(2), .int(3)]))
    }

    func testParseEmptyObject() throws {
        XCTAssertEqual(try JSONParser.parse("{}"), .object([]))
    }

    func testParseObject() throws {
        let result = try JSONParser.parse("{\"key\": \"value\", \"num\": 42}")
        if case .object(let pairs) = result {
            XCTAssertEqual(pairs.count, 2)
            XCTAssertEqual(pairs[0].0, "key")
            XCTAssertEqual(pairs[0].1, .string("value"))
            XCTAssertEqual(pairs[1].0, "num")
            XCTAssertEqual(pairs[1].1, .int(42))
        } else {
            XCTFail("Expected object")
        }
    }

    func testParseNested() throws {
        let json = "{\"arr\": [1, {\"nested\": true}]}"
        let result = try JSONParser.parse(json)
        if case .object(let pairs) = result {
            XCTAssertEqual(pairs[0].0, "arr")
            if case .array(let arr) = pairs[0].1 {
                XCTAssertEqual(arr.count, 2)
                XCTAssertEqual(arr[0], .int(1))
            } else {
                XCTFail("Expected array")
            }
        } else {
            XCTFail("Expected object")
        }
    }

    func testParseInvalidJSON() {
        XCTAssertThrowsError(try JSONParser.parse("{invalid}"))
        XCTAssertThrowsError(try JSONParser.parse(""))
    }

    func testParseRequest() throws {
        let json = "{\"method\": \"getinfo\", \"params\": [], \"id\": \"1\"}"
        let request = try JSONParser.parseRequest(json)
        XCTAssertEqual(request.method, "getinfo")
        XCTAssertTrue(request.params.isEmpty)
        XCTAssertEqual(request.id, .string("1"))
    }

    func testParseRequestWithParams() throws {
        let json = "{\"method\": \"getblock\", \"params\": [\"abc123\", true], \"id\": 1}"
        let request = try JSONParser.parseRequest(json)
        XCTAssertEqual(request.method, "getblock")
        XCTAssertEqual(request.params.count, 2)
        XCTAssertEqual(request.params[0], .string("abc123"))
        XCTAssertEqual(request.params[1], .bool(true))
        XCTAssertEqual(request.id, .int(1))
    }

    func testParseWhitespace() throws {
        let json = "  {  \"method\"  :  \"test\"  ,  \"params\"  :  [  ]  }  "
        let request = try JSONParser.parseRequest(json)
        XCTAssertEqual(request.method, "test")
    }
}

// MARK: - JSON Encoder Tests

final class JSONEncoderTests: XCTestCase {

    func testEncodeNull() {
        XCTAssertEqual(JSONEncoder.encode(.null), "null")
    }

    func testEncodeBool() {
        XCTAssertEqual(JSONEncoder.encode(.bool(true)), "true")
        XCTAssertEqual(JSONEncoder.encode(.bool(false)), "false")
    }

    func testEncodeInt() {
        XCTAssertEqual(JSONEncoder.encode(.int(42)), "42")
        XCTAssertEqual(JSONEncoder.encode(.int(-1)), "-1")
    }

    func testEncodeString() {
        XCTAssertEqual(JSONEncoder.encode(.string("hello")), "\"hello\"")
    }

    func testEncodeStringWithEscapes() {
        XCTAssertEqual(JSONEncoder.encode(.string("a\"b")), "\"a\\\"b\"")
        XCTAssertEqual(JSONEncoder.encode(.string("a\nb")), "\"a\\nb\"")
    }

    func testEncodeArray() {
        let result = JSONEncoder.encode(.array([.int(1), .string("two"), .bool(true)]))
        XCTAssertEqual(result, "[1,\"two\",true]")
    }

    func testEncodeObject() {
        let result = JSONEncoder.encode(.object([("a", .int(1)), ("b", .string("c"))]))
        XCTAssertEqual(result, "{\"a\":1,\"b\":\"c\"}")
    }

    func testEncodeResponse() {
        let response = RPCResponse.success(.int(42), id: .string("1"))
        let json = JSONEncoder.encode(response)
        XCTAssertTrue(json.contains("\"result\":42"))
        XCTAssertTrue(json.contains("\"error\":null"))
        XCTAssertTrue(json.contains("\"id\":\"1\""))
    }

    func testEncodeErrorResponse() {
        let response = RPCResponse.failure(.methodNotFound("test"), id: .int(1))
        let json = JSONEncoder.encode(response)
        XCTAssertTrue(json.contains("\"result\":null"))
        XCTAssertTrue(json.contains("-32601"))
        XCTAssertTrue(json.contains("\"id\":1"))
    }

    func testEncodeRequest() {
        let request = RPCRequest(method: "getinfo", params: [], id: .string("1"))
        let json = JSONEncoder.encode(request)
        XCTAssertTrue(json.contains("\"method\":\"getinfo\""))
        XCTAssertTrue(json.contains("\"params\":[]"))
    }
}

// MARK: - JSON Roundtrip Tests

final class JSONRoundtripTests: XCTestCase {

    func testRoundtripValues() throws {
        let values: [JSONValue] = [
            .null,
            .bool(true),
            .bool(false),
            .int(0),
            .int(12345),
            .int(-999),
            .string("hello world"),
            .string(""),
            .array([]),
            .array([.int(1), .string("two")]),
            .object([]),
            .object([("key", .string("value"))]),
        ]

        for original in values {
            let encoded = JSONEncoder.encode(original)
            let decoded = try JSONParser.parse(encoded)
            XCTAssertEqual(decoded, original, "Roundtrip failed for \(original)")
        }
    }

    func testRoundtripNested() throws {
        let original: JSONValue = .object([
            ("name", .string("test")),
            ("data", .array([.int(1), .null, .object([("nested", .bool(true))])])),
        ])
        let encoded = JSONEncoder.encode(original)
        let decoded = try JSONParser.parse(encoded)
        XCTAssertEqual(decoded, original)
    }
}

// MARK: - JSONValue Accessor Tests

final class JSONValueTests: XCTestCase {

    func testStringValue() {
        XCTAssertEqual(JSONValue.string("test").stringValue, "test")
        XCTAssertNil(JSONValue.int(1).stringValue)
    }

    func testIntValue() {
        XCTAssertEqual(JSONValue.int(42).intValue, 42)
        XCTAssertNil(JSONValue.string("42").intValue)
    }

    func testBoolValue() {
        XCTAssertEqual(JSONValue.bool(true).boolValue, true)
        XCTAssertNil(JSONValue.null.boolValue)
    }

    func testSubscriptKey() {
        let obj: JSONValue = .object([("a", .int(1)), ("b", .int(2))])
        XCTAssertEqual(obj["a"], .int(1))
        XCTAssertEqual(obj["b"], .int(2))
        XCTAssertNil(obj["c"])
    }

    func testSubscriptIndex() {
        let arr: JSONValue = .array([.int(10), .int(20)])
        XCTAssertEqual(arr[0], .int(10))
        XCTAssertEqual(arr[1], .int(20))
        XCTAssertNil(arr[2])
        XCTAssertNil(arr[-1])
    }
}

// MARK: - RPC Dispatcher Tests

final class RPCDispatcherTests: XCTestCase {

    func testDispatchKnownMethod() {
        let dispatcher = RPCDispatcher(handlers: [
            "getinfo": { _ in .string("ok") },
        ])

        let request = RPCRequest(method: "getinfo", id: .int(1))
        let response = dispatcher.dispatch(request)

        XCTAssertEqual(response.result, .string("ok"))
        XCTAssertNil(response.error)
        XCTAssertEqual(response.id, .int(1))
    }

    func testDispatchUnknownMethod() {
        let dispatcher = RPCDispatcher(handlers: [:])

        let request = RPCRequest(method: "unknown", id: .int(1))
        let response = dispatcher.dispatch(request)

        XCTAssertNil(response.result)
        XCTAssertNotNil(response.error)
        XCTAssertEqual(response.error?.code, -32601)
    }

    func testDispatchWithParams() {
        let dispatcher = RPCDispatcher(handlers: [
            "add": { req in
                guard req.params.count >= 2,
                      let a = req.params[0].intValue,
                      let b = req.params[1].intValue else {
                    throw RPCError.invalidParams("Need two integers")
                }
                return .int(a + b)
            },
        ])

        let request = RPCRequest(method: "add", params: [.int(3), .int(4)], id: .string("x"))
        let response = dispatcher.dispatch(request)
        XCTAssertEqual(response.result, .int(7))
    }

    func testDispatchHandlerThrows() {
        let dispatcher = RPCDispatcher(handlers: [
            "fail": { _ in throw RPCError.invalidParams("bad") },
        ])

        let request = RPCRequest(method: "fail", id: .int(1))
        let response = dispatcher.dispatch(request)

        XCTAssertNil(response.result)
        XCTAssertEqual(response.error?.code, -32602)
        XCTAssertEqual(response.error?.message, "bad")
    }

    func testHandleRaw() {
        let dispatcher = RPCDispatcher(handlers: [
            "echo": { req in req.params.first ?? .null },
        ])

        let json = "{\"method\":\"echo\",\"params\":[\"hello\"],\"id\":1}"
        let responseJson = dispatcher.handleRaw(json)

        XCTAssertTrue(responseJson.contains("\"hello\""))
        XCTAssertTrue(responseJson.contains("\"id\":1"))
    }

    func testHandleRawBatch() {
        let dispatcher = RPCDispatcher(handlers: [
            "ping": { (_: RPCRequest) in .string("pong") },
        ])

        let json = "[{\"method\":\"ping\",\"params\":[],\"id\":1},{\"method\":\"ping\",\"params\":[],\"id\":2}]"
        let responseJson = dispatcher.handleRaw(json)

        // Should be a JSON array
        XCTAssertTrue(responseJson.hasPrefix("["))
        XCTAssertTrue(responseJson.hasSuffix("]"))
    }

    func testHandleRawInvalidJSON() {
        let dispatcher = RPCDispatcher(handlers: [:])
        let responseJson = dispatcher.handleRaw("{invalid")
        XCTAssertTrue(responseJson.contains("-32700"))
    }

    func testMethodsList() {
        let dispatcher = RPCDispatcher(handlers: [
            "getinfo": { (_: RPCRequest) in .null },
            "getblock": { (_: RPCRequest) in .null },
        ])
        XCTAssertEqual(dispatcher.methods, ["getblock", "getinfo"])
    }
}

// MARK: - RPC Methods Tests

final class RPCMethodsTests: XCTestCase {

    func testGetBlockCount() {
        let result = RPCMethods.getBlockCount(12345)
        XCTAssertEqual(result, .int(12345))
    }

    func testGetBestBlockHash() {
        let hash = Hash256.zero
        let result = RPCMethods.getBestBlockHash(hash)
        XCTAssertEqual(result, .string(hash.hex))
    }

    func testGetBlockchainInfo() {
        let result = RPCMethods.getBlockchainInfo(
            chain: "main",
            blocks: 100,
            headers: 100,
            bestHash: .zero,
            treeRoot: .zero,
            bits: 0x1d00ffff,
            medianTime: 1234567890,
            chainwork: "00000000000000000000000000000000000000000000000000000000000000ff",
            progress: 0.5
        )

        if case .object(let pairs) = result {
            let dict = Dictionary(pairs, uniquingKeysWith: { _, last in last })
            XCTAssertEqual(dict["chain"], .string("main"))
            XCTAssertEqual(dict["blocks"], .int(100))
            XCTAssertEqual(dict["mediantime"], .int(1234567890))
        } else {
            XCTFail("Expected object")
        }
    }

    func testGetMempoolInfo() {
        let result = RPCMethods.getMempoolInfo(size: 10, bytes: 5000, orphans: 2)
        if case .object(let pairs) = result {
            let dict = Dictionary(pairs, uniquingKeysWith: { _, last in last })
            XCTAssertEqual(dict["size"], .int(10))
            XCTAssertEqual(dict["bytes"], .int(5000))
            XCTAssertEqual(dict["orphans"], .int(2))
        } else {
            XCTFail("Expected object")
        }
    }

    func testGetNetworkInfo() {
        let result = RPCMethods.getNetworkInfo(
            version: 3,
            subversion: "/fbd:test/",
            protocolversion: 3,
            connections: 8
        )
        if case .object(let pairs) = result {
            let dict = Dictionary(pairs, uniquingKeysWith: { _, last in last })
            XCTAssertEqual(dict["connections"], .int(8))
            XCTAssertEqual(dict["subversion"], .string("/fbd:test/"))
        } else {
            XCTFail("Expected object")
        }
    }

    func testDifficultyFromBits() {
        // Bitcoin genesis bits (0x1d00ffff) = difficulty 1.0 by convention
        let btcDiff = RPCMethods.difficultyFromBits(0x1d00_ffff)
        XCTAssertEqual(btcDiff, 1.0, accuracy: 0.001)

        // Fistbump genesis (0x207fffff) has a very easy target
        let hnsDiff = RPCMethods.difficultyFromBits(0x207f_ffff)
        XCTAssertLessThan(hnsDiff, 1.0)

        // Harder bits = higher difficulty
        let hardDiff = RPCMethods.difficultyFromBits(0x1d00_ffff)
        XCTAssertGreaterThan(hardDiff, hnsDiff)
    }

    func testFormatTransaction() {
        let tx = Transaction(
            inputs: [Input(prevout: .null)],
            outputs: [Output(value: 1000, address: .null)]
        )
        let result = RPCMethods.formatTransaction(tx, confirmations: 5)
        if case .object(let pairs) = result {
            let dict = Dictionary(pairs, uniquingKeysWith: { _, last in last })
            XCTAssertEqual(dict["confirmations"], .int(5))
            if case .array(let inputs) = dict["inputs"] {
                XCTAssertEqual(inputs.count, 1)
            } else {
                XCTFail("Expected inputs array")
            }
        } else {
            XCTFail("Expected object")
        }
    }

    func testFormatBlockHeader() throws {
        let header = BlockHeader(
            time: 1234567890,
            version: 0,
            bits: 0x1d00ffff
        )
        let entry = try ChainEntry.fromBlock(header, prev: nil, slots: 4)
        let result = RPCMethods.formatBlockHeader(entry: entry)

        if case .object(let pairs) = result {
            let dict = Dictionary(pairs, uniquingKeysWith: { _, last in last })
            XCTAssertEqual(dict["height"], .int(0))
            XCTAssertEqual(dict["time"], .int(1234567890))
        } else {
            XCTFail("Expected object")
        }
    }
}

// MARK: - RPC Auth Tests

final class RPCAuthTests: XCTestCase {

    func testValidAuth() {
        XCTAssertTrue(RPCAuth.validate(username: "x", password: "secret123", apiKey: "secret123"))
    }

    func testInvalidAuth() {
        XCTAssertFalse(RPCAuth.validate(username: "x", password: "wrong", apiKey: "secret123"))
    }

    func testDifferentLengthFails() {
        XCTAssertFalse(RPCAuth.validate(username: "x", password: "short", apiKey: "longersecret"))
    }

    func testIsLocalhost() {
        XCTAssertTrue(RPCAuth.isLocalhost("127.0.0.1"))
        XCTAssertTrue(RPCAuth.isLocalhost("::1"))
        XCTAssertTrue(RPCAuth.isLocalhost("localhost"))
        XCTAssertFalse(RPCAuth.isLocalhost("192.168.1.1"))
    }
}

// MARK: - RPC Error Tests

final class RPCErrorTests: XCTestCase {

    func testErrorCodes() {
        XCTAssertEqual(RPCError.parseError("test").code, -32700)
        XCTAssertEqual(RPCError.invalidRequest("test").code, -32600)
        XCTAssertEqual(RPCError.methodNotFound("test").code, -32601)
        XCTAssertEqual(RPCError.invalidParams("test").code, -32602)
        XCTAssertEqual(RPCError.internalError("test").code, -32603)
        XCTAssertEqual(RPCError.notFound("test").code, -1)
        XCTAssertEqual(RPCError.notSupported("test").code, -2)
    }

    func testErrorMessages() {
        XCTAssertEqual(RPCError.parseError("bad json").message, "bad json")
        XCTAssertEqual(RPCError.methodNotFound("no such method").message, "no such method")
    }
}

// MARK: - RPC Config Tests

final class RPCConfigTests: XCTestCase {

    func testDefaultConfig() {
        let config = RPCConfig()
        XCTAssertEqual(config.host, "127.0.0.1")
        XCTAssertEqual(config.port, 32869)
        XCTAssertNil(config.apiKey)
        XCTAssertFalse(config.noAuth)
    }

    func testCustomConfig() {
        let config = RPCConfig(host: "0.0.0.0", port: 42869, apiKey: "mykey", noAuth: false)
        XCTAssertEqual(config.host, "0.0.0.0")
        XCTAssertEqual(config.port, 42869)
        XCTAssertEqual(config.apiKey, "mykey")
    }
}
