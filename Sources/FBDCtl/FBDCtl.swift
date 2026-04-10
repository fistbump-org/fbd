import ArgumentParser
import Base
import Foundation
#if canImport(FoundationNetworking)
import FoundationNetworking
#endif
#if os(Windows)
import WinSDK
#elseif canImport(Glibc)
import Glibc
#elseif canImport(Android)
import Android
#endif

@main
struct FBDCtl: AsyncParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "fbdctl",
        abstract: "JSON-RPC client for fbd",
        version: Constants.fullVersion
    )

    static func main() async {
        let args = CommandLine.arguments.dropFirst()
        if args.contains("--help") || args.contains("-h") {
            print("fbdctl v\(Constants.fullVersion)")
            print("https://fbd.dev")
            return
        }
        do {
            let command = try parseAsRoot()
            if var asyncCommand = command as? AsyncParsableCommand {
                try await asyncCommand.run()
            }
        } catch {
            exit(withError: error)
        }
    }

    @Option(name: .long, help: "Network: main, testnet, regtest, simnet")
    var network: String = "main"

    @Option(name: .long, help: "RPC host")
    var rpcHost: String = "127.0.0.1"

    @Option(name: .long, help: "RPC port (0 = auto from network)")
    var rpcPort: Int = 0

    @Option(name: .long, help: "API key for authentication")
    var apiKey: String?

    @Option(name: .long, help: "Wallet name (for wallet commands)")
    var wallet: String?

    @Argument(help: "RPC method name")
    var method: String?

    @Argument(parsing: .captureForPassthrough, help: "RPC parameters")
    var params: [String] = []

    private var useJQ: Bool {
        #if os(Windows)
        return false
        #else
        guard isatty(STDOUT_FILENO) != 0 else { return false }
        return FileManager.default.isExecutableFile(atPath: "/usr/bin/jq")
            || FileManager.default.isExecutableFile(atPath: "/usr/local/bin/jq")
            || FileManager.default.isExecutableFile(atPath: "/opt/homebrew/bin/jq")
        #endif
    }

    private func printJSON(_ json: String) {
        let pretty = prettyJSON(json)
        if useJQ {
            let proc = Process()
            proc.executableURL = URL(fileURLWithPath: "/usr/bin/env")
            proc.arguments = ["jq", "."]
            let pipe = Pipe()
            pipe.fileHandleForWriting.write(Data(pretty.utf8))
            pipe.fileHandleForWriting.closeFile()
            proc.standardInput = pipe
            try? proc.run()
            proc.waitUntilExit()
        } else {
            print(pretty)
        }
    }

    func run() async throws {
        guard let method = method else {
            print("fbdctl v\(Constants.fullVersion)")
            print("https://fbd.dev")
            return
        }

        let port = resolvePort()
        let url = URL(string: "http://\(rpcHost):\(port)/")!

        // Extract --wallet from passthrough params (captureForPassthrough
        // swallows flags that appear after the method argument)
        var filteredParams = [String]()
        var walletName = wallet
        var i = params.startIndex
        while i < params.endIndex {
            if params[i] == "--wallet" && i + 1 < params.endIndex {
                walletName = params[i + 1]
                i += 2
            } else {
                filteredParams.append(params[i])
                i += 1
            }
        }

        let rpcParams: [Any] = filteredParams.map { autoDetect($0) }

        var body: [String: Any] = [
            "method": method,
            "params": rpcParams,
            "id": 1,
        ]
        if let w = walletName { body["wallet"] = w }

        let jsonData = try JSONSerialization.data(withJSONObject: body)

        var request = URLRequest(url: url)
        request.httpMethod = "POST"
        request.httpBody = jsonData
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        request.setValue("fbdctl", forHTTPHeaderField: "User-Agent")

        let effectiveApiKey = apiKey ?? readCookie()
        if let key = effectiveApiKey {
            let credentials = Data("x:\(key)".utf8).base64EncodedString()
            request.setValue("Basic \(credentials)", forHTTPHeaderField: "Authorization")
        }

        let data: Data
        let response: URLResponse
        do {
            (data, response) = try await URLSession.shared.data(for: request)
        } catch {
            printError("Connection failed: \(error.localizedDescription)")
            throw ExitCode(1)
        }

        guard let http = response as? HTTPURLResponse else {
            printError("Invalid response")
            throw ExitCode(1)
        }

        guard let rawJSON = String(data: data, encoding: .utf8) else {
            printError("Invalid response encoding")
            throw ExitCode(1)
        }

        guard http.statusCode == 200 else {
            if let errorVal = extractJSONValue(from: rawJSON, key: "error"), errorVal != "null" {
                printJSON("{\"result\":null,\"error\":\(errorVal)}")
            } else {
                printJSON("{\"result\":null,\"error\":{\"code\":\(http.statusCode),\"message\":\"HTTP \(http.statusCode)\"}}")
            }
            throw ExitCode(1)
        }

        // Check for RPC-level error
        if let errorVal = extractJSONValue(from: rawJSON, key: "error"), errorVal != "null" {
            printJSON("{\"result\":null,\"error\":\(errorVal)}")
            throw ExitCode(1)
        }

        // Extract result directly from server JSON — preserves exact formatting
        let result = extractJSONValue(from: rawJSON, key: "result") ?? "null"
        printJSON("{\"result\":\(result),\"error\":null}")
    }

    // MARK: - Helpers

    private func readCookie() -> String? {
        let subdir: String
        switch network {
        case "testnet": subdir = "testnet"
        case "regtest": subdir = "regtest"
        case "simnet":  subdir = "simnet"
        default:        subdir = ""
        }
        #if os(Windows)
        let base: String
        if let localAppData = ProcessInfo.processInfo.environment["LOCALAPPDATA"] {
            base = localAppData + "\\fbd"
        } else {
            base = "C:\\fbd"
        }
        #else
        let base = NSString(string: "~/.fbd").expandingTildeInPath
        #endif
        let cookiePath = subdir.isEmpty ? base + "/.cookie" : base + "/\(subdir)/.cookie"
        guard let data = FileManager.default.contents(atPath: cookiePath),
              let key = String(data: data, encoding: .utf8)?.trimmingCharacters(in: .whitespacesAndNewlines),
              !key.isEmpty else {
            return nil
        }
        return key
    }

    private func resolvePort() -> Int {
        if rpcPort != 0 { return rpcPort }
        switch network {
        case "testnet": return 42869
        case "regtest": return 52869
        case "simnet":  return 62869
        default:        return 32869
        }
    }

    private func autoDetect(_ value: String) -> Any {
        if value == "true" { return true }
        if value == "false" { return false }
        if let i = Int(value) { return i }
        if let d = Double(value), value.contains(".") { return d }
        // Try parsing as JSON (arrays, objects)
        if (value.hasPrefix("[") || value.hasPrefix("{")) {
            if let data = value.data(using: .utf8),
               let json = try? JSONSerialization.jsonObject(with: data) {
                return json
            }
        }
        // Comma-separated values become a JSON array (for xpubs, pstx hex,
        // etc.) — but ONLY if the comma is actually separating two or more
        // things. A shell token like `10.5,` (number with trailing comma,
        // common in `sendmany none <addr> 10.5, none <addr2> 20.0` style
        // commands) splits to a single non-empty piece, which means the
        // user clearly typed it as a number-with-segment-separator, not a
        // list. Pass it through as a string with the comma intact so the
        // server-side parser can still see the segment boundary.
        if value.contains(",") {
            let pieces = value.split(separator: ",").map { String($0) }
            let nonEmpty = pieces.filter { !$0.isEmpty }
            if nonEmpty.count >= 2 {
                return pieces
            }
        }
        return value
    }

    /// Extract the raw JSON value for a top-level key, preserving original formatting.
    private func extractJSONValue(from json: String, key: String) -> String? {
        // Search only at the top-level object depth to avoid matching
        // keys inside nested objects (e.g., "error" inside a result).
        let pattern = "\"\(key)\""
        var searchStart = json.startIndex
        var keyRange: Range<String.Index>?
        while let range = json.range(of: pattern, range: searchStart..<json.endIndex) {
            // Check that this key is at top-level depth (depth 1, inside the outermost {})
            var depth = 0
            var inStr = false
            var esc = false
            for c in json[json.startIndex..<range.lowerBound] {
                if esc { esc = false; continue }
                if c == "\\" && inStr { esc = true; continue }
                if c == "\"" { inStr = !inStr; continue }
                if !inStr {
                    if c == "{" || c == "[" { depth += 1 }
                    else if c == "}" || c == "]" { depth -= 1 }
                }
            }
            if depth == 1 {
                keyRange = range
                break
            }
            searchStart = range.upperBound
        }
        guard let keyRange else { return nil }

        var idx = keyRange.upperBound
        while idx < json.endIndex && json[idx] != ":" { idx = json.index(after: idx) }
        guard idx < json.endIndex else { return nil }
        idx = json.index(after: idx)

        while idx < json.endIndex && json[idx].isWhitespace { idx = json.index(after: idx) }
        guard idx < json.endIndex else { return nil }

        let start = idx
        let ch = json[idx]

        if ch == "{" || ch == "[" {
            let open = ch
            let close: Character = ch == "{" ? "}" : "]"
            var depth = 1
            var inStr = false
            var esc = false
            idx = json.index(after: idx)
            while idx < json.endIndex && depth > 0 {
                let c = json[idx]
                if esc { esc = false }
                else if c == "\\" && inStr { esc = true }
                else if c == "\"" { inStr = !inStr }
                else if !inStr {
                    if c == open { depth += 1 }
                    else if c == close { depth -= 1 }
                }
                idx = json.index(after: idx)
            }
            return String(json[start..<idx])
        } else if ch == "\"" {
            idx = json.index(after: idx)
            while idx < json.endIndex {
                if json[idx] == "\\" { idx = json.index(after: idx) }
                else if json[idx] == "\"" {
                    idx = json.index(after: idx)
                    return String(json[start..<idx])
                }
                idx = json.index(after: idx)
            }
            return nil
        } else {
            while idx < json.endIndex && json[idx] != "," && json[idx] != "}" && json[idx] != "]" {
                idx = json.index(after: idx)
            }
            return String(json[start..<idx]).trimmingCharacters(in: .whitespaces)
        }
    }

    /// Pretty-print compact JSON with 2-space indentation, preserving all values exactly.
    private func prettyJSON(_ json: String) -> String {
        var out = ""
        var indent = 0
        var inStr = false
        var esc = false

        for ch in json {
            if esc { out.append(ch); esc = false; continue }
            if ch == "\\" && inStr { out.append(ch); esc = true; continue }
            if ch == "\"" { inStr = !inStr; out.append(ch); continue }
            if inStr { out.append(ch); continue }

            switch ch {
            case "{", "[":
                out.append(ch)
                indent += 1
                out.append("\n")
                out.append(String(repeating: "  ", count: indent))
            case "}", "]":
                indent -= 1
                out.append("\n")
                out.append(String(repeating: "  ", count: indent))
                out.append(ch)
            case ",":
                out.append(",\n")
                out.append(String(repeating: "  ", count: indent))
            case ":":
                out.append(": ")
            default:
                if !ch.isWhitespace { out.append(ch) }
            }
        }
        return out
    }

    private func printError(_ message: String) {
        FileHandle.standardError.write(Data("\(message)\n".utf8))
    }
}
