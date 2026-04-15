import Foundation
import Logging
import Node

/// Custom log handler that produces clean, single-letter-level output:
///
///     I) [2026-02-24T02:13:10-05:00] node | Initializing fbd network=main version=X.Y.Z
///
struct FBDLogHandler: LogHandler {
    var logLevel: Logger.Level
    var metadata: Logger.Metadata = [:]

    private let label: String

    private static let timeFormatter: DateFormatter = {
        let f = DateFormatter()
        f.dateFormat = "yyyy-MM-dd'T'HH:mm:ssZZZZZ"
        return f
    }()

    /// stderr file handle for writing log output.
    private static let stderr = FileHandle.standardError

    /// Fixed source column width (longest source: "mempool" = 7).
    private static let sourceWidth = 7

    init(label: String) {
        self.label = label
        self.logLevel = .info
    }

    subscript(metadataKey key: String) -> Logger.Metadata.Value? {
        get { metadata[key] }
        set { metadata[key] = newValue }
    }

    func log(
        level: Logger.Level,
        message: Logger.Message,
        metadata: Logger.Metadata?,
        source: String,
        file: String,
        function: String,
        line: UInt
    ) {
        let time = Self.timeFormatter.string(from: Date())
        let lvl = levelChar(level)
        let srcName = source.lowercased()
        let src = srcName.padding(toLength: Self.sourceWidth + 1, withPad: " ", startingAt: 0)

        // Merge per-logger metadata with call-site metadata
        let merged = mergedMetadata(metadata)
        let meta = formatMetadata(merged)

        var line = "\(lvl)) [\(time)] \(src)| \(message)"
        if !meta.isEmpty {
            line += " \(meta)"
        }
        line += "\n"

        Self.stderr.write(Data(line.utf8))
        // Broadcast to WebSocket subscribers (if node is running).
        NodeContext.logBroadcast?(String(line.dropLast()))
    }

    private func levelChar(_ level: Logger.Level) -> Character {
        switch level {
        case .trace:    return "T"
        case .debug:    return "D"
        case .info:     return "I"
        case .notice:   return "N"
        case .warning:  return "W"
        case .error:    return "E"
        case .critical: return "C"
        }
    }

    private func mergedMetadata(_ callsite: Logger.Metadata?) -> Logger.Metadata {
        if let callsite = callsite, !callsite.isEmpty {
            return self.metadata.merging(callsite) { _, new in new }
        }
        return self.metadata
    }

    private func formatMetadata(_ metadata: Logger.Metadata) -> String {
        if metadata.isEmpty { return "" }
        return metadata.sorted(by: { $0.key < $1.key })
            .map { "\($0.key)=\($0.value)" }
            .joined(separator: " ")
    }
}
