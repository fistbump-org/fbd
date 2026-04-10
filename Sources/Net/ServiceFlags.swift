/// Service flags advertised by peers in the version message.
public struct ServiceFlags: OptionSet, Sendable, Equatable {
    public let rawValue: UInt32

    public init(rawValue: UInt32) {
        self.rawValue = rawValue
    }

    /// Full node — can serve blocks and transactions.
    public static let network = ServiceFlags(rawValue: 1 << 0)

    /// Supports bloom filtering (BIP37-style SPV).
    public static let bloom = ServiceFlags(rawValue: 1 << 1)

    /// Periodically broadcasts the local tip header to all handshaked peers
    /// so that peer.state.height stays fresh for every connection even in
    /// the absence of push-relay traffic. Used by the explorer /nodes page
    /// to decide whether a peer's reported height is trustworthy.
    public static let tipGossip = ServiceFlags(rawValue: 1 << 2)

    /// The default local services we advertise.
    public static let localServices: ServiceFlags = [.network, .tipGossip]

    /// The required services for outbound peers.
    public static let requiredServices: ServiceFlags = [.network]
}
