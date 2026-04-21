/// Protocol-level constants for the Fistbump network.
public enum Constants {
    // MARK: - Version

    /// The fbd version string.
    public static let version = "0.3.1"

    /// The git commit hash at build time (short), set by BuildInfo.swift.
    /// Falls back to "unknown" if not built from a git repo.
    public static var buildHash: String { _buildHash }

    /// Full version string including build hash, e.g. "X.Y.Z (abc1234)".
    public static var fullVersion: String {
        "\(version) (\(buildHash))"
    }

    // MARK: - Block

    /// Maximum block weight (serialized size including witness discount).
    public static let maxBlockWeight: Int = 4_000_000

    /// Maximum block size in bytes (excluding witness data).
    public static let maxBlockSize: Int = 1_000_000

    /// Maximum size of a single transaction in bytes.
    public static let maxTxSize: Int = 1_000_000

    /// Maximum signature operations per block.
    public static let maxBlockSigops: Int = 80_000

    // MARK: - Maturity & Timing

    /// Number of confirmations before a coinbase output is spendable.
    public static let coinbaseMaturity: Int = 100

    /// Target block interval in seconds (2 minutes).
    public static let targetSpacing: Int = 120

    /// Number of blocks between difficulty adjustments.
    public static let difficultyAdjustmentInterval: Int = 72

    // MARK: - Supply

    /// Block subsidy halving interval (in blocks).
    public static let halvingInterval: Int = 1_051_200

    /// Initial block reward in bumps (500 FBC).
    public static let baseReward: Int64 = 500 * Amount.coinValue

    // MARK: - Names / Covenants

    /// Maximum length of a Fistbump name in bytes.
    public static let maxNameLength: Int = 63

    /// Number of blocks in a name auction's open period (1 hour).
    public static let openPeriod: Int = 30

    /// Number of blocks in a name auction's bidding period (3 days).
    public static let biddingPeriod: Int = 2_160

    /// Number of blocks in a name auction's reveal period (1 day).
    public static let revealPeriod: Int = 720

    /// Number of blocks for the register deadline after reveal (71 hours).
    public static let registerDeadline: Int = 2_130

    /// Renewal window in blocks (approximately 1 year).
    public static let renewalWindow: Int = 262_800

    // MARK: - Network

    /// Protocol version.
    public static let protocolVersion: UInt32 = 3

    /// Minimum accepted protocol version.
    public static let minProtocolVersion: UInt32 = 1

    /// Maximum number of items in an inventory message.
    public static let maxInvItems: Int = 50_000

    /// Maximum message payload size in bytes (8 MB).
    public static let maxMessageSize: Int = 8_000_000

    /// Default number of connections to maintain.
    public static let defaultMaxPeers: Int = 8

    // MARK: - Script

    /// Maximum script size in bytes.
    public static let maxScriptSize: Int = 10_000

    /// Maximum number of items on the script stack.
    public static let maxStackSize: Int = 1_000

    /// Maximum size of a single stack element in bytes.
    public static let maxScriptElementSize: Int = 520
}
