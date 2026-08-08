import Base
import CBalloon
import Foundation

// MARK: - Mining Buffer (pre-allocated, reusable across hashes)

final class MiningBuffer: @unchecked Sendable {
    let buf: UnsafeMutablePointer<UInt8>
    let inp: UnsafeMutablePointer<UInt8>
    let prefetchInp: UnsafeMutablePointer<UInt8>
    let slots: Int
    private let hugePageMode: Int32
    var cancelled: Int32 = 0

    init(slots: Int) {
        self.slots = slots
        var mode: Int32 = 0
        self.buf = balloon_alloc_buffer(slots * 32, &mode).assumingMemoryBound(to: UInt8.self)
        self.hugePageMode = mode
        self.inp = .allocate(capacity: 128)
        self.prefetchInp = .allocate(capacity: 128)
    }

    deinit {
        balloon_free_buffer(buf, slots * 32, hugePageMode)
        inp.deallocate()
        prefetchInp.deallocate()
    }
}

final class BufferPool: @unchecked Sendable {
    private var available: [MiningBuffer] = []
    private let lock = NSLock()
    private let slots: Int
    private let maxPooled: Int

    init(slots: Int, maxPooled: Int = 0) {
        self.slots = slots
        self.maxPooled = maxPooled > 0 ? maxPooled : 32
    }

    func checkout() -> MiningBuffer {
        lock.lock()
        if let buf = available.popLast() {
            lock.unlock()
            buf.cancelled = 0
            return buf
        }
        lock.unlock()
        return MiningBuffer(slots: slots)
    }

    func checkin(_ buf: MiningBuffer) {
        lock.lock()
        if available.count < maxPooled {
            available.append(buf)
            lock.unlock()
        } else {
            lock.unlock()
            // Drop the buffer - deallocated by MiningBuffer.deinit
        }
    }
}

// MARK: - Fast BalloonHash (C with prefetching, test-validated)

enum FastBalloonHash {

    struct Cancelled: Error {}

    static func hash(
        password: [UInt8],
        salt: [UInt8],
        buffer: MiningBuffer,
        slots: Int,
        rounds: Int,
        delta: Int,
        isCancelled: (() -> Bool)? = nil
    ) throws -> [UInt8] {
        buffer.cancelled = 0

        var output = [UInt8](repeating: 0, count: 32)
        let result = password.withUnsafeBufferPointer { pw in
            salt.withUnsafeBufferPointer { sl in
                output.withUnsafeMutableBufferPointer { out in
                    if let isCancelled, isCancelled() { return Int32(-1) }
                    return balloon_hash_fast(
                        pw.baseAddress!, Int32(pw.count),
                        sl.baseAddress!, Int32(sl.count),
                        buffer.buf, buffer.inp, buffer.prefetchInp,
                        Int32(slots), Int32(rounds), Int32(delta),
                        out.baseAddress!, &buffer.cancelled
                    )
                }
            }
        }

        if result != 0 { throw Cancelled() }
        return output
    }
}
