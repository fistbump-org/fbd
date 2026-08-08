#ifndef BALLOON_FAST_H
#define BALLOON_FAST_H

#include <stdint.h>
#include <stddef.h>

/// Compute BalloonHash using a pre-allocated buffer with prefetching.
///
/// - password/password_len: pre-hashed password (typically 32 bytes)
/// - salt/salt_len: nonce + extraNonce (typically 28 bytes)
/// - buf: pre-allocated buffer of slots*32 bytes (NOT zeroed — expand writes every slot)
/// - inp: scratch buffer of at least 128 bytes
/// - prefetch_inp: second scratch buffer of at least 128 bytes (for lookahead)
/// - output: 32-byte result
/// - cancelled: pointer to int flag; checked every 65K slots, returns -1 if set
///
/// Returns 0 on success, -1 if cancelled.
int balloon_hash_fast(
    const uint8_t *password, int password_len,
    const uint8_t *salt, int salt_len,
    uint8_t *buf,
    uint8_t *inp,
    uint8_t *prefetch_inp,
    int slots, int rounds, int delta,
    uint8_t *output,
    const volatile int *cancelled
);

/// Exposed for testing: single-block BLAKE2b-256.
void balloon_blake2b256_test(const uint8_t *input, int input_len, uint8_t *output);

/// Allocate a buffer with huge page support (Linux: MAP_HUGETLB → THP → malloc).
/// Sets *used_hugepages to: 0 = malloc, 1 = mmap+THP, 2 = explicit huge pages.
void *balloon_alloc_buffer(size_t size, int *used_hugepages);

/// Free a buffer allocated with balloon_alloc_buffer.
void balloon_free_buffer(void *ptr, size_t size, int used_hugepages);

/// Simple BalloonHash WITHOUT prefetching (for correctness validation).
int balloon_hash_simple(
    const uint8_t *password, int password_len,
    const uint8_t *salt, int salt_len,
    uint8_t *buf,
    uint8_t *inp,
    int slots, int rounds, int delta,
    uint8_t *output,
    const volatile int *cancelled
);

#endif
