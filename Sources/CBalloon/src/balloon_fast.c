#include "balloon_fast.h"
#include <string.h>
#include <stdlib.h>
#if defined(__linux__)
#include <sys/mman.h>
#endif

// ---------------------------------------------------------------------------
// Platform detection
// ---------------------------------------------------------------------------

// SSSE3 BLAKE2b for x86-64 (validated against balloon-test vectors).
#if defined(__x86_64__) && defined(__SSSE3__)
    #include <tmmintrin.h>
    #define BLAKE2B_SSSE3 1
#elif defined(__aarch64__) || defined(_M_ARM64)
  #include <arm_neon.h>
  #define BLAKE2B_NEON 1
#endif

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

static inline void store_u64le(uint8_t *p, uint64_t v) {
    p[0] = (uint8_t)(v);       p[1] = (uint8_t)(v >> 8);
    p[2] = (uint8_t)(v >> 16); p[3] = (uint8_t)(v >> 24);
    p[4] = (uint8_t)(v >> 32); p[5] = (uint8_t)(v >> 40);
    p[6] = (uint8_t)(v >> 48); p[7] = (uint8_t)(v >> 56);
}

static inline uint64_t load_u64le(const uint8_t *p) {
    return (uint64_t)p[0]       | ((uint64_t)p[1] << 8)
         | ((uint64_t)p[2] << 16) | ((uint64_t)p[3] << 24)
         | ((uint64_t)p[4] << 32) | ((uint64_t)p[5] << 40)
         | ((uint64_t)p[6] << 48) | ((uint64_t)p[7] << 56);
}

static inline void copy32(const uint8_t *src, uint8_t *dst) {
    memcpy(dst, src, 32);
}

// BLAKE2b IV
static const uint64_t iv[8] = {
    0x6a09e667f3bcc908ULL, 0xbb67ae8584caa73bULL,
    0x3c6ef372fe94f82bULL, 0xa54ff53a5f1d36f1ULL,
    0x510e527fade682d1ULL, 0x9b05688c2b3e6c1fULL,
    0x1f83d9abfb41bd6bULL, 0x5be0cd19137e2179ULL,
};

// Sigma schedule (12 rounds × 16 entries, flat)
static const uint8_t sigma[192] = {
     0, 1, 2, 3, 4, 5, 6, 7, 8, 9,10,11,12,13,14,15,
    14,10, 4, 8, 9,15,13, 6, 1,12, 0, 2,11, 7, 5, 3,
    11, 8,12, 0, 5, 2,15,13,10,14, 3, 6, 7, 1, 9, 4,
     7, 9, 3, 1,13,12,11,14, 2, 6, 5,10, 4, 0,15, 8,
     9, 0, 5, 7, 2, 4,10,15,14, 1,11,12, 6, 8, 3,13,
     2,12, 6,10, 0,11, 8, 3, 4,13, 7, 5,15,14, 1, 9,
    12, 5, 1,15,14,13, 4,10, 0, 7, 6, 3, 9, 2, 8,11,
    13,11, 7,14,12, 1, 3, 9, 5, 0,15, 4, 8, 6, 2,10,
     6,15,14, 9,11, 3, 0, 8,12, 2,13, 7, 1, 4,10, 5,
    10, 2, 8, 4, 7, 6, 1, 5,15,11, 9,14, 3,12,13, 0,
     0, 1, 2, 3, 4, 5, 6, 7, 8, 9,10,11,12,13,14,15,
    14,10, 4, 8, 9,15,13, 6, 1,12, 0, 2,11, 7, 5, 3,
};

// ---------------------------------------------------------------------------
// BLAKE2b-256 single-block: SSSE3 implementation
// ---------------------------------------------------------------------------

#if BLAKE2B_SSSE3

// Shuffle masks for 64-bit lane rotations via SSSE3 _mm_shuffle_epi8.
// Each mask maps output[i] = input[(i+N)%8] within each 64-bit lane.
// ROTR16: shift each 64-bit lane right by 16 bits (2 bytes)
static const uint8_t ROT16[16] __attribute__((aligned(16))) = {
    2,3,4,5,6,7,0,1, 10,11,12,13,14,15,8,9
};
// ROTR24: shift each 64-bit lane right by 24 bits (3 bytes)
static const uint8_t ROT24[16] __attribute__((aligned(16))) = {
    3,4,5,6,7,0,1,2, 11,12,13,14,15,8,9,10
};

#define ROTR32(x)  _mm_shuffle_epi32((x), _MM_SHUFFLE(2,3,0,1))
#define ROTR24(x)  _mm_shuffle_epi8((x), *(const __m128i*)ROT24)
#define ROTR16(x)  _mm_shuffle_epi8((x), *(const __m128i*)ROT16)
#define ROTR63(x)  _mm_xor_si128(_mm_srli_epi64((x), 63), _mm_add_epi64((x), (x)))

#define G1(r1l,r2l,r3l,r4l,r1h,r2h,r3h,r4h,b0,b1)  \
    r1l = _mm_add_epi64(_mm_add_epi64(r1l, b0), r2l); \
    r1h = _mm_add_epi64(_mm_add_epi64(r1h, b1), r2h); \
    r4l = _mm_xor_si128(r4l, r1l); r4h = _mm_xor_si128(r4h, r1h); \
    r4l = ROTR32(r4l); r4h = ROTR32(r4h); \
    r3l = _mm_add_epi64(r3l, r4l); r3h = _mm_add_epi64(r3h, r4h); \
    r2l = _mm_xor_si128(r2l, r3l); r2h = _mm_xor_si128(r2h, r3h); \
    r2l = ROTR24(r2l); r2h = ROTR24(r2h);

#define G2(r1l,r2l,r3l,r4l,r1h,r2h,r3h,r4h,b0,b1)  \
    r1l = _mm_add_epi64(_mm_add_epi64(r1l, b0), r2l); \
    r1h = _mm_add_epi64(_mm_add_epi64(r1h, b1), r2h); \
    r4l = _mm_xor_si128(r4l, r1l); r4h = _mm_xor_si128(r4h, r1h); \
    r4l = ROTR16(r4l); r4h = ROTR16(r4h); \
    r3l = _mm_add_epi64(r3l, r4l); r3h = _mm_add_epi64(r3h, r4h); \
    r2l = _mm_xor_si128(r2l, r3l); r2h = _mm_xor_si128(r2h, r3h); \
    r2l = ROTR63(r2l); r2h = ROTR63(r2h);

#define DIAG(r1l,r2l,r3l,r4l,r1h,r2h,r3h,r4h) { \
    __m128i t0, t1; \
    t0 = _mm_alignr_epi8(r2h, r2l, 8); t1 = _mm_alignr_epi8(r2l, r2h, 8); \
    r2l = t0; r2h = t1; \
    t0 = r3l; r3l = r3h; r3h = t0; \
    t0 = _mm_alignr_epi8(r4h, r4l, 8); t1 = _mm_alignr_epi8(r4l, r4h, 8); \
    r4l = t1; r4h = t0; \
}

#define UNDIAG(r1l,r2l,r3l,r4l,r1h,r2h,r3h,r4h) { \
    __m128i t0, t1; \
    t0 = _mm_alignr_epi8(r2l, r2h, 8); t1 = _mm_alignr_epi8(r2h, r2l, 8); \
    r2l = t0; r2h = t1; \
    t0 = r3l; r3l = r3h; r3h = t0; \
    t0 = _mm_alignr_epi8(r4l, r4h, 8); t1 = _mm_alignr_epi8(r4h, r4l, 8); \
    r4l = t1; r4h = t0; \
}

static void blake2b256_single(const uint8_t *input, int len, uint8_t *output) {
    // Load message words (zero-padded)
    uint64_t m[16];
    memset(m, 0, sizeof(m));
    memcpy(m, input, (size_t)len < 128 ? (size_t)len : 128);

    // State init: h = IV ^ param_block (digest=32, key=0, fanout=1, depth=1)
    __m128i row1l = _mm_set_epi64x((long long)iv[1], (long long)(iv[0] ^ 0x01010020ULL));
    __m128i row1h = _mm_set_epi64x((long long)iv[3], (long long)iv[2]);
    __m128i row2l = _mm_set_epi64x((long long)iv[5], (long long)iv[4]);
    __m128i row2h = _mm_set_epi64x((long long)iv[7], (long long)iv[6]);
    __m128i row3l = _mm_set_epi64x((long long)iv[1], (long long)iv[0]);
    __m128i row3h = _mm_set_epi64x((long long)iv[3], (long long)iv[2]);
    __m128i row4l = _mm_set_epi64x((long long)iv[5], (long long)(iv[4] ^ (uint64_t)len));
    __m128i row4h = _mm_set_epi64x((long long)iv[7], (long long)(~iv[6]));

    // Save initial state for finalization (only first 4 words needed for 256-bit)
    __m128i orig1l = row1l, orig1h = row1h;

    // 12 rounds
    for (int r = 0; r < 12; r++) {
        const uint8_t *s = sigma + r * 16;
        __m128i b0, b1;

        // Column step: G1 adds x words, G2 adds y words
        // G(v0,..,m[s[0]],m[s[1]]), G(v1,..,m[s[2]],m[s[3]]),
        // G(v2,..,m[s[4]],m[s[5]]), G(v3,..,m[s[6]],m[s[7]])
        // row1l=(v0,v1), row1h=(v2,v3) → b0 low=v0's word, b0 high=v1's word
        b0 = _mm_set_epi64x((long long)m[s[2]], (long long)m[s[0]]);   // x: v0, v1
        b1 = _mm_set_epi64x((long long)m[s[6]], (long long)m[s[4]]);   // x: v2, v3
        G1(row1l,row2l,row3l,row4l,row1h,row2h,row3h,row4h,b0,b1);
        b0 = _mm_set_epi64x((long long)m[s[3]], (long long)m[s[1]]);   // y: v0, v1
        b1 = _mm_set_epi64x((long long)m[s[7]], (long long)m[s[5]]);   // y: v2, v3
        G2(row1l,row2l,row3l,row4l,row1h,row2h,row3h,row4h,b0,b1);

        // Diagonalize
        DIAG(row1l,row2l,row3l,row4l,row1h,row2h,row3h,row4h);

        // Diagonal step
        b0 = _mm_set_epi64x((long long)m[s[10]], (long long)m[s[8]]);  // x: v0, v1
        b1 = _mm_set_epi64x((long long)m[s[14]], (long long)m[s[12]]); // x: v2, v3
        G1(row1l,row2l,row3l,row4l,row1h,row2h,row3h,row4h,b0,b1);
        b0 = _mm_set_epi64x((long long)m[s[11]], (long long)m[s[9]]);  // y: v0, v1
        b1 = _mm_set_epi64x((long long)m[s[15]], (long long)m[s[13]]); // y: v2, v3
        G2(row1l,row2l,row3l,row4l,row1h,row2h,row3h,row4h,b0,b1);

        // Undiagonalize
        UNDIAG(row1l,row2l,row3l,row4l,row1h,row2h,row3h,row4h);
    }

    // Finalize: h ^= v[0..3] ^ v[8..11] (only 256 bits needed)
    row1l = _mm_xor_si128(_mm_xor_si128(orig1l, row1l), row3l);
    row1h = _mm_xor_si128(_mm_xor_si128(orig1h, row1h), row3h);

    _mm_storeu_si128((__m128i *)(output),      row1l);
    _mm_storeu_si128((__m128i *)(output + 16), row1h);
}

// ---------------------------------------------------------------------------
// BLAKE2b-256 single-block: NEON implementation
// ---------------------------------------------------------------------------

#elif BLAKE2B_NEON

#define ROTR32(x) vreinterpretq_u64_u32(vrev64q_u32(vreinterpretq_u32_u64(x)))
#define ROTR24(x) vorrq_u64(vshrq_n_u64(x, 24), vshlq_n_u64(x, 40))
#define ROTR16(x) vorrq_u64(vshrq_n_u64(x, 16), vshlq_n_u64(x, 48))
#define ROTR63(x) veorq_u64(vshrq_n_u64(x, 63), vaddq_u64(x, x))

// Full 4-wide G macros: 8-register layout (matches SSSE3 structure).
// Each row is split into low (lanes 0-1) and high (lanes 2-3) uint64x2_t pairs.
#define G1N(r1l,r2l,r3l,r4l,r1h,r2h,r3h,r4h,b0,b1) \
    r1l = vaddq_u64(vaddq_u64(r1l, b0), r2l); \
    r1h = vaddq_u64(vaddq_u64(r1h, b1), r2h); \
    r4l = veorq_u64(r4l, r1l); r4h = veorq_u64(r4h, r1h); \
    r4l = ROTR32(r4l); r4h = ROTR32(r4h); \
    r3l = vaddq_u64(r3l, r4l); r3h = vaddq_u64(r3h, r4h); \
    r2l = veorq_u64(r2l, r3l); r2h = veorq_u64(r2h, r3h); \
    r2l = ROTR24(r2l); r2h = ROTR24(r2h);

#define G2N(r1l,r2l,r3l,r4l,r1h,r2h,r3h,r4h,b0,b1) \
    r1l = vaddq_u64(vaddq_u64(r1l, b0), r2l); \
    r1h = vaddq_u64(vaddq_u64(r1h, b1), r2h); \
    r4l = veorq_u64(r4l, r1l); r4h = veorq_u64(r4h, r1h); \
    r4l = ROTR16(r4l); r4h = ROTR16(r4h); \
    r3l = vaddq_u64(r3l, r4l); r3h = vaddq_u64(r3h, r4h); \
    r2l = veorq_u64(r2l, r3l); r2h = veorq_u64(r2h, r3h); \
    r2l = ROTR63(r2l); r2h = ROTR63(r2h);

#define DIAG_NEON(r1l,r2l,r3l,r4l,r1h,r2h,r3h,r4h) { \
    uint64x2_t t0, t1; \
    t0 = vextq_u64(r2l, r2h, 1); t1 = vextq_u64(r2h, r2l, 1); \
    r2l = t0; r2h = t1; \
    t0 = r3l; r3l = r3h; r3h = t0; \
    t0 = vextq_u64(r4l, r4h, 1); t1 = vextq_u64(r4h, r4l, 1); \
    r4l = t1; r4h = t0; \
}

#define UNDIAG_NEON(r1l,r2l,r3l,r4l,r1h,r2h,r3h,r4h) { \
    uint64x2_t t0, t1; \
    t0 = vextq_u64(r2h, r2l, 1); t1 = vextq_u64(r2l, r2h, 1); \
    r2l = t0; r2h = t1; \
    t0 = r3l; r3l = r3h; r3h = t0; \
    t0 = vextq_u64(r4h, r4l, 1); t1 = vextq_u64(r4l, r4h, 1); \
    r4l = t1; r4h = t0; \
}

static void blake2b256_single(const uint8_t *input, int len, uint8_t *output) {
    uint64_t m[16];
    memset(m, 0, sizeof(m));
    memcpy(m, input, (size_t)len < 128 ? (size_t)len : 128);

    // State init: h = IV ^ param_block (digest=32, key=0, fanout=1, depth=1)
    uint64x2_t row1l = vcombine_u64(vcreate_u64(iv[0] ^ 0x01010020ULL), vcreate_u64(iv[1]));
    uint64x2_t row1h = vcombine_u64(vcreate_u64(iv[2]), vcreate_u64(iv[3]));
    uint64x2_t row2l = vcombine_u64(vcreate_u64(iv[4]), vcreate_u64(iv[5]));
    uint64x2_t row2h = vcombine_u64(vcreate_u64(iv[6]), vcreate_u64(iv[7]));
    uint64x2_t row3l = vcombine_u64(vcreate_u64(iv[0]), vcreate_u64(iv[1]));
    uint64x2_t row3h = vcombine_u64(vcreate_u64(iv[2]), vcreate_u64(iv[3]));
    uint64x2_t row4l = vcombine_u64(vcreate_u64(iv[4] ^ (uint64_t)len), vcreate_u64(iv[5]));
    uint64x2_t row4h = vcombine_u64(vcreate_u64(~iv[6]), vcreate_u64(iv[7]));

    // Save initial state for finalization (only first 4 words needed for 256-bit)
    uint64x2_t orig1l = row1l, orig1h = row1h;

    // 12 rounds
    for (int r = 0; r < 12; r++) {
        const uint8_t *s = sigma + r * 16;
        uint64x2_t b0, b1;

        // Column step
        b0 = vcombine_u64(vcreate_u64(m[s[0]]), vcreate_u64(m[s[2]]));
        b1 = vcombine_u64(vcreate_u64(m[s[4]]), vcreate_u64(m[s[6]]));
        G1N(row1l,row2l,row3l,row4l,row1h,row2h,row3h,row4h,b0,b1);
        b0 = vcombine_u64(vcreate_u64(m[s[1]]), vcreate_u64(m[s[3]]));
        b1 = vcombine_u64(vcreate_u64(m[s[5]]), vcreate_u64(m[s[7]]));
        G2N(row1l,row2l,row3l,row4l,row1h,row2h,row3h,row4h,b0,b1);

        DIAG_NEON(row1l,row2l,row3l,row4l,row1h,row2h,row3h,row4h);

        // Diagonal step
        b0 = vcombine_u64(vcreate_u64(m[s[8]]), vcreate_u64(m[s[10]]));
        b1 = vcombine_u64(vcreate_u64(m[s[12]]), vcreate_u64(m[s[14]]));
        G1N(row1l,row2l,row3l,row4l,row1h,row2h,row3h,row4h,b0,b1);
        b0 = vcombine_u64(vcreate_u64(m[s[9]]), vcreate_u64(m[s[11]]));
        b1 = vcombine_u64(vcreate_u64(m[s[13]]), vcreate_u64(m[s[15]]));
        G2N(row1l,row2l,row3l,row4l,row1h,row2h,row3h,row4h,b0,b1);

        UNDIAG_NEON(row1l,row2l,row3l,row4l,row1h,row2h,row3h,row4h);
    }

    // Finalize: h ^= v[0..3] ^ v[8..11] (only 256 bits needed)
    row1l = veorq_u64(veorq_u64(orig1l, row1l), row3l);
    row1h = veorq_u64(veorq_u64(orig1h, row1h), row3h);

    vst1q_u8(output,      vreinterpretq_u8_u64(row1l));
    vst1q_u8(output + 16, vreinterpretq_u8_u64(row1h));
}

// ---------------------------------------------------------------------------
// BLAKE2b-256 single-block: scalar fallback
// ---------------------------------------------------------------------------

#else

static void blake2b256_single(const uint8_t *input, int len, uint8_t *output) {
    uint64_t m[16];
    memset(m, 0, sizeof(m));
    memcpy(m, input, (size_t)len < 128 ? (size_t)len : 128);

    uint64_t h0 = iv[0] ^ 0x01010020ULL, h1 = iv[1], h2 = iv[2], h3 = iv[3];

    uint64_t v[16];
    v[0]=h0; v[1]=h1; v[2]=h2; v[3]=h3;
    v[4]=iv[4]; v[5]=iv[5]; v[6]=iv[6]; v[7]=iv[7];
    v[8]=iv[0]; v[9]=iv[1]; v[10]=iv[2]; v[11]=iv[3];
    v[12]=iv[4]^(uint64_t)len; v[13]=iv[5]; v[14]=~iv[6]; v[15]=iv[7];

    for (int r = 0; r < 12; r++) {
        const uint8_t *s = sigma + r * 16;
        #define MIX(a,b,c,d,x,y) \
            v[a]=v[a]+v[b]+x; v[d]^=v[a]; v[d]=(v[d]>>32)|(v[d]<<32); \
            v[c]=v[c]+v[d]; v[b]^=v[c]; v[b]=(v[b]>>24)|(v[b]<<40); \
            v[a]=v[a]+v[b]+y; v[d]^=v[a]; v[d]=(v[d]>>16)|(v[d]<<48); \
            v[c]=v[c]+v[d]; v[b]^=v[c]; v[b]=(v[b]>>63)|(v[b]<<1);
        MIX(0,4, 8,12,m[s[0]],m[s[1]]); MIX(1,5, 9,13,m[s[2]],m[s[3]]);
        MIX(2,6,10,14,m[s[4]],m[s[5]]); MIX(3,7,11,15,m[s[6]],m[s[7]]);
        MIX(0,5,10,15,m[s[8]],m[s[9]]); MIX(1,6,11,12,m[s[10]],m[s[11]]);
        MIX(2,7, 8,13,m[s[12]],m[s[13]]); MIX(3,4, 9,14,m[s[14]],m[s[15]]);
        #undef MIX
    }

    store_u64le(output,      h0 ^ v[0] ^ v[8]);
    store_u64le(output + 8,  h1 ^ v[1] ^ v[9]);
    store_u64le(output + 16, h2 ^ v[2] ^ v[10]);
    store_u64le(output + 24, h3 ^ v[3] ^ v[11]);
}

#endif

// ---------------------------------------------------------------------------
// Prefetch-aware random index pre-computation
// ---------------------------------------------------------------------------

/// Compute the random neighbor index for a given slot without touching the buffer.
/// This is the "step 2a" of the mix phase — deterministic from (counter, round, i, j).
static inline int compute_random_idx(
    uint64_t counter, int round, int i, int j, int slots, uint8_t *scratch
) {
    store_u64le(scratch, counter);
    store_u64le(scratch + 8,  (uint64_t)round);
    store_u64le(scratch + 16, (uint64_t)i);
    store_u64le(scratch + 24, (uint64_t)j);
    uint8_t tmp[32];
    blake2b256_single(scratch, 32, tmp);
    return (int)(load_u64le(tmp) % (uint64_t)slots);
}

// ---------------------------------------------------------------------------
// BalloonHash with prefetching
// ---------------------------------------------------------------------------

int balloon_hash_fast(
    const uint8_t *password, int password_len,
    const uint8_t *salt, int salt_len,
    uint8_t *buf,
    uint8_t *inp,
    uint8_t *prefetch_inp,
    int slots, int rounds, int delta,
    uint8_t *output,
    const volatile int *cancelled
) {
    uint64_t counter = 0;

    // Phase 1: Expand — fills every slot sequentially
    store_u64le(inp, counter);
    int len = 8;
    memcpy(inp + len, password, (size_t)password_len); len += password_len;
    memcpy(inp + len, salt, (size_t)salt_len); len += salt_len;
    blake2b256_single(inp, len, buf);
    counter++;

    for (int i = 1; i < slots; i++) {
        if ((i & 0xFFFF) == 0 && cancelled && *cancelled) return -1;
        store_u64le(inp, counter);
        copy32(buf + (i - 1) * 32, inp + 8);
        blake2b256_single(inp, 40, buf + i * 32);
        counter++;
    }

    // Phase 2: Mix — pipelined prefetch.
    // Pre-compute each slot's random index one iteration ahead using the
    // separate prefetch_inp scratch buffer. This gives the prefetch 2+ full
    // BLAKE2b calls of lead time (~100-200ns) to hide DRAM latency on the
    // 512 MB random-access buffer, vs ~20ns with the naive approach.
    {
        // Seed the pipeline: compute first slot's random index ahead of time.
        int next_idx = compute_random_idx(counter + 1, 0, 0, 0, slots, prefetch_inp);
        __builtin_prefetch(buf + (size_t)next_idx * 32, 0, 0);

        for (int round = 0; round < rounds; round++) {
            for (int i = 0; i < slots; i++) {
                if ((i & 0xFFFF) == 0 && cancelled && *cancelled) return -1;
                int off = i * 32;

                // Step 1: mix with previous neighbor (sequential — likely cached).
                // During this BLAKE2b, the previously-issued prefetch loads data.
                store_u64le(inp, counter);
                copy32(buf + off, inp + 8);
                int prev = (i == 0) ? slots - 1 : i - 1;
                copy32(buf + prev * 32, inp + 40);
                blake2b256_single(inp, 72, buf + off);
                counter++;

                for (int j = 0; j < delta; j++) {
                    // Step 2: use the pre-computed random index (should be warm).
                    int idx = next_idx;

                    // Step 3: pipeline — pre-compute the NEXT random index now,
                    // before this slot's mix-random BLAKE2b. The prefetch gets
                    // the mix-random call + next mix-previous call as lead time.
                    if (j + 1 < delta) {
                        // Next delta step within same slot
                        next_idx = compute_random_idx(counter + 1, round, i, j + 1,
                                                      slots, prefetch_inp);
                    } else if (i + 1 < slots) {
                        // First delta step of next slot
                        next_idx = compute_random_idx(counter + 2, round, i + 1, 0,
                                                      slots, prefetch_inp);
                    } else if (round + 1 < rounds) {
                        // First delta step of next round
                        next_idx = compute_random_idx(counter + 2, round + 1, 0, 0,
                                                      slots, prefetch_inp);
                    }
                    __builtin_prefetch(buf + (size_t)next_idx * 32, 0, 0);

                    // Step 4: mix with random neighbor.
                    store_u64le(inp, counter);
                    copy32(buf + off, inp + 8);
                    copy32(buf + (size_t)idx * 32, inp + 40);
                    blake2b256_single(inp, 72, buf + off);
                    counter++;
                }
            }
        }
    }

    // Phase 3: Extract
    memcpy(output, buf + (size_t)(slots - 1) * 32, 32);
    return 0;
}

// Exposed for testing
void balloon_blake2b256_test(const uint8_t *input, int input_len, uint8_t *output) {
    blake2b256_single(input, input_len, output);
}

// ---------------------------------------------------------------------------
// Buffer allocation with huge page support
// ---------------------------------------------------------------------------

void *balloon_alloc_buffer(size_t size, int *used_hugepages) {
    *used_hugepages = 0;
#if defined(__linux__)
    // Try explicit huge pages (requires sysctl vm.nr_hugepages configuration)
    void *p = mmap(NULL, size, PROT_READ | PROT_WRITE,
                   MAP_PRIVATE | MAP_ANONYMOUS | 0x40000 /*MAP_HUGETLB*/, -1, 0);
    if (p != MAP_FAILED) {
        *used_hugepages = 2; // explicit huge pages
        return p;
    }
    // Fall back to regular pages with transparent huge page hint
    p = mmap(NULL, size, PROT_READ | PROT_WRITE,
             MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (p != MAP_FAILED) {
        madvise(p, size, 14); // MADV_HUGEPAGE
        *used_hugepages = 1; // mmap with THP
        return p;
    }
#endif
    // Fall back to standard allocation
    return malloc(size);
}

void balloon_free_buffer(void *ptr, size_t size, int used_hugepages) {
#if defined(__linux__)
    if (used_hugepages > 0) {
        munmap(ptr, size);
        return;
    }
#endif
    (void)size;
    (void)used_hugepages;
    free(ptr);
}

// ---------------------------------------------------------------------------

// Simple BalloonHash — direct translation of the algorithm, no prefetch optimization.
int balloon_hash_simple(
    const uint8_t *password, int password_len,
    const uint8_t *salt, int salt_len,
    uint8_t *buf,
    uint8_t *inp,
    int slots, int rounds, int delta,
    uint8_t *output,
    const volatile int *cancelled
) {
    uint64_t counter = 0;

    // Phase 1: Expand
    store_u64le(inp, counter);
    int len = 8;
    memcpy(inp + len, password, (size_t)password_len); len += password_len;
    memcpy(inp + len, salt, (size_t)salt_len); len += salt_len;
    blake2b256_single(inp, len, buf);
    counter++;

    for (int i = 1; i < slots; i++) {
        if ((i & 0xFFFF) == 0 && cancelled && *cancelled) return -1;
        store_u64le(inp, counter);
        copy32(buf + (i - 1) * 32, inp + 8);
        blake2b256_single(inp, 40, buf + i * 32);
        counter++;
    }

    // Phase 2: Mix — straight translation, no prefetch
    for (int round = 0; round < rounds; round++) {
        for (int i = 0; i < slots; i++) {
            if ((i & 0xFFFF) == 0 && cancelled && *cancelled) return -1;
            int off = i * 32;

            store_u64le(inp, counter);
            copy32(buf + off, inp + 8);
            int prev = (i == 0) ? slots - 1 : i - 1;
            copy32(buf + prev * 32, inp + 40);
            blake2b256_single(inp, 72, buf + off);
            counter++;

            for (int j = 0; j < delta; j++) {
                store_u64le(inp, counter);
                store_u64le(inp + 8,  (uint64_t)round);
                store_u64le(inp + 16, (uint64_t)i);
                store_u64le(inp + 24, (uint64_t)j);
                uint8_t tmp[32];
                blake2b256_single(inp, 32, tmp);
                int idx = (int)(load_u64le(tmp) % (uint64_t)slots);

                store_u64le(inp, counter);
                copy32(buf + off, inp + 8);
                copy32(buf + (size_t)idx * 32, inp + 40);
                blake2b256_single(inp, 72, buf + off);
                counter++;
            }
        }
    }

    memcpy(output, buf + (size_t)(slots - 1) * 32, 32);
    return 0;
}
