/* Intel SM3-NI state layout and schedule adapted from Intel IPP Cryptography,
 * pcpsm3l9_ni_as.asm (Apache-2.0). This file is compiled only with -msm3. */
#include "sm3_x86_ni.h"
#include <immintrin.h>
#include <string.h>

static inline __m128i rotl32(__m128i x, int n) {
    return _mm_or_si128(_mm_slli_epi32(x, n), _mm_srli_epi32(x, 32 - n));
}

#define SM3_MSG(W0,W1,W2,W3,OUT,T1,T2) do { \
    (OUT) = _mm_alignr_epi8((W2), (W1), 12); \
    (T1) = _mm_srli_si128((W3), 4); \
    (OUT) = _mm_sm3msg1_epi32((OUT), (T1), (W0)); \
    (T1) = _mm_alignr_epi8((W1), (W0), 12); \
    (T2) = _mm_alignr_epi8((W3), (W2), 8); \
    (OUT) = _mm_sm3msg2_epi32((OUT), (T1), (T2)); \
} while (0)

#define SM3_ROUNDS4(ABEF,CDGH,W0,W1,T,R) do { \
    (T) = _mm_unpacklo_epi64((W0), (W1)); \
    (CDGH) = _mm_sm3rnds2_epi32((CDGH), (ABEF), (T), (R)); \
    (T) = _mm_unpackhi_epi64((W0), (W1)); \
    (ABEF) = _mm_sm3rnds2_epi32((ABEF), (CDGH), (T), (R) + 2); \
} while (0)

static void sm3_ni_compress(uint32_t state[8], const uint8_t* data, size_t blocks) {
    const __m128i swap = _mm_setr_epi8(3,2,1,0, 7,6,5,4, 11,10,9,8, 15,14,13,12);
    __m128i s0 = _mm_loadu_si128((const __m128i*)(const void*)state);
    __m128i s1 = _mm_loadu_si128((const __m128i*)(const void*)(state + 4));
    __m128i x0 = _mm_shuffle_epi32(s0, 0x1b);
    __m128i x1 = _mm_shuffle_epi32(s1, 0x1b);
    __m128i abef = _mm_unpackhi_epi64(x1, x0);
    __m128i cdgh = _mm_unpacklo_epi64(x1, x0);
    cdgh = _mm_blend_epi32(rotl32(cdgh, 23), rotl32(cdgh, 13), 0x3);

    while (blocks--) {
        __m128i old_abef = abef, old_cdgh = cdgh;
        __m128i w0 = _mm_shuffle_epi8(_mm_loadu_si128((const __m128i*)(const void*)(data +  0)), swap);
        __m128i w1 = _mm_shuffle_epi8(_mm_loadu_si128((const __m128i*)(const void*)(data + 16)), swap);
        __m128i w2 = _mm_shuffle_epi8(_mm_loadu_si128((const __m128i*)(const void*)(data + 32)), swap);
        __m128i w3 = _mm_shuffle_epi8(_mm_loadu_si128((const __m128i*)(const void*)(data + 48)), swap);
        __m128i wn, t1, t2;

        SM3_MSG(w0,w1,w2,w3,wn,t1,t2); SM3_ROUNDS4(abef,cdgh,w0,w1,t1, 0); w0=wn;
        SM3_MSG(w1,w2,w3,w0,wn,t1,t2); SM3_ROUNDS4(abef,cdgh,w1,w2,t1, 4); w1=wn;
        SM3_MSG(w2,w3,w0,w1,wn,t1,t2); SM3_ROUNDS4(abef,cdgh,w2,w3,t1, 8); w2=wn;
        SM3_MSG(w3,w0,w1,w2,wn,t1,t2); SM3_ROUNDS4(abef,cdgh,w3,w0,t1,12); w3=wn;
        SM3_MSG(w0,w1,w2,w3,wn,t1,t2); SM3_ROUNDS4(abef,cdgh,w0,w1,t1,16); w0=wn;
        SM3_MSG(w1,w2,w3,w0,wn,t1,t2); SM3_ROUNDS4(abef,cdgh,w1,w2,t1,20); w1=wn;
        SM3_MSG(w2,w3,w0,w1,wn,t1,t2); SM3_ROUNDS4(abef,cdgh,w2,w3,t1,24); w2=wn;
        SM3_MSG(w3,w0,w1,w2,wn,t1,t2); SM3_ROUNDS4(abef,cdgh,w3,w0,t1,28); w3=wn;
        SM3_MSG(w0,w1,w2,w3,wn,t1,t2); SM3_ROUNDS4(abef,cdgh,w0,w1,t1,32); w0=wn;
        SM3_MSG(w1,w2,w3,w0,wn,t1,t2); SM3_ROUNDS4(abef,cdgh,w1,w2,t1,36); w1=wn;
        SM3_MSG(w2,w3,w0,w1,wn,t1,t2); SM3_ROUNDS4(abef,cdgh,w2,w3,t1,40); w2=wn;
        SM3_MSG(w3,w0,w1,w2,wn,t1,t2); SM3_ROUNDS4(abef,cdgh,w3,w0,t1,44); w3=wn;
        SM3_MSG(w0,w1,w2,w3,wn,t1,t2); SM3_ROUNDS4(abef,cdgh,w0,w1,t1,48); w0=wn;
        SM3_ROUNDS4(abef,cdgh,w1,w2,t1,52);
        SM3_ROUNDS4(abef,cdgh,w2,w3,t1,56);
        SM3_ROUNDS4(abef,cdgh,w3,w0,t1,60);
        abef = _mm_xor_si128(abef, old_abef);
        cdgh = _mm_xor_si128(cdgh, old_cdgh);
        data += 64;
    }

    cdgh = _mm_blend_epi32(rotl32(cdgh, 9), rotl32(cdgh, 19), 0x3);
    x0 = _mm_shuffle_epi32(abef, 0x1b);
    x1 = _mm_shuffle_epi32(cdgh, 0x1b);
    s0 = _mm_unpacklo_epi64(x0, x1);
    s1 = _mm_unpackhi_epi64(x0, x1);
    _mm_storeu_si128((__m128i*)(void*)state, s0);
    _mm_storeu_si128((__m128i*)(void*)(state + 4), s1);
}

static void store_be32(uint8_t* p, uint32_t x) {
    p[0]=(uint8_t)(x>>24); p[1]=(uint8_t)(x>>16); p[2]=(uint8_t)(x>>8); p[3]=(uint8_t)x;
}

void hasher_sm3_x86_ni(const uint8_t* input, size_t size, uint8_t output[32]) {
    uint32_t state[8] = {0x7380166fu,0x4914b2b9u,0x172442d7u,0xda8a0600u,
                         0xa96f30bcu,0x163138aau,0xe38dee4du,0xb0fb0e4eu};
    uint8_t tail[128] = {0};
    size_t blocks = size / 64, rem = size & 63, pad_blocks;
    uint64_t bits = (uint64_t)size << 3;
    size_t i;
    if (blocks) sm3_ni_compress(state, input, blocks);
    if (rem) memcpy(tail, input + blocks * 64, rem);
    tail[rem] = 0x80;
    pad_blocks = rem < 56 ? 1 : 2;
    for (i=0;i<8;i++) tail[pad_blocks*64-1-i]=(uint8_t)(bits>>(i*8));
    sm3_ni_compress(state, tail, pad_blocks);
    for (i=0;i<8;i++) store_be32(output+i*4,state[i]);
}
