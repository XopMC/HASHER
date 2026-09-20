#include "sha256.h"
#include <string.h>
#include <stdlib.h>

//SHA256 implementation optimized for x86_64 and ARM CPUs

static const uint32_t SHA256_K[64] = {
    0x428A2F98, 0x71374491, 0xB5C0FBCF, 0xE9B5DBA5, 0x3956C25B, 0x59F111F1, 0x923F82A4, 0xAB1C5ED5,
    0xD807AA98, 0x12835B01, 0x243185BE, 0x550C7DC3, 0x72BE5D74, 0x80DEB1FE, 0x9BDC06A7, 0xC19BF174,
    0xE49B69C1, 0xEFBE4786, 0x0FC19DC6, 0x240CA1CC, 0x2DE92C6F, 0x4A7484AA, 0x5CB0A9DC, 0x76F988DA,
    0x983E5152, 0xA831C66D, 0xB00327C8, 0xBF597FC7, 0xC6E00BF3, 0xD5A79147, 0x06CA6351, 0x14292967,
    0x27B70A85, 0x2E1B2138, 0x4D2C6DFC, 0x53380D13, 0x650A7354, 0x766A0ABB, 0x81C2C92E, 0x92722C85,
    0xA2BFE8A1, 0xA81A664B, 0xC24B8B70, 0xC76C51A3, 0xD192E819, 0xD6990624, 0xF40E3585, 0x106AA070,
    0x19A4C116, 0x1E376C08, 0x2748774C, 0x34B0BCB5, 0x391C0CB3, 0x4ED8AA4A, 0x5B9CCA4F, 0x682E6FF3,
    0x748F82EE, 0x78A5636F, 0x84C87814, 0x8CC70208, 0x90BEFFFA, 0xA4506CEB, 0xBEF9A3F7, 0xC67178F2,
};

static const uint32_t SHA256_IV[8] = {
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
};

// https://github.com/noloader/SHA-Intrinsics/blob/master/sha256-arm.c
#if defined(__ARM_NEON) && defined(__ARM_FEATURE_CRYPTO)
#include <arm_neon.h>

void sha256_32(uint32_t state[8], const uint8_t data[], uint32_t length) {
    uint32x4_t STATE0, STATE1, ABEF_SAVE, CDGH_SAVE;
    uint32x4_t MSG0, MSG1, MSG2, MSG3;
    uint32x4_t TMP0, TMP1, TMP2;

    /* Load state */
    // STATE0 = vld1q_uint32_t(&state[0]);
    // STATE1 = vld1q_uint32_t(&state[4]);
    STATE0 = vld1q_uint32_t(&SHA256_IV[0]);
    STATE1 = vld1q_uint32_t(&SHA256_IV[4]);

    while (length >= 64) {
        /* Save state */
        ABEF_SAVE = STATE0;
        CDGH_SAVE = STATE1;

        /* Load message */
        MSG0 = vld1q_uint32_t((const uint32_t*)(data + 0));
        MSG1 = vld1q_uint32_t((const uint32_t*)(data + 16));
        MSG2 = vld1q_uint32_t((const uint32_t*)(data + 32));
        MSG3 = vld1q_uint32_t((const uint32_t*)(data + 48));

        /* Reverse for little endian */
        MSG0 = vreinterpretq_uint32_t_uint8_t(vrev32q_uint8_t(vreinterpretq_uint8_t_uint32_t(MSG0)));
        MSG1 = vreinterpretq_uint32_t_uint8_t(vrev32q_uint8_t(vreinterpretq_uint8_t_uint32_t(MSG1)));
        MSG2 = vreinterpretq_uint32_t_uint8_t(vrev32q_uint8_t(vreinterpretq_uint8_t_uint32_t(MSG2)));
        MSG3 = vreinterpretq_uint32_t_uint8_t(vrev32q_uint8_t(vreinterpretq_uint8_t_uint32_t(MSG3)));

        TMP0 = vaddq_uint32_t(MSG0, vld1q_uint32_t(&SHA256_K[0x00]));

        /* Rounds 0-3 */
        MSG0 = vsha256su0q_uint32_t(MSG0, MSG1);
        TMP2 = STATE0;
        TMP1 = vaddq_uint32_t(MSG1, vld1q_uint32_t(&SHA256_K[0x04]));
        STATE0 = vsha256hq_uint32_t(STATE0, STATE1, TMP0);
        STATE1 = vsha256h2q_uint32_t(STATE1, TMP2, TMP0);
        MSG0 = vsha256su1q_uint32_t(MSG0, MSG2, MSG3);

        /* Rounds 4-7 */
        MSG1 = vsha256su0q_uint32_t(MSG1, MSG2);
        TMP2 = STATE0;
        TMP0 = vaddq_uint32_t(MSG2, vld1q_uint32_t(&SHA256_K[0x08]));
        STATE0 = vsha256hq_uint32_t(STATE0, STATE1, TMP1);
        STATE1 = vsha256h2q_uint32_t(STATE1, TMP2, TMP1);
        MSG1 = vsha256su1q_uint32_t(MSG1, MSG3, MSG0);

        /* Rounds 8-11 */
        MSG2 = vsha256su0q_uint32_t(MSG2, MSG3);
        TMP2 = STATE0;
        TMP1 = vaddq_uint32_t(MSG3, vld1q_uint32_t(&SHA256_K[0x0c]));
        STATE0 = vsha256hq_uint32_t(STATE0, STATE1, TMP0);
        STATE1 = vsha256h2q_uint32_t(STATE1, TMP2, TMP0);
        MSG2 = vsha256su1q_uint32_t(MSG2, MSG0, MSG1);

        /* Rounds 12-15 */
        MSG3 = vsha256su0q_uint32_t(MSG3, MSG0);
        TMP2 = STATE0;
        TMP0 = vaddq_uint32_t(MSG0, vld1q_uint32_t(&SHA256_K[0x10]));
        STATE0 = vsha256hq_uint32_t(STATE0, STATE1, TMP1);
        STATE1 = vsha256h2q_uint32_t(STATE1, TMP2, TMP1);
        MSG3 = vsha256su1q_uint32_t(MSG3, MSG1, MSG2);

        /* Rounds 16-19 */
        MSG0 = vsha256su0q_uint32_t(MSG0, MSG1);
        TMP2 = STATE0;
        TMP1 = vaddq_uint32_t(MSG1, vld1q_uint32_t(&SHA256_K[0x14]));
        STATE0 = vsha256hq_uint32_t(STATE0, STATE1, TMP0);
        STATE1 = vsha256h2q_uint32_t(STATE1, TMP2, TMP0);
        MSG0 = vsha256su1q_uint32_t(MSG0, MSG2, MSG3);

        /* Rounds 20-23 */
        MSG1 = vsha256su0q_uint32_t(MSG1, MSG2);
        TMP2 = STATE0;
        TMP0 = vaddq_uint32_t(MSG2, vld1q_uint32_t(&SHA256_K[0x18]));
        STATE0 = vsha256hq_uint32_t(STATE0, STATE1, TMP1);
        STATE1 = vsha256h2q_uint32_t(STATE1, TMP2, TMP1);
        MSG1 = vsha256su1q_uint32_t(MSG1, MSG3, MSG0);

        /* Rounds 24-27 */
        MSG2 = vsha256su0q_uint32_t(MSG2, MSG3);
        TMP2 = STATE0;
        TMP1 = vaddq_uint32_t(MSG3, vld1q_uint32_t(&SHA256_K[0x1c]));
        STATE0 = vsha256hq_uint32_t(STATE0, STATE1, TMP0);
        STATE1 = vsha256h2q_uint32_t(STATE1, TMP2, TMP0);
        MSG2 = vsha256su1q_uint32_t(MSG2, MSG0, MSG1);

        /* Rounds 28-31 */
        MSG3 = vsha256su0q_uint32_t(MSG3, MSG0);
        TMP2 = STATE0;
        TMP0 = vaddq_uint32_t(MSG0, vld1q_uint32_t(&SHA256_K[0x20]));
        STATE0 = vsha256hq_uint32_t(STATE0, STATE1, TMP1);
        STATE1 = vsha256h2q_uint32_t(STATE1, TMP2, TMP1);
        MSG3 = vsha256su1q_uint32_t(MSG3, MSG1, MSG2);

        /* Rounds 32-35 */
        MSG0 = vsha256su0q_uint32_t(MSG0, MSG1);
        TMP2 = STATE0;
        TMP1 = vaddq_uint32_t(MSG1, vld1q_uint32_t(&SHA256_K[0x24]));
        STATE0 = vsha256hq_uint32_t(STATE0, STATE1, TMP0);
        STATE1 = vsha256h2q_uint32_t(STATE1, TMP2, TMP0);
        MSG0 = vsha256su1q_uint32_t(MSG0, MSG2, MSG3);

        /* Rounds 36-39 */
        MSG1 = vsha256su0q_uint32_t(MSG1, MSG2);
        TMP2 = STATE0;
        TMP0 = vaddq_uint32_t(MSG2, vld1q_uint32_t(&SHA256_K[0x28]));
        STATE0 = vsha256hq_uint32_t(STATE0, STATE1, TMP1);
        STATE1 = vsha256h2q_uint32_t(STATE1, TMP2, TMP1);
        MSG1 = vsha256su1q_uint32_t(MSG1, MSG3, MSG0);

        /* Rounds 40-43 */
        MSG2 = vsha256su0q_uint32_t(MSG2, MSG3);
        TMP2 = STATE0;
        TMP1 = vaddq_uint32_t(MSG3, vld1q_uint32_t(&SHA256_K[0x2c]));
        STATE0 = vsha256hq_uint32_t(STATE0, STATE1, TMP0);
        STATE1 = vsha256h2q_uint32_t(STATE1, TMP2, TMP0);
        MSG2 = vsha256su1q_uint32_t(MSG2, MSG0, MSG1);

        /* Rounds 44-47 */
        MSG3 = vsha256su0q_uint32_t(MSG3, MSG0);
        TMP2 = STATE0;
        TMP0 = vaddq_uint32_t(MSG0, vld1q_uint32_t(&SHA256_K[0x30]));
        STATE0 = vsha256hq_uint32_t(STATE0, STATE1, TMP1);
        STATE1 = vsha256h2q_uint32_t(STATE1, TMP2, TMP1);
        MSG3 = vsha256su1q_uint32_t(MSG3, MSG1, MSG2);

        /* Rounds 48-51 */
        TMP2 = STATE0;
        TMP1 = vaddq_uint32_t(MSG1, vld1q_uint32_t(&SHA256_K[0x34]));
        STATE0 = vsha256hq_uint32_t(STATE0, STATE1, TMP0);
        STATE1 = vsha256h2q_uint32_t(STATE1, TMP2, TMP0);

        /* Rounds 52-55 */
        TMP2 = STATE0;
        TMP0 = vaddq_uint32_t(MSG2, vld1q_uint32_t(&SHA256_K[0x38]));
        STATE0 = vsha256hq_uint32_t(STATE0, STATE1, TMP1);
        STATE1 = vsha256h2q_uint32_t(STATE1, TMP2, TMP1);

        /* Rounds 56-59 */
        TMP2 = STATE0;
        TMP1 = vaddq_uint32_t(MSG3, vld1q_uint32_t(&SHA256_K[0x3c]));
        STATE0 = vsha256hq_uint32_t(STATE0, STATE1, TMP0);
        STATE1 = vsha256h2q_uint32_t(STATE1, TMP2, TMP0);

        /* Rounds 60-63 */
        TMP2 = STATE0;
        STATE0 = vsha256hq_uint32_t(STATE0, STATE1, TMP1);
        STATE1 = vsha256h2q_uint32_t(STATE1, TMP2, TMP1);

        /* Combine state */
        STATE0 = vaddq_uint32_t(STATE0, ABEF_SAVE);
        STATE1 = vaddq_uint32_t(STATE1, CDGH_SAVE);

        data += 64;
        length -= 64;
    }

    /* Save state */
    vst1q_uint32_t(&state[0], STATE0);
    vst1q_uint32_t(&state[4], STATE1);
}

void sha256(uint8_t in[], uint32_t size, uint8_t out[])
{
    uint32_t msg_len = size;
    uint32_t blocks = (msg_len + 9 + 63) / 64;
    uint32_t padded_len = blocks * 64;

    uint8_t* buf = (uint8_t*)malloc(padded_len);
    memcpy(buf, in, msg_len);

    buf[msg_len] = 0x80;
    memset(buf + msg_len + 1, 0, padded_len - msg_len - 1 - 8);

    uint64_t bit_len = (uint64_t)msg_len << 3;
    for (int i = 0; i < 8; ++i)
        buf[padded_len - 8 + i] = (uint8_t)(bit_len >> (56 - 8 * i));

    uint32_t state[8] = { 0 };
    sha256_32(state, buf, padded_len);
    free(buf);

    for (int w = 0; w < 8; ++w) {
        uint32_t v = state[w];
        out[w * 4 + 0] = (uint8_t)(v >> 24);
        out[w * 4 + 1] = (uint8_t)(v >> 16);
        out[w * 4 + 2] = (uint8_t)(v >> 8);
        out[w * 4 + 3] = (uint8_t)(v);
    }
}

// https://github.com/noloader/SHA-Intrinsics/blob/master/sha256-x86.c
#elif defined(__x86_64__) && defined(__SHA__)
  // #warning "SHA256: Using x86-64 with SHA intrinsics"
#include <immintrin.h>

void sha256_32(uint32_t state[8], const uint8_t data[], uint32_t length) {
    __m128i STATE0, STATE1;
    __m128i MSG, TMP;
    __m128i MSG0, MSG1, MSG2, MSG3;
    __m128i ABEF_SAVE, CDGH_SAVE;
    const __m128i MASK = _mm_set_epi64x(0x0c0d0e0f08090a0bULL, 0x0405060700010203ULL);

    /* Load initial values */
    // TMP = _mm_loadu_si128((const __m128i *)&state[0]);
    // STATE1 = _mm_loadu_si128((const __m128i *)&state[4]);
    TMP = _mm_loadu_si128((const __m128i*) & SHA256_IV[0]);
    STATE1 = _mm_loadu_si128((const __m128i*) & SHA256_IV[4]);

    TMP = _mm_shuffle_epi32(TMP, 0xB1);          /* CDAB */
    STATE1 = _mm_shuffle_epi32(STATE1, 0x1B);    /* EFGH */
    STATE0 = _mm_alignr_epi8(TMP, STATE1, 8);    /* ABEF */
    STATE1 = _mm_blend_epi16(STATE1, TMP, 0xF0); /* CDGH */

    while (length >= 64) {
        /* Save current state */
        ABEF_SAVE = STATE0;
        CDGH_SAVE = STATE1;

        /* Rounds 0-3 */
        MSG = _mm_loadu_si128((const __m128i*)(data + 0));
        MSG0 = _mm_shuffle_epi8(MSG, MASK);
        MSG = _mm_add_epi32(MSG0, _mm_set_epi64x(0xE9B5DBA5B5C0FBCFULL, 0x71374491428A2F98ULL));
        STATE1 = _mm_sha256rnds2_epuint32_t(STATE1, STATE0, MSG);
        MSG = _mm_shuffle_epi32(MSG, 0x0E);
        STATE0 = _mm_sha256rnds2_epuint32_t(STATE0, STATE1, MSG);

        /* Rounds 4-7 */
        MSG1 = _mm_loadu_si128((const __m128i*)(data + 16));
        MSG1 = _mm_shuffle_epi8(MSG1, MASK);
        MSG = _mm_add_epi32(MSG1, _mm_set_epi64x(0xAB1C5ED5923F82A4ULL, 0x59F111F13956C25BULL));
        STATE1 = _mm_sha256rnds2_epuint32_t(STATE1, STATE0, MSG);
        MSG = _mm_shuffle_epi32(MSG, 0x0E);
        STATE0 = _mm_sha256rnds2_epuint32_t(STATE0, STATE1, MSG);
        MSG0 = _mm_sha256msg1_epuint32_t(MSG0, MSG1);

        /* Rounds 8-11 */
        MSG2 = _mm_loadu_si128((const __m128i*)(data + 32));
        MSG2 = _mm_shuffle_epi8(MSG2, MASK);
        MSG = _mm_add_epi32(MSG2, _mm_set_epi64x(0x550C7DC3243185BEULL, 0x12835B01D807AA98ULL));
        STATE1 = _mm_sha256rnds2_epuint32_t(STATE1, STATE0, MSG);
        MSG = _mm_shuffle_epi32(MSG, 0x0E);
        STATE0 = _mm_sha256rnds2_epuint32_t(STATE0, STATE1, MSG);
        MSG1 = _mm_sha256msg1_epuint32_t(MSG1, MSG2);

        /* Rounds 12-15 */
        MSG3 = _mm_loadu_si128((const __m128i*)(data + 48));
        MSG3 = _mm_shuffle_epi8(MSG3, MASK);
        MSG = _mm_add_epi32(MSG3, _mm_set_epi64x(0xC19BF1749BDC06A7ULL, 0x80DEB1FE72BE5D74ULL));
        STATE1 = _mm_sha256rnds2_epuint32_t(STATE1, STATE0, MSG);
        TMP = _mm_alignr_epi8(MSG3, MSG2, 4);
        MSG0 = _mm_add_epi32(MSG0, TMP);
        MSG0 = _mm_sha256msg2_epuint32_t(MSG0, MSG3);
        MSG = _mm_shuffle_epi32(MSG, 0x0E);
        STATE0 = _mm_sha256rnds2_epuint32_t(STATE0, STATE1, MSG);
        MSG2 = _mm_sha256msg1_epuint32_t(MSG2, MSG3);

        /* Rounds 16-19 */
        MSG = _mm_add_epi32(MSG0, _mm_set_epi64x(0x240CA1CC0FC19DC6ULL, 0xEFBE4786E49B69C1ULL));
        STATE1 = _mm_sha256rnds2_epuint32_t(STATE1, STATE0, MSG);
        TMP = _mm_alignr_epi8(MSG0, MSG3, 4);
        MSG1 = _mm_add_epi32(MSG1, TMP);
        MSG1 = _mm_sha256msg2_epuint32_t(MSG1, MSG0);
        MSG = _mm_shuffle_epi32(MSG, 0x0E);
        STATE0 = _mm_sha256rnds2_epuint32_t(STATE0, STATE1, MSG);
        MSG3 = _mm_sha256msg1_epuint32_t(MSG3, MSG0);

        /* Rounds 20-23 */
        MSG = _mm_add_epi32(MSG1, _mm_set_epi64x(0x76F988DA5CB0A9DCULL, 0x4A7484AA2DE92C6FULL));
        STATE1 = _mm_sha256rnds2_epuint32_t(STATE1, STATE0, MSG);
        TMP = _mm_alignr_epi8(MSG1, MSG0, 4);
        MSG2 = _mm_add_epi32(MSG2, TMP);
        MSG2 = _mm_sha256msg2_epuint32_t(MSG2, MSG1);
        MSG = _mm_shuffle_epi32(MSG, 0x0E);
        STATE0 = _mm_sha256rnds2_epuint32_t(STATE0, STATE1, MSG);
        MSG0 = _mm_sha256msg1_epuint32_t(MSG0, MSG1);

        /* Rounds 24-27 */
        MSG = _mm_add_epi32(MSG2, _mm_set_epi64x(0xBF597FC7B00327C8ULL, 0xA831C66D983E5152ULL));
        STATE1 = _mm_sha256rnds2_epuint32_t(STATE1, STATE0, MSG);
        TMP = _mm_alignr_epi8(MSG2, MSG1, 4);
        MSG3 = _mm_add_epi32(MSG3, TMP);
        MSG3 = _mm_sha256msg2_epuint32_t(MSG3, MSG2);
        MSG = _mm_shuffle_epi32(MSG, 0x0E);
        STATE0 = _mm_sha256rnds2_epuint32_t(STATE0, STATE1, MSG);
        MSG1 = _mm_sha256msg1_epuint32_t(MSG1, MSG2);

        /* Rounds 28-31 */
        MSG = _mm_add_epi32(MSG3, _mm_set_epi64x(0x1429296706CA6351ULL, 0xD5A79147C6E00BF3ULL));
        STATE1 = _mm_sha256rnds2_epuint32_t(STATE1, STATE0, MSG);
        TMP = _mm_alignr_epi8(MSG3, MSG2, 4);
        MSG0 = _mm_add_epi32(MSG0, TMP);
        MSG0 = _mm_sha256msg2_epuint32_t(MSG0, MSG3);
        MSG = _mm_shuffle_epi32(MSG, 0x0E);
        STATE0 = _mm_sha256rnds2_epuint32_t(STATE0, STATE1, MSG);
        MSG2 = _mm_sha256msg1_epuint32_t(MSG2, MSG3);

        /* Rounds 32-35 */
        MSG = _mm_add_epi32(MSG0, _mm_set_epi64x(0x53380D134D2C6DFCULL, 0x2E1B213827B70A85ULL));
        STATE1 = _mm_sha256rnds2_epuint32_t(STATE1, STATE0, MSG);
        TMP = _mm_alignr_epi8(MSG0, MSG3, 4);
        MSG1 = _mm_add_epi32(MSG1, TMP);
        MSG1 = _mm_sha256msg2_epuint32_t(MSG1, MSG0);
        MSG = _mm_shuffle_epi32(MSG, 0x0E);
        STATE0 = _mm_sha256rnds2_epuint32_t(STATE0, STATE1, MSG);
        MSG3 = _mm_sha256msg1_epuint32_t(MSG3, MSG0);

        /* Rounds 36-39 */
        MSG = _mm_add_epi32(MSG1, _mm_set_epi64x(0x92722C8581C2C92EULL, 0x766A0ABB650A7354ULL));
        STATE1 = _mm_sha256rnds2_epuint32_t(STATE1, STATE0, MSG);
        TMP = _mm_alignr_epi8(MSG1, MSG0, 4);
        MSG2 = _mm_add_epi32(MSG2, TMP);
        MSG2 = _mm_sha256msg2_epuint32_t(MSG2, MSG1);
        MSG = _mm_shuffle_epi32(MSG, 0x0E);
        STATE0 = _mm_sha256rnds2_epuint32_t(STATE0, STATE1, MSG);
        MSG0 = _mm_sha256msg1_epuint32_t(MSG0, MSG1);

        /* Rounds 40-43 */
        MSG = _mm_add_epi32(MSG2, _mm_set_epi64x(0xC76C51A3C24B8B70ULL, 0xA81A664BA2BFE8A1ULL));
        STATE1 = _mm_sha256rnds2_epuint32_t(STATE1, STATE0, MSG);
        TMP = _mm_alignr_epi8(MSG2, MSG1, 4);
        MSG3 = _mm_add_epi32(MSG3, TMP);
        MSG3 = _mm_sha256msg2_epuint32_t(MSG3, MSG2);
        MSG = _mm_shuffle_epi32(MSG, 0x0E);
        STATE0 = _mm_sha256rnds2_epuint32_t(STATE0, STATE1, MSG);
        MSG1 = _mm_sha256msg1_epuint32_t(MSG1, MSG2);

        /* Rounds 44-47 */
        MSG = _mm_add_epi32(MSG3, _mm_set_epi64x(0x106AA070F40E3585ULL, 0xD6990624D192E819ULL));
        STATE1 = _mm_sha256rnds2_epuint32_t(STATE1, STATE0, MSG);
        TMP = _mm_alignr_epi8(MSG3, MSG2, 4);
        MSG0 = _mm_add_epi32(MSG0, TMP);
        MSG0 = _mm_sha256msg2_epuint32_t(MSG0, MSG3);
        MSG = _mm_shuffle_epi32(MSG, 0x0E);
        STATE0 = _mm_sha256rnds2_epuint32_t(STATE0, STATE1, MSG);
        MSG2 = _mm_sha256msg1_epuint32_t(MSG2, MSG3);

        /* Rounds 48-51 */
        MSG = _mm_add_epi32(MSG0, _mm_set_epi64x(0x34B0BCB52748774CULL, 0x1E376C0819A4C116ULL));
        STATE1 = _mm_sha256rnds2_epuint32_t(STATE1, STATE0, MSG);
        TMP = _mm_alignr_epi8(MSG0, MSG3, 4);
        MSG1 = _mm_add_epi32(MSG1, TMP);
        MSG1 = _mm_sha256msg2_epuint32_t(MSG1, MSG0);
        MSG = _mm_shuffle_epi32(MSG, 0x0E);
        STATE0 = _mm_sha256rnds2_epuint32_t(STATE0, STATE1, MSG);
        MSG3 = _mm_sha256msg1_epuint32_t(MSG3, MSG0);

        /* Rounds 52-55 */
        MSG = _mm_add_epi32(MSG1, _mm_set_epi64x(0x682E6FF35B9CCA4FULL, 0x4ED8AA4A391C0CB3ULL));
        STATE1 = _mm_sha256rnds2_epuint32_t(STATE1, STATE0, MSG);
        TMP = _mm_alignr_epi8(MSG1, MSG0, 4);
        MSG2 = _mm_add_epi32(MSG2, TMP);
        MSG2 = _mm_sha256msg2_epuint32_t(MSG2, MSG1);
        MSG = _mm_shuffle_epi32(MSG, 0x0E);
        STATE0 = _mm_sha256rnds2_epuint32_t(STATE0, STATE1, MSG);

        /* Rounds 56-59 */
        MSG = _mm_add_epi32(MSG2, _mm_set_epi64x(0x8CC7020884C87814ULL, 0x78A5636F748F82EEULL));
        STATE1 = _mm_sha256rnds2_epuint32_t(STATE1, STATE0, MSG);
        TMP = _mm_alignr_epi8(MSG2, MSG1, 4);
        MSG3 = _mm_add_epi32(MSG3, TMP);
        MSG3 = _mm_sha256msg2_epuint32_t(MSG3, MSG2);
        MSG = _mm_shuffle_epi32(MSG, 0x0E);
        STATE0 = _mm_sha256rnds2_epuint32_t(STATE0, STATE1, MSG);

        /* Rounds 60-63 */
        MSG = _mm_add_epi32(MSG3, _mm_set_epi64x(0xC67178F2BEF9A3F7ULL, 0xA4506CEB90BEFFFAULL));
        STATE1 = _mm_sha256rnds2_epuint32_t(STATE1, STATE0, MSG);
        MSG = _mm_shuffle_epi32(MSG, 0x0E);
        STATE0 = _mm_sha256rnds2_epuint32_t(STATE0, STATE1, MSG);

        /* Combine state  */
        STATE0 = _mm_add_epi32(STATE0, ABEF_SAVE);
        STATE1 = _mm_add_epi32(STATE1, CDGH_SAVE);

        data += 64;
        length -= 64;
    }

    TMP = _mm_shuffle_epi32(STATE0, 0x1B);       /* FEBA */
    STATE1 = _mm_shuffle_epi32(STATE1, 0xB1);    /* DCHG */
    STATE0 = _mm_blend_epi16(TMP, STATE1, 0xF0); /* DCBA */
    STATE1 = _mm_alignr_epi8(STATE1, TMP, 8);    /* ABEF */

    /* Save state */
    _mm_storeu_si128((__m128i*) & state[0], STATE0);
    _mm_storeu_si128((__m128i*) & state[4], STATE1);
}


void sha256(uint8_t in[], uint32_t size, uint8_t out[])
{
    uint32_t msg_len = size;
    uint32_t blocks = (msg_len + 9 + 63) / 64;
    uint32_t padded_len = blocks * 64;

    uint8_t* buf = (uint8_t*)malloc(padded_len);
    memcpy(buf, in, msg_len);

    buf[msg_len] = 0x80;
    memset(buf + msg_len + 1, 0, padded_len - msg_len - 1 - 8);

    uint64_t bit_len = (uint64_t)msg_len << 3;
    for (int i = 0; i < 8; ++i)
        buf[padded_len - 8 + i] = (uint8_t)(bit_len >> (56 - 8 * i));

    uint32_t state[8] = { 0 };
    sha256_32(state, buf, padded_len);
    free(buf);

    for (int w = 0; w < 8; ++w) {
        uint32_t v = state[w];
        out[w * 4 + 0] = (uint8_t)(v >> 24);
        out[w * 4 + 1] = (uint8_t)(v >> 16);
        out[w * 4 + 2] = (uint8_t)(v >> 8);
        out[w * 4 + 3] = (uint8_t)(v);
    }
}

#else
//#warning "SHA256: no intrinsics available, using fallback implementation"

static inline uint32_t rotr(uint32_t x, uint32_t n) { return (x >> n) | (x << (32 - n)); }
static inline uint32_t MAJ(uint32_t a, uint32_t b, uint32_t c) { return (a & b) ^ (a & c) ^ (b & c); }
static inline uint32_t CH(uint32_t e, uint32_t f, uint32_t g) { return (e & f) ^ (~e & g); }
static inline void ROUND(uint32_t a, uint32_t b, uint32_t c, uint32_t* d, uint32_t e, uint32_t f, uint32_t g, uint32_t* h, uint32_t m, uint32_t k) {
    uint32_t s = CH(e, f, g) + (rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25)) + k + m;
    *d += s + *h;
    *h += s + MAJ(a, b, c) + (rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22));
}

void sha256_32(uint32_t state[8], const uint8_t data[], uint32_t length) {
    uint32_t s0, s1;
    uint32_t a, b, c, d, e, f, g, h;
    for (int i = 0; i < 8; i++) state[i] = SHA256_IV[i];

    while (length >= 64) {
        a = state[0];
        b = state[1];
        c = state[2];
        d = state[3];
        e = state[4];
        f = state[5];
        g = state[6];
        h = state[7];

        uint32_t w[80] = { 0 };
        for (int i = 0; i < 16; i++) {
            int k = i * 4;
            w[i] = (data[k] << 24) | (data[k + 1] << 16) | (data[k + 2] << 8) | data[k + 3];
        }

        // Expand 16 words to 64 words
        for (int i = 16; i < 64; i++) {
            uint32_t x = w[i - 15];
            uint32_t y = w[i - 2];

            s0 = rotr(x, 7) ^ rotr(x, 18) ^ (x >> 3);
            s1 = rotr(y, 17) ^ rotr(y, 19) ^ (y >> 10);
            w[i] = w[i - 16] + s0 + w[i - 7] + s1;
        }

        for (int i = 0; i < 64; i += 8) {
            ROUND(a, b, c, &d, e, f, g, &h, w[i + 0], SHA256_K[i + 0]);
            ROUND(h, a, b, &c, d, e, f, &g, w[i + 1], SHA256_K[i + 1]);
            ROUND(g, h, a, &b, c, d, e, &f, w[i + 2], SHA256_K[i + 2]);
            ROUND(f, g, h, &a, b, c, d, &e, w[i + 3], SHA256_K[i + 3]);
            ROUND(e, f, g, &h, a, b, c, &d, w[i + 4], SHA256_K[i + 4]);
            ROUND(d, e, f, &g, h, a, b, &c, w[i + 5], SHA256_K[i + 5]);
            ROUND(c, d, e, &f, g, h, a, &b, w[i + 6], SHA256_K[i + 6]);
            ROUND(b, c, d, &e, f, g, h, &a, w[i + 7], SHA256_K[i + 7]);
        }

        state[0] += a;
        state[1] += b;
        state[2] += c;
        state[3] += d;
        state[4] += e;
        state[5] += f;
        state[6] += g;
        state[7] += h;

        data += 64;
        length -= 64;
    }
}


void sha256(uint8_t in[], uint32_t size, uint8_t out[])
{
    uint32_t msg_len = size;
    uint32_t blocks = (msg_len + 9 + 63) / 64;
    uint32_t padded_len = blocks * 64;

    uint8_t* buf = (uint8_t*)malloc(padded_len);
    memcpy(buf, in, msg_len);

    buf[msg_len] = 0x80;
    memset(buf + msg_len + 1, 0, padded_len - msg_len - 1 - 8);

    uint64_t bit_len = (uint64_t)msg_len << 3;
    for (int i = 0; i < 8; ++i)
        buf[padded_len - 8 + i] = (uint8_t)(bit_len >> (56 - 8 * i));

    uint32_t state[8] = { 0 };
    sha256_32(state, buf, padded_len);
    free(buf);

    for (int w = 0; w < 8; ++w) {
        uint32_t v = state[w];
        out[w * 4 + 0] = (uint8_t)(v >> 24);
        out[w * 4 + 1] = (uint8_t)(v >> 16);
        out[w * 4 + 2] = (uint8_t)(v >> 8);
        out[w * 4 + 3] = (uint8_t)(v);
    }
}
#endif