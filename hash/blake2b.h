#pragma once
#include <cstdint>
#include <cstring>

#define ROTR64(x, n) (((x) >> (n)) | ((x) << (64 - (n))))

static const uint64_t blake2b_IV[8] = {
    0x6A09E667F3BCC908ULL, 0xBB67AE8584CAA73BULL,
    0x3C6EF372FE94F82BULL, 0xA54FF53A5F1D36F1ULL,
    0x510E527FADE682D1ULL, 0x9B05688C2B3E6C1FULL,
    0x1F83D9ABFB41BD6BULL, 0x5BE0CD19137E2179ULL
};

static const uint8_t blake2b_sigma[12][16] = {
    { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9,10,11,12,13,14,15 },
    {14,10, 4, 8, 9,15,13, 6, 1,12, 0, 2,11, 7, 5, 3 },
    {11, 8,12, 0, 5, 2,15,13,10,14, 3, 6, 7, 1, 9, 4 },
    { 7, 9, 3, 1,13,12,11,14, 2, 6, 5,10, 4, 0,15, 8 },
    { 9, 0, 5, 7, 2, 4,10,15,14, 1,11,12, 6, 8, 3,13 },
    { 2,12, 6,10, 0,11, 8, 3, 4,13, 7, 5,15,14, 1, 9 },
    {12, 5, 1,15,14,13, 4,10, 0, 7, 6, 3, 9, 2, 8,11 },
    {13,11, 7,14,12, 1, 3, 9, 5, 0,15, 4, 8, 6, 2,10 },
    { 6,15,14, 9,11, 3, 0, 8,12, 2,13, 7, 1, 4,10, 5 },
    {10, 2, 8, 4, 7, 6, 1, 5,15,11, 9,14, 3,12,13, 0 },
    { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9,10,11,12,13,14,15 },
    {14,10, 4, 8, 9,15,13, 6, 1,12, 0, 2,11, 7, 5, 3 }
};

inline uint64_t load64(const uint8_t* p) {
    uint64_t r = 0;
    for (int i = 0; i < 8; i++) r |= (uint64_t)p[i] << (8 * i);
    return r;
}

inline void store64(uint8_t* out, uint64_t v) {
    for (int i = 0; i < 8; i++) out[i] = (v >> (8 * i)) & 0xFF;
}

inline void G(uint64_t& a, uint64_t& b, uint64_t& c, uint64_t& d, uint64_t x, uint64_t y) {
    a = a + b + x;
    d = ROTR64(d ^ a, 32);
    c = c + d;
    b = ROTR64(b ^ c, 24);
    a = a + b + y;
    d = ROTR64(d ^ a, 16);
    c = c + d;
    b = ROTR64(b ^ c, 63);
}

void blake2b_compress(uint64_t h[8], const uint8_t block[128], uint64_t t0, uint64_t t1, bool last) {
    uint64_t m[16], v[16];
    for (int i = 0; i < 16; i++) m[i] = load64(block + i * 8);

    for (int i = 0; i < 8; i++) {
        v[i] = h[i];
        v[i + 8] = blake2b_IV[i];
    }

    v[12] ^= t0;
    v[13] ^= t1;
    if (last) v[14] = ~v[14];

    for (int r = 0; r < 12; r++) {
        const uint8_t* s = blake2b_sigma[r];
        G(v[0], v[4], v[8], v[12], m[s[0]], m[s[1]]);
        G(v[1], v[5], v[9], v[13], m[s[2]], m[s[3]]);
        G(v[2], v[6], v[10], v[14], m[s[4]], m[s[5]]);
        G(v[3], v[7], v[11], v[15], m[s[6]], m[s[7]]);
        G(v[0], v[5], v[10], v[15], m[s[8]], m[s[9]]);
        G(v[1], v[6], v[11], v[12], m[s[10]], m[s[11]]);
        G(v[2], v[7], v[8], v[13], m[s[12]], m[s[13]]);
        G(v[3], v[4], v[9], v[14], m[s[14]], m[s[15]]);
    }

    for (int i = 0; i < 8; i++) h[i] ^= v[i] ^ v[i + 8];
}

void Blake2b_256(const uint8_t* data, size_t len, uint8_t out[32]) {
    uint64_t h[8];
    uint8_t block[128] = { 0 };
    uint64_t t0 = 0, t1 = 0;

    for (int i = 0; i < 8; i++) {
        h[i] = blake2b_IV[i];
    }
    h[0] ^= 0x01010020ULL;

    size_t offset = 0;
    while (offset + 128 <= len) {
        t0 += 128;
        if (t0 < 128) t1++;
        blake2b_compress(h, data + offset, t0, t1, false);
        offset += 128;
    }

    size_t rem = len - offset;
    memcpy(block, data + offset, rem);
    t0 += rem;
    if (t0 < rem) t1++;
    blake2b_compress(h, block, t0, t1, true);

    for (int i = 0; i < 4; i++) {
        store64(out + i * 8, h[i]);
    }
}