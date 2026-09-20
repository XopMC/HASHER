#include "ripemd256.h"
#include <string.h>

#define ROL32(x,n) (((x)<<(n))|((x)>>(32-(n))))
#define F1(x,y,z) ((x) ^ (y) ^ (z))
#define F2(x,y,z) (((x)&(y)) | (~(x)&(z)))
#define F3(x,y,z) (((x)|~(y)) ^ (z))
#define F4(x,y,z) (((x)&(z)) | ((y)&~(z)))
#define F5(x,y,z) ((x) ^ ((y)| ~(z)))
#define MIN(a,b) ((a) < (b) ? (a) : (b))

static const uint32_t IV[8] = {
    0x67452301u,0xEFCDAB89u,0x98BADCFEu,0x10325476u,
    0x76543210u,0xFEDCBA98u,0x89ABCDEFu,0x01234567u };

static const uint32_t KL[4] = {         
    0x00000000u, 0x5A827999u, 0x6ED9EBA1u, 0x8F1BBCDCu };
static const uint32_t KR[4] = {           
    0x50A28BE6u, 0x5C4DD124u, 0x6D703EF3u, 0x00000000u };

static const uint8_t R[64] = {
  0, 1, 2, 3, 4, 5, 6, 7,  8, 9,10,11,12,13,14,15,
  7, 4,13, 1,10, 6,15, 3, 12, 0, 9, 5, 2,14,11, 8,
  3,10,14, 4, 9,15, 8, 1,  2, 7, 0, 6,13,11, 5,12,
  1, 9,11,10, 0, 8,12, 4, 13, 3, 7,15,14, 5, 6, 2 };

static const uint8_t RR[64] = {
  5,14, 7, 0, 9, 2,11, 4, 13, 6,15, 8, 1,10, 3,12,
  6,11, 3, 7, 0,13, 5,10, 14,15, 8,12, 4, 9, 1, 2,
 15, 5, 1, 3, 7,14, 6, 9, 11, 8,12, 2,10, 0, 4,13,
  8, 6, 4, 1, 3,11,15, 0,  5,12, 2,13, 9, 7,10,14 };

static const uint8_t S[64] = {
 11,14,15,12, 5, 8, 7, 9, 11,13,14,15, 6, 7, 9, 8,
  7, 6, 8,13,11, 9, 7,15,  7,12,15, 9,11, 7,13,12,
 11,13, 6, 7,14, 9,13,15, 14, 8,13, 6, 5,12, 7, 5,
 11,12,14,15,14,15, 9, 8,  9,14, 5, 6, 8, 6, 5,12 };

static const uint8_t SS[64] = {
  8, 9, 9,11,13,15,15, 5,  7, 7, 8,11,14,14,12, 6,
  9,13,15, 7,12, 8, 9,11,  7, 7,12, 7, 6,15,13,11,
  9, 7,15,11, 8, 6, 6,14, 12,13, 5,14,13,13, 7, 5,
 15, 5, 8,11,14,14, 6,14,  6, 9,12, 9,12, 5,15, 8 };


#define F(j,x,y,z) ( (j<16)?((x)^(y)^(z))                      \
                   :(j<32)?(((x)&(y))|(~(x)&(z)))              \
                   :(j<48)?(((x)|~(y))^(z))                    \
                          :(((x)&(z))|((y)&~(z))) )

#define K(j)   ((j<16)?0x00000000u:(j<32)?0x5A827999u:(j<48)?0x6ED9EBA1u:0x8F1BBCDCu)
#define KK(j)  ((j<16)?0x50A28BE6u:(j<32)?0x5C4DD124u:(j<48)?0x6D703EF3u:0x00000000u)


static void ripemd256_compress(uint32_t H[8], const uint32_t X[16])
{
    uint32_t a = H[0], b = H[1], c = H[2], d = H[3];
    uint32_t aa = H[4], bb = H[5], cc = H[6], dd = H[7];

    for (int j = 0; j < 64; ++j) {
        uint32_t t = ROL32(a + F(j, b, c, d) + X[R[j]] + K(j), S[j]);
        a = d; d = c; c = b; b = t;

        t = ROL32(aa + F(63 - j, bb, cc, dd) + X[RR[j]] + KK(j), SS[j]);
        aa = dd; dd = cc; cc = bb; bb = t;

        if (j == 15) { uint32_t tmp = a; a = aa; aa = tmp; }
        else if (j == 31) { uint32_t tmp = b; b = bb; bb = tmp; }
        else if (j == 47) { uint32_t tmp = c; c = cc; cc = tmp; }
        else if (j == 63) { uint32_t tmp = d; d = dd; dd = tmp; }
    }

    H[0] += a;  H[1] += b;  H[2] += c;  H[3] += d;
    H[4] += aa; H[5] += bb; H[6] += cc; H[7] += dd;
}


void ripemd256_init(ripemd256_ctx* ctx)
{
    memcpy(ctx->H, IV, sizeof(IV));
    ctx->len = 0; ctx->idx = 0;
}

static inline void process_block(ripemd256_ctx* ctx)
{
    uint32_t W[16];
    for (int i = 0; i < 16; i++)          
        W[i] = ((uint32_t*)ctx->buf)[i];
    ripemd256_compress(ctx->H, W);
}

void ripemd256_update(ripemd256_ctx* ctx, const void* msg, size_t len)
{
    const uint8_t* p = (const uint8_t*)msg;
    ctx->len += (uint64_t)len << 3;
    if (ctx->idx) {
        size_t n = MIN(64 - ctx->idx, len);
        memcpy(ctx->buf + ctx->idx, p, n);
        ctx->idx += n; p += n; len -= n;
        if (ctx->idx == 64) { process_block(ctx); ctx->idx = 0; }
    }
    while (len >= 64) { memcpy(ctx->buf, p, 64); process_block(ctx); p += 64; len -= 64; }
    if (len) { memcpy(ctx->buf, p, len); ctx->idx = len; }
}

void ripemd256_final(ripemd256_ctx* ctx, uint8_t out[RIPEMD256_DIGEST_LEN])
{
    size_t i = ctx->idx;
    ctx->buf[i++] = 0x80;
    if (i > 56) { memset(ctx->buf + i, 0, 64 - i); process_block(ctx); i = 0; }
    memset(ctx->buf + i, 0, 56 - i);
    for (int k = 0; k < 8; k++) ctx->buf[56 + k] = (uint8_t)(ctx->len >> (k * 8));
    process_block(ctx);

    for (int j = 0; j < 8; ++j) {
        uint32_t v = ctx->H[j];       
        out[j * 4 + 0] = (uint8_t)v;        
        out[j * 4 + 1] = (uint8_t)(v >> 8);
        out[j * 4 + 2] = (uint8_t)(v >> 16);
        out[j * 4 + 3] = (uint8_t)(v >> 24);
    }
}


void ripemd256_batch(const uint8_t* messages,
    const unsigned long long* lengths,
    unsigned long long         count,
    uint8_t* out)
{
    size_t* off = (size_t*)malloc(sizeof(size_t) * count);
    size_t cur = 0;
    for (size_t i = 0; i < count; ++i) {
        off[i] = cur;
        cur += lengths[i] + 1;    
    }

    size_t i = 0;
    for (; i + 3 < count; i += 4) {
        ripemd256(messages + off[i + 0], lengths[i + 0], out + (i + 0) * 32);
        ripemd256(messages + off[i + 1], lengths[i + 1], out + (i + 1) * 32);
        ripemd256(messages + off[i + 2], lengths[i + 2], out + (i + 2) * 32);
        ripemd256(messages + off[i + 3], lengths[i + 3], out + (i + 3) * 32);
    }
    for (; i < count; ++i)
        ripemd256(messages + off[i], lengths[i], out + i * 32);

    free(off);
}