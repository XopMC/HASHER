/*  ripemd256.h –  public-domain, C99   */
#pragma once
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>

#ifdef __cplusplus
extern "C" {
#endif

#define RIPEMD256_DIGEST_LEN 32

    typedef struct {
        uint32_t H[8];          
        uint64_t len;           
        uint8_t  buf[64];      
        size_t   idx;           
    } ripemd256_ctx;

    void ripemd256_init(ripemd256_ctx* ctx);
    void ripemd256_update(ripemd256_ctx* ctx, const void* msg, size_t len);
    void ripemd256_final(ripemd256_ctx* ctx, uint8_t digest[RIPEMD256_DIGEST_LEN]);

    static inline void ripemd256(const void* msg, unsigned long long len, uint8_t dig[RIPEMD256_DIGEST_LEN])
    {
        ripemd256_ctx c; ripemd256_init(&c); ripemd256_update(&c, msg, len); ripemd256_final(&c, dig);
    }
    void ripemd256_batch(const uint8_t* messages, const unsigned long long* lengths, unsigned long long count, uint8_t* out);

#ifdef __cplusplus
}
#endif
