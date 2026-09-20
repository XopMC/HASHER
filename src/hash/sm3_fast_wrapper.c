#include <stddef.h>
#include <stdint.h>
#include <gmssl/sm3.h>

void hasher_gmssl_sm3_digest(const uint8_t* input, size_t input_size,
                             uint8_t output[32]) {
    SM3_CTX ctx;
    hasher_gmssl_sm3_init(&ctx);
    hasher_gmssl_sm3_update(&ctx, input, input_size);
    hasher_gmssl_sm3_finish(&ctx, output);
}
