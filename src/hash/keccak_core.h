#ifndef HASHER_KECCAK_CORE_H
#define HASHER_KECCAK_CORE_H
#include <stddef.h>
#include <stdint.h>

typedef struct hasher_keccak_ctx {
    _Alignas(32) uint64_t lanes[25];
    size_t rate;
    size_t position;
} hasher_keccak_ctx;

int hasher_keccak_init(hasher_keccak_ctx* ctx, size_t rate);
int hasher_keccak_update(hasher_keccak_ctx* ctx, const uint8_t* input, size_t size);
int hasher_keccak_final(hasher_keccak_ctx* ctx, uint8_t suffix, uint8_t* output, size_t output_size);
int hasher_keccak_hash(size_t rate, uint8_t suffix, const uint8_t* input, size_t input_size,
                       uint8_t* output, size_t output_size);
void hasher_keccak_select_backend(int use_avx512, int use_avx2, int use_arm_sha3);
const char* hasher_keccak_backend(void);
int hasher_keccak_hash4(size_t rate, uint8_t suffix,
    const uint8_t* const input[4], const size_t input_size[4],
    uint8_t* const output[4], size_t output_size);
#endif
