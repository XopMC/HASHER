#ifndef HASHER_KECCAK_X4_H
#define HASHER_KECCAK_X4_H

#include <stddef.h>
#include <stdint.h>

typedef int (*hasher_keccak_x4_fn)(size_t rate, uint8_t suffix,
    const uint8_t* const input[4], const size_t input_size[4],
    uint8_t* const output[4], size_t output_size);

int hasher_keccak_x4_avx2(size_t rate, uint8_t suffix,
    const uint8_t* const input[4], const size_t input_size[4],
    uint8_t* const output[4], size_t output_size);
int hasher_keccak_x4_avx512(size_t rate, uint8_t suffix,
    const uint8_t* const input[4], const size_t input_size[4],
    uint8_t* const output[4], size_t output_size);
int hasher_keccak_x4_arm_sha3(size_t rate, uint8_t suffix,
    const uint8_t* const input[4], const size_t input_size[4],
    uint8_t* const output[4], size_t output_size);

#endif
