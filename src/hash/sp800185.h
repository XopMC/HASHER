#ifndef HASHER_SP800185_H
#define HASHER_SP800185_H

#include <stddef.h>
#include <stdint.h>

int hasher_cshake(unsigned strength, const uint8_t* input, size_t input_size,
                  const uint8_t* function_name, size_t function_name_size,
                  const uint8_t* custom, size_t custom_size,
                  uint8_t* output, size_t output_size);
int hasher_tuplehash(unsigned strength, int xof,
                     const uint8_t* input, size_t input_size,
                     const uint8_t* custom, size_t custom_size,
                     uint8_t* output, size_t output_size);
int hasher_parallelhash(unsigned strength, int xof,
                        const uint8_t* input, size_t input_size,
                        const uint8_t* custom, size_t custom_size,
                        size_t block_size, uint8_t* output, size_t output_size);
int hasher_kmac(unsigned strength, int xof,
                const uint8_t* key, size_t key_size,
                const uint8_t* input, size_t input_size,
                const uint8_t* custom, size_t custom_size,
                uint8_t* output, size_t output_size);

#endif
