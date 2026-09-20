#ifndef HASHER_SHA512_FAST_H
#define HASHER_SHA512_FAST_H
#include <stddef.h>
#include <stdint.h>
enum { HASHER_SHA384_VARIANT=1, HASHER_SHA512_VARIANT=2, HASHER_SHA512_224_VARIANT=3, HASHER_SHA512_256_VARIANT=4 };
void hasher_sha512_fast_select(int use_avx, int use_arm_sha512);
int hasher_sha512_fast(const uint8_t* input, size_t size, uint8_t* output, size_t output_size, int variant);
const char* hasher_sha512_fast_backend(void);
#endif
