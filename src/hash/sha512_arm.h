#ifndef HASHER_SHA512_ARM_H
#define HASHER_SHA512_ARM_H
#include <stddef.h>
#include <stdint.h>
void hasher_sha512_arm_compress(uint64_t state[8], const uint8_t* data, size_t blocks);
#endif
