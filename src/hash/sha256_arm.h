#ifndef HASHER_SHA256_ARM_H
#define HASHER_SHA256_ARM_H
#include <stddef.h>
#include <stdint.h>
void hasher_sha256_arm(const uint8_t* input, size_t size, uint8_t output[32], int sha224);
void hasher_sha1_arm(const uint8_t* input, size_t size, uint8_t output[20]);
#endif
