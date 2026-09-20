#ifndef HASHER_SM3_ARM_NI_H
#define HASHER_SM3_ARM_NI_H

#include <stddef.h>
#include <stdint.h>

void hasher_sm3_arm_ni(const uint8_t* input, size_t size, uint8_t output[32]);

#endif
