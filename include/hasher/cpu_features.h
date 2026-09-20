#ifndef HASHER_CPU_FEATURES_H
#define HASHER_CPU_FEATURES_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct hasher_cpu_features {
    uint8_t sse2, ssse3, sse41, sha, sha512, sm3, avx, avx2;
    uint8_t avx512f, avx512bw, avx512vl;
    uint8_t neon, arm_sha1, arm_sha2, arm_sha3, arm_sha512, arm_sm3;
} hasher_cpu_features;

void hasher_detect_cpu_features(hasher_cpu_features* features);

#ifdef __cplusplus
}
#endif
#endif
