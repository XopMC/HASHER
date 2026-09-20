#include "hasher/cpu_features.h"
#include <string.h>

#if defined(_MSC_VER)
#include <intrin.h>
#elif defined(__x86_64__) || defined(__i386__)
#include <cpuid.h>
#endif

#if defined(__linux__) && defined(__aarch64__)
#include <sys/auxv.h>
#include <asm/hwcap.h>
#endif

#if defined(__APPLE__) && defined(__aarch64__)
#include <sys/types.h>
#include <sys/sysctl.h>
#endif
#if defined(_WIN32) && defined(_M_ARM64)
#include <windows.h>
#endif

#if defined(_M_X64) || defined(_M_IX86) || defined(__x86_64__) || defined(__i386__)
static uint64_t read_xcr0(void) {
#if defined(_MSC_VER) && (defined(_M_X64) || defined(_M_IX86))
    return _xgetbv(0);
#elif defined(__x86_64__) || defined(__i386__)
    uint32_t lo, hi;
    __asm__ volatile("xgetbv" : "=a"(lo), "=d"(hi) : "c"(0));
    return ((uint64_t)hi << 32) | lo;
#else
    return 0;
#endif
}
#endif

void hasher_detect_cpu_features(hasher_cpu_features* f) {
    memset(f, 0, sizeof(*f));
#if defined(_M_X64) || defined(_M_IX86)
    int r[4];
    int max_leaf;
    uint64_t xcr0 = 0;
    __cpuidex(r, 0, 0);
    max_leaf = r[0];
    __cpuidex(r, 1, 0);
    f->sse2 = (uint8_t)((r[3] >> 26) & 1);
    f->ssse3 = (uint8_t)((r[2] >> 9) & 1);
    f->sse41 = (uint8_t)((r[2] >> 19) & 1);
    if (((r[2] >> 27) & 1) && ((r[2] >> 28) & 1)) xcr0 = read_xcr0();
    f->avx = (uint8_t)((xcr0 & 0x6) == 0x6);
    if (max_leaf >= 7) {
        __cpuidex(r, 7, 0);
        f->sha = (uint8_t)((r[1] >> 29) & 1);
        f->avx2 = (uint8_t)(f->avx && ((r[1] >> 5) & 1));
        f->avx512f = (uint8_t)(((xcr0 & 0xe6) == 0xe6) && ((r[1] >> 16) & 1));
        f->avx512bw = (uint8_t)(f->avx512f && ((r[1] >> 30) & 1));
        f->avx512vl = (uint8_t)(f->avx512f && ((r[1] >> 31) & 1));
        __cpuidex(r, 7, 1);
        f->sha512 = (uint8_t)(f->avx2 && ((r[0] >> 0) & 1));
        f->sm3 = (uint8_t)((r[0] >> 1) & 1);
    }
#elif defined(__x86_64__) || defined(__i386__)
    unsigned a, b, c, d;
    uint64_t xcr0 = 0;
    if (__get_cpuid(1, &a, &b, &c, &d)) {
        f->sse2 = (uint8_t)((d >> 26) & 1);
        f->ssse3 = (uint8_t)((c >> 9) & 1);
        f->sse41 = (uint8_t)((c >> 19) & 1);
        if (((c >> 27) & 1) && ((c >> 28) & 1)) xcr0 = read_xcr0();
        f->avx = (uint8_t)((xcr0 & 0x6) == 0x6);
    }
    if (__get_cpuid_count(7, 0, &a, &b, &c, &d)) {
        f->sha = (uint8_t)((b >> 29) & 1);
        f->avx2 = (uint8_t)(f->avx && ((b >> 5) & 1));
        f->avx512f = (uint8_t)(((xcr0 & 0xe6) == 0xe6) && ((b >> 16) & 1));
        f->avx512bw = (uint8_t)(f->avx512f && ((b >> 30) & 1));
        f->avx512vl = (uint8_t)(f->avx512f && ((b >> 31) & 1));
        if (__get_cpuid_count(7, 1, &a, &b, &c, &d)) {
            f->sha512 = (uint8_t)(f->avx2 && ((a >> 0) & 1));
            f->sm3 = (uint8_t)((a >> 1) & 1);
        }
    }
#elif defined(__linux__) && defined(__aarch64__)
    {
        unsigned long hw = getauxval(AT_HWCAP);
        f->neon = (uint8_t)((hw & HWCAP_ASIMD) != 0);
#ifdef HWCAP_SHA1
        f->arm_sha1 = (uint8_t)((hw & HWCAP_SHA1) != 0);
#endif
#ifdef HWCAP_SHA2
        f->arm_sha2 = (uint8_t)((hw & HWCAP_SHA2) != 0);
#endif
#ifdef HWCAP_SHA3
        f->arm_sha3 = (uint8_t)((hw & HWCAP_SHA3) != 0);
#endif
#ifdef HWCAP_SHA512
        f->arm_sha512 = (uint8_t)((hw & HWCAP_SHA512) != 0);
#endif
#ifdef HWCAP_SM3
        f->arm_sm3 = (uint8_t)((hw & HWCAP_SM3) != 0);
#endif
    }
#elif defined(__APPLE__) && defined(__aarch64__)
    f->neon = 1;
#define READ_SYSCTL(name, field) do { int v = 0; size_t n = sizeof(v); \
    if (sysctlbyname(name, &v, &n, NULL, 0) == 0) f->field = (uint8_t)(v != 0); } while (0)
    READ_SYSCTL("hw.optional.arm.FEAT_SHA1", arm_sha1);
    READ_SYSCTL("hw.optional.arm.FEAT_SHA256", arm_sha2);
    READ_SYSCTL("hw.optional.arm.FEAT_SHA3", arm_sha3);
    READ_SYSCTL("hw.optional.arm.FEAT_SHA512", arm_sha512);
    READ_SYSCTL("hw.optional.arm.FEAT_SM3", arm_sm3);
#undef READ_SYSCTL
#elif defined(_WIN32) && defined(_M_ARM64)
    f->neon = 1;
    if (IsProcessorFeaturePresent(PF_ARM_V8_CRYPTO_INSTRUCTIONS_AVAILABLE)) {
        f->arm_sha1 = 1;
        f->arm_sha2 = 1;
    }
#ifdef PF_ARM_SHA3_INSTRUCTIONS_AVAILABLE
    f->arm_sha3 = (uint8_t)(IsProcessorFeaturePresent(PF_ARM_SHA3_INSTRUCTIONS_AVAILABLE) != 0);
#endif
#ifdef PF_ARM_SHA512_INSTRUCTIONS_AVAILABLE
    f->arm_sha512 = (uint8_t)(IsProcessorFeaturePresent(PF_ARM_SHA512_INSTRUCTIONS_AVAILABLE) != 0);
#endif
#endif
}
