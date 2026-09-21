#include "hasher/hash_api.h"
#include "hasher/cpu_features.h"
#include "sp800185.h"
#include "keccak_core.h"
#include "sha512_fast.h"
#include "blake3_control.h"
#include "legacy_rhash.h"
#include "evpkdf.h"
#include "pbkdf.h"
#include "pbkdf2.h"
#if defined(HASHER_SM3_X86_NI)
#include "sm3_x86_ni.h"
#endif
#if defined(HASHER_SM3_ARM_NI)
#include "sm3_arm_ni.h"
#endif
#include <limits.h>
#include <stdlib.h>
#include <string.h>
#include <tomcrypt.h>
#include <blake3.h>
#include <xxhash.h>
#if defined(HASHER_HAVE_ARM_SHA2)
#include "sha256_arm.h"
#endif
#if defined(HASHER_XXH_X86_DISPATCH)
#define XXH_DISPATCH_DISABLE_REPLACE
#include <xxh_x86dispatch.h>
#endif

static const hasher_algorithm algorithms[] = {
 {HASHER_SHA1,"sha1",20,20,HASHER_FIXED_OUTPUT},
 {HASHER_SHA224,"sha224",28,28,HASHER_FIXED_OUTPUT},
 {HASHER_SHA256,"sha256",32,32,HASHER_FIXED_OUTPUT},
 {HASHER_SHA384,"sha384",48,48,HASHER_FIXED_OUTPUT},
 {HASHER_SHA512,"sha512",64,64,HASHER_FIXED_OUTPUT},
 {HASHER_SHA512_224,"sha512/224",28,28,HASHER_FIXED_OUTPUT},
 {HASHER_SHA512_256,"sha512/256",32,32,HASHER_FIXED_OUTPUT},
 {HASHER_SHA3_224,"sha3-224",28,28,HASHER_FIXED_OUTPUT},
 {HASHER_SHA3_256,"sha3-256",32,32,HASHER_FIXED_OUTPUT},
 {HASHER_SHA3_384,"sha3-384",48,48,HASHER_FIXED_OUTPUT},
 {HASHER_SHA3_512,"sha3-512",64,64,HASHER_FIXED_OUTPUT},
 {HASHER_KECCAK_224,"keccak-224",28,28,HASHER_FIXED_OUTPUT},
 {HASHER_KECCAK_256,"keccak-256",32,32,HASHER_FIXED_OUTPUT},
 {HASHER_KECCAK_384,"keccak-384",48,48,HASHER_FIXED_OUTPUT},
 {HASHER_KECCAK_512,"keccak-512",64,64,HASHER_FIXED_OUTPUT},
 {HASHER_SHAKE128,"shake128",0,32,HASHER_VARIABLE_OUTPUT},
 {HASHER_SHAKE256,"shake256",0,64,HASHER_VARIABLE_OUTPUT},
 {HASHER_CSHAKE128,"cshake128",0,32,HASHER_VARIABLE_OUTPUT|HASHER_CUSTOM_SUPPORTED|HASHER_FUNCTION_NAME_SUPPORTED},
 {HASHER_CSHAKE256,"cshake256",0,64,HASHER_VARIABLE_OUTPUT|HASHER_CUSTOM_SUPPORTED|HASHER_FUNCTION_NAME_SUPPORTED},
 {HASHER_MD2,"md2",16,16,HASHER_FIXED_OUTPUT},
 {HASHER_MD4,"md4",16,16,HASHER_FIXED_OUTPUT},
 {HASHER_MD5,"md5",16,16,HASHER_FIXED_OUTPUT},
 {HASHER_RMD128,"rmd-128",16,16,HASHER_FIXED_OUTPUT},
 {HASHER_RMD160,"rmd-160",20,20,HASHER_FIXED_OUTPUT},
 {HASHER_RMD256,"rmd-256",32,32,HASHER_FIXED_OUTPUT},
 {HASHER_RMD320,"rmd-320",40,40,HASHER_FIXED_OUTPUT},
 {HASHER_BLAKE2B,"blake2b",0,64,HASHER_VARIABLE_OUTPUT},
 {HASHER_BLAKE2S,"blake2s",0,32,HASHER_VARIABLE_OUTPUT},
 {HASHER_BLAKE3,"blake3",0,32,HASHER_VARIABLE_OUTPUT},
 {HASHER_XXH128,"xxh128",16,16,HASHER_FIXED_OUTPUT|HASHER_SEED_SUPPORTED},
 {HASHER_SM3,"sm3",32,32,HASHER_FIXED_OUTPUT},
 {HASHER_KMAC128,"kmac128",0,32,HASHER_VARIABLE_OUTPUT|HASHER_CUSTOM_SUPPORTED},
 {HASHER_KMAC256,"kmac256",0,64,HASHER_VARIABLE_OUTPUT|HASHER_CUSTOM_SUPPORTED},
 {HASHER_KMACXOF128,"kmacxof128",0,32,HASHER_VARIABLE_OUTPUT|HASHER_CUSTOM_SUPPORTED},
 {HASHER_KMACXOF256,"kmacxof256",0,64,HASHER_VARIABLE_OUTPUT|HASHER_CUSTOM_SUPPORTED},
 {HASHER_TUPLEHASH128,"tuplehash128",0,32,HASHER_VARIABLE_OUTPUT|HASHER_CUSTOM_SUPPORTED},
 {HASHER_TUPLEHASH256,"tuplehash256",0,64,HASHER_VARIABLE_OUTPUT|HASHER_CUSTOM_SUPPORTED},
 {HASHER_TUPLEHASHXOF128,"tuplehashxof128",0,32,HASHER_VARIABLE_OUTPUT|HASHER_CUSTOM_SUPPORTED},
 {HASHER_TUPLEHASHXOF256,"tuplehashxof256",0,64,HASHER_VARIABLE_OUTPUT|HASHER_CUSTOM_SUPPORTED},
 {HASHER_PARALLELHASH128,"parallelhash128",0,32,HASHER_VARIABLE_OUTPUT|HASHER_CUSTOM_SUPPORTED|HASHER_BLOCK_SIZE_SUPPORTED},
 {HASHER_PARALLELHASH256,"parallelhash256",0,64,HASHER_VARIABLE_OUTPUT|HASHER_CUSTOM_SUPPORTED|HASHER_BLOCK_SIZE_SUPPORTED},
 {HASHER_PARALLELHASHXOF128,"parallelhashxof128",0,32,HASHER_VARIABLE_OUTPUT|HASHER_CUSTOM_SUPPORTED|HASHER_BLOCK_SIZE_SUPPORTED},
 {HASHER_PARALLELHASHXOF256,"parallelhashxof256",0,64,HASHER_VARIABLE_OUTPUT|HASHER_CUSTOM_SUPPORTED|HASHER_BLOCK_SIZE_SUPPORTED},
 {HASHER_HMAC_MD5,"hmac-md5",16,16,HASHER_FIXED_OUTPUT},
 {HASHER_HMAC_SHA1,"hmac-sha1",20,20,HASHER_FIXED_OUTPUT},
 {HASHER_HMAC_SHA224,"hmac-sha224",28,28,HASHER_FIXED_OUTPUT},
 {HASHER_HMAC_SHA256,"hmac-sha256",32,32,HASHER_FIXED_OUTPUT},
 {HASHER_HMAC_SHA384,"hmac-sha384",48,48,HASHER_FIXED_OUTPUT},
 {HASHER_HMAC_SHA512,"hmac-sha512",64,64,HASHER_FIXED_OUTPUT},
 {HASHER_EVP_KDF_MD5,"evpkdf-md5",0,32,HASHER_VARIABLE_OUTPUT|HASHER_KDF},
 {HASHER_EVP_KDF_SHA1,"evpkdf-sha1",0,32,HASHER_VARIABLE_OUTPUT|HASHER_KDF},
 {HASHER_EVP_KDF_SHA224,"evpkdf-sha224",0,32,HASHER_VARIABLE_OUTPUT|HASHER_KDF},
 {HASHER_EVP_KDF_SHA256,"evpkdf-sha256",0,32,HASHER_VARIABLE_OUTPUT|HASHER_KDF},
 {HASHER_EVP_KDF_SHA384,"evpkdf-sha384",0,32,HASHER_VARIABLE_OUTPUT|HASHER_KDF},
 {HASHER_EVP_KDF_SHA512,"evpkdf-sha512",0,32,HASHER_VARIABLE_OUTPUT|HASHER_KDF},
 {HASHER_EVP_KDF_RMD160,"evpkdf-rmd160",0,32,HASHER_VARIABLE_OUTPUT|HASHER_KDF},
 {HASHER_EVP_KDF_KECCAK256,"evpkdf-keccak256",0,32,HASHER_VARIABLE_OUTPUT|HASHER_KDF},
 {HASHER_EVP_KDF_KECCAK512,"evpkdf-keccak512",0,32,HASHER_VARIABLE_OUTPUT|HASHER_KDF},
 {HASHER_PBKDF_MD5,"pbkdf-md5",0,16,HASHER_VARIABLE_OUTPUT|HASHER_KDF},
 {HASHER_PBKDF_SHA1,"pbkdf-sha1",0,20,HASHER_VARIABLE_OUTPUT|HASHER_KDF},
 {HASHER_PBKDF_SHA224,"pbkdf-sha224",0,28,HASHER_VARIABLE_OUTPUT|HASHER_KDF},
 {HASHER_PBKDF_SHA256,"pbkdf-sha256",0,32,HASHER_VARIABLE_OUTPUT|HASHER_KDF},
 {HASHER_PBKDF_SHA384,"pbkdf-sha384",0,48,HASHER_VARIABLE_OUTPUT|HASHER_KDF},
 {HASHER_PBKDF_SHA512,"pbkdf-sha512",0,64,HASHER_VARIABLE_OUTPUT|HASHER_KDF},
 {HASHER_PBKDF_RMD160,"pbkdf-rmd160",0,20,HASHER_VARIABLE_OUTPUT|HASHER_KDF},
 {HASHER_PBKDF_KECCAK256,"pbkdf-keccak256",0,32,HASHER_VARIABLE_OUTPUT|HASHER_KDF},
 {HASHER_PBKDF_KECCAK512,"pbkdf-keccak512",0,64,HASHER_VARIABLE_OUTPUT|HASHER_KDF},
 {HASHER_PBKDF2_DIRECT_MD5,"pbkdf2-md5",0,32,HASHER_VARIABLE_OUTPUT|HASHER_KDF},
 {HASHER_PBKDF2_DIRECT_SHA1,"pbkdf2-sha1",0,32,HASHER_VARIABLE_OUTPUT|HASHER_KDF},
 {HASHER_PBKDF2_DIRECT_SHA224,"pbkdf2-sha224",0,32,HASHER_VARIABLE_OUTPUT|HASHER_KDF},
 {HASHER_PBKDF2_DIRECT_SHA256,"pbkdf2-sha256",0,32,HASHER_VARIABLE_OUTPUT|HASHER_KDF},
 {HASHER_PBKDF2_DIRECT_SHA384,"pbkdf2-sha384",0,32,HASHER_VARIABLE_OUTPUT|HASHER_KDF},
 {HASHER_PBKDF2_DIRECT_SHA512,"pbkdf2-sha512",0,32,HASHER_VARIABLE_OUTPUT|HASHER_KDF},
 {HASHER_PBKDF2_DIRECT_RMD160,"pbkdf2-rmd160",0,32,HASHER_VARIABLE_OUTPUT|HASHER_KDF},
 {HASHER_PBKDF2_DIRECT_KECCAK256,"pbkdf2-keccak256",0,32,HASHER_VARIABLE_OUTPUT|HASHER_KDF},
 {HASHER_PBKDF2_DIRECT_KECCAK512,"pbkdf2-keccak512",0,32,HASHER_VARIABLE_OUTPUT|HASHER_KDF},
 {HASHER_PBKDF2_MD5,"pbkdf2-hmac-md5",0,32,HASHER_VARIABLE_OUTPUT|HASHER_KDF},
 {HASHER_PBKDF2_SHA1,"pbkdf2-hmac-sha1",0,32,HASHER_VARIABLE_OUTPUT|HASHER_KDF},
 {HASHER_PBKDF2_SHA224,"pbkdf2-hmac-sha224",0,32,HASHER_VARIABLE_OUTPUT|HASHER_KDF},
 {HASHER_PBKDF2_SHA256,"pbkdf2-hmac-sha256",0,32,HASHER_VARIABLE_OUTPUT|HASHER_KDF},
 {HASHER_PBKDF2_SHA384,"pbkdf2-hmac-sha384",0,32,HASHER_VARIABLE_OUTPUT|HASHER_KDF},
 {HASHER_PBKDF2_SHA512,"pbkdf2-hmac-sha512",0,32,HASHER_VARIABLE_OUTPUT|HASHER_KDF}
};

static int sha256_index = -1, sha512_index = -1;
static const struct ltc_hash_descriptor* selected_sha1 = &sha1_portable_desc;
static const struct ltc_hash_descriptor* selected_sha224 = &sha224_portable_desc;
static const struct ltc_hash_descriptor* selected_sha256 = &sha256_portable_desc;
static const struct ltc_hash_descriptor* selected_sha384 = &sha384_portable_desc;
static const struct ltc_hash_descriptor* selected_sha512 = &sha512_portable_desc;
static const struct ltc_hash_descriptor* selected_sha512_224 = &sha512_224_portable_desc;
static const struct ltc_hash_descriptor* selected_sha512_256 = &sha512_256_portable_desc;
static int selected_sha_native;
static int selected_sha512_native;
static int selected_arm_sha2;
static int selected_arm_sha1;
static int selected_blake2_fast;
#if defined(HASHER_XXH_X86_DISPATCH)
static int selected_xxh_dispatch;
#endif
static int selected_sm3_fast;
static int selected_sm3_x86_ni;
static int selected_sm3_arm_ni;
static int selected_blake3_simd = 1;
static int arm_hmac_supported(hasher_algorithm_id base);
static int use_arm_hmac(hasher_algorithm_id base,int pbkdf2);
static int use_arm_hash_segments(hasher_algorithm_id base);
static const hasher_algorithm* algorithm_by_id(hasher_algorithm_id id);
#if defined(HASHER_BLAKE2_FAST_X86) || defined(HASHER_BLAKE2_FAST_ARM)
int hasher_fast_blake2b(void*, size_t, const void*, size_t, const void*, size_t);
int hasher_fast_blake2s(void*, size_t, const void*, size_t, const void*, size_t);
#endif
#if defined(HASHER_SM3_FAST_X86) || defined(HASHER_SM3_FAST_ARM)
void hasher_gmssl_sm3_digest(const uint8_t*, size_t, uint8_t[32]);
#endif

int hasher_library_init(void) {
    hasher_cpu_features features;
    const char* force = getenv("HASHER_FORCE_IMPL");
    int force_portable = force && strcmp(force, "portable") == 0;
    int force_native = force && (strcmp(force, "native") == 0 || strcmp(force, "simd") == 0);
    if (force && !force_portable && !force_native && strcmp(force, "auto") != 0) return -1;
    hasher_detect_cpu_features(&features);
    if (force_portable) {
        hasher_blake3_force_portable();
        selected_blake3_simd = 0;
    }
    hasher_keccak_select_backend(!force_portable && features.avx512f && features.avx512vl,
                                 !force_portable && features.avx2,
                                 !force_portable && features.arm_sha3);
    hasher_sha512_fast_select(!force_portable && features.avx,
                              !force_portable && features.arm_sha512);
#if defined(HASHER_BLAKE2_FAST_X86)
    selected_blake2_fast = !force_portable && features.sse41;
#elif defined(HASHER_BLAKE2_FAST_ARM)
    selected_blake2_fast = !force_portable && features.neon;
#endif
#if defined(HASHER_SM3_FAST_X86)
    selected_sm3_fast = !force_portable && features.ssse3;
#elif defined(HASHER_SM3_FAST_ARM)
    selected_sm3_fast = !force_portable && features.neon;
#endif
#if defined(HASHER_SM3_X86_NI)
    selected_sm3_x86_ni = !force_portable && features.sm3 && features.ssse3 && features.avx2;
#endif
#if defined(HASHER_SM3_ARM_NI)
    selected_sm3_arm_ni = !force_portable && features.arm_sm3;
#endif
#if defined(HASHER_XXH_X86_DISPATCH)
    selected_xxh_dispatch = !force_portable;
#endif
#if defined(HASHER_HAVE_ARM_SHA2)
    if (!force_portable && features.arm_sha1) selected_arm_sha1 = 1;
    if (!force_portable && features.arm_sha2) selected_arm_sha2 = 1;
#endif
#if defined(LTC_SHA1_X86) && defined(LTC_SHA224_X86) && defined(LTC_SHA256_X86)
    if (!force_portable && features.sha) {
        selected_sha1 = &sha1_x86_desc;
        selected_sha224 = &sha224_x86_desc;
        selected_sha256 = &sha256_x86_desc;
        selected_sha_native = 1;
    }
#endif
#if defined(LTC_SHA384_X86) && defined(LTC_SHA512_X86) && defined(LTC_SHA512_224_X86) && defined(LTC_SHA512_256_X86)
    if (!force_portable && features.sha512) {
        selected_sha384 = &sha384_x86_desc;
        selected_sha512 = &sha512_x86_desc;
        selected_sha512_224 = &sha512_224_x86_desc;
        selected_sha512_256 = &sha512_256_x86_desc;
        selected_sha512_native = 1;
    }
#endif
    if (force_native && !selected_sha_native && !selected_sha512_native && !selected_arm_sha1 && !selected_arm_sha2 &&
        !selected_sm3_x86_ni && !selected_sm3_arm_ni && !selected_sm3_fast) return -1;
    sha256_index = register_hash(selected_sha256);
    sha512_index = register_hash(selected_sha512);
    return sha256_index >= 0 && sha512_index >= 0 ? 0 : -1;
}

static hasher_algorithm_id underlying_base(hasher_algorithm_id id){
    switch(id){
    case HASHER_HMAC_MD5:case HASHER_EVP_KDF_MD5:case HASHER_PBKDF_MD5:case HASHER_PBKDF2_DIRECT_MD5:case HASHER_PBKDF2_MD5:return HASHER_MD5;
    case HASHER_HMAC_SHA1:case HASHER_EVP_KDF_SHA1:case HASHER_PBKDF_SHA1:case HASHER_PBKDF2_DIRECT_SHA1:case HASHER_PBKDF2_SHA1:return HASHER_SHA1;
    case HASHER_HMAC_SHA224:case HASHER_EVP_KDF_SHA224:case HASHER_PBKDF_SHA224:case HASHER_PBKDF2_DIRECT_SHA224:case HASHER_PBKDF2_SHA224:return HASHER_SHA224;
    case HASHER_HMAC_SHA256:case HASHER_EVP_KDF_SHA256:case HASHER_PBKDF_SHA256:case HASHER_PBKDF2_DIRECT_SHA256:case HASHER_PBKDF2_SHA256:return HASHER_SHA256;
    case HASHER_HMAC_SHA384:case HASHER_EVP_KDF_SHA384:case HASHER_PBKDF_SHA384:case HASHER_PBKDF2_DIRECT_SHA384:case HASHER_PBKDF2_SHA384:return HASHER_SHA384;
    case HASHER_HMAC_SHA512:case HASHER_EVP_KDF_SHA512:case HASHER_PBKDF_SHA512:case HASHER_PBKDF2_DIRECT_SHA512:case HASHER_PBKDF2_SHA512:return HASHER_SHA512;
    case HASHER_EVP_KDF_RMD160:case HASHER_PBKDF_RMD160:case HASHER_PBKDF2_DIRECT_RMD160:return HASHER_RMD160;
    case HASHER_EVP_KDF_KECCAK256:case HASHER_PBKDF_KECCAK256:case HASHER_PBKDF2_DIRECT_KECCAK256:return HASHER_KECCAK_256;
    case HASHER_EVP_KDF_KECCAK512:case HASHER_PBKDF_KECCAK512:case HASHER_PBKDF2_DIRECT_KECCAK512:return HASHER_KECCAK_512;
    default:return HASHER_ALGORITHM_COUNT;}
}

const char* hasher_selected_backend(hasher_algorithm_id id) {
    hasher_algorithm_id base=underlying_base(id);
    switch (id) {
    case HASHER_SHA1: case HASHER_SHA224: case HASHER_SHA256:
#if defined(HASHER_HAVE_ARM_SHA2)
        if (id==HASHER_SHA1&&selected_arm_sha1) return "arm-sha1";
        if ((id==HASHER_SHA224||id==HASHER_SHA256)&&selected_arm_sha2) return "arm-sha2";
#endif
        return selected_sha_native ? "x86-sha" : "portable";
    case HASHER_SHA384: case HASHER_SHA512: case HASHER_SHA512_224: case HASHER_SHA512_256:
        return selected_sha512_native ? "x86-sha512" : hasher_sha512_fast_backend();
    case HASHER_BLAKE3: return selected_blake3_simd ? "runtime-simd" : "portable";
    case HASHER_BLAKE2B: case HASHER_BLAKE2S: return selected_blake2_fast ? "official-simd-c" : "portable";
    case HASHER_MD4: case HASHER_MD5: case HASHER_RMD160: return "rhash-c";
    case HASHER_SM3: return selected_sm3_x86_ni ? "x86-sm3ni" : selected_sm3_arm_ni ? "arm-sm3" : selected_sm3_fast ? "gmssl-simd-c" : "portable";
    case HASHER_HMAC_SHA1: case HASHER_HMAC_SHA224: case HASHER_HMAC_SHA256:
        return selected_sha_native?"x86-sha-hmac":use_arm_hmac(base,0)?"arm-sha-hmac":"portable-hmac";
    case HASHER_HMAC_SHA384: case HASHER_HMAC_SHA512:
        return selected_sha512_native?"x86-sha512-hmac":use_arm_hmac(base,0)?"arm-sha512-hmac":"portable-hmac";
    case HASHER_HMAC_MD5:
#if defined(__linux__) && defined(__aarch64__)
        return "portable-hmac";
#else
        return "rhash-hmac";
#endif
    case HASHER_EVP_KDF_MD5:case HASHER_EVP_KDF_RMD160:return "evpkdf/rhash-c";
    case HASHER_EVP_KDF_SHA1:case HASHER_EVP_KDF_SHA224:case HASHER_EVP_KDF_SHA256:
    case HASHER_EVP_KDF_SHA384:case HASHER_EVP_KDF_SHA512:
        return ((base==HASHER_SHA1||base==HASHER_SHA224||base==HASHER_SHA256)&&selected_sha_native)?"evpkdf/x86-sha":
               ((base==HASHER_SHA384||base==HASHER_SHA512)&&selected_sha512_native)?"evpkdf/x86-sha512":use_arm_hash_segments(base)?"evpkdf/arm-sha":"evpkdf/portable";
    case HASHER_EVP_KDF_KECCAK256:case HASHER_EVP_KDF_KECCAK512:return hasher_keccak_backend();
    case HASHER_PBKDF_MD5: case HASHER_PBKDF_SHA1: case HASHER_PBKDF_SHA224:
    case HASHER_PBKDF_SHA256: case HASHER_PBKDF_SHA384: case HASHER_PBKDF_SHA512:
    case HASHER_PBKDF_RMD160: case HASHER_PBKDF_KECCAK256: case HASHER_PBKDF_KECCAK512:
        if(base==HASHER_MD5||base==HASHER_RMD160)return "pbkdf/rhash-c";
        if(base==HASHER_KECCAK_256||base==HASHER_KECCAK_512)return hasher_keccak_backend();
        return ((base==HASHER_SHA1||base==HASHER_SHA224||base==HASHER_SHA256)&&selected_sha_native)?"pbkdf/x86-sha":
               ((base==HASHER_SHA384||base==HASHER_SHA512)&&selected_sha512_native)?"pbkdf/x86-sha512":use_arm_hash_segments(base)?"pbkdf/arm-sha":"pbkdf/portable";
    case HASHER_PBKDF2_DIRECT_MD5: case HASHER_PBKDF2_DIRECT_SHA1: case HASHER_PBKDF2_DIRECT_SHA224:
    case HASHER_PBKDF2_DIRECT_SHA256: case HASHER_PBKDF2_DIRECT_SHA384: case HASHER_PBKDF2_DIRECT_SHA512:
    case HASHER_PBKDF2_DIRECT_RMD160: case HASHER_PBKDF2_DIRECT_KECCAK256: case HASHER_PBKDF2_DIRECT_KECCAK512:
        if(base==HASHER_MD5||base==HASHER_RMD160)return "pbkdf2-direct/rhash-c";
        if(base==HASHER_KECCAK_256||base==HASHER_KECCAK_512)return hasher_keccak_backend();
        return ((base==HASHER_SHA1||base==HASHER_SHA224||base==HASHER_SHA256)&&selected_sha_native)?"pbkdf2-direct/x86-sha":
               ((base==HASHER_SHA384||base==HASHER_SHA512)&&selected_sha512_native)?"pbkdf2-direct/x86-sha512":use_arm_hash_segments(base)?"pbkdf2-direct/arm-sha":"pbkdf2-direct/portable";
    case HASHER_PBKDF2_MD5: case HASHER_PBKDF2_SHA1: case HASHER_PBKDF2_SHA224:
    case HASHER_PBKDF2_SHA256: case HASHER_PBKDF2_SHA384: case HASHER_PBKDF2_SHA512:
        if(base==HASHER_MD5)return "pbkdf2/rhash-hmac";
        return ((base==HASHER_SHA1||base==HASHER_SHA224||base==HASHER_SHA256)&&selected_sha_native)?"pbkdf2/x86-sha-hmac":
               ((base==HASHER_SHA384||base==HASHER_SHA512)&&selected_sha512_native)?"pbkdf2/x86-sha512-hmac":use_arm_hmac(base,1)?"pbkdf2/arm-sha-hmac":"pbkdf2/portable-hmac";
    case HASHER_SHA3_224: case HASHER_SHA3_256: case HASHER_SHA3_384: case HASHER_SHA3_512:
    case HASHER_KECCAK_224: case HASHER_KECCAK_256: case HASHER_KECCAK_384: case HASHER_KECCAK_512:
    case HASHER_SHAKE128: case HASHER_SHAKE256: case HASHER_CSHAKE128: case HASHER_CSHAKE256:
    case HASHER_KMAC128: case HASHER_KMAC256: case HASHER_KMACXOF128: case HASHER_KMACXOF256:
    case HASHER_TUPLEHASH128: case HASHER_TUPLEHASH256: case HASHER_TUPLEHASHXOF128: case HASHER_TUPLEHASHXOF256:
    case HASHER_PARALLELHASH128: case HASHER_PARALLELHASH256: case HASHER_PARALLELHASHXOF128: case HASHER_PARALLELHASHXOF256:
        return hasher_keccak_backend();
    case HASHER_XXH128:
#if defined(HASHER_XXH_X86_DISPATCH)
        return selected_xxh_dispatch ? "x86-runtime-simd" : "portable";
#elif defined(__aarch64__) || defined(_M_ARM64)
        return "neon";
#else
        return "portable";
#endif
    default: return "portable";
    }
}

const hasher_algorithm* hasher_algorithms(size_t* count) {
    if (count) *count = sizeof(algorithms) / sizeof(algorithms[0]);
    return algorithms;
}

static int eq(const char* a, const char* b) { return strcmp(a, b) == 0; }

const hasher_algorithm* hasher_find_algorithm(const char* option) {
    size_t i;
    const char* n = option;
    if (*n == '-') ++n;
    if (eq(n,"keccak256")) n="keccak-256";
    else if (eq(n,"rmd128")) n="rmd-128";
    else if (eq(n,"rmd160")) n="rmd-160";
    else if (eq(n,"rmd256") || eq(n,"rmd260")) n="rmd-256";
    else if (eq(n,"rmd320")) n="rmd-320";
    else if (eq(n,"turplehash128")) n="tuplehash128";
    else if (eq(n,"turplehash256")) n="tuplehash256";
    else if (eq(n,"turplehashxof128")) n="tuplehashxof128";
    else if (eq(n,"turplehashxof256")) n="tuplehashxof256";
    else if (!strncmp(n,"pbkdf-hmac-",11)) {
        static char alias[64];
        size_t length = strlen(n + 11);
        if (length + 13 < sizeof(alias)) { memcpy(alias,"pbkdf2-hmac-",12); memcpy(alias+12,n+11,length+1); n=alias; }
    }
    for (i = 0; i < sizeof(algorithms)/sizeof(algorithms[0]); ++i)
        if (eq(n, algorithms[i].name)) return &algorithms[i];
    return NULL;
}

size_t hasher_output_size(const hasher_algorithm* a, const hasher_params* p) {
    if (!a) return 0;
    if (a->fixed_output_size) return a->fixed_output_size;
    return p && p->output_size ? p->output_size : a->default_output_size;
}

static const struct ltc_hash_descriptor* descriptor(hasher_algorithm_id id) {
    switch (id) {
    case HASHER_SHA1: return selected_sha1; case HASHER_SHA224: return selected_sha224;
    case HASHER_SHA256: return selected_sha256; case HASHER_SHA384: return selected_sha384;
    case HASHER_SHA512: return selected_sha512; case HASHER_SHA512_224: return selected_sha512_224;
    case HASHER_SHA512_256: return selected_sha512_256;
    case HASHER_SHA3_224: return &sha3_224_desc; case HASHER_SHA3_256: return &sha3_256_desc;
    case HASHER_SHA3_384: return &sha3_384_desc; case HASHER_SHA3_512: return &sha3_512_desc;
    case HASHER_KECCAK_224: return &keccak224_desc; case HASHER_KECCAK_256: return &keccak256_desc;
    case HASHER_KECCAK_384: return &keccak384_desc; case HASHER_KECCAK_512: return &keccak512_desc;
    case HASHER_MD2: return &md2_desc; case HASHER_MD4: return &md4_desc; case HASHER_MD5: return &md5_desc;
    case HASHER_RMD128: return &rmd128_desc; case HASHER_RMD160: return &rmd160_desc;
    case HASHER_RMD256: return &rmd256_desc; case HASHER_RMD320: return &rmd320_desc;
    case HASHER_SM3: return &sm3_desc; default: return NULL;
    }
}

static int hash_segments(void* user, const uint8_t* const* data, const size_t* size,
                         size_t count, uint8_t* output, size_t output_size) {
    hasher_algorithm_id id = (hasher_algorithm_id)(uintptr_t)user;
    const struct ltc_hash_descriptor* d = descriptor(id);
    size_t i;
    if(id==HASHER_MD5||id==HASHER_RMD160||use_arm_hash_segments(id)){
        uint8_t local[1156];const uint8_t* joined;uint8_t* allocated=NULL;size_t total=0,position=0;hasher_params p={0};const hasher_algorithm* a=algorithm_by_id(id);int result;
        if(count==1){joined=data[0];total=size[0];}
        else{for(i=0;i<count;++i){if(size[i]>SIZE_MAX-total)return -1;total+=size[i];}allocated=total>sizeof(local)?(uint8_t*)malloc(total):local;if(!allocated&&total)return -1;for(i=0;i<count;++i){if(size[i])memcpy(allocated+position,data[i],size[i]);position+=size[i];}joined=allocated;}
        if(id==HASHER_MD5){if(output_size!=16)result=-1;else{hasher_rhash_md5(joined,total,output);result=0;}}
        else if(id==HASHER_RMD160){if(output_size!=20)result=-1;else{hasher_rhash_rmd160(joined,total,output);result=0;}}
        else result=hasher_compute(a,&p,joined,total,output,output_size)==CRYPT_OK?0:-1;
        if(allocated&&allocated!=local)free(allocated);return result;
    }
    if (id == HASHER_KECCAK_256 || id == HASHER_KECCAK_512) {
        hasher_keccak_ctx ctx;
        size_t rate = id == HASHER_KECCAK_256 ? 136u : 72u;
        if ((id == HASHER_KECCAK_256 ? 32u : 64u) != output_size || hasher_keccak_init(&ctx, rate)) return -1;
        for (i = 0; i < count; ++i) if (hasher_keccak_update(&ctx, data[i], size[i])) return -1;
        return hasher_keccak_final(&ctx, 0x01, output, output_size);
    }
    if (d) {
        hash_state state;
        int err;
        if (d->hashsize != output_size || (err = d->init(&state)) != CRYPT_OK) return -1;
        for (i = 0; i < count; ++i) {
            if (size[i] > ULONG_MAX) return -1;
            if (size[i] && (err = d->process(&state, data[i], (unsigned long)size[i])) != CRYPT_OK) return -1;
        }
        return d->done(&state, output) == CRYPT_OK ? 0 : -1;
    }
    return -1;
}

typedef struct direct_prefix_state {
    hasher_algorithm_id id;
    const struct ltc_hash_descriptor* descriptor;
    union {
        hash_state ltc;
        hasher_keccak_ctx keccak;
        _Alignas(32) uint8_t rhash[512];
    } state;
} direct_prefix_state;

static int direct_prefix_prepare(direct_prefix_state* state,hasher_algorithm_id id,
 const uint8_t* prefix,size_t prefix_size){
 const struct ltc_hash_descriptor* d=descriptor(id);int err;
 if(!state||(!prefix&&prefix_size))return -1;state->id=id;state->descriptor=NULL;
 if(id==HASHER_MD5||id==HASHER_RMD160)
  return hasher_rhash_prefix_prepare(state->state.rhash,sizeof(state->state.rhash),id==HASHER_RMD160,prefix,prefix_size);
 if(id==HASHER_KECCAK_256||id==HASHER_KECCAK_512){size_t rate=id==HASHER_KECCAK_256?136u:72u;
  if(hasher_keccak_init(&state->state.keccak,rate))return -1;return prefix_size?hasher_keccak_update(&state->state.keccak,prefix,prefix_size):0;}
 if(!d||prefix_size>ULONG_MAX)return -1;state->descriptor=d;if((err=d->init(&state->state.ltc))!=CRYPT_OK)return -1;
 return prefix_size&&d->process(&state->state.ltc,prefix,(unsigned long)prefix_size)!=CRYPT_OK?-1:0;
}

static int direct_prefix_compute(void* user,const uint8_t* const* suffix,const size_t* size,
 size_t count,uint8_t* output){
 const direct_prefix_state* state=(const direct_prefix_state*)user;size_t i;
 if(!state||!output)return -1;
 if(state->id==HASHER_MD5||state->id==HASHER_RMD160)return hasher_rhash_prefix_compute(state->state.rhash,suffix,size,count,output);
 if(state->id==HASHER_KECCAK_256||state->id==HASHER_KECCAK_512){hasher_keccak_ctx ctx=state->state.keccak;
  for(i=0;i<count;++i)if(hasher_keccak_update(&ctx,suffix[i],size[i]))return -1;
  return hasher_keccak_final(&ctx,0x01,output,state->id==HASHER_KECCAK_256?32u:64u);}
 if(state->descriptor){hash_state ctx=state->state.ltc;int err;for(i=0;i<count;++i){if(size[i]>ULONG_MAX)return -1;
   if(size[i]&&(err=state->descriptor->process(&ctx,suffix[i],(unsigned long)size[i]))!=CRYPT_OK)return -1;}
  return state->descriptor->done(&ctx,output)==CRYPT_OK?0:-1;}return -1;
}

static int direct_prefix_worthwhile(hasher_algorithm_id id){
#if defined(_WIN32) && defined(_M_X64)
 return id==HASHER_MD5||id==HASHER_RMD160||id==HASHER_SHA224||id==HASHER_SHA256||id==HASHER_SHA384||id==HASHER_KECCAK_256;
#elif defined(__x86_64__)
 return id==HASHER_MD5||id==HASHER_RMD160||id==HASHER_SHA224||id==HASHER_KECCAK_512;
#elif defined(__APPLE__) && defined(__aarch64__)
 return id==HASHER_MD5||id==HASHER_RMD160||id==HASHER_KECCAK_256||id==HASHER_KECCAK_512;
#elif defined(__linux__) && defined(__aarch64__)
 return id==HASHER_MD5||id==HASHER_RMD160||id==HASHER_KECCAK_256;
#elif defined(_WIN32) && defined(_M_ARM64)
 return id==HASHER_MD5||id==HASHER_RMD160||id==HASHER_KECCAK_256||id==HASHER_KECCAK_512;
#else
 (void)id;return 0;
#endif
}

static int evpkdf_base(hasher_algorithm_id id, hasher_algorithm_id* base, size_t* digest_size) {
    switch (id) {
    case HASHER_EVP_KDF_MD5:*base=HASHER_MD5;*digest_size=16;return 0;
    case HASHER_EVP_KDF_SHA1:*base=HASHER_SHA1;*digest_size=20;return 0;
    case HASHER_EVP_KDF_SHA224:*base=HASHER_SHA224;*digest_size=28;return 0;
    case HASHER_EVP_KDF_SHA256:*base=HASHER_SHA256;*digest_size=32;return 0;
    case HASHER_EVP_KDF_SHA384:*base=HASHER_SHA384;*digest_size=48;return 0;
    case HASHER_EVP_KDF_SHA512:*base=HASHER_SHA512;*digest_size=64;return 0;
    case HASHER_EVP_KDF_RMD160:*base=HASHER_RMD160;*digest_size=20;return 0;
    case HASHER_EVP_KDF_KECCAK256:*base=HASHER_KECCAK_256;*digest_size=32;return 0;
    case HASHER_EVP_KDF_KECCAK512:*base=HASHER_KECCAK_512;*digest_size=64;return 0;
    default:return -1;
    }
}

static int pbkdf_base(hasher_algorithm_id id, hasher_algorithm_id* base, size_t* digest_size) {
    switch(id){
    case HASHER_PBKDF_MD5:*base=HASHER_MD5;*digest_size=16;return 0;
    case HASHER_PBKDF_SHA1:*base=HASHER_SHA1;*digest_size=20;return 0;
    case HASHER_PBKDF_SHA224:*base=HASHER_SHA224;*digest_size=28;return 0;
    case HASHER_PBKDF_SHA256:*base=HASHER_SHA256;*digest_size=32;return 0;
    case HASHER_PBKDF_SHA384:*base=HASHER_SHA384;*digest_size=48;return 0;
    case HASHER_PBKDF_SHA512:*base=HASHER_SHA512;*digest_size=64;return 0;
    case HASHER_PBKDF_RMD160:*base=HASHER_RMD160;*digest_size=20;return 0;
    case HASHER_PBKDF_KECCAK256:*base=HASHER_KECCAK_256;*digest_size=32;return 0;
    case HASHER_PBKDF_KECCAK512:*base=HASHER_KECCAK_512;*digest_size=64;return 0;
    default:return -1;}
}

static int pbkdf2_direct_base(hasher_algorithm_id id, hasher_algorithm_id* base, size_t* digest_size) {
    switch(id){
    case HASHER_PBKDF2_DIRECT_MD5:*base=HASHER_MD5;*digest_size=16;return 0;
    case HASHER_PBKDF2_DIRECT_SHA1:*base=HASHER_SHA1;*digest_size=20;return 0;
    case HASHER_PBKDF2_DIRECT_SHA224:*base=HASHER_SHA224;*digest_size=28;return 0;
    case HASHER_PBKDF2_DIRECT_SHA256:*base=HASHER_SHA256;*digest_size=32;return 0;
    case HASHER_PBKDF2_DIRECT_SHA384:*base=HASHER_SHA384;*digest_size=48;return 0;
    case HASHER_PBKDF2_DIRECT_SHA512:*base=HASHER_SHA512;*digest_size=64;return 0;
    case HASHER_PBKDF2_DIRECT_RMD160:*base=HASHER_RMD160;*digest_size=20;return 0;
    case HASHER_PBKDF2_DIRECT_KECCAK256:*base=HASHER_KECCAK_256;*digest_size=32;return 0;
    case HASHER_PBKDF2_DIRECT_KECCAK512:*base=HASHER_KECCAK_512;*digest_size=64;return 0;
    default:return -1;}
}

static int pbkdf2_base(hasher_algorithm_id id, hasher_algorithm_id* base, size_t* digest_size, size_t* block_size) {
    switch(id){
    case HASHER_PBKDF2_MD5:*base=HASHER_MD5;*digest_size=16;*block_size=64;return 0;
    case HASHER_PBKDF2_SHA1:*base=HASHER_SHA1;*digest_size=20;*block_size=64;return 0;
    case HASHER_PBKDF2_SHA224:*base=HASHER_SHA224;*digest_size=28;*block_size=64;return 0;
    case HASHER_PBKDF2_SHA256:*base=HASHER_SHA256;*digest_size=32;*block_size=64;return 0;
    case HASHER_PBKDF2_SHA384:*base=HASHER_SHA384;*digest_size=48;*block_size=128;return 0;
    case HASHER_PBKDF2_SHA512:*base=HASHER_SHA512;*digest_size=64;*block_size=128;return 0;
    default:return -1;}
}

static int fixed_hash(const struct ltc_hash_descriptor* d, const uint8_t* in, size_t n, uint8_t* out) {
    hash_state st;
    int err;
    if (!d || n > ULONG_MAX) return CRYPT_INVALID_ARG;
    if ((err = d->init(&st)) != CRYPT_OK) return err;
    if (n && (err = d->process(&st, in, (unsigned long)n)) != CRYPT_OK) return err;
    return d->done(&st, out);
}

typedef struct prepared_hmac_internal {
    hash_state inner;
    hash_state outer;
    const struct ltc_hash_descriptor* descriptor;
    size_t digest_size;
} prepared_hmac_internal;
_Static_assert(sizeof(prepared_hmac_internal) <= sizeof(((hasher_hmac_prepared*)0)->opaque), "HMAC prepared storage is too small");
static int prepare_hmac_descriptor(const struct ltc_hash_descriptor* d,const uint8_t* key,size_t key_size,hasher_hmac_prepared* prepared);

#define HASHER_ARM_HMAC_MAGIC UINT64_C(0x43414d484d524148)
typedef struct arm_hmac_prepared {uint64_t magic;hasher_algorithm_id base;size_t block,digest;uint8_t ipad[128],opad[128];} arm_hmac_prepared;

static const hasher_algorithm* algorithm_by_id(hasher_algorithm_id id){size_t i;for(i=0;i<sizeof(algorithms)/sizeof(algorithms[0]);++i)if(algorithms[i].id==id)return &algorithms[i];return NULL;}
static int arm_hmac_supported(hasher_algorithm_id base){
    (void)base;
#if defined(HASHER_HAVE_ARM_SHA2)
    if(base==HASHER_SHA1)return selected_arm_sha1;
    if(base==HASHER_SHA224||base==HASHER_SHA256)return selected_arm_sha2;
#endif
#if defined(__aarch64__) || defined(_M_ARM64)
    if(base==HASHER_SHA384||base==HASHER_SHA512)return strcmp(hasher_sha512_fast_backend(),"arm-sha512")==0;
#endif
    return 0;
}
static int prepare_arm_hmac(hasher_algorithm_id base,const uint8_t* key,size_t key_size,hasher_hmac_prepared* prepared){
    arm_hmac_prepared* h=(arm_hmac_prepared*)prepared->opaque;uint8_t block[128]={0},digest[64];size_t block_size,digest_size,i;const hasher_algorithm* a=algorithm_by_id(base);hasher_params p={0};
    if(!arm_hmac_supported(base)||!a)return -1;block_size=(base==HASHER_SHA384||base==HASHER_SHA512)?128:64;digest_size=a->fixed_output_size;
    if(key_size>block_size){if(hasher_compute(a,&p,key,key_size,digest,digest_size)!=CRYPT_OK)return -1;memcpy(block,digest,digest_size);}else if(key_size)memcpy(block,key,key_size);
    memset(prepared,0,sizeof(*prepared));h->magic=HASHER_ARM_HMAC_MAGIC;h->base=base;h->block=block_size;h->digest=digest_size;for(i=0;i<block_size;++i){h->ipad[i]=(uint8_t)(block[i]^0x36u);h->opad[i]=(uint8_t)(block[i]^0x5cu);}return 0;
}
static int arm_hmac_compute_segments(const arm_hmac_prepared* h,const uint8_t* const* data,const size_t* size,size_t count,uint8_t* output){
    uint8_t local[128+1028],inner[64],outer[192];uint8_t* buffer=local;size_t total=h->block,i,position;const hasher_algorithm* a=algorithm_by_id(h->base);hasher_params p={0};
    for(i=0;i<count;++i){if(size[i]>SIZE_MAX-total)return -1;total+=size[i];}if(total>sizeof(local)){buffer=(uint8_t*)malloc(total);if(!buffer)return -1;}memcpy(buffer,h->ipad,h->block);position=h->block;for(i=0;i<count;++i){if(size[i])memcpy(buffer+position,data[i],size[i]);position+=size[i];}
    if(hasher_compute(a,&p,buffer,total,inner,h->digest)!=CRYPT_OK){if(buffer!=local)free(buffer);return -1;}if(buffer!=local)free(buffer);memcpy(outer,h->opad,h->block);memcpy(outer+h->block,inner,h->digest);return hasher_compute(a,&p,outer,h->block+h->digest,output,h->digest)==CRYPT_OK?0:-1;
}
static int use_arm_hmac(hasher_algorithm_id base,int pbkdf2){
    if(!arm_hmac_supported(base))return 0;
#if defined(__linux__) && defined(__aarch64__)
    return pbkdf2?(base==HASHER_SHA1||base==HASHER_SHA224||base==HASHER_SHA256||base==HASHER_SHA512):base==HASHER_SHA224;
#elif defined(__APPLE__) && defined(__aarch64__)
    (void)pbkdf2;return base==HASHER_SHA224||base==HASHER_SHA256;
#else
    (void)pbkdf2;return 1;
#endif
}
static int use_arm_hash_segments(hasher_algorithm_id base){
    if(!arm_hmac_supported(base))return 0;
#if defined(__linux__) && defined(__aarch64__)
    return base!=HASHER_SHA512;
#elif defined(__APPLE__) && defined(__aarch64__)
    return base==HASHER_SHA1||base==HASHER_SHA224||base==HASHER_SHA256;
#else
    return 1;
#endif
}
static int prepare_base_hmac(hasher_algorithm_id base,const uint8_t* key,size_t key_size,hasher_hmac_prepared* prepared,int pbkdf2){
    if(use_arm_hmac(base,pbkdf2))return prepare_arm_hmac(base,key,key_size,prepared)==0?CRYPT_OK:CRYPT_INVALID_ARG;
    if(base==HASHER_MD5){
#if defined(__linux__) && defined(__aarch64__)
        if(!pbkdf2)return prepare_hmac_descriptor(descriptor(base),key,key_size,prepared);
#endif
        return hasher_rhash_hmac_md5_prepare(prepared->opaque,sizeof(prepared->opaque),key,key_size)==0?CRYPT_OK:CRYPT_INVALID_ARG;
    }
    return prepare_hmac_descriptor(descriptor(base),key,key_size,prepared);
}

static int prepare_hmac_descriptor(const struct ltc_hash_descriptor* d,const uint8_t* key,size_t key_size,hasher_hmac_prepared* prepared){
    prepared_hmac_internal* h;uint8_t key_block[128]={0},key_hash[64],ipad[128],opad[128];size_t block,digest,i;int err;
    if(!d||(!key&&key_size)||!prepared)return CRYPT_INVALID_ARG;block=d->blocksize;digest=d->hashsize;if(block>sizeof(key_block)||digest>sizeof(key_hash))return CRYPT_INVALID_ARG;
    if(key_size>block){if((err=fixed_hash(d,key,key_size,key_hash))!=CRYPT_OK)return err;memcpy(key_block,key_hash,digest);}else if(key_size)memcpy(key_block,key,key_size);
    for(i=0;i<block;++i){ipad[i]=(uint8_t)(key_block[i]^0x36);opad[i]=(uint8_t)(key_block[i]^0x5c);}memset(prepared,0,sizeof(*prepared));h=(prepared_hmac_internal*)prepared->opaque;h->descriptor=d;h->digest_size=digest;
    if((err=d->init(&h->inner))!=CRYPT_OK)return err;if((err=d->process(&h->inner,ipad,(unsigned long)block))!=CRYPT_OK)return err;if((err=d->init(&h->outer))!=CRYPT_OK)return err;return d->process(&h->outer,opad,(unsigned long)block);
}

int hasher_hmac_prepare(const hasher_algorithm* a,const hasher_params* p,hasher_hmac_prepared* prepared) {
    static const uint8_t empty_key=0;
    hasher_algorithm_id base;
    const uint8_t* key=p&&p->key?p->key:&empty_key;size_t key_size=p?p->key_size:0;
    if(!a||!prepared||((!p||!p->key)&&key_size))return CRYPT_INVALID_ARG;
    switch(a->id){case HASHER_HMAC_MD5:base=HASHER_MD5;break;case HASHER_HMAC_SHA1:base=HASHER_SHA1;break;case HASHER_HMAC_SHA224:base=HASHER_SHA224;break;case HASHER_HMAC_SHA256:base=HASHER_SHA256;break;case HASHER_HMAC_SHA384:base=HASHER_SHA384;break;case HASHER_HMAC_SHA512:base=HASHER_SHA512;break;default:return CRYPT_INVALID_ARG;}
    return prepare_base_hmac(base,key,key_size,prepared,0);
}

static int hmac_prepared_segments(void* user,const uint8_t* const* data,const size_t* size,size_t count,uint8_t* output){
    const arm_hmac_prepared* arm=(const arm_hmac_prepared*)((const hasher_hmac_prepared*)user)->opaque;if(arm->magic==HASHER_ARM_HMAC_MAGIC)return arm_hmac_compute_segments(arm,data,size,count,output);
    if(hasher_rhash_hmac_md5_is_prepared(((const hasher_hmac_prepared*)user)->opaque))return hasher_rhash_hmac_md5_compute(((const hasher_hmac_prepared*)user)->opaque,data,size,count,output);
    const prepared_hmac_internal* h=(const prepared_hmac_internal*)((const hasher_hmac_prepared*)user)->opaque;hash_state inner=h->inner,outer=h->outer;uint8_t digest[64];size_t i;int err;
    for(i=0;i<count;++i){if(size[i]>ULONG_MAX)return -1;if(size[i]&&(err=h->descriptor->process(&inner,data[i],(unsigned long)size[i]))!=CRYPT_OK)return -1;}
    if(h->descriptor->done(&inner,digest)!=CRYPT_OK||h->descriptor->process(&outer,digest,(unsigned long)h->digest_size)!=CRYPT_OK||h->descriptor->done(&outer,output)!=CRYPT_OK)return -1;return 0;
}

int hasher_hmac_compute_prepared(const hasher_hmac_prepared* prepared,const uint8_t* input,size_t input_size,uint8_t* output,size_t output_size) {
    const prepared_hmac_internal* h;hash_state inner,outer;uint8_t digest[64];int err;
    if(!prepared||(!input&&input_size)||!output)return CRYPT_INVALID_ARG;
    {const arm_hmac_prepared* arm=(const arm_hmac_prepared*)prepared->opaque;if(arm->magic==HASHER_ARM_HMAC_MAGIC){const uint8_t* data[1]={input};const size_t size[1]={input_size};return output_size==arm->digest&&arm_hmac_compute_segments(arm,data,size,1,output)==0?CRYPT_OK:CRYPT_INVALID_ARG;}}
    if(hasher_rhash_hmac_md5_is_prepared(prepared->opaque)){const uint8_t* data[1]={input};const size_t size[1]={input_size};return output_size==16&&hasher_rhash_hmac_md5_compute(prepared->opaque,data,size,1,output)==0?CRYPT_OK:CRYPT_INVALID_ARG;}
    h=(const prepared_hmac_internal*)prepared->opaque;
    if(!h->descriptor||output_size!=h->digest_size||input_size>ULONG_MAX)return CRYPT_INVALID_ARG;
    inner=h->inner;if(input_size&&(err=h->descriptor->process(&inner,input,(unsigned long)input_size))!=CRYPT_OK)return err;
    if((err=h->descriptor->done(&inner,digest))!=CRYPT_OK)return err;outer=h->outer;
    if((err=h->descriptor->process(&outer,digest,(unsigned long)h->digest_size))!=CRYPT_OK)return err;
    return h->descriptor->done(&outer,output);
}

int hasher_compute(const hasher_algorithm* a, const hasher_params* p,
                   const uint8_t* in, size_t n, uint8_t* out, size_t out_size) {
    static const uint8_t empty_key=0;
    hasher_params defaults;
    hash_state st;
    int err;
    const struct ltc_hash_descriptor* d;
    if(!p){memset(&defaults,0,sizeof(defaults));defaults.key=&empty_key;p=&defaults;}
    else if(!p->key){if(p->key_size)return CRYPT_INVALID_ARG;defaults=*p;defaults.key=&empty_key;p=&defaults;}
    if (!a || !out || (!in && n) || out_size != hasher_output_size(a,p)) return CRYPT_INVALID_ARG;
    if (a->flags & HASHER_KDF) {
        hasher_algorithm_id base;
        size_t digest_size, block_size;
        uint64_t iterations = p && p->kdf_iterations ? p->kdf_iterations :
            (a->id>=HASHER_PBKDF2_DIRECT_MD5&&a->id<=HASHER_PBKDF2_SHA512?10000u:1u);
        int result;
        if (!evpkdf_base(a->id, &base, &digest_size))
            result=hasher_evpkdf_derive(hash_segments,(void*)(uintptr_t)base,digest_size,in,n,p?p->salt:NULL,p?p->salt_size:0,iterations,out,out_size);
        else if (!pbkdf_base(a->id,&base,&digest_size))
            result=hasher_pbkdf1_derive(hash_segments,(void*)(uintptr_t)base,digest_size,in,n,p?p->salt:NULL,p?p->salt_size:0,iterations,out,out_size);
        else if (!pbkdf2_direct_base(a->id,&base,&digest_size)){
            direct_prefix_state state;
            if(use_arm_hash_segments(base)||!direct_prefix_worthwhile(base))result=hasher_pbkdf2_direct_derive(hash_segments,(void*)(uintptr_t)base,digest_size,in,n,p?p->salt:NULL,p?p->salt_size:0,iterations,out,out_size);
            else if(direct_prefix_prepare(&state,base,in,n))result=-1;
            else result=hasher_pbkdf2_direct_derive_prepared(direct_prefix_compute,&state,digest_size,p?p->salt:NULL,p?p->salt_size:0,iterations,out,out_size);
        }
        else if (!pbkdf2_base(a->id,&base,&digest_size,&block_size))
        {hasher_hmac_prepared prepared;(void)block_size;
            if(prepare_base_hmac(base,in,n,&prepared,1)!=CRYPT_OK)return CRYPT_INVALID_ARG;
            result=hasher_pbkdf2_derive_prepared(hmac_prepared_segments,&prepared,digest_size,p?p->salt:NULL,p?p->salt_size:0,iterations,out,out_size);}
        else return CRYPT_INVALID_ARG;
        return result==0?CRYPT_OK:CRYPT_INVALID_ARG;
    }
    if (a->id == HASHER_MD4) { hasher_rhash_md4(in,n,out); return CRYPT_OK; }
    if (a->id == HASHER_MD5) { hasher_rhash_md5(in,n,out); return CRYPT_OK; }
    if (a->id == HASHER_RMD160) { hasher_rhash_rmd160(in,n,out); return CRYPT_OK; }
    switch (a->id) {
    case HASHER_SHA3_224: return hasher_keccak_hash(144,0x06,in,n,out,out_size)==0?CRYPT_OK:CRYPT_INVALID_ARG;
    case HASHER_SHA3_256: return hasher_keccak_hash(136,0x06,in,n,out,out_size)==0?CRYPT_OK:CRYPT_INVALID_ARG;
    case HASHER_SHA3_384: return hasher_keccak_hash(104,0x06,in,n,out,out_size)==0?CRYPT_OK:CRYPT_INVALID_ARG;
    case HASHER_SHA3_512: return hasher_keccak_hash(72,0x06,in,n,out,out_size)==0?CRYPT_OK:CRYPT_INVALID_ARG;
    case HASHER_KECCAK_224: return hasher_keccak_hash(144,0x01,in,n,out,out_size)==0?CRYPT_OK:CRYPT_INVALID_ARG;
    case HASHER_KECCAK_256: return hasher_keccak_hash(136,0x01,in,n,out,out_size)==0?CRYPT_OK:CRYPT_INVALID_ARG;
    case HASHER_KECCAK_384: return hasher_keccak_hash(104,0x01,in,n,out,out_size)==0?CRYPT_OK:CRYPT_INVALID_ARG;
    case HASHER_KECCAK_512: return hasher_keccak_hash(72,0x01,in,n,out,out_size)==0?CRYPT_OK:CRYPT_INVALID_ARG;
    default: break;
    }
#if defined(HASHER_HAVE_SHA512_AVX)
    if (!selected_sha512_native) {
        int variant = a->id==HASHER_SHA384?HASHER_SHA384_VARIANT:a->id==HASHER_SHA512?HASHER_SHA512_VARIANT:
                      a->id==HASHER_SHA512_224?HASHER_SHA512_224_VARIANT:a->id==HASHER_SHA512_256?HASHER_SHA512_256_VARIANT:0;
        if (variant && hasher_sha512_fast(in,n,out,out_size,variant)==0) return CRYPT_OK;
    }
#endif
#if defined(HASHER_SM3_X86_NI)
    if (selected_sm3_x86_ni && a->id == HASHER_SM3) {
        hasher_sm3_x86_ni(in, n, out);
        return CRYPT_OK;
    }
#endif
#if defined(HASHER_SM3_ARM_NI)
    if (selected_sm3_arm_ni && a->id == HASHER_SM3) {
        hasher_sm3_arm_ni(in, n, out);
        return CRYPT_OK;
    }
#endif
#if defined(HASHER_SM3_FAST_X86) || defined(HASHER_SM3_FAST_ARM)
    if (selected_sm3_fast && a->id == HASHER_SM3) {
        hasher_gmssl_sm3_digest(in, n, out);
        return CRYPT_OK;
    }
#endif
    d = descriptor(a->id);
#if defined(HASHER_HAVE_ARM_SHA2)
    if (selected_arm_sha1 && a->id == HASHER_SHA1) {
        if (n > UINT64_MAX / 8) return CRYPT_INVALID_ARG;
        hasher_sha1_arm(in, n, out);
        return CRYPT_OK;
    }
    if (selected_arm_sha2 && (a->id == HASHER_SHA224 || a->id == HASHER_SHA256)) {
        if (n > UINT64_MAX / 8) return CRYPT_INVALID_ARG;
        hasher_sha256_arm(in, n, out, a->id == HASHER_SHA224);
        return CRYPT_OK;
    }
#endif
    if (d) return fixed_hash(d, in, n, out);
    switch (a->id) {
    case HASHER_SHAKE128: case HASHER_SHAKE256:
        return hasher_keccak_hash(a->id == HASHER_SHAKE128 ? 168 : 136,0x1f,in,n,out,out_size)==0?CRYPT_OK:CRYPT_INVALID_ARG;
    case HASHER_CSHAKE128: case HASHER_CSHAKE256:
        return hasher_cshake(a->id == HASHER_CSHAKE128 ? 128 : 256, in,n,
            p?p->function_name:NULL,p?p->function_name_size:0,
            p?p->customization:NULL,p?p->customization_size:0,out,out_size);
    case HASHER_BLAKE2B:
        if (out_size < 1 || out_size > 64) return CRYPT_INVALID_ARG;
#if defined(HASHER_BLAKE2_FAST_X86) || defined(HASHER_BLAKE2_FAST_ARM)
        if (selected_blake2_fast) return hasher_fast_blake2b(out,out_size,in,n,NULL,0)==0?CRYPT_OK:CRYPT_INVALID_ARG;
#endif
        if ((err=blake2b_init(&st,(unsigned long)out_size,NULL,0))!=CRYPT_OK) return err;
        if (n && (err=blake2b_process(&st,in,(unsigned long)n))!=CRYPT_OK) return err;
        return blake2b_done(&st,out);
    case HASHER_BLAKE2S:
        if (out_size < 1 || out_size > 32) return CRYPT_INVALID_ARG;
#if defined(HASHER_BLAKE2_FAST_X86) || defined(HASHER_BLAKE2_FAST_ARM)
        if (selected_blake2_fast) return hasher_fast_blake2s(out,out_size,in,n,NULL,0)==0?CRYPT_OK:CRYPT_INVALID_ARG;
#endif
        if ((err=blake2s_init(&st,(unsigned long)out_size,NULL,0))!=CRYPT_OK) return err;
        if (n && (err=blake2s_process(&st,in,(unsigned long)n))!=CRYPT_OK) return err;
        return blake2s_done(&st,out);
    case HASHER_BLAKE3: {
        blake3_hasher h; blake3_hasher_init(&h); blake3_hasher_update(&h,in,n);
        blake3_hasher_finalize(&h,out,out_size); return CRYPT_OK; }
    case HASHER_XXH128: {
        XXH128_hash_t h;
#if defined(HASHER_XXH_X86_DISPATCH)
        h=selected_xxh_dispatch?XXH3_128bits_withSeed_dispatch(in,n,p?p->seed:0):XXH3_128bits_withSeed(in,n,p?p->seed:0);
#else
        h=XXH3_128bits_withSeed(in,n,p?p->seed:0);
#endif
        XXH128_canonical_t c;
        XXH128_canonicalFromHash(&c,h); memcpy(out,c.digest,16); return CRYPT_OK; }
    case HASHER_KMAC128: case HASHER_KMAC256: case HASHER_KMACXOF128: case HASHER_KMACXOF256: {
        return hasher_kmac((a->id==HASHER_KMAC128||a->id==HASHER_KMACXOF128)?128:256,
            a->id==HASHER_KMACXOF128||a->id==HASHER_KMACXOF256,
            p->key,p->key_size,in,n,p->customization,p->customization_size,out,out_size); }
    case HASHER_TUPLEHASH128: case HASHER_TUPLEHASH256:
    case HASHER_TUPLEHASHXOF128: case HASHER_TUPLEHASHXOF256:
        return hasher_tuplehash((a->id==HASHER_TUPLEHASH128||a->id==HASHER_TUPLEHASHXOF128)?128:256,
            a->id==HASHER_TUPLEHASHXOF128||a->id==HASHER_TUPLEHASHXOF256,
            in,n,p?p->customization:NULL,p?p->customization_size:0,out,out_size);
    case HASHER_PARALLELHASH128: case HASHER_PARALLELHASH256:
    case HASHER_PARALLELHASHXOF128: case HASHER_PARALLELHASHXOF256:
        return hasher_parallelhash((a->id==HASHER_PARALLELHASH128||a->id==HASHER_PARALLELHASHXOF128)?128:256,
            a->id==HASHER_PARALLELHASHXOF128||a->id==HASHER_PARALLELHASHXOF256,
            in,n,p?p->customization:NULL,p?p->customization_size:0,
            p&&p->parallel_block_size?p->parallel_block_size:1024,out,out_size);
    case HASHER_HMAC_MD5: case HASHER_HMAC_SHA1: case HASHER_HMAC_SHA224:
    case HASHER_HMAC_SHA256: case HASHER_HMAC_SHA384: case HASHER_HMAC_SHA512: {
        hasher_hmac_prepared prepared;int h=hasher_hmac_prepare(a,p,&prepared);if(h!=CRYPT_OK)return h;
        return hasher_hmac_compute_prepared(&prepared,in,n,out,out_size);}
    default: return CRYPT_INVALID_ARG;
    }
}

int hasher_compute_batch4(const hasher_algorithm* a, const hasher_params* p,
                          const uint8_t* const input[4], const size_t input_size[4],
                          uint8_t* const output[4], size_t output_size) {
    size_t rate=0;uint8_t suffix=0;
    if(!a||!input||!input_size||!output||output_size!=hasher_output_size(a,p))return CRYPT_INVALID_ARG;
    switch(a->id){
    case HASHER_SHA3_224: rate=144;suffix=0x06;break;case HASHER_SHA3_256: rate=136;suffix=0x06;break;
    case HASHER_SHA3_384: rate=104;suffix=0x06;break;case HASHER_SHA3_512: rate=72;suffix=0x06;break;
    case HASHER_KECCAK_224: rate=144;suffix=0x01;break;case HASHER_KECCAK_256: rate=136;suffix=0x01;break;
    case HASHER_KECCAK_384: rate=104;suffix=0x01;break;case HASHER_KECCAK_512: rate=72;suffix=0x01;break;
    case HASHER_SHAKE128: rate=168;suffix=0x1f;break;case HASHER_SHAKE256: rate=136;suffix=0x1f;break;
    case HASHER_CSHAKE128: case HASHER_CSHAKE256:
        if(p&&(p->function_name_size||p->customization_size))return CRYPT_INVALID_ARG;
        rate=a->id==HASHER_CSHAKE128?168:136;suffix=0x1f;break;
    default:return CRYPT_INVALID_ARG;
    }
    return hasher_keccak_hash4(rate,suffix,input,input_size,output,output_size)==0?CRYPT_OK:CRYPT_INVALID_ARG;
}

const char* hasher_error_string(int error) { return error==CRYPT_OK?"ok":error_to_string(error); }
