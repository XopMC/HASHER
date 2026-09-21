#ifndef HASHER_HASH_API_H
#define HASHER_HASH_API_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

enum hasher_flags {
    HASHER_FIXED_OUTPUT = 1u << 0,
    HASHER_VARIABLE_OUTPUT = 1u << 1,
    HASHER_KEY_REQUIRED = 1u << 2,
    HASHER_CUSTOM_SUPPORTED = 1u << 3,
    HASHER_FUNCTION_NAME_SUPPORTED = 1u << 4,
    HASHER_BLOCK_SIZE_SUPPORTED = 1u << 5,
    HASHER_SEED_SUPPORTED = 1u << 6,
    HASHER_KDF = 1u << 7
};

typedef enum hasher_algorithm_id {
    HASHER_SHA1, HASHER_SHA224, HASHER_SHA256, HASHER_SHA384,
    HASHER_SHA512, HASHER_SHA512_224, HASHER_SHA512_256,
    HASHER_SHA3_224, HASHER_SHA3_256, HASHER_SHA3_384, HASHER_SHA3_512,
    HASHER_KECCAK_224, HASHER_KECCAK_256, HASHER_KECCAK_384, HASHER_KECCAK_512,
    HASHER_SHAKE128, HASHER_SHAKE256, HASHER_CSHAKE128, HASHER_CSHAKE256,
    HASHER_MD2, HASHER_MD4, HASHER_MD5,
    HASHER_RMD128, HASHER_RMD160, HASHER_RMD256, HASHER_RMD320,
    HASHER_BLAKE2B, HASHER_BLAKE2S, HASHER_BLAKE3, HASHER_XXH128, HASHER_SM3,
    HASHER_KMAC128, HASHER_KMAC256, HASHER_KMACXOF128, HASHER_KMACXOF256,
    HASHER_TUPLEHASH128, HASHER_TUPLEHASH256,
    HASHER_TUPLEHASHXOF128, HASHER_TUPLEHASHXOF256,
    HASHER_PARALLELHASH128, HASHER_PARALLELHASH256,
    HASHER_PARALLELHASHXOF128, HASHER_PARALLELHASHXOF256,
    HASHER_HMAC_MD5, HASHER_HMAC_SHA1, HASHER_HMAC_SHA224,
    HASHER_HMAC_SHA256, HASHER_HMAC_SHA384, HASHER_HMAC_SHA512,
    HASHER_EVP_KDF_MD5, HASHER_EVP_KDF_SHA1, HASHER_EVP_KDF_SHA224,
    HASHER_EVP_KDF_SHA256, HASHER_EVP_KDF_SHA384, HASHER_EVP_KDF_SHA512,
    HASHER_EVP_KDF_RMD160, HASHER_EVP_KDF_KECCAK256, HASHER_EVP_KDF_KECCAK512,
    HASHER_PBKDF_MD5, HASHER_PBKDF_SHA1, HASHER_PBKDF_SHA224, HASHER_PBKDF_SHA256,
    HASHER_PBKDF_SHA384, HASHER_PBKDF_SHA512, HASHER_PBKDF_RMD160,
    HASHER_PBKDF_KECCAK256, HASHER_PBKDF_KECCAK512,
    HASHER_PBKDF2_DIRECT_MD5, HASHER_PBKDF2_DIRECT_SHA1,
    HASHER_PBKDF2_DIRECT_SHA224, HASHER_PBKDF2_DIRECT_SHA256,
    HASHER_PBKDF2_DIRECT_SHA384, HASHER_PBKDF2_DIRECT_SHA512,
    HASHER_PBKDF2_DIRECT_RMD160, HASHER_PBKDF2_DIRECT_KECCAK256,
    HASHER_PBKDF2_DIRECT_KECCAK512,
    HASHER_PBKDF2_MD5, HASHER_PBKDF2_SHA1, HASHER_PBKDF2_SHA224,
    HASHER_PBKDF2_SHA256, HASHER_PBKDF2_SHA384, HASHER_PBKDF2_SHA512,
    HASHER_ALGORITHM_COUNT
} hasher_algorithm_id;

typedef struct hasher_params {
    const uint8_t* key;
    size_t key_size;
    const uint8_t* function_name;
    size_t function_name_size;
    const uint8_t* customization;
    size_t customization_size;
    size_t output_size;
    size_t parallel_block_size;
    uint64_t seed;
    const uint8_t* salt;
    size_t salt_size;
    uint64_t kdf_iterations;
} hasher_params;

typedef struct hasher_hmac_prepared {
#ifdef __cplusplus
    alignas(64) unsigned char opaque[4096];
#else
    _Alignas(64) unsigned char opaque[4096];
#endif
} hasher_hmac_prepared;

typedef struct hasher_sp800185_prepared {
#ifdef __cplusplus
    alignas(64) unsigned char opaque[512];
#else
    _Alignas(64) unsigned char opaque[512];
#endif
} hasher_sp800185_prepared;

typedef struct hasher_algorithm {
    hasher_algorithm_id id;
    const char* name;
    size_t fixed_output_size;
    size_t default_output_size;
    uint32_t flags;
} hasher_algorithm;

int hasher_library_init(void);
const hasher_algorithm* hasher_algorithms(size_t* count);
const hasher_algorithm* hasher_find_algorithm(const char* option);
size_t hasher_output_size(const hasher_algorithm* algorithm, const hasher_params* params);
int hasher_compute(const hasher_algorithm* algorithm, const hasher_params* params,
                   const uint8_t* input, size_t input_size,
                   uint8_t* output, size_t output_size);
int hasher_compute_batch4(const hasher_algorithm* algorithm, const hasher_params* params,
                          const uint8_t* const input[4], const size_t input_size[4],
                          uint8_t* const output[4], size_t output_size);
int hasher_hmac_prepare(const hasher_algorithm* algorithm, const hasher_params* params,
                        hasher_hmac_prepared* prepared);
int hasher_hmac_compute_prepared(const hasher_hmac_prepared* prepared,
                                 const uint8_t* input, size_t input_size,
                                 uint8_t* output, size_t output_size);
int hasher_sp800185_prepare(const hasher_algorithm* algorithm, const hasher_params* params,
                            hasher_sp800185_prepared* prepared);
int hasher_sp800185_compute_prepared(const hasher_sp800185_prepared* prepared,
                                     const uint8_t* input, size_t input_size,
                                     uint8_t* output, size_t output_size);
const char* hasher_error_string(int error);
const char* hasher_selected_backend(hasher_algorithm_id id);

#ifdef __cplusplus
}
#endif
#endif
