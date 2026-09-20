#ifndef HASHER_EVP_KDF_H
#define HASHER_EVP_KDF_H
#include <stddef.h>
#include <stdint.h>

typedef int (*hasher_kdf_hash_segments_fn)(void* user,
    const uint8_t* const* data, const size_t* size, size_t count,
    uint8_t* output, size_t output_size);

int hasher_evpkdf_derive(hasher_kdf_hash_segments_fn hash, void* user,
    size_t digest_size, const uint8_t* password, size_t password_size,
    const uint8_t* salt, size_t salt_size, uint64_t iterations,
    uint8_t* output, size_t output_size);
#endif
