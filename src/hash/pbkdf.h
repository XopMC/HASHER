#ifndef HASHER_PBKDF_H
#define HASHER_PBKDF_H
#include "evpkdf.h"
int hasher_pbkdf1_derive(hasher_kdf_hash_segments_fn hash, void* user,
    size_t digest_size, const uint8_t* password, size_t password_size,
    const uint8_t* salt, size_t salt_size, uint64_t iterations,
    uint8_t* output, size_t output_size);
#endif
