#ifndef HASHER_PBKDF2_H
#define HASHER_PBKDF2_H
#include <stddef.h>
#include <stdint.h>
#include "pbkdf.h"
typedef int (*hasher_kdf_prf_segments_fn)(void* user,const uint8_t* const* data,
 const size_t* size,size_t count,uint8_t* output);
typedef int (*hasher_kdf_hash_suffix_fn)(void* user,const uint8_t* const* suffix,
 const size_t* size,size_t count,uint8_t* output);
int hasher_pbkdf2_derive_prepared(hasher_kdf_prf_segments_fn prf,void* user,
 size_t digest_size,const uint8_t* salt,size_t salt_size,uint64_t iterations,
 uint8_t* output,size_t output_size);
int hasher_pbkdf2_direct_derive(hasher_kdf_hash_segments_fn hash,void* user,
 size_t digest_size,const uint8_t* password,size_t password_size,
 const uint8_t* salt,size_t salt_size,uint64_t iterations,
 uint8_t* output,size_t output_size);
int hasher_pbkdf2_direct_derive_prepared(hasher_kdf_hash_suffix_fn hash,void* user,
 size_t digest_size,const uint8_t* salt,size_t salt_size,uint64_t iterations,
 uint8_t* output,size_t output_size);
#endif
