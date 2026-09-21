#ifndef HASHER_LEGACY_RHASH_H
#define HASHER_LEGACY_RHASH_H

#include <stddef.h>
#include <stdint.h>

void hasher_rhash_md4(const uint8_t* input, size_t size, uint8_t output[16]);
void hasher_rhash_md5(const uint8_t* input, size_t size, uint8_t output[16]);
void hasher_rhash_rmd160(const uint8_t* input, size_t size, uint8_t output[20]);
int hasher_rhash_prefix_prepare(void* storage,size_t storage_size,int ripemd160,
 const uint8_t* prefix,size_t prefix_size);
int hasher_rhash_prefix_compute(const void* storage,const uint8_t* const* suffix,
 const size_t* size,size_t count,uint8_t* output);
int hasher_rhash_hmac_md5_prepare(void* prepared, size_t prepared_size, const uint8_t* key, size_t key_size);
int hasher_rhash_hmac_md5_is_prepared(const void* prepared);
int hasher_rhash_hmac_md5_compute(const void* prepared, const uint8_t* const* data,
                                  const size_t* size, size_t count, uint8_t output[16]);

#endif
