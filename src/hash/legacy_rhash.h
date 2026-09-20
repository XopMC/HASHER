#ifndef HASHER_LEGACY_RHASH_H
#define HASHER_LEGACY_RHASH_H

#include <stddef.h>
#include <stdint.h>

void hasher_rhash_md4(const uint8_t* input, size_t size, uint8_t output[16]);
void hasher_rhash_md5(const uint8_t* input, size_t size, uint8_t output[16]);
void hasher_rhash_rmd160(const uint8_t* input, size_t size, uint8_t output[20]);
int hasher_rhash_hmac_md5_prepare(void* prepared, size_t prepared_size, const uint8_t* key, size_t key_size);
int hasher_rhash_hmac_md5_is_prepared(const void* prepared);
int hasher_rhash_hmac_md5_compute(const void* prepared, const uint8_t* const* data,
                                  const size_t* size, size_t count, uint8_t output[16]);

#endif
