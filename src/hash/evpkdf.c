#include "evpkdf.h"
#include <string.h>

int hasher_evpkdf_derive(hasher_kdf_hash_segments_fn hash, void* user,
    size_t digest_size, const uint8_t* password, size_t password_size,
    const uint8_t* salt, size_t salt_size, uint64_t iterations,
    uint8_t* output, size_t output_size) {
    uint8_t digest[64];
    size_t produced = 0, previous_size = 0;
    if (!hash || !digest_size || digest_size > sizeof(digest) || !iterations ||
        (!password && password_size) || (!salt && salt_size) || (!output && output_size)) return -1;
    while (produced < output_size) {
        const uint8_t* parts[3] = { digest, password, salt };
        size_t sizes[3] = { previous_size, password_size, salt_size };
        uint64_t round;
        size_t take;
        if (hash(user, parts, sizes, 3, digest, digest_size) != 0) return -1;
        for (round = 1; round < iterations; ++round) {
            const uint8_t* one[1] = { digest };
            const size_t one_size[1] = { digest_size };
            if (hash(user, one, one_size, 1, digest, digest_size) != 0) return -1;
        }
        take = output_size - produced;
        if (take > digest_size) take = digest_size;
        memcpy(output + produced, digest, take);
        produced += take;
        previous_size = digest_size;
    }
    return 0;
}
