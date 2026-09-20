#include "sp800185.h"
#include "keccak_core.h"
#include "hasher/hash_api.h"
#include <limits.h>
#include <string.h>
#include <tomcrypt.h>

static size_t left_encode(uint64_t value, uint8_t out[9]) {
    size_t n = 1, i;
    uint64_t v = value;
    while ((v >>= 8) != 0) ++n;
    out[0] = (uint8_t)n;
    for (i = 0; i < n; ++i) out[n - i] = (uint8_t)(value >> (8 * i));
    return n + 1;
}

static size_t right_encode(uint64_t value, uint8_t out[9]) {
    size_t n = 1, i;
    uint64_t v = value;
    while ((v >>= 8) != 0) ++n;
    for (i = 0; i < n; ++i) out[n - 1 - i] = (uint8_t)(value >> (8 * i));
    out[n] = (uint8_t)n;
    return n + 1;
}

static int absorb(hasher_keccak_ctx* st, const uint8_t* data, size_t size) {
    return hasher_keccak_update(st, data, size) == 0 ? CRYPT_OK : CRYPT_INVALID_ARG;
}

static int absorb_encode_string(hasher_keccak_ctx* st, const uint8_t* s, size_t size, size_t* total) {
    uint8_t enc[9];
    size_t n;
    int err;
    if (size > UINT64_MAX / 8) return CRYPT_INVALID_ARG;
    n = left_encode((uint64_t)size * 8, enc);
    if ((err = absorb(st, enc, n)) != CRYPT_OK) return err;
    if ((err = absorb(st, s, size)) != CRYPT_OK) return err;
    *total += n + size;
    return CRYPT_OK;
}

static int cshake_init(hasher_keccak_ctx* st, unsigned strength,
                       const uint8_t* name, size_t name_size,
                       const uint8_t* custom, size_t custom_size) {
    uint8_t enc[9], zero[168] = {0};
    const size_t rate = strength == 128 ? 168u : 136u;
    size_t total, n, padding;
    int err;
    if (strength != 128 && strength != 256) return CRYPT_INVALID_ARG;
    if (hasher_keccak_init(st, rate) != 0) return CRYPT_INVALID_ARG;
    if (name_size == 0 && custom_size == 0) return CRYPT_OK;
    n = left_encode((uint64_t)rate, enc);
    if ((err = absorb(st, enc, n)) != CRYPT_OK) return err;
    total = n;
    if ((err = absorb_encode_string(st, name, name_size, &total)) != CRYPT_OK) return err;
    if ((err = absorb_encode_string(st, custom, custom_size, &total)) != CRYPT_OK) return err;
    padding = (rate - (total % rate)) % rate;
    return absorb(st, zero, padding);
}

static int cshake_finish(hasher_keccak_ctx* st, int plain_shake, uint8_t* output, size_t output_size) {
    return hasher_keccak_final(st, plain_shake ? 0x1fu : 0x04u, output, output_size) == 0 ? CRYPT_OK : CRYPT_INVALID_ARG;
}

int hasher_cshake(unsigned strength, const uint8_t* input, size_t input_size,
                  const uint8_t* function_name, size_t function_name_size,
                  const uint8_t* custom, size_t custom_size,
                  uint8_t* output, size_t output_size) {
    hasher_keccak_ctx st;
    int err;
    const int plain = function_name_size == 0 && custom_size == 0;
    if ((err = cshake_init(&st, strength, function_name, function_name_size,
                           custom, custom_size)) != CRYPT_OK) return err;
    if ((err = absorb(&st, input, input_size)) != CRYPT_OK) return err;
    return cshake_finish(&st, plain, output, output_size);
}

int hasher_tuplehash(unsigned strength, int xof,
                     const uint8_t* input, size_t input_size,
                     const uint8_t* custom, size_t custom_size,
                     uint8_t* output, size_t output_size) {
    static const uint8_t name[] = "TupleHash";
    hasher_keccak_ctx st;
    uint8_t enc[9];
    size_t total = 0, n;
    int err;
    if (output_size > UINT64_MAX / 8) return CRYPT_INVALID_ARG;
    if ((err = cshake_init(&st, strength, name, sizeof(name) - 1,
                           custom, custom_size)) != CRYPT_OK) return err;
    if ((err = absorb_encode_string(&st, input, input_size, &total)) != CRYPT_OK) return err;
    (void)total;
    n = right_encode(xof ? 0 : (uint64_t)output_size * 8, enc);
    if ((err = absorb(&st, enc, n)) != CRYPT_OK) return err;
    return cshake_finish(&st, 0, output, output_size);
}

int hasher_parallelhash(unsigned strength, int xof,
                        const uint8_t* input, size_t input_size,
                        const uint8_t* custom, size_t custom_size,
                        size_t block_size, uint8_t* output, size_t output_size) {
    static const uint8_t name[] = "ParallelHash";
    hasher_keccak_ctx outer;
    uint8_t enc[9], digest[64];
    const size_t inner_size = strength == 128 ? 32u : 64u;
    size_t offset = 0, n;
    uint64_t blocks = 0;
    int err;
    if (block_size == 0 || block_size > UINT64_MAX || output_size > UINT64_MAX / 8)
        return CRYPT_INVALID_ARG;
    if ((err = cshake_init(&outer, strength, name, sizeof(name) - 1,
                           custom, custom_size)) != CRYPT_OK) return err;
    n = left_encode((uint64_t)block_size, enc);
    if ((err = absorb(&outer, enc, n)) != CRYPT_OK) return err;
    while (offset < input_size) {
        size_t chunk = input_size - offset;
        if (chunk > block_size) chunk = block_size;
        if ((err = hasher_cshake(strength, input + offset, chunk, NULL, 0, NULL, 0,
                                 digest, inner_size)) != CRYPT_OK) return err;
        if ((err = absorb(&outer, digest, inner_size)) != CRYPT_OK) return err;
        offset += chunk;
        ++blocks;
    }
    n = right_encode(blocks, enc);
    if ((err = absorb(&outer, enc, n)) != CRYPT_OK) return err;
    n = right_encode(xof ? 0 : (uint64_t)output_size * 8, enc);
    if ((err = absorb(&outer, enc, n)) != CRYPT_OK) return err;
    return cshake_finish(&outer, 0, output, output_size);
}

int hasher_kmac(unsigned strength, int xof,
                const uint8_t* key, size_t key_size,
                const uint8_t* input, size_t input_size,
                const uint8_t* custom, size_t custom_size,
                uint8_t* output, size_t output_size) {
    static const uint8_t name[] = "KMAC";
    hasher_keccak_ctx st;
    uint8_t enc[9], zero[168] = {0};
    size_t rate = strength == 128 ? 168u : 136u;
    size_t total, n, padding;
    int err;
    if (!key || output_size > UINT64_MAX / 8) return CRYPT_INVALID_ARG;
    if ((err = cshake_init(&st, strength, name, sizeof(name) - 1, custom, custom_size)) != CRYPT_OK) return err;
    n = left_encode((uint64_t)rate, enc);
    if ((err = absorb(&st, enc, n)) != CRYPT_OK) return err;
    total = n;
    if ((err = absorb_encode_string(&st, key, key_size, &total)) != CRYPT_OK) return err;
    padding = (rate - (total % rate)) % rate;
    if ((err = absorb(&st, zero, padding)) != CRYPT_OK) return err;
    if ((err = absorb(&st, input, input_size)) != CRYPT_OK) return err;
    n = right_encode(xof ? 0 : (uint64_t)output_size * 8, enc);
    if ((err = absorb(&st, enc, n)) != CRYPT_OK) return err;
    return cshake_finish(&st, 0, output, output_size);
}

enum { PREP_CSHAKE=1, PREP_KMAC=2, PREP_TUPLE=3, PREP_PARALLEL=4 };
typedef struct sp800185_internal {
    hasher_keccak_ctx base;
    unsigned kind;
    unsigned strength;
    int xof;
    int plain;
    size_t block_size;
} sp800185_internal;
_Static_assert(sizeof(sp800185_internal) <= sizeof(((hasher_sp800185_prepared*)0)->opaque), "SP800-185 prepared storage is too small");

int hasher_sp800185_prepare(const hasher_algorithm* a,const hasher_params* p,hasher_sp800185_prepared* prepared) {
    static const uint8_t kmac_name[]="KMAC",tuple_name[]="TupleHash",parallel_name[]="ParallelHash";
    static const uint8_t empty_key=0;
    sp800185_internal* h;uint8_t enc[9],zero[168]={0};size_t rate,total,n,padding;int err;
    if(!a||!p||!prepared)return CRYPT_INVALID_ARG;memset(prepared,0,sizeof(*prepared));h=(sp800185_internal*)prepared->opaque;
    h->strength=(a->id==HASHER_CSHAKE128||a->id==HASHER_KMAC128||a->id==HASHER_KMACXOF128||a->id==HASHER_TUPLEHASH128||a->id==HASHER_TUPLEHASHXOF128||a->id==HASHER_PARALLELHASH128||a->id==HASHER_PARALLELHASHXOF128)?128:256;
    switch(a->id){
    case HASHER_CSHAKE128:case HASHER_CSHAKE256:h->kind=PREP_CSHAKE;h->plain=p->function_name_size==0&&p->customization_size==0;if((err=cshake_init(&h->base,h->strength,p->function_name,p->function_name_size,p->customization,p->customization_size))!=CRYPT_OK)return err;break;
    case HASHER_KMAC128:case HASHER_KMAC256:case HASHER_KMACXOF128:case HASHER_KMACXOF256:
        if(!p->key&&p->key_size)return CRYPT_INVALID_ARG;h->kind=PREP_KMAC;h->xof=a->id==HASHER_KMACXOF128||a->id==HASHER_KMACXOF256;
        if((err=cshake_init(&h->base,h->strength,kmac_name,sizeof(kmac_name)-1,p->customization,p->customization_size))!=CRYPT_OK)return err;
        rate=h->strength==128?168u:136u;n=left_encode((uint64_t)rate,enc);if((err=absorb(&h->base,enc,n))!=CRYPT_OK)return err;total=n;
        if((err=absorb_encode_string(&h->base,p->key?p->key:&empty_key,p->key_size,&total))!=CRYPT_OK)return err;padding=(rate-total%rate)%rate;if((err=absorb(&h->base,zero,padding))!=CRYPT_OK)return err;break;
    case HASHER_TUPLEHASH128:case HASHER_TUPLEHASH256:case HASHER_TUPLEHASHXOF128:case HASHER_TUPLEHASHXOF256:
        h->kind=PREP_TUPLE;h->xof=a->id==HASHER_TUPLEHASHXOF128||a->id==HASHER_TUPLEHASHXOF256;
        if((err=cshake_init(&h->base,h->strength,tuple_name,sizeof(tuple_name)-1,p->customization,p->customization_size))!=CRYPT_OK)return err;break;
    case HASHER_PARALLELHASH128:case HASHER_PARALLELHASH256:case HASHER_PARALLELHASHXOF128:case HASHER_PARALLELHASHXOF256:
        h->kind=PREP_PARALLEL;h->xof=a->id==HASHER_PARALLELHASHXOF128||a->id==HASHER_PARALLELHASHXOF256;h->block_size=p->parallel_block_size?p->parallel_block_size:1024;
        if((err=cshake_init(&h->base,h->strength,parallel_name,sizeof(parallel_name)-1,p->customization,p->customization_size))!=CRYPT_OK)return err;n=left_encode((uint64_t)h->block_size,enc);if((err=absorb(&h->base,enc,n))!=CRYPT_OK)return err;break;
    default:return CRYPT_INVALID_ARG;
    }
    return CRYPT_OK;
}

int hasher_sp800185_compute_prepared(const hasher_sp800185_prepared* prepared,const uint8_t* input,size_t input_size,uint8_t* output,size_t output_size) {
    const sp800185_internal* h;hasher_keccak_ctx st;uint8_t enc[9],digest[64],batch_digest[4][64];size_t n,total=0,offset=0,inner_size,rate;uint64_t blocks=0;int err;
    if(!prepared||(!input&&input_size)||(!output&&output_size)||output_size>UINT64_MAX/8)return CRYPT_INVALID_ARG;h=(const sp800185_internal*)prepared->opaque;if(!h->kind)return CRYPT_INVALID_ARG;st=h->base;
    if(h->kind==PREP_CSHAKE){if((err=absorb(&st,input,input_size))!=CRYPT_OK)return err;return cshake_finish(&st,h->plain,output,output_size);}
    if(h->kind==PREP_KMAC){if((err=absorb(&st,input,input_size))!=CRYPT_OK)return err;n=right_encode(h->xof?0:(uint64_t)output_size*8,enc);if((err=absorb(&st,enc,n))!=CRYPT_OK)return err;return cshake_finish(&st,0,output,output_size);}
    if(h->kind==PREP_TUPLE){if((err=absorb_encode_string(&st,input,input_size,&total))!=CRYPT_OK)return err;n=right_encode(h->xof?0:(uint64_t)output_size*8,enc);if((err=absorb(&st,enc,n))!=CRYPT_OK)return err;return cshake_finish(&st,0,output,output_size);}
    inner_size=h->strength==128?32u:64u;rate=h->strength==128?168u:136u;
    while(h->block_size<rate&&h->block_size<=SIZE_MAX/4&&input_size-offset>=h->block_size*4){
        const uint8_t* batch_input[4]={input+offset,input+offset+h->block_size,input+offset+h->block_size*2,input+offset+h->block_size*3};
        const size_t batch_size[4]={h->block_size,h->block_size,h->block_size,h->block_size};
        uint8_t* batch_output[4]={batch_digest[0],batch_digest[1],batch_digest[2],batch_digest[3]};size_t i;
        if(hasher_keccak_hash4(rate,0x1f,batch_input,batch_size,batch_output,inner_size)!=0)break;
        for(i=0;i<4;++i)if((err=absorb(&st,batch_digest[i],inner_size))!=CRYPT_OK)return err;offset+=h->block_size*4;blocks+=4;
    }
    while(offset<input_size){size_t chunk=input_size-offset;if(chunk>h->block_size)chunk=h->block_size;if((err=hasher_cshake(h->strength,input+offset,chunk,NULL,0,NULL,0,digest,inner_size))!=CRYPT_OK)return err;if((err=absorb(&st,digest,inner_size))!=CRYPT_OK)return err;offset+=chunk;++blocks;}
    n=right_encode(blocks,enc);if((err=absorb(&st,enc,n))!=CRYPT_OK)return err;n=right_encode(h->xof?0:(uint64_t)output_size*8,enc);if((err=absorb(&st,enc,n))!=CRYPT_OK)return err;return cshake_finish(&st,0,output,output_size);
}
