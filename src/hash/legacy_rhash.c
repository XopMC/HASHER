#include "legacy_rhash.h"
#include "md4.h"
#include "md5.h"
#include "ripemd-160.h"
#include <string.h>

#define HASHER_RHASH_HMAC_MD5_MAGIC UINT64_C(0x35444d484d485352)
typedef struct rhash_hmac_md5_prepared { uint64_t magic; md5_ctx inner, outer; } rhash_hmac_md5_prepared;
#define HASHER_RHASH_PREFIX_MAGIC UINT64_C(0x5849464552504852)
typedef struct rhash_prefix_prepared {uint64_t magic;int ripemd160;union{md5_ctx md5;ripemd160_ctx rmd;}state;} rhash_prefix_prepared;

void hasher_rhash_md4(const uint8_t* input, size_t size, uint8_t output[16]) {
    md4_ctx ctx;
    rhash_md4_init(&ctx);
    rhash_md4_update(&ctx, input, size);
    rhash_md4_final(&ctx, output);
}

void hasher_rhash_md5(const uint8_t* input, size_t size, uint8_t output[16]) {
    md5_ctx ctx;
    rhash_md5_init(&ctx);
    rhash_md5_update(&ctx, input, size);
    rhash_md5_final(&ctx, output);
}

void hasher_rhash_rmd160(const uint8_t* input, size_t size, uint8_t output[20]) {
    ripemd160_ctx ctx;
    rhash_ripemd160_init(&ctx);
    rhash_ripemd160_update(&ctx, input, size);
    rhash_ripemd160_final(&ctx, output);
}

int hasher_rhash_prefix_prepare(void* storage,size_t storage_size,int ripemd160,
 const uint8_t* prefix,size_t prefix_size){
 rhash_prefix_prepared* p=(rhash_prefix_prepared*)storage;
 if(!p||storage_size<sizeof(*p)||(!prefix&&prefix_size))return -1;memset(p,0,sizeof(*p));p->magic=HASHER_RHASH_PREFIX_MAGIC;p->ripemd160=!!ripemd160;
 if(p->ripemd160){rhash_ripemd160_init(&p->state.rmd);if(prefix_size)rhash_ripemd160_update(&p->state.rmd,prefix,prefix_size);}
 else{rhash_md5_init(&p->state.md5);if(prefix_size)rhash_md5_update(&p->state.md5,prefix,prefix_size);}return 0;
}
int hasher_rhash_prefix_compute(const void* storage,const uint8_t* const* suffix,
 const size_t* size,size_t count,uint8_t* output){
 const rhash_prefix_prepared* p=(const rhash_prefix_prepared*)storage;size_t i;if(!p||p->magic!=HASHER_RHASH_PREFIX_MAGIC||!output)return -1;
 if(p->ripemd160){ripemd160_ctx c=p->state.rmd;for(i=0;i<count;++i)if(size[i])rhash_ripemd160_update(&c,suffix[i],size[i]);rhash_ripemd160_final(&c,output);}
 else{md5_ctx c=p->state.md5;for(i=0;i<count;++i)if(size[i])rhash_md5_update(&c,suffix[i],size[i]);rhash_md5_final(&c,output);}return 0;
}

int hasher_rhash_hmac_md5_prepare(void* storage,size_t storage_size,const uint8_t* key,size_t key_size){
    rhash_hmac_md5_prepared* p=(rhash_hmac_md5_prepared*)storage;uint8_t block[64]={0},digest[16],ipad[64],opad[64];size_t i;
    if(!storage||storage_size<sizeof(*p)||(!key&&key_size))return -1;
    if(key_size>64){hasher_rhash_md5(key,key_size,digest);memcpy(block,digest,16);}else if(key_size)memcpy(block,key,key_size);
    for(i=0;i<64;++i){ipad[i]=(uint8_t)(block[i]^0x36u);opad[i]=(uint8_t)(block[i]^0x5cu);}
    memset(p,0,sizeof(*p));p->magic=HASHER_RHASH_HMAC_MD5_MAGIC;rhash_md5_init(&p->inner);rhash_md5_update(&p->inner,ipad,64);rhash_md5_init(&p->outer);rhash_md5_update(&p->outer,opad,64);return 0;
}
int hasher_rhash_hmac_md5_is_prepared(const void* storage){const rhash_hmac_md5_prepared* p=(const rhash_hmac_md5_prepared*)storage;return p&&p->magic==HASHER_RHASH_HMAC_MD5_MAGIC;}
int hasher_rhash_hmac_md5_compute(const void* storage,const uint8_t* const* data,const size_t* size,size_t count,uint8_t output[16]){
    const rhash_hmac_md5_prepared* p=(const rhash_hmac_md5_prepared*)storage;md5_ctx inner,outer;uint8_t digest[16];size_t i;if(!hasher_rhash_hmac_md5_is_prepared(storage)||!output)return -1;inner=p->inner;outer=p->outer;
    for(i=0;i<count;++i)if(size[i])rhash_md5_update(&inner,data[i],size[i]);rhash_md5_final(&inner,digest);rhash_md5_update(&outer,digest,16);rhash_md5_final(&outer,output);return 0;
}
