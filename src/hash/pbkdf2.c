#include "pbkdf2.h"
#include <string.h>
int hasher_pbkdf2_derive_prepared(hasher_kdf_prf_segments_fn prf,void* user,
 size_t digest_size,const uint8_t* salt,size_t salt_size,uint64_t iterations,
 uint8_t* output,size_t output_size){uint8_t u[64],accumulator[64],counter[4];uint64_t block_index=1;size_t produced=0,i;
 if(!prf||!iterations||!digest_size||digest_size>sizeof(u)||output_size>(uint64_t)digest_size*UINT32_MAX)return -1;
 while(produced<output_size){const uint8_t* first[2]={salt,counter};const size_t first_size[2]={salt_size,4};uint64_t round;size_t take;
  counter[0]=(uint8_t)(block_index>>24);counter[1]=(uint8_t)(block_index>>16);counter[2]=(uint8_t)(block_index>>8);counter[3]=(uint8_t)block_index;
  if(prf(user,first,first_size,2,u))return -1;memcpy(accumulator,u,digest_size);
  for(round=1;round<iterations;++round){const uint8_t* one[1]={u};const size_t one_size[1]={digest_size};if(prf(user,one,one_size,1,u))return -1;for(i=0;i<digest_size;++i)accumulator[i]^=u[i];}
  take=output_size-produced;if(take>digest_size)take=digest_size;memcpy(output+produced,accumulator,take);produced+=take;++block_index;}return 0;}
