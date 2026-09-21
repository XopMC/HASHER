#include "pbkdf2.h"
#include <stdlib.h>
#include <string.h>

int hasher_pbkdf2_direct_derive(hasher_kdf_hash_segments_fn hash,void* user,
 size_t digest_size,const uint8_t* password,size_t password_size,
 const uint8_t* salt,size_t salt_size,uint64_t iterations,
 uint8_t* output,size_t output_size){
 uint8_t u[64],accumulator[64],counter[4],local[1156];uint8_t* message=local;uint32_t block_index=1;size_t produced=0,i,suffix_capacity,message_capacity;
 if(!hash||!iterations||!digest_size||digest_size>sizeof(u)||(!password&&password_size)||
    (!salt&&salt_size)||(!output&&output_size)||output_size>(uint64_t)digest_size*UINT32_MAX)return -1;
 if(salt_size>SIZE_MAX-4)return -1;suffix_capacity=salt_size+4;if(suffix_capacity<digest_size)suffix_capacity=digest_size;
 if(password_size>SIZE_MAX-suffix_capacity)return -1;message_capacity=password_size+suffix_capacity;
 if(message_capacity>sizeof(local)){message=(uint8_t*)malloc(message_capacity);if(!message)return -1;}
 if(password_size)memcpy(message,password,password_size);
 while(produced<output_size){const uint8_t* one[1]={message};size_t one_size[1];uint64_t round;size_t take;
  counter[0]=(uint8_t)(block_index>>24);counter[1]=(uint8_t)(block_index>>16);counter[2]=(uint8_t)(block_index>>8);counter[3]=(uint8_t)block_index;
  if(salt_size)memcpy(message+password_size,salt,salt_size);
  memcpy(message+password_size+salt_size,counter,4);one_size[0]=password_size+salt_size+4;
  if(hash(user,one,one_size,1,u,digest_size))goto fail;memcpy(accumulator,u,digest_size);
  for(round=1;round<iterations;++round){memcpy(message+password_size,u,digest_size);one_size[0]=password_size+digest_size;
   if(hash(user,one,one_size,1,u,digest_size))goto fail;for(i=0;i<digest_size;++i)accumulator[i]^=u[i];}
  take=output_size-produced;if(take>digest_size)take=digest_size;memcpy(output+produced,accumulator,take);produced+=take;
  if(produced<output_size&&block_index==UINT32_MAX)goto fail;++block_index;}
 if(message!=local)free(message);return 0;
fail:if(message!=local)free(message);return -1;}

int hasher_pbkdf2_direct_derive_prepared(hasher_kdf_hash_suffix_fn hash,void* user,
 size_t digest_size,const uint8_t* salt,size_t salt_size,uint64_t iterations,
 uint8_t* output,size_t output_size){
 uint8_t u[64],accumulator[64],counter[4];uint32_t block_index=1;size_t produced=0,i;
 if(!hash||!iterations||!digest_size||digest_size>sizeof(u)||(!salt&&salt_size)||
    (!output&&output_size)||output_size>(uint64_t)digest_size*UINT32_MAX)return -1;
 while(produced<output_size){const uint8_t* first[2]={salt,counter};const size_t first_size[2]={salt_size,4};uint64_t round;size_t take;
  counter[0]=(uint8_t)(block_index>>24);counter[1]=(uint8_t)(block_index>>16);counter[2]=(uint8_t)(block_index>>8);counter[3]=(uint8_t)block_index;
  if(hash(user,first,first_size,2,u))return -1;memcpy(accumulator,u,digest_size);
  for(round=1;round<iterations;++round){const uint8_t* one[1]={u};const size_t one_size[1]={digest_size};
   if(hash(user,one,one_size,1,u))return -1;for(i=0;i<digest_size;++i)accumulator[i]^=u[i];}
  take=output_size-produced;if(take>digest_size)take=digest_size;memcpy(output+produced,accumulator,take);produced+=take;
  if(produced<output_size&&block_index==UINT32_MAX)return -1;++block_index;}
 return 0;}

int hasher_pbkdf2_derive_prepared(hasher_kdf_prf_segments_fn prf,void* user,
 size_t digest_size,const uint8_t* salt,size_t salt_size,uint64_t iterations,
 uint8_t* output,size_t output_size){uint8_t u[64],accumulator[64],counter[4];uint64_t block_index=1;size_t produced=0,i;
 if(!prf||!iterations||!digest_size||digest_size>sizeof(u)||output_size>(uint64_t)digest_size*UINT32_MAX)return -1;
 while(produced<output_size){const uint8_t* first[2]={salt,counter};const size_t first_size[2]={salt_size,4};uint64_t round;size_t take;
  counter[0]=(uint8_t)(block_index>>24);counter[1]=(uint8_t)(block_index>>16);counter[2]=(uint8_t)(block_index>>8);counter[3]=(uint8_t)block_index;
  if(prf(user,first,first_size,2,u))return -1;memcpy(accumulator,u,digest_size);
  for(round=1;round<iterations;++round){const uint8_t* one[1]={u};const size_t one_size[1]={digest_size};if(prf(user,one,one_size,1,u))return -1;for(i=0;i<digest_size;++i)accumulator[i]^=u[i];}
  take=output_size-produced;if(take>digest_size)take=digest_size;memcpy(output+produced,accumulator,take);produced+=take;++block_index;}return 0;}
