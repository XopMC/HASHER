#include "pbkdf.h"
#include <string.h>
int hasher_pbkdf1_derive(hasher_kdf_hash_segments_fn hash,void* user,size_t digest_size,
 const uint8_t* password,size_t password_size,const uint8_t* salt,size_t salt_size,
 uint64_t iterations,uint8_t* output,size_t output_size){uint8_t digest[64];uint64_t round;
 const uint8_t* first[2]={password,salt};const size_t first_size[2]={password_size,salt_size};
 if(!hash||!iterations||output_size>digest_size||digest_size>sizeof(digest))return -1;
 if(hash(user,first,first_size,2,digest,digest_size))return -1;
 for(round=1;round<iterations;++round){const uint8_t* one[1]={digest};const size_t one_size[1]={digest_size};if(hash(user,one,one_size,1,digest,digest_size))return -1;}
 memcpy(output,digest,output_size);return 0;}
