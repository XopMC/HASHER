#include "hasher/hash_api.h"
#include <cstdio>
#include <cstring>
#include <initializer_list>

static int hex_digit(char c) {
    if(c>='0'&&c<='9')return c-'0'; if(c>='a'&&c<='f')return c-'a'+10;
    if(c>='A'&&c<='F')return c-'A'+10; return -1;
}
static int from_hex(const char* s, unsigned char* out) {
    int n=0; while (*s) { int a=hex_digit(s[0]),b=hex_digit(s[1]);if(a<0||b<0)return -1;
        out[n++]=(unsigned char)((a<<4)|b);s+=2;}return n;
}
static int check_data(const char* name,const unsigned char* input,size_t input_size,
                      const hasher_params* params,const char* expected) {
    const hasher_algorithm* a=hasher_find_algorithm(name); hasher_params empty{};
    const hasher_params* p=params?params:&empty;
    unsigned char got[128],want[128];size_t n=hasher_output_size(a,p);
    int wn=from_hex(expected,want);int e=hasher_compute(a,p,input,input_size,got,n);
    if(e||wn!=(int)n||std::memcmp(got,want,n)){std::fprintf(stderr,"FAIL %s\n",name);return 1;} return 0;
}
static int check(const char* name,const char* expected){return check_data(name,(const unsigned char*)"abc",3,nullptr,expected);}
static int smoke_all(void){
    size_t count=0;const hasher_algorithm* all=hasher_algorithms(&count);unsigned char out[128];
    const unsigned char key[]="0123456789abcdef";hasher_params p{};p.key=key;p.key_size=16;p.output_size=32;p.parallel_block_size=8;
    for(size_t i=0;i<count;++i){hasher_params q=p;if(all[i].id>=HASHER_PBKDF_MD5&&all[i].id<=HASHER_PBKDF_KECCAK512)q.output_size=all[i].default_output_size;size_t n=hasher_output_size(&all[i],&q);if(n>sizeof(out)||hasher_compute(&all[i],&q,(const unsigned char*)"abc",3,out,n)){
        std::fprintf(stderr,"SMOKE FAIL %s\n",all[i].name);return 1;}}
    return count==HASHER_ALGORITHM_COUNT?0:1;
}
static int check_prepared_hmac(void){
    unsigned char key[1024],msg[1024],a[64],b[64];for(size_t i=0;i<sizeof(key);++i)key[i]=(unsigned char)(i*17u+3u);for(size_t i=0;i<sizeof(msg);++i)msg[i]=(unsigned char)(i*29u+7u);
    const size_t keys[]={0,1,64,65,128,129,1024},messages[]={0,1,55,56,63,64,65,127,128,129,1024};
    for(const char* name:{"hmac-md5","hmac-sha1","hmac-sha224","hmac-sha256","hmac-sha384","hmac-sha512"}){const hasher_algorithm* alg=hasher_find_algorithm(name);size_t out=alg->fixed_output_size;
        for(size_t kn:keys){hasher_params p{};p.key=key;p.key_size=kn;hasher_hmac_prepared prepared{};if(hasher_hmac_prepare(alg,&p,&prepared))return 1;
            for(size_t mn:messages){if(hasher_compute(alg,&p,msg,mn,a,out)||hasher_hmac_compute_prepared(&prepared,msg,mn,b,out)||std::memcmp(a,b,out)){std::fprintf(stderr,"PREPARED FAIL %s\n",name);return 1;}}}}
    return 0;
}
static int check_prepared_sp800185(void){
    const char* names[]={"cshake128","cshake256","kmac128","kmac256","kmacxof128","kmacxof256","tuplehash128","tuplehash256","tuplehashxof128","tuplehashxof256","parallelhash128","parallelhash256","parallelhashxof128","parallelhashxof256"};
    unsigned char key[64],msg[1024],a[128],b[128];for(size_t i=0;i<sizeof(key);++i)key[i]=(unsigned char)(i+0x40);for(size_t i=0;i<sizeof(msg);++i)msg[i]=(unsigned char)(i*31u+9u);
    const unsigned char custom[]="prepared-test";const size_t messages[]={0,1,63,64,65,135,136,137,167,168,169,1024};
    for(const char* name:names){const hasher_algorithm* alg=hasher_find_algorithm(name);hasher_params p{};p.key=key;p.key_size=sizeof(key);p.customization=custom;p.customization_size=sizeof(custom)-1;p.parallel_block_size=8;p.output_size=alg->default_output_size;
        hasher_sp800185_prepared prepared{};if(hasher_sp800185_prepare(alg,&p,&prepared))return 1;size_t out=hasher_output_size(alg,&p);
        for(size_t mn:messages){if(hasher_compute(alg,&p,msg,mn,a,out)||hasher_sp800185_compute_prepared(&prepared,msg,mn,b,out)||std::memcmp(a,b,out)){std::fprintf(stderr,"PREPARED FAIL %s\n",name);return 1;}}}
    return 0;
}
static int check_cshake_empty_equals_shake(void){
    const unsigned char msg[137]={0};const size_t sizes[]={1,16,31,32,33,64,127};
    unsigned char a[127],b[127];
    for(const char* strength:{"128","256"}){
        char shake[16],cshake[16];std::snprintf(shake,sizeof(shake),"shake%s",strength);std::snprintf(cshake,sizeof(cshake),"cshake%s",strength);
        const hasher_algorithm* sa=hasher_find_algorithm(shake);const hasher_algorithm* ca=hasher_find_algorithm(cshake);
        for(size_t n:sizes){hasher_params p{};p.output_size=n;
            if(hasher_compute(sa,&p,msg,sizeof(msg),a,n)||hasher_compute(ca,&p,msg,sizeof(msg),b,n)||std::memcmp(a,b,n)){
                std::fprintf(stderr,"cSHAKE empty N/S mismatch %s/%zu\n",strength,n);return 1;}}
    }
    return 0;
}
static int check_arm_keccak_batch4(void){
    const hasher_algorithm* a=hasher_find_algorithm("sha3-256");
    if(!a||std::strncmp(hasher_selected_backend(a->id),"arm-sha3-c",10)!=0)return 0;
    unsigned char messages[4][135],batch[4][32],single[4][32];
    const unsigned char* input[4]={messages[0],messages[1],messages[2],messages[3]};
    unsigned char* output[4]={batch[0],batch[1],batch[2],batch[3]};
    const size_t sizes[4]={0,1,64,135};hasher_params p{};
    for(size_t i=0;i<4;++i)for(size_t j=0;j<sizeof(messages[i]);++j)messages[i][j]=(unsigned char)(i*47u+j*131u+9u);
    if(hasher_compute_batch4(a,&p,input,sizes,output,sizeof(batch[0]))!=0){std::fprintf(stderr,"ARM KECCAK BATCH unavailable\n");return 1;}
    for(size_t i=0;i<4;++i)if(hasher_compute(a,&p,input[i],sizes[i],single[i],sizeof(single[i]))||std::memcmp(batch[i],single[i],sizeof(single[i]))){
        std::fprintf(stderr,"ARM KECCAK BATCH mismatch %zu\n",i);return 1;}
    return 0;
}
int main(){int f=0;if(hasher_library_init())return 2;
 f+=check("sha1","a9993e364706816aba3e25717850c26c9cd0d89d");
 f+=check("sha224","23097d223405d8228642a477bda255b32aadbce4bda0b3f7e36c9da7");
 f+=check("sha256","ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
 f+=check("sha384","cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7");
 f+=check("sha512","ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f");
 f+=check("sha512/224","4634270f707b6a54daae7530460842e20e37ed265ceee9a43e8924aa");
 f+=check("sha512/256","53048e2681941ef99b2e29b76b4c7dabe4c2d0c634fc6d46e0e2f13107e7af23");
 f+=check("sha3-224","e642824c3f8cf24ad09234ee7d3c766fc9a3a5168d0c94ad73b46fdf");
 f+=check("sha3-256","3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532");
 f+=check("sha3-384","ec01498288516fc926459f58e2c6ad8df9b473cb0fc08c2596da7cf0e49be4b298d88cea927ac7f539f1edf228376d25");
 f+=check("sha3-512","b751850b1a57168a5693cd924b6b096e08f621827444f70d884f5d0240d2712e10e116e9192af3c91a7ec57647e3934057340b4cf408d5a56592f8274eec53f0");
 f+=check("keccak-224","c30411768506ebe1c2871b1ee2e87d38df342317300a9b97a95ec6a8");
 f+=check("keccak-256","4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45");
 f+=check("keccak-384","f7df1165f033337be098e7d288ad6a2f74409d7a60b49c36642218de161b1f99f8c681e4afaf31a34db29fb763e3c28e");
 f+=check("keccak-512","18587dc2ea106b9a1563e32b3312421ca164c7f1f07bc922a9c83d77cea3a1e5d0c69910739025372dc14ac9642629379540c17e2a65b19d77aa511a9d00bb96");
 f+=check("md2","da853b0d3f88d99b30283a69e6ded6bb");
 f+=check("md4","a448017aaf21d8525fc10ae87aa6729d");
 f+=check("md5","900150983cd24fb0d6963f7d28e17f72");
 f+=check("rmd-128","c14a12199c66e4ba84636b0f69144c77");
 f+=check("rmd-160","8eb208f7e05d987a9b044a8e98c6b087f15a0bfc");
 f+=check("rmd-256","afbd6e228b9d8cbbcef5ca2d03e6dba10ac0bc7dcbe4680e1e42d2e975459b65");
 f+=check("rmd-320","de4c01b3054f8930a79d09ae738e92301e5a17085beffdc1b8d116713e74f82fa942d64cdbc4682d");
 f+=check("blake2b","ba80a53f981c4d0d6a2797b69f12f6e94c212f14685ac4b74b12bb6fdbffa2d17d87c5392aab792dc252d5de4533cc9518d38aa8dbf1925ab92386edd4009923");
 f+=check("blake2s","508c5e8c327c14e2e1a72ba34eeb452f37458b209ed63a294d999b4c86675982");
 f+=check("blake3","6437b3ac38465133ffb63b75273a8db548c558465d79db03fd359c6cd5bd9d85");
 f+=check("shake128","5881092dd818bf5cf8a3ddb793fbcba74097d5c526a6d35f97b83351940f2cc8");
 f+=check("shake256","483366601360a8771c6863080cc4114d8db44530f8f1e1ee4f94ea37e78b5739d5a15bef186a5386c75744c0527e1faa9f8726e462a12a4feb06bd8801e751e4");
 f+=check("sm3","66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0");
 f+=check("xxh128","06b05ab6733a618578af5f94892f3950");
 f+=check_data("xxh128",(const unsigned char*)"",0,nullptr,"99aa06d3014798d86001c324468d497f");
 {const unsigned char x[]={0,1,2,3},custom[]="Email Signature";hasher_params p{};p.customization=custom;p.customization_size=15;p.output_size=32;
  f+=check_data("cshake128",x,sizeof(x),&p,"c1c36925b6409a04f1b504fcbca9d82b4017277cb5ed2b2065fc1d3814d5aaf5");}
 {const unsigned char x[]={0,1,2,3},custom[]="Email Signature";hasher_params p{};p.customization=custom;p.customization_size=15;p.output_size=64;
  f+=check_data("cshake256",x,sizeof(x),&p,"d008828e2b80ac9d2218ffee1d070c48b8e4c87bff32c9699d5b6896eee0edd164020e2be0560858d9c00c037e34a96937c561a74c412bb4c746469527281c8c");}
 {unsigned char key[32];for(unsigned i=0;i<32;++i)key[i]=(unsigned char)(0x40+i);const unsigned char x[]={0,1,2,3};const unsigned char tag[]="My Tagged Application";
  hasher_params p{};p.key=key;p.key_size=sizeof(key);p.output_size=32;
  f+=check_data("kmac128",x,sizeof(x),&p,"e5780b0d3ea6f7d3a429c5706aa43a00fadbd7d49628839e3187243f456ee14e");
  f+=check_data("kmacxof128",x,sizeof(x),&p,"cd83740bbd92ccc8cf032b1481a0f4460e7ca9dd12b08a0c4031178bacd6ec35");
  p.customization=tag;p.customization_size=21;p.output_size=64;
  f+=check_data("kmac256",x,sizeof(x),&p,"20c570c31346f703c9ac36c61c03cb64c3970d0cfc787e9b79599d273a68d2f7f69d4cc3de9d104a351689f27cf6f5951f0103f33f4f24871024d9c27773a8dd");
  f+=check_data("kmacxof256",x,sizeof(x),&p,"1755133f1534752aad0748f2c706fb5c784512cab835cd15676b16c0c6647fa96faa7af634a0bf8ff6df39374fa00fad9a39e322a7c92065a64eb1fb0801eb2b");}
 {const unsigned char key[]="0123456789abcdef",custom[]="custom";hasher_params p{};p.key=key;p.key_size=16;p.customization=custom;p.customization_size=6;p.output_size=32;
  f+=check_data("kmac128",(const unsigned char*)"abc",3,&p,"d36173a4855dcab670d4aafb69f9d38b2a5f9899779753e41064497c0a6e2d58");}
 {hasher_params p{};p.output_size=32;f+=check_data("tuplehash128",(const unsigned char*)"abc",3,&p,"873195cadfea6bc6a71cdd903da87afb49fd232d71db817c3abcad48ad8a7898");}
 {hasher_params p{};p.output_size=32;p.parallel_block_size=8;f+=check_data("parallelhash128",(const unsigned char*)"abc",3,&p,"10e25248a5b5ef8cfbbcb0f9d14c7e1786d0a3a2304197fbd1351617dc7e74a8");}
 {const unsigned char x[]={0,1,2,3,4,5,6,7,0x10,0x11,0x12,0x13,0x14,0x15,0x16,0x17,0x20,0x21,0x22,0x23,0x24,0x25,0x26,0x27};
  hasher_params p{};p.parallel_block_size=8;p.output_size=32;
  f+=check_data("parallelhash128",x,sizeof(x),&p,"ba8dc1d1d979331d3f813603c67f72609ab5e44b94a0b8f9af46514454a2b4f5");
  f+=check_data("parallelhashxof128",x,sizeof(x),&p,"fe47d661e49ffe5b7d999922c062356750caf552985b8e8ce6667f2727c3c8d3");
  p.output_size=64;
  f+=check_data("parallelhash256",x,sizeof(x),&p,"bc1ef124da34495e948ead207dd9842235da432d2bbc54b4c110e64c451105531b7f2a3e0ce055c02805e7c2de1fb746af97a1dd01f43b824e31b87612410429");
  f+=check_data("parallelhashxof256",x,sizeof(x),&p,"c10a052722614684144d28474850b410757e3cba87651ba167a5cbddff7f466675fbf84bcae7378ac444be681d729499afca667fb879348bfdda427863c82f1c");}
 {const unsigned char key[]="key";hasher_params p{};p.key=key;p.key_size=3;
  f+=check_data("hmac-md5",(const unsigned char*)"abc",3,&p,"d2fe98063f876b03193afb49b4979591");
  f+=check_data("hmac-sha1",(const unsigned char*)"abc",3,&p,"4fd0b215276ef12f2b3e4c8ecac2811498b656fc");
  f+=check_data("hmac-sha224",(const unsigned char*)"abc",3,&p,"f524670b7e34f31467de0aa96593861cf65117d414fb2d86158d760e");
  f+=check_data("hmac-sha256",(const unsigned char*)"abc",3,&p,"9c196e32dc0175f86f4b1cb89289d6619de6bee699e4c378e68309ed97a1a6ab");
  f+=check_data("hmac-sha384",(const unsigned char*)"abc",3,&p,"30ddb9c8f347cffbfb44e519d814f074cf4047a55d6f563324f1c6a33920e5edfb2a34bac60bdc96cd33a95623d7d638");
  f+=check_data("hmac-sha512",(const unsigned char*)"abc",3,&p,"3926a207c8c42b0c41792cbd3e1a1aaaf5f7a25704f62dfc939c4987dd7ce060009c5bb1c2447355b3216f10b537e9afa7b64a4e5391b0d631172d07939e087a");}
 {hasher_params p{};
  f+=check_data("hmac-sha256",(const unsigned char*)"abc",3,&p,"fd7adb152c05ef80dccf50a1fa4c05d5a3ec6da95575fc312ae7c5d091836351");}
 {const unsigned char salt[]="salt";hasher_params p{};p.salt=salt;p.salt_size=4;p.kdf_iterations=2;
  f+=check_data("pbkdf-md5",(const unsigned char*)"password",8,&p,"5b6dad229782c6547d1b20d5668eb834");
  f+=check_data("pbkdf-sha1",(const unsigned char*)"password",8,&p,"47e97e39e2b32b15eb9278e53f7bfca57f8e6b2c");
  f+=check_data("pbkdf-sha224",(const unsigned char*)"password",8,&p,"a3a102fae8f409305769897a349cb538d742633c91b980d6615dfd03");
  f+=check_data("pbkdf-sha256",(const unsigned char*)"password",8,&p,"a6b9d96cc74d52749372886896349c07e2137fe8788b496d76f6d56e49a9bd52");
  f+=check_data("pbkdf-sha384",(const unsigned char*)"password",8,&p,"9f491e14c1c201ac0eb48928370b6efb9371d0a026b82becafa547399072d5ef2917fb46b3d9ee049ddc5fc53d8f1c43");
  f+=check_data("pbkdf-sha512",(const unsigned char*)"password",8,&p,"e79c79d0608a4b278ece52f6d0b59768a4f08bddc7708d23b7ac0e95a2fdcc2fb1c4638a2d15c30eb3b19ad23bd3539b91a74ff896897d0da1b6d8cd0b109470");
  f+=check_data("pbkdf-rmd160",(const unsigned char*)"password",8,&p,"ddf4eb0c202623aca8c40897cf4f987c0e1bbb85");
  f+=check_data("pbkdf-keccak256",(const unsigned char*)"password",8,&p,"3e182714af4c63d444a89cb71afcbc87aa4aa6898def19a1a5884499e0e93be3");
  f+=check_data("pbkdf-keccak512",(const unsigned char*)"password",8,&p,"0e81fff3a4cabbb7e24d12d4017b7d4850c4e8ee385e87b1ab6e041e20847174704e438f0d0d80f6f25f64c731fa9cfdd2d9b953127a87e52f939eb6a042da24");
  f+=check_data("pbkdf2-md5",(const unsigned char*)"password",8,&p,"4750c1b18f304e41a55ba1ff157a62cefc3d5e1070d970dd943490a881f167cd");
  f+=check_data("pbkdf2-sha1",(const unsigned char*)"password",8,&p,"9daaf515c937a9ecf7952dd2d35b44d28305b8a80a5d2ae1115c7b4abb1bc602");
  f+=check_data("pbkdf2-sha224",(const unsigned char*)"password",8,&p,"20ec85d05aedaecd1033657c9c0cd65168639bc0c19375144061ab7982e31f02");
  f+=check_data("pbkdf2-sha256",(const unsigned char*)"password",8,&p,"eb81bb537eb16b0b73d0ad1ed9fb8727a6138a8c7c4b69496028e39d2ea0375a");
  f+=check_data("pbkdf2-sha384",(const unsigned char*)"password",8,&p,"826464287c69591594676ecee79a0c883117ae312a677d6a14f35176be6b5e3d");
  f+=check_data("pbkdf2-sha512",(const unsigned char*)"password",8,&p,"7568e7424be4bffd24a9ac11005b452029d8435b4290ae981568d36586080831");
  f+=check_data("pbkdf2-rmd160",(const unsigned char*)"password",8,&p,"cb55caf5448d5e6f1b8faa97cac6733e94667318257373aba293eecbed4340cd");
  f+=check_data("pbkdf2-keccak256",(const unsigned char*)"password",8,&p,"8532501f786cb3e232726005ecc2bc527e3f0191e56098eacd4681dcdaa844e9");
  f+=check_data("pbkdf2-keccak512",(const unsigned char*)"password",8,&p,"71053ad5225f13698250299abaca5c553a019b7c370683e9fa7716587cf0e1fc");
  p.output_size=32;
  f+=check_data("pbkdf2-hmac-md5",(const unsigned char*)"password",8,&p,"042407b552be345ad6eee2cf2f7ed01dd9662d8f0c6950eaec7124aa0c82279e");
  f+=check_data("pbkdf2-hmac-sha1",(const unsigned char*)"password",8,&p,"ea6c014dc72d6f8ccd1ed92ace1d41f0d8de8957cae93136266537a8d7bf4b76");
  f+=check_data("pbkdf2-hmac-sha224",(const unsigned char*)"password",8,&p,"93200ffa96c5776d38fa10abdf8f5bfc0054b9718513df472d2331d2d1e66a3f");
  f+=check_data("pbkdf2-hmac-sha256",(const unsigned char*)"password",8,&p,"ae4d0c95af6b46d32d0adff928f06dd02a303f8ef3c251dfd6e2d85a95474c43");
  f+=check_data("pbkdf2-hmac-sha384",(const unsigned char*)"password",8,&p,"54f775c6d790f21930459162fc535dbf04a939185127016a04176a0730c6f1f4");
  f+=check_data("pbkdf2-hmac-sha512",(const unsigned char*)"password",8,&p,"e1d9c16aa681708a45f5c7c4e215ceb66e011a2e9f0040713f18aefdb866d53c");}
 {const unsigned char salt[]="salt";hasher_params p{};p.salt=salt;p.salt_size=4;p.output_size=32;
  f+=check_data("pbkdf2-hmac-sha256",(const unsigned char*)"password",8,&p,"5ec02b91a4b59c6f59dd5fbe4ca649ece4fa8568cdb8ba36cf41426e8805522b");}
 {const unsigned char salt[]="saltsalt";hasher_params p{};p.salt=salt;p.salt_size=8;p.output_size=32;p.kdf_iterations=1;
  f+=check_data("evpkdf-md5",(const unsigned char*)"password",8,&p,"fdbdf3419fff98bdb0241390f62a9db35f4aba29d77566377997314ebfc709f2");
  f+=check_data("evpkdf-sha1",(const unsigned char*)"password",8,&p,"cab86dd6261710891e8cb56ee3625691a75df344f0bff4c12cf3596fc00b39c7");
  f+=check_data("evpkdf-sha224",(const unsigned char*)"password",8,&p,"f251913e30ff7e49e9a805c713e3c7176f42b6d5d0b337662bfd9187c3099139");
  f+=check_data("evpkdf-sha256",(const unsigned char*)"password",8,&p,"0c8cde87480244c4d1bbd7401f70b7aebedf5a4453d01a7665db51aaf4d7dd72");
  f+=check_data("evpkdf-sha384",(const unsigned char*)"password",8,&p,"a03622583be880c4428d90e6af25ea7f826e670359d714e166d31f79e070da37");
  f+=check_data("evpkdf-sha512",(const unsigned char*)"password",8,&p,"f59c47563e18a26c2aa8589829c22313130bc7665b9587d744673828ca9b82f1");
  f+=check_data("evpkdf-rmd160",(const unsigned char*)"password",8,&p,"3438f2e8b1d4d639ce440b69a8d46ea33fbb95eb9d574713d87183513472535f");
  f+=check_data("evpkdf-keccak256",(const unsigned char*)"password",8,&p,"0b2b3ec7e67c16c207807b150471571c8d7eee985c8503f6a52249ee010cacb6");
  f+=check_data("evpkdf-keccak512",(const unsigned char*)"password",8,&p,"e5a1aa7293a456bb8092457a86d66fefc977ade939eaa37424a2bf5b177ffb0e");}
 {const unsigned char salt[]="saltsalt";hasher_params p{};p.salt=salt;p.salt_size=8;p.output_size=48;p.kdf_iterations=1;
  f+=check_data("evpkdf-md5",(const unsigned char*)"password",8,&p,"fdbdf3419fff98bdb0241390f62a9db35f4aba29d77566377997314ebfc709f20b5ca7b1081f94b1ac12e3c8ba87d05a");}
 f+=smoke_all();
 f+=check_arm_keccak_batch4();
 f+=check_prepared_hmac();
 f+=check_prepared_sp800185();
 f+=check_cshake_empty_equals_shake();
 if(!f)std::fwrite("ok\n",1,3,stdout);return f?1:0;}
