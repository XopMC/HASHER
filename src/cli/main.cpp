#if defined(__linux__) && !defined(_GNU_SOURCE)
#define _GNU_SOURCE
#endif
#include "hasher/hash_api.h"
#include "hasher/cpu_features.h"

#include <algorithm>
#include <atomic>
#include <cerrno>
#include <csignal>
#include <condition_variable>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <mutex>
#include <string>
#include <thread>
#include <vector>
#if defined(__aarch64__) || defined(_M_ARM64)
#include <arm_neon.h>
#endif

#ifdef _WIN32
#include <fcntl.h>
#include <io.h>
#endif
#ifdef __linux__
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
#endif

static const char kHelp[] = R"HELP([!] ================== HASHER FULL HELP ==================

[!] HASHER BY @XopMC

[!] [!] QUICK START [!]
[!] -h / -help                    Show this help and exit.
[!] -i FILE                       Input file, repeatable. STDIN when absent.
[!] -hex                          Fast permissive hexadecimal decoding.
[!] -iter LIST                    Iterations, example: 1,3-5.
[!]
[!] Default: SHA-256, iteration 1, auto threads, STDIN when -i is absent.
[!]
[!] [!] INPUT / OUTPUT [!] [!]
[!] UTF-8 by default; bytes are hashed unchanged. -hex never rejects a line.
[!] Odd -hex lines are padded with zero on the left: 123 -> 0123.
[!] First 1024 bytes per line are used; LF/CRLF is removed.
[!] Repeat -i for multiple files. Without -i, input comes from STDIN.
[!] Each lowercase hex digest is printed on its own line with \n.
[!] Order: input line -> selected algorithm -> requested iteration.
[!]
[!] [!] HASH ALGORITHMS [!] [!]
[!] -sha1                                            SHA-1, 20-byte digest.
[!] -sha224 -sha256                                  SHA-2, 28/32-byte digest.
[!] -sha384 -sha512                                  SHA-2, 48/64-byte digest.
[!] -sha512/224 -sha512/256                          SHA-512 truncated variants, 28/32 bytes.
[!] -sha3-224 -sha3-256 -sha3-384 -sha3-512          FIPS 202 SHA-3.
[!] -keccak-224 -keccak-256 -keccak-384 -keccak-512  Original Keccak.
[!] -shake128 -shake256                              FIPS 202 XOF; default 32/64 output bytes.
[!] -cshake128 -cshake256                            SP 800-185 customizable XOF; 32/64 bytes.
[!] -md2 -md4 -md5                                   Legacy 16-byte digests.
[!] -rmd-128 -rmd-160 -rmd-256 -rmd-320              RIPEMD, 16/20/32/40 bytes.
[!] -blake2b -blake2s                                BLAKE2, default 64/32 bytes.
[!] -blake3                                          BLAKE3 XOF, default 32 bytes.
[!] -xxh128                                          XXH3 128-bit, 16 bytes; optional seed.
[!] -sm3                                             SM3, 32-byte digest.
[!] -kmac128 -kmac256                                SP 800-185 KMAC; default 32/64 bytes.
[!] -kmacxof128 -kmacxof256                          SP 800-185 KMAC XOF; default 32/64 bytes.
[!] -tuplehash128 -tuplehash256                      One-element TupleHash; default 32/64 bytes.
[!] -tuplehashxof128 -tuplehashxof256                TupleHash XOF; default 32/64 bytes.
[!] -parallelhash128 -parallelhash256                ParallelHash; default 32/64 bytes.
[!] -parallelhashxof128 -parallelhashxof256          ParallelHash XOF; 32/64 bytes.
[!]
[!] -hmac-md5 -hmac-sha1 -hmac-sha224 -hmac-sha256 
[!] -hmac-sha384 -hmac-sha512                        HMAC with the selected digest; key optional.
[!]
[!] -pbkdf-md5 -pbkdf-sha1 -pbkdf-sha224
[!] -pbkdf-sha256 -pbkdf-sha384
[!] -pbkdf-sha512 -pbkdf-rmd160
[!] -pbkdf-keccak256 -pbkdf-keccak512                Direct PBKDF hash chain.
[!]
[!] -pbkdf2-hmac-md5 -pbkdf2-hmac-sha1
[!] -pbkdf2-hmac-sha224 -pbkdf2-hmac-sha256
[!] -pbkdf2-hmac-sha384 -pbkdf2-hmac-sha512          Standard PBKDF2-HMAC.
[!]
[!] -evpkdf-md5 -evpkdf-sha1 -evpkdf-sha224
[!] -evpkdf-sha256 -evpkdf-sha384
[!] -evpkdf-sha512 -evpkdf-rmd160
[!] -evpkdf-keccak256 -evpkdf-keccak512              OpenSSL/CryptoJS-compatible EvpKDF.
[!]
[!] [!] XOF / KEYED PARAMETERS [!] [!]
[!] -key TEXT / -key-hex HEX       HMAC/KMAC key (default: empty, 0 bytes).
[!] -func TEXT / -func-hex HEX     cSHAKE function name (default: empty).
[!] -custom TEXT / -custom-hex HEX Customization string (default: empty).
[!] -len BYTES                     XOF/BLAKE output size, max 1048576.
[!] -bsize BYTES                   ParallelHash block size, default 1024.
[!] -seed HEX                      XXH128 seed, default 0.
[!] -salt TEXT / -salt-hex HEX     KDF salt (default: empty).
[!] -kiter N                       KDF rounds; PBKDF2 default 10000, others 1.
[!]
[!] PBKDF is the direct hash chain (standard PBKDF1 for MD5/SHA1; extended for others).
[!] XOF 128 variants output 32 bytes by default; 256 variants output 64.
[!] Empty -func and -custom make cSHAKE equal to SHAKE.
[!]
[!] [!] ITERATIONS [!] [!]
[!] digest1=H(input); digestN=H(binary digestN-1).
[!] Only requested iterations are printed; the chain is calculated once.
[!] -iter repeats the whole selected algorithm; -kiter controls rounds inside a KDF.
[!]
[!] Examples:
[!] HASHER.exe -sha256 -sha512 -rmd256 -i file.txt
[!] type file.txt | HASHER.exe -sha256
[!] ./HASHER -shake128 -len 64 -iter 1,3-5
[!] ./HASHER -hmac-sha256 -key-hex 001122 -i file.txt
[!] ./HASHER -cshake128 -custom App -len 48 -i first -i second
[!] ./HASHER -parallelhash256 -bsize 256 -len 64 -i data.txt
[!] ./HASHER -pbkdf2-hmac-sha256 -salt saltsalt -kiter 10000 -len 32 -i passwords.txt
[!]
[!] Compatibility aliases: -keccak256, -rmd160, -rmd256, -rmd260, -turplehash*.
[!] Legacy aliases: -key-utf8, -function-name-utf8/-function-name-hex,
[!] -custom-utf8, -out-len, -block-size and -seed-hex remain supported.
[!] Repeating an algorithm does not repeat output; its first position is kept.
[!] Explicit algorithm options disable the implicit default SHA-256.
[!]
[!] Limitations:
[!] Lines are limited to 1024 input bytes; the remaining bytes are discarded.
[!] -len and -bsize accept 1..1048576 bytes; -t accepts 0..8.
[!] Output has no names or separators: exactly one hexadecimal digest per line.
[!]
[!] Errors:
[!] Exit codes: 0 success/help, 1 CLI/input, 2 I/O, 3 internal/runtime.
[!] I/O failures are reported; malformed -hex lines never stop the stream.
[!]
[!] [!] OPTIONAL [!] [!]
[!] -t N                          CPU threads: 0=auto (default), 1-8 explicit.
[!] =================================================================
)HELP";

static void write_text(FILE* f, const std::string& s) { if (!s.empty()) std::fwrite(s.data(),1,s.size(),f); }
static int fail(const std::string& s, int code=1) { write_text(stderr,"[!] "+s+" [!]\n"); return code; }

struct Config {
    std::vector<const hasher_algorithm*> algorithms;
    std::vector<std::string> files;
    std::vector<uint64_t> iterations{1};
    std::vector<uint8_t> key, function_name, custom, salt;
    hasher_params params{};
    hasher_hmac_prepared hmac[HASHER_ALGORITHM_COUNT]{};
    bool hmac_ready[HASHER_ALGORITHM_COUNT]{};
    hasher_sp800185_prepared sp800185[HASHER_ALGORITHM_COUNT]{};
    bool sp800185_ready[HASHER_ALGORITHM_COUNT]{};
    bool hex=false, key_set=false, salt_set=false, out_len_set=false, threads_set=false;
    unsigned threads=0;
};

static uint8_t kHexDecode[256];
static uint16_t kHexPairs[256];
static void init_hex_decode(){static const char h[]="0123456789abcdef";std::memset(kHexDecode,0xff,sizeof(kHexDecode));for(unsigned i=0;i<10;++i)kHexDecode['0'+i]=(uint8_t)i;for(unsigned i=0;i<6;++i){kHexDecode['a'+i]=(uint8_t)(10+i);kHexDecode['A'+i]=(uint8_t)(10+i);}for(unsigned i=0;i<256;++i)kHexPairs[i]=(uint16_t)((uint8_t)h[i>>4]|((uint16_t)(uint8_t)h[i&15]<<8));}
static bool decode_hex(const uint8_t* in,size_t n,std::vector<uint8_t>& out) {
    if(n&1) return false; out.resize(n/2);
    for(size_t i=0;i<n;i+=2){uint8_t a=kHexDecode[in[i]],b=kHexDecode[in[i+1]];if((a|b)==0xff)return false;out[i/2]=(uint8_t)((a<<4)|b);}return true;
}
static bool parse_u64(const char* s,int base,uint64_t& v) {
    if(!s||!*s||*s=='-')return false; char* e=nullptr; errno=0; unsigned long long x=std::strtoull(s,&e,base);
    if(errno||!e||*e)return false;v=(uint64_t)x;return true;
}
static bool parse_iterations(const char* s,std::vector<uint64_t>& out) {
    out.clear(); const char* p=s;
    while(*p){char* e=nullptr;errno=0;unsigned long long a=std::strtoull(p,&e,10);if(errno||e==p||a==0)return false;
        unsigned long long b=a;if(*e=='-'){p=e+1;errno=0;b=std::strtoull(p,&e,10);if(errno||e==p||b<a)return false;}
        for(unsigned long long x=a;;++x){out.push_back((uint64_t)x);if(x==b)break;if(x==~0ull)return false;}
        if(*e==0)break;if(*e!=',')return false;p=e+1;if(!*p)return false;}
    std::sort(out.begin(),out.end());out.erase(std::unique(out.begin(),out.end()),out.end());return !out.empty();
}
static bool add_algorithm(Config& c,const hasher_algorithm* a){for(auto* x:c.algorithms)if(x->id==a->id)return true;c.algorithms.push_back(a);return true;}

static int parse_args(int argc,char** argv,Config& c) {
    for(int i=1;i<argc;++i){const char* a=argv[i];
        if(!std::strcmp(a,"-h")||!std::strcmp(a,"-help")){std::fwrite(kHelp,1,sizeof(kHelp)-1,stdout);return 10;}
        if(!std::strcmp(a,"-i")){if(++i>=argc)return fail("Missing file after -i");c.files.emplace_back(argv[i]);continue;}
        if(!std::strcmp(a,"-hex")){c.hex=true;continue;}
        if(!std::strcmp(a,"-iter")){if(++i>=argc||!parse_iterations(argv[i],c.iterations))return fail("Invalid -iter list");continue;}
        if(!std::strcmp(a,"-t")||!std::strcmp(a,"-threads")){uint64_t v;if(++i>=argc||!parse_u64(argv[i],10,v)||v>8)return fail("-t must be 0..8");c.threads=(unsigned)v;c.threads_set=true;continue;}
        auto bytes_arg=[&](std::vector<uint8_t>& dst,bool hex)->bool{if(++i>=argc)return false;const auto* p=(const uint8_t*)argv[i];size_t n=std::strlen(argv[i]);if(hex)return decode_hex(p,n,dst);dst.assign(p,p+n);return true;};
        if(!std::strcmp(a,"-key")||!std::strcmp(a,"-key-utf8")||!std::strcmp(a,"-key-hex")){if(c.key_set)return fail("Specify exactly one key option");if(!bytes_arg(c.key,std::strstr(a,"-hex")!=nullptr))return fail("Invalid key");c.key_set=true;continue;}
        if(!std::strcmp(a,"-func")||!std::strcmp(a,"-func-hex")||!std::strcmp(a,"-function-name-utf8")||!std::strcmp(a,"-function-name-hex")){if(!bytes_arg(c.function_name,std::strstr(a,"-hex")!=nullptr))return fail("Invalid function name");continue;}
        if(!std::strcmp(a,"-custom")||!std::strcmp(a,"-custom-utf8")||!std::strcmp(a,"-custom-hex")){if(!bytes_arg(c.custom,std::strstr(a,"-hex")!=nullptr))return fail("Invalid customization");continue;}
        if(!std::strcmp(a,"-salt")||!std::strcmp(a,"-salt-hex")){if(c.salt_set)return fail("Specify one salt option");if(!bytes_arg(c.salt,std::strstr(a,"-hex")!=nullptr))return fail("Invalid salt");c.salt_set=true;continue;}
        if(!std::strcmp(a,"-kiter")){uint64_t v;if(++i>=argc||!parse_u64(argv[i],10,v)||!v)return fail("-kiter must be positive");c.params.kdf_iterations=v;continue;}
        if(!std::strcmp(a,"-len")||!std::strcmp(a,"-out-len")){uint64_t v;if(++i>=argc||!parse_u64(argv[i],10,v)||v<1||v>1048576)return fail("-len must be 1..1048576");c.params.output_size=(size_t)v;c.out_len_set=true;continue;}
        if(!std::strcmp(a,"-bsize")||!std::strcmp(a,"-block-size")){uint64_t v;if(++i>=argc||!parse_u64(argv[i],10,v)||v<1||v>1048576)return fail("-bsize must be 1..1048576");c.params.parallel_block_size=(size_t)v;continue;}
        if(!std::strcmp(a,"-seed")||!std::strcmp(a,"-seed-hex")){uint64_t v;if(++i>=argc||!parse_u64(argv[i],16,v))return fail("Invalid -seed");c.params.seed=v;continue;}
        if(!std::strncmp(a,"-snake",6)||!std::strncmp(a,"-csnake",7))return fail("Unknown option; use -shake128/-shake256 or -cshake128/-cshake256");
        if(const hasher_algorithm* h=hasher_find_algorithm(a)){add_algorithm(c,h);continue;}
        return fail(std::string("Unknown option: ")+a);
    }
    if(c.algorithms.empty())add_algorithm(c,hasher_find_algorithm("sha256"));
    static const uint8_t empty=0;
    c.params.key=c.key.empty()?&empty:c.key.data();c.params.key_size=c.key.size();
    c.params.function_name=c.function_name.empty()?nullptr:c.function_name.data();c.params.function_name_size=c.function_name.size();
    c.params.customization=c.custom.empty()?nullptr:c.custom.data();c.params.customization_size=c.custom.size();
    c.params.salt=c.salt.empty()?nullptr:c.salt.data();c.params.salt_size=c.salt.size();
    if(!c.params.parallel_block_size)c.params.parallel_block_size=1024;
    {bool has_kdf=false;for(auto* h:c.algorithms)has_kdf=has_kdf||(h->flags&HASHER_KDF)!=0;
     if(!has_kdf&&(c.salt_set||c.params.kdf_iterations))return fail("-salt and -kiter require a KDF algorithm");}
    for(auto* h:c.algorithms){
        if(c.out_len_set&&(h->flags&HASHER_FIXED_OUTPUT))return fail(std::string("-out-len is not valid for -")+h->name);
        if(h->id>=HASHER_PBKDF_MD5&&h->id<=HASHER_PBKDF_KECCAK512&&hasher_output_size(h,&c.params)>h->default_output_size)
            return fail(std::string("-len exceeds digest size for -")+h->name);
        if(h->id>=HASHER_HMAC_MD5&&h->id<=HASHER_HMAC_SHA512){if(hasher_hmac_prepare(h,&c.params,&c.hmac[h->id]))return fail(std::string("Cannot prepare -")+h->name,3);c.hmac_ready[h->id]=true;}
        if((h->id>=HASHER_CSHAKE128&&h->id<=HASHER_CSHAKE256)||(h->id>=HASHER_KMAC128&&h->id<=HASHER_PARALLELHASHXOF256)){
            if(hasher_sp800185_prepare(h,&c.params,&c.sp800185[h->id]))return fail(std::string("Cannot prepare -")+h->name,3);c.sp800185_ready[h->id]=true;}
    }
    return 0;
}

class Reader {
    FILE* f_; std::vector<uint8_t> b_; size_t p_=0,n_=0; bool eof_=false;
public: explicit Reader(FILE* f):f_(f),b_(1u<<20){}
    bool line(uint8_t out[1024],size_t& len,bool& ioerr){len=0;bool any=false,discarded=false;ioerr=false;
        for(;;){if(p_==n_){n_=std::fread(b_.data(),1,b_.size(),f_);p_=0;if(!n_){eof_=true;if(std::ferror(f_))ioerr=true;return any;}}
            const uint8_t* begin=b_.data()+p_;const uint8_t* nl=(const uint8_t*)std::memchr(begin,'\n',n_-p_);size_t end=nl?(size_t)(nl-b_.data()):n_;size_t available=end-p_;any=any||available!=0;
            size_t room=1024-len;size_t take=std::min(room,available);if(take){std::memcpy(out+len,begin,take);len+=take;}if(take<available)discarded=true;p_=end;
            if(nl){++p_;if(!discarded&&len&&out[len-1]=='\r')--len;return true;}}}
};

struct Record{uint8_t data[1024];size_t len=0;std::string output,error;};
static void append_digest(std::string& result,const uint8_t* digest,size_t size){
    size_t old=result.size(),j=0;result.resize(old+size*2+1);char* destination=result.data()+old;
#if defined(__aarch64__) || defined(_M_ARM64)
    const uint8x16_t nine=vdupq_n_u8(9),zero=vdupq_n_u8((uint8_t)'0'),alpha=vdupq_n_u8(39),low_mask=vdupq_n_u8(15);
    for(;j+16<=size;j+=16){uint8x16_t bytes=vld1q_u8(digest+j),hi=vshrq_n_u8(bytes,4),lo=vandq_u8(bytes,low_mask);
        hi=vaddq_u8(vaddq_u8(hi,zero),vandq_u8(vcgtq_u8(hi,nine),alpha));lo=vaddq_u8(vaddq_u8(lo,zero),vandq_u8(vcgtq_u8(lo,nine),alpha));
        vst1q_u8((uint8_t*)destination+j*2,vzip1q_u8(hi,lo));vst1q_u8((uint8_t*)destination+j*2+16,vzip2q_u8(hi,lo));}
#endif
    for(;j<size;++j){uint16_t pair=kHexPairs[digest[j]];std::memcpy(destination+j*2,&pair,2);}destination[size*2]='\n';
}
static void decode_hex_line(const uint8_t* input,size_t size,uint8_t* output){
    size_t i=0,o=0;
    if(size&1){output[o++]=(uint8_t)((input[0]&15u)+(input[0]>>6)*9u);i=1;}
#if defined(__aarch64__) || defined(_M_ARM64)
    const uint8x16_t low_mask=vdupq_n_u8(0x0f),nine=vdupq_n_u8(9);
    for(;i+32<=size;i+=32){uint8x16_t c0=vld1q_u8(input+i),c1=vld1q_u8(input+i+16);
        uint8x16_t n0=vaddq_u8(vandq_u8(c0,low_mask),vmulq_u8(vshrq_n_u8(c0,6),nine));
        uint8x16_t n1=vaddq_u8(vandq_u8(c1,low_mask),vmulq_u8(vshrq_n_u8(c1,6),nine));
        uint8x16_t hi=vuzp1q_u8(n0,n1),lo=vuzp2q_u8(n0,n1);vst1q_u8(output+o,vorrq_u8(vshlq_n_u8(hi,4),lo));o+=16;}
#endif
    for(;i<size;i+=2){uint8_t a=(uint8_t)((input[i]&15u)+(input[i]>>6)*9u),b=(uint8_t)((input[i+1]&15u)+(input[i+1]>>6)*9u);output[o++]=(uint8_t)((a<<4)|b);}
}
static bool compute_batch4_lines(const Config& c,Record* records){
    uint8_t digest[4][200];uint8_t* output[4]={digest[0],digest[1],digest[2],digest[3]};
    const uint8_t* input[4]={records[0].data,records[1].data,records[2].data,records[3].data};
    size_t sizes[4]={records[0].len,records[1].len,records[2].len,records[3].len};
    if(c.hex||c.algorithms.size()!=1||c.iterations.size()!=1||c.iterations[0]!=1)return false;
    size_t outn=hasher_output_size(c.algorithms[0],&c.params);if(outn>sizeof(digest[0]))return false;
    if(hasher_compute_batch4(c.algorithms[0],&c.params,input,sizes,output,outn)!=0)return false;
    for(size_t i=0;i<4;++i)append_digest(records[i].output,digest[i],outn);return true;
}
static size_t batch4_rate(const Config& c){
    if(c.hex||c.algorithms.size()!=1||c.iterations.size()!=1||c.iterations[0]!=1)return 0;
    const hasher_algorithm* a=c.algorithms[0];if(!std::strstr(hasher_selected_backend(a->id),"+x4"))return 0;
    switch(a->id){
    case HASHER_SHA3_224: case HASHER_KECCAK_224:return 144;
    case HASHER_SHA3_256: case HASHER_KECCAK_256:return 136;
    case HASHER_SHA3_384: case HASHER_KECCAK_384:return 104;
    case HASHER_SHA3_512: case HASHER_KECCAK_512:return 72;
    case HASHER_SHAKE128:return c.params.output_size<=168?168:0;
    case HASHER_SHAKE256:return c.params.output_size<=136?136:0;
    case HASHER_CSHAKE128:return !c.params.function_name_size&&!c.params.customization_size&&c.params.output_size<=168?168:0;
    case HASHER_CSHAKE256:return !c.params.function_name_size&&!c.params.customization_size&&c.params.output_size<=136?136:0;
    default:return 0;}
}
static bool compute_line(const Config& c,const uint8_t* data,size_t size,std::string& result,std::string& error){
    uint8_t decoded[512];
    if(c.hex){decode_hex_line(data,size,decoded);data=decoded;size=(size+1)/2;}
    for(auto* a:c.algorithms){size_t outn=hasher_output_size(a,&c.params);uint8_t prev_local[128],next_local[128];std::vector<uint8_t> prev_heap,next_heap;
        uint8_t* prev=prev_local;uint8_t* next=next_local;if(outn>sizeof(prev_local)){prev_heap.resize(outn);next_heap.resize(outn);prev=prev_heap.data();next=next_heap.data();}size_t checkpoint=0;
        for(uint64_t it=1;it<=c.iterations.back();++it){const uint8_t* in=it==1?data:prev;size_t inlen=it==1?size:outn;
            int e=c.hmac_ready[a->id]?hasher_hmac_compute_prepared(&c.hmac[a->id],in,inlen,next,outn):
                  c.sp800185_ready[a->id]?hasher_sp800185_compute_prepared(&c.sp800185[a->id],in,inlen,next,outn):
                  hasher_compute(a,&c.params,in,inlen,next,outn);if(e){error=std::string(a->name)+": "+hasher_error_string(e);return false;}std::swap(prev,next);
            if(checkpoint<c.iterations.size()&&c.iterations[checkpoint]==it){append_digest(result,prev,outn);++checkpoint;}}
    }return true;
}

class Pool{
    const Config& c_;std::vector<std::thread>w_;std::mutex m_;std::condition_variable start_,done_;std::vector<Record>* batch_=nullptr;
    std::atomic<size_t> next_{0};size_t batch_count_=0,generation_=0,finished_=0;bool stop_=false;
    void worker(){size_t seen=0;for(;;){{std::unique_lock<std::mutex>l(m_);start_.wait(l,[&]{return stop_||generation_!=seen;});if(stop_)return;seen=generation_;}
        for(;;){size_t first=next_.fetch_add(16),end;if(!batch_||first>=batch_count_)break;end=std::min(first+16,batch_count_);
            size_t i=first;for(;i+4<=end;i+=4){if(!compute_batch4_lines(c_,batch_->data()+i))break;}
            for(;i<end;++i){auto&r=(*batch_)[i];compute_line(c_,r.data,r.len,r.output,r.error);}}
        {std::lock_guard<std::mutex>l(m_);if(++finished_==w_.size())done_.notify_one();}}}
public:Pool(const Config&c,unsigned n):c_(c){for(unsigned i=0;i<n;++i)w_.emplace_back([this]{worker();});}
    size_t size()const{return w_.size();}
    ~Pool(){{std::lock_guard<std::mutex>l(m_);stop_=true;++generation_;}start_.notify_all();for(auto&t:w_)t.join();}
    void start(std::vector<Record>&b,size_t count){{std::lock_guard<std::mutex>l(m_);batch_=&b;batch_count_=count;next_=0;finished_=0;++generation_;}start_.notify_all();}
    void wait_done(){std::unique_lock<std::mutex>l(m_);done_.wait(l,[&]{return finished_==w_.size();});batch_=nullptr;batch_count_=0;}
    void run(std::vector<Record>&b,size_t count){start(b,count);wait_done();}
};

class Writer{std::vector<char>b_;size_t n_=0;bool bad_=false;public:Writer():b_(1u<<20){}~Writer(){flush();}
 void flush(){if(n_&&!bad_){size_t w=std::fwrite(b_.data(),1,n_,stdout);bad_=w!=n_;n_=0;}}
 void put(const std::string&s){if(bad_)return;size_t p=0;while(p<s.size()){size_t room=b_.size()-n_;if(!room){flush();if(bad_)return;room=b_.size();}size_t x=std::min(room,s.size()-p);std::memcpy(b_.data()+n_,s.data()+p,x);n_+=x;p+=x;}}
 bool bad(){return bad_;}};

static int process_stream(FILE* f,const std::string& name,const Config& c,Pool*& pool,unsigned threads,Writer& writer,uint64_t& line_no){
    size_t per_line=0;for(auto* a:c.algorithms){size_t n=hasher_output_size(a,&c.params);if(n>(SIZE_MAX-1)/2){per_line=SIZE_MAX;break;}size_t unit=n*2+1;if(c.iterations.size()>SIZE_MAX/unit){per_line=SIZE_MAX;break;}size_t total=unit*c.iterations.size();if(per_line>SIZE_MAX-total){per_line=SIZE_MAX;break;}per_line+=total;}
    size_t capacity=per_line&&per_line!=(size_t)-1?(64u<<20)/per_line:4096;if(capacity<1)capacity=1;if(capacity>4096)capacity=4096;
    std::vector<Record>b[2];b[0].resize(capacity);b[1].resize(capacity);if(per_line!=SIZE_MAX)for(auto& batch:b)for(auto& record:batch)record.output.reserve(per_line);
    Reader r(f);auto read_batch=[&](std::vector<Record>& batch,size_t& used,bool& io,uint64_t& first){used=0;io=false;first=line_no+1;while(used<batch.size()){batch[used].output.clear();batch[used].error.clear();if(!r.line(batch[used].data,batch[used].len,io))break;++used;++line_no;}};
    auto write_batch=[&](std::vector<Record>& batch,size_t used,uint64_t first)->int{for(size_t i=0;i<used;++i){if(!batch[i].error.empty())return fail(name+":"+std::to_string(first+i)+": "+batch[i].error);writer.put(batch[i].output);if(writer.bad())return fail("Output write error",2);}return 0;};
    size_t used=0;bool io=false;uint64_t first=0;read_batch(b[0],used,io,first);if(!used)return io?fail("Read error: "+name,2):0;
    if(!c.threads_set&&threads>4){size_t rate=batch4_rate(c);const char* backend=c.algorithms.size()==1?hasher_selected_backend(c.algorithms[0]->id):"";
        if(rate&&std::strstr(backend,"avx")){size_t eligible=0;for(size_t i=0;i<used;++i)eligible+=b[0][i].len<rate;if(eligible*4>=used*3)threads=4;}}
    bool parallel=threads>1&&((c.threads_set&&c.threads>0)||used>=256);if(!parallel){for(;;){for(size_t i=0;i<used;++i)compute_line(c,b[0][i].data,b[0][i].len,b[0][i].output,b[0][i].error);int rc=write_batch(b[0],used,first);if(rc)return rc;if(io)return fail("Read error: "+name,2);read_batch(b[0],used,io,first);if(!used)return io?fail("Read error: "+name,2):0;}}
    if(pool&&pool->size()!=threads){delete pool;pool=nullptr;}if(!pool)pool=new Pool(c,threads);int current=0;pool->start(b[current],used);for(;;){int next=current^1;size_t next_used=0;bool next_io=false;uint64_t next_first=0;read_batch(b[next],next_used,next_io,next_first);pool->wait_done();if(next_used)pool->start(b[next],next_used);int rc=write_batch(b[current],used,first);if(rc){if(next_used)pool->wait_done();return rc;}if(!next_used)return next_io?fail("Read error: "+name,2):0;current=next;used=next_used;io=next_io;first=next_first;if(io){pool->wait_done();rc=write_batch(b[current],used,first);return rc?rc:fail("Read error: "+name,2);}}
}

static unsigned auto_threads(const Config& c,unsigned available){
    if(available<2)return 1;if(c.algorithms.size()>1||c.iterations.back()>1)return std::min(8u,available);
    hasher_algorithm_id id=c.algorithms[0]->id;if(id==HASHER_XXH128){
#if defined(__x86_64__) || defined(_M_X64)
        return std::min(2u,available);
#elif defined(__APPLE__) && defined(__aarch64__)
        return std::min(4u,available);
#else
        return 1;
#endif
    }
    if(id>=HASHER_EVP_KDF_MD5&&id<=HASHER_PBKDF2_SHA512){uint64_t rounds=c.params.kdf_iterations;
        if(!rounds&&id>=HASHER_PBKDF2_MD5)rounds=10000;if(rounds>=32)return std::min(8u,available);}
#if defined(__linux__) && defined(__aarch64__)
    return std::min(8u,available);
#elif defined(__APPLE__) && defined(__aarch64__)
    return std::min(id==HASHER_BLAKE3?4u:8u,available);
#elif defined(_WIN32) && defined(_M_X64)
    switch(id){
    case HASHER_HMAC_SHA1:case HASHER_HMAC_SHA256:
    case HASHER_PBKDF_SHA1:case HASHER_PBKDF_SHA224:case HASHER_PBKDF_SHA256:
    case HASHER_EVP_KDF_SHA256:return std::min(4u,available);
    default:break;}
    if((id>=HASHER_HMAC_MD5&&id<=HASHER_HMAC_SHA512)||(id>=HASHER_EVP_KDF_MD5&&id<=HASHER_PBKDF2_SHA512))return std::min(8u,available);
    {bool light=id==HASHER_BLAKE2S||id==HASHER_BLAKE3||id==HASHER_MD4||id==HASHER_SHA1||id==HASHER_SHA224||id==HASHER_SHA256;return std::min(light?4u:8u,available);}
#elif defined(__x86_64__)
    switch(id){
    case HASHER_HMAC_SHA1:case HASHER_HMAC_SHA256:
    case HASHER_PBKDF_SHA1:case HASHER_PBKDF_SHA224:case HASHER_PBKDF_SHA256:
    case HASHER_EVP_KDF_SHA256:return std::min(4u,available);
    default:break;}
    if((id>=HASHER_HMAC_MD5&&id<=HASHER_HMAC_SHA512)||(id>=HASHER_EVP_KDF_MD5&&id<=HASHER_PBKDF2_SHA512))return std::min(8u,available);
    bool light=id==HASHER_BLAKE2S||id==HASHER_BLAKE3||id==HASHER_MD4||
        id==HASHER_SHA1||id==HASHER_SHA224||id==HASHER_SHA256;
    return std::min(light?4u:8u,available);
#else
    bool heavy=id==HASHER_MD2||id==HASHER_KMAC128||id==HASHER_KMAC256||id==HASHER_KMACXOF128||id==HASHER_KMACXOF256||
        id==HASHER_TUPLEHASH128||id==HASHER_TUPLEHASH256||id==HASHER_TUPLEHASHXOF128||id==HASHER_TUPLEHASHXOF256||
        id==HASHER_PARALLELHASH128||id==HASHER_PARALLELHASH256||id==HASHER_PARALLELHASHXOF128||id==HASHER_PARALLELHASHXOF256||id==HASHER_HMAC_SHA512;
    return std::min(heavy?8u:4u,available);
#endif
}

int main(int argc,char**argv){
#ifndef _WIN32
    std::signal(SIGPIPE,SIG_IGN);
#endif
#ifdef _WIN32
    _setmode(_fileno(stdin),_O_BINARY);_setmode(_fileno(stdout),_O_BINARY);
#endif
#ifdef __linux__
    {struct stat st;if(fstat(STDIN_FILENO,&st)==0&&S_ISFIFO(st.st_mode))(void)fcntl(STDIN_FILENO,F_SETPIPE_SZ,1<<20);if(fstat(STDOUT_FILENO,&st)==0&&S_ISFIFO(st.st_mode))(void)fcntl(STDOUT_FILENO,F_SETPIPE_SZ,1<<20);}
#endif
    init_hex_decode();if(hasher_library_init())return fail("Hash library initialization failed",3);Config c;int pr=parse_args(argc,argv,c);if(pr==10)return 0;if(pr)return pr;
    unsigned hc=std::thread::hardware_concurrency();if(!hc)hc=1;unsigned threads=c.threads_set&&c.threads?c.threads:auto_threads(c,std::min(8u,hc));
    Pool* pool=nullptr;Writer writer;int rc=0;uint64_t line=0;
    if(c.files.empty())rc=process_stream(stdin,"STDIN",c,pool,threads,writer,line);else{bool stdin_used=false;for(auto&path:c.files){FILE*f=nullptr;if(path=="-"){if(stdin_used){rc=fail("STDIN specified more than once");break;}stdin_used=true;f=stdin;}else f=std::fopen(path.c_str(),"rb");if(!f){rc=fail("Cannot open: "+path,2);break;}line=0;rc=process_stream(f,path,c,pool,threads,writer,line);if(f!=stdin)std::fclose(f);if(rc)break;}}
    delete pool;writer.flush();if(writer.bad()&&!rc)rc=2;return rc;
}
