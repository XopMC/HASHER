#include "hasher/hash_api.h"
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <vector>

int main(int argc,char** argv){
  const char* name=argc>1?argv[1]:"sha256";size_t size=argc>2?(size_t)std::strtoull(argv[2],nullptr,10):1024;
  size_t rounds=argc>3?(size_t)std::strtoull(argv[3],nullptr,10):1000000;
  if(hasher_library_init())return 2;const hasher_algorithm* a=hasher_find_algorithm(name);if(!a||size>1048576||!rounds)return 1;
  hasher_params p{};const unsigned char key[]="0123456789abcdef";p.key=key;p.key_size=16;p.output_size=a->default_output_size;p.parallel_block_size=1024;
  std::vector<unsigned char> in(size),out(hasher_output_size(a,&p));for(size_t i=0;i<size;++i)in[i]=(unsigned char)(i*131u+17u);
  volatile unsigned sink=0;auto begin=std::chrono::steady_clock::now();for(size_t i=0;i<rounds;++i){if(hasher_compute(a,&p,in.data(),in.size(),out.data(),out.size()))return 3;sink^=out[i%out.size()];}
  double seconds=std::chrono::duration<double>(std::chrono::steady_clock::now()-begin).count();double mib=(double)size*(double)rounds/(1024.0*1024.0)/seconds;
  char line[512];int n=std::snprintf(line,sizeof(line),"%s,%s,%zu,%zu,%.6f,%.3f,%.0f,%u\n",a->name,hasher_selected_backend(a->id),size,rounds,seconds,mib,(double)rounds/seconds,(unsigned)sink);
  if(n>0)std::fwrite(line,1,(size_t)n,stdout);return 0;
}
