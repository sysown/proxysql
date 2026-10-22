from pathlib import Path
import subprocess,tempfile
here=Path(__file__).resolve().parent
root=here/'source' if (here/'source').is_dir() else here.parent/'results/result-buffer-reuse/source'
def function(text,name):
 a=text.index(name);a=text.rfind('\n',0,a)+1;b=text.index('{',a);depth=1;i=b+1
 while depth:
  depth+=(text[i]=='{')-(text[i]=='}');i+=1
 return text[a:i]
header='''#include <cstdlib>
#include <cstring>
#include <vector>
#include <cassert>
#include <cstdio>
#include <random>
struct Packet { unsigned char* data; unsigned size; };
struct Queue { std::vector<Packet> p; void add(void* x,unsigned n){p.push_back({(unsigned char*)x,n});} };
'''
code=header
for ns,file in [('Old','PgSQL_Protocol.before.cpp'),('New','PgSQL_Protocol.cpp')]:
 s=(root/file).read_text()
 code+='namespace '+ns+' {\n'+'''class PgSQL_Query_Result {
 public:
 unsigned char* buffer=(unsigned char*)malloc(PGSQL_RESULTSET_BUFLEN);
 unsigned buffer_used=0; Queue PSarrayOUT;
 unsigned buffer_available_capacity() const{return PGSQL_RESULTSET_BUFLEN-buffer_used;}
 void buffer_to_PSarrayOut(); unsigned char* buffer_reserve_space(unsigned size);
 void drain(){for(auto p:PSarrayOUT.p)free(p.data);PSarrayOUT.p.clear();}
 ~PgSQL_Query_Result(){drain();free(buffer);}
};
'''
 for name in ['void PgSQL_Query_Result::buffer_to_PSarrayOut()', 'unsigned char* PgSQL_Query_Result::buffer_reserve_space(unsigned int size)']:code+=function(s,name)+'\n'
 code+='}\n'
code+='''int main(){
 std::mt19937 rng(42);Old::PgSQL_Query_Result a;New::PgSQL_Query_Result b;
 unsigned cases=0;
 for(unsigned n=0;n<=PGSQL_RESULTSET_BUFLEN;n++) {
  auto oldbuffer=b.buffer;auto x=a.buffer_reserve_space(n);auto y=b.buffer_reserve_space(n);
  assert(x&&y);for(unsigned i=0;i<n;i++)x[i]=y[i]=(unsigned char)(i+n);
  a.buffer_to_PSarrayOut();b.buffer_to_PSarrayOut();assert(!a.buffer_used&&!b.buffer_used);
  assert(a.PSarrayOUT.p.size()==b.PSarrayOUT.p.size());
  if(n<PGSQL_RESULTSET_BUFLEN/2)assert(b.buffer==oldbuffer);
  for(unsigned i=0;i<a.PSarrayOUT.p.size();i++){
   auto p=a.PSarrayOUT.p[i],q=b.PSarrayOUT.p[i];assert(p.size==q.size);assert(!memcmp(p.data,q.data,p.size));
   assert(q.data!=b.buffer);
  }
  // Leave several queued results outstanding to verify independent ownership.
  if(n%5==0){a.drain();b.drain();}
  cases++;
 }
 a.drain();b.drain();
 for(unsigned k=0;k<2000;k++){
  unsigned n=rng()%(PGSQL_RESULTSET_BUFLEN+2);
  auto x=a.buffer_reserve_space(n),y=b.buffer_reserve_space(n);assert(bool(x)==bool(y));
  if(x)for(unsigned i=0;i<n;i++)x[i]=y[i]=(unsigned char)(i+k);
  if(k%3==0){a.buffer_to_PSarrayOut();b.buffer_to_PSarrayOut();}
  assert(a.PSarrayOUT.p.size()==b.PSarrayOUT.p.size());
  for(unsigned i=0;i<a.PSarrayOUT.p.size();i++){
   auto p=a.PSarrayOUT.p[i],q=b.PSarrayOUT.p[i];assert(p.size==q.size);assert(!memcmp(p.data,q.data,p.size));
  }
  if(k%5==0){a.drain();b.drain();}
  cases++;
 }
 printf("PASS buffer=%u: %u cases; payload equivalence, small-buffer retention, queued-packet independence, reserve/flush boundaries\\n",PGSQL_RESULTSET_BUFLEN,cases);
}
'''
with tempfile.TemporaryDirectory(prefix='pgsql-result-buffer-') as td:
 p=Path(td);(p/'check.cpp').write_text(code)
 for size in [16384,8192]:
  subprocess.run(['g++','-std=c++17','-O1','-g','-fsanitize=address,undefined','-fno-omit-frame-pointer',f'-DPGSQL_RESULTSET_BUFLEN={size}',str(p/'check.cpp'),'-o',str(p/'check')],check=True)
  subprocess.run([str(p/'check')],check=True)
