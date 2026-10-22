from pathlib import Path
import tempfile
_scratch=tempfile.TemporaryDirectory(prefix="pgsql-tokenizer-validation-")
_work=Path(_scratch.name)
_inputs=Path(__file__).resolve().parent/"tokenizer-inputs"
for _name in ["tokenizer-before.cpp","tokenizer-after.cpp","c_tokenizer.h"]:
 (_work/_name).write_bytes((_inputs/_name).read_bytes())
import subprocess,ctypes,re
class Tok(ctypes.Structure):
 _fields_=[('buffer',ctypes.c_char*128),('s_length',ctypes.c_int),('s',ctypes.c_void_p),('delimiters',ctypes.c_char_p),('current',ctypes.c_void_p),('next',ctypes.c_void_p),('ignore',ctypes.c_int)]
libs=[]
for v in ['before','after']:
 s=(_work/('tokenizer-'+v+'.cpp')).read_text().split('\nvoid c_split_2(')[0].replace('"c_tokenizer.h"','"'+str(_work/'c_tokenizer.h')+'"')
 start=s.index('static inline size_t tokenizer_strlen');end=s.index('\nvoid tokenizer(',start)
 s=s[:start]+'extern "C" { size_t test_forced_length; }\nstatic inline size_t tokenizer_strlen(const char*) { return test_forced_length; }\n'+s[end:]
 path=Path(str(_work/('tokenizer-'+v+'-narrowing.cpp')));path.write_text(s)
 subprocess.run(['g++','-O2','-std=c++17','-shared','-fPIC',str(path),'-o',str(path.with_suffix('.so'))],check=True)
 lib=ctypes.CDLL(str(path.with_suffix('.so')));lib.tokenizer.argtypes=[ctypes.POINTER(Tok),ctypes.c_char_p,ctypes.c_char_p,ctypes.c_int];lib.free_tokenizer.argtypes=[ctypes.POINTER(Tok)];libs.append(lib)
def result(lib,n):
 ctypes.c_size_t.in_dll(lib,'test_forced_length').value=n
 t=Tok();lib.tokenizer(ctypes.byref(t),b'a'*512,b' ;',1)
 out=(t.s_length,ctypes.string_at(t.s) if t.s else None);lib.free_tokenizer(ctypes.byref(t));return out
cases=[0,1,5,126,127,128,255,2**31-1,2**31,2**31+1,2**32-1,2**32,2**32+1,2**32+127,2**32+128,2**64-1]
for n in cases:assert result(libs[0],n)==result(libs[1],n),n
print('PASS:',len(cases),'forced-length differential cases check size_t-to-int narrowing without allocating multi-gigabyte input; same bounded bytes and explicit NUL as snprintf.')
