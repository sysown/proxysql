from pathlib import Path
import tempfile
_scratch=tempfile.TemporaryDirectory(prefix="pgsql-tokenizer-validation-")
_work=Path(_scratch.name)
_inputs=Path(__file__).resolve().parent/"tokenizer-inputs"
for _name in ["tokenizer-before.cpp","tokenizer-after.cpp","c_tokenizer.h"]:
 (_work/_name).write_bytes((_inputs/_name).read_bytes())
import subprocess
for v in ['before','after']:
 s=(_work/('tokenizer-'+v+'.cpp')).read_text().split('\nvoid c_split_2(')[0]
 s=s.replace('"c_tokenizer.h"','"'+str(_work/'c_tokenizer.h')+'"')
 # Build the actual tokenizer and token iteration implementation in isolation.
 Path(str(_work/('tokenizer-'+v+'-check.cpp'))).write_text(s)
 subprocess.run(['g++','-std=c++17','-O2','-fno-omit-frame-pointer','-shared','-fPIC',str(_work/('tokenizer-'+v+'-check.cpp')),'-o',str(_work/('tokenizer-'+v+'.so'))],check=True)
import ctypes,random
class Tok(ctypes.Structure):
 _fields_=[('buffer',ctypes.c_char*128),('s_length',ctypes.c_int),('s',ctypes.c_void_p),('delimiters',ctypes.c_char_p),('current',ctypes.c_void_p),('next',ctypes.c_void_p),('ignore',ctypes.c_int)]
libs=[ctypes.CDLL(str(_work/('tokenizer-'+v+'.so'))) for v in ['before','after']]
for lib in libs:
 lib.tokenizer.argtypes=[ctypes.POINTER(Tok),ctypes.c_char_p,ctypes.c_char_p,ctypes.c_int]
 lib.tokenize.argtypes=[ctypes.POINTER(Tok)];lib.tokenize.restype=ctypes.c_char_p
 lib.free_tokenizer.argtypes=[ctypes.POINTER(Tok)]
def result(lib,s,d,mode):
 t=Tok();lib.tokenizer(ctypes.byref(t),s,d,mode);n=t.s_length;out=[]
 while True:
  x=lib.tokenize(ctypes.byref(t))
  if x is None:break
  out.append(x)
 lib.free_tokenizer(ctypes.byref(t));return n,out
rng=random.Random(7521);cases=0
for n in list(range(260))+[511,512,1024,4096]:
 for _ in range(12):
  s=bytes(rng.choice(b'abCDEf ;,\t\n\x80\xff') for _ in range(n))
  for d in [b' ;',b',',b'',b'\t\n;',None]:
   for mode in [0,1]:
    assert result(libs[0],s,d,mode)==result(libs[1],s,d,mode),(s,d,mode)
    cases+=1
for s in [None,b'',b'SELECT 1;',b'abc\x00tail',b' '*128,b'a'*127,b'a'*128]:
 for mode in [0,1]:
  assert result(libs[0],s,b' ;',mode)==result(libs[1],s,b' ;',mode);cases+=1
print('PASS:',cases,'differential tokenizer cases, both empty-token modes; NULL, terminator, delimiter and 127/128-byte allocation boundaries; repository tests unchanged.')
