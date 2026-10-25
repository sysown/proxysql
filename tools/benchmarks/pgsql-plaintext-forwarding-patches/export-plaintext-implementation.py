from pathlib import Path
import tarfile,json,subprocess
r=Path.home()/'pg-network-bench';out=r/'results/plaintext-implementation'
assert (out/'verification.json').exists() and (out/'call-verification.json').exists()
w=r/'src/proxysql-tls-handshake-cache'
(out/'product.patch').write_text(subprocess.check_output(['git','-C',str(w),'diff','058f0f5a2..754dc4af4','--','lib','include'],text=True))
(out/'commit-messages.txt').write_text(subprocess.check_output(['git','-C',str(w),'log','--reverse','--format=full','058f0f5a2..754dc4af4'],text=True))
with tarfile.open('/tmp/plaintext-implementation-evidence.tgz','w:gz') as archive:
 for f in out.iterdir():
  if f.is_file():archive.add(f,arcname=f.name)
 paths=[x['directory'] for name in ['runs.json','diagnostics.json','excluded.json'] for x in json.loads((out/name).read_text())]
 for path in paths:
  p=Path(path)
  for f in p.iterdir():
   if f.is_file() and f.suffix in ['.json','.txt','.bt','.jsonl','.stderr','.sql'] and f.name!='stacks.txt':archive.add(f,arcname=str(Path(p.name)/f.name))
 for name in ['plaintext-implementation-binaries.json','plaintext-implementation-dependency-check.json','plaintext-copy-guard-build.log','plaintext-scheduler-build.log','plaintext-rows-build.log','plaintext-implementation-verification.log']:
  archive.add(r/name,arcname=name)
 archive.add(w/'lib/obj/.build_flags',arcname='lib-build-flags.txt');archive.add(w/'src/obj/.build_flags',arcname='src-build-flags.txt')
print('Evidence exported; raw transaction archives stay remote.',flush=True)
