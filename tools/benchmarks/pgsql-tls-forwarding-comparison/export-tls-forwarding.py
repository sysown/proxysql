from pathlib import Path
import tarfile,json,sys
r=Path.home()/'pg-network-bench';series=Path(sys.argv[1]);assert (series/'verification.json').exists()
with tarfile.open('/tmp/tls-forwarding-evidence.tgz','w:gz') as archive:
 for f in series.iterdir():
  if f.is_file():archive.add(f,arcname=str(Path(series.name)/f.name))
 for run in json.loads((series/'runs.json').read_text()):
  p=Path(run['directory'])
  for f in p.iterdir():
   if f.is_file() and f.suffix in ['.json','.txt','.sql']:archive.add(f,arcname=str(Path(p.name)/f.name))
 archive.add(r/'tls-forwarding-binaries.json',arcname='tls-forwarding-binaries.json')
print('Exported verified evidence; raw latency logs remain remote.')
