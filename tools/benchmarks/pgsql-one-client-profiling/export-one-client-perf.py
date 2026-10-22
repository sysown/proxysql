from pathlib import Path
import subprocess,sys,json,hashlib
p=Path(sys.argv[1])
for name,args in [('perf-header.txt',['--header-only']),('perf-self.txt',['--no-children','--show-nr-samples','--show-total-period','--percent-limit','0','--sort','dso,symbol','--field-separator','|','-g','none']),('perf-inclusive.txt',['--children','--percent-limit','0.5','--sort','dso,symbol','--field-separator','|','-g','none'])]:
 with (p/name).open('w') as f:subprocess.run(['sudo','-n','perf','report','-f','-i',str(p/'perf.data'),'--stdio']+args,stdout=f,check=True)
 # Keep exported text clean for git diff --check.
 text=(p/name).read_text();(p/name).write_text('\n'.join(x.rstrip() for x in text.splitlines())+'\n')
assert '# Total Lost Samples: 0' in (p/'perf-self.txt').read_text()
meta=json.loads((p/'binary.json').read_text())
(p/'raw-artifact.json').write_text(json.dumps(dict(path=str(p/'perf.data'),bytes=(p/'perf.data').stat().st_size,sha256=hashlib.sha256((p/'perf.data').read_bytes()).hexdigest(),binary=meta),indent=2))
print((p/'perf-self.txt').read_text()[:9500])
