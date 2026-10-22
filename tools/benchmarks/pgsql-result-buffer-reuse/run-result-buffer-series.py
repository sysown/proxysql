from pathlib import Path
import subprocess,json,time
r=Path.home()/'pg-network-bench';out=r/'results/result-buffer-series';out.mkdir(exist_ok=True)
order=['base16','reuse16','reuse8','reuse8','reuse16','base16'];runs=[]
for index,mode in enumerate(order,1):
 print(f'RUN {index}/{len(order)}: {mode}',flush=True)
 before=set((r/'results').glob('result-buffer-one-plain-*'))
 subprocess.run(['python3',str(r/'benchmark-result-buffer.py'),mode],cwd=r,check=True)
 new=set((r/'results').glob('result-buffer-one-plain-*'))-before;assert len(new)==1
 p=new.pop();summary=json.loads((p/'summary.json').read_text());runs.append(dict(index=index,mode=mode,path=str(p),summary=summary));(out/'series.json').write_text(json.dumps(runs,indent=2)+'\n')
 print(f'COMPLETED {index}: {mode} {summary["tps"]:.2f} TPS; user {summary["user_us_per_query"]:.3f} us/query',flush=True)
print('COMPLETE: six unprofiled runs in balanced order.',flush=True)
