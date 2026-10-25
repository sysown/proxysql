from pathlib import Path
import json,subprocess
r=Path.home()/'pg-network-bench';out=r/'results/plaintext-implementation';out.mkdir(exist_ok=True)
runs=[];excluded=[];diagnostics=[]
for d in sorted((r/'results').glob('plain-opt-*')):
 if (d/'EXCLUDED.json').exists():excluded.append(dict(directory=str(d),**json.loads((d/'EXCLUDED.json').read_text())));continue
 if not (d/'summary.json').exists():continue
 s=json.loads((d/'summary.json').read_text());b=json.loads((d/'binary.json').read_text())
 row=dict(proxy=s['mode'],workload=s['workload'],directory=str(d))
 if b['profiling']:diagnostics.append(row)
 else:runs.append(row)
assert len(runs)==7,(runs,excluded)
assert len(diagnostics)==1,diagnostics
(out/'runs.json').write_text(json.dumps(runs,indent=2)+'\n');(out/'excluded.json').write_text(json.dumps(excluded,indent=2)+'\n');(out/'diagnostics.json').write_text(json.dumps(diagnostics,indent=2)+'\n')
subprocess.run(['python3','verify-plaintext-implementation.py',str(out)],cwd=r,check=True)
p=Path(diagnostics[0]['directory']);c=json.loads((p/'call-summary.json').read_text());q=c['queries'];calls=c['maps']['@calls']
assert c['maps']['@gates']==2 and c['boundary_slack_pct']<1
assert calls.get('5',0)==0,calls
assert 1.9<float(calls['1'])/q<2.1,calls
assert .9<float(calls['6'])/q<1.1,calls
assert 41.5<c['maps']['@row_count']/q<42.5,c
assert c['maps'].get('@syscalls',{}).get('tracepoint:syscalls:sys_enter_connect',0)==0
samples=json.loads((p/'samples.json').read_text());assert all(x['ConnOK']=='10' and x['ConnERR']=='0' and int(x['ConnUsed'])+int(x['ConnFree'])==10 for x in samples)
b=json.loads((p/'binary.json').read_text());pid=b['pid'];stat=Path(f'/proc/{pid}/stat');assert not stat.exists() or stat.read_text().split()[2]=='Z'
(out/'call-verification.json').write_text(json.dumps(dict(queries=q,seconds=c['seconds'],boundary_slack_pct=c['boundary_slack_pct'],calls_per_query=c['calls_per_query'],rows_per_query=c['maps']['@row_count']/q,row_wire_bytes_per_query=c['maps']['@row_bytes']/q,extra_handler_removed=True,copy_regex_calls=0,ten_backends_retained=True,no_connect_calls=True),indent=2)+'\n')
print('PASS: diagnostic confirms two handlers, no COPY regex and a row batch covering the full result.',flush=True)

meta=json.loads((p/'binary.json').read_text());binary=r/meta['metadata']['file'];maps=(p/'maps.txt').read_text()
base=min(int(parts[0].split('-')[0],16)-int(parts[2],16) for line in maps.splitlines() if len(parts:=line.split())>=6 and parts[-1]==str(binary))
resolved=[]
for key,count in c['maps']['@handler'].items():
 addr=int(key.split(',')[0])-base-1
 resolved.append(dict(raw=key,count=count,calls_per_query=count/q,address=hex(addr),source=subprocess.check_output(['addr2line','-C','-f','-e',str(binary),hex(addr)],text=True).splitlines()))
(out/'handler-callsites.json').write_text(json.dumps(resolved,indent=2)+'\n')
