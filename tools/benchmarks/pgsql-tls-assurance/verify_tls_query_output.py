from pathlib import Path
import subprocess,hashlib,json

def verify(out,args,env,query_file,root):
 direct=list(args);direct[direct.index('-p')+1]='5432'
 opts=['-q','-A','-t','-v','ON_ERROR_STOP=1','-f',str(root/query_file)]
 back=subprocess.run(direct+opts,env=env,capture_output=True,check=True,timeout=20)
 front=subprocess.run(args+opts,env=env,capture_output=True,check=True,timeout=20)
 assert front.stdout==back.stdout,(front.stdout[:200],back.stdout[:200])
 rows=len(front.stdout.splitlines());assert rows==(1 if query_file=='select1.sql' else 42),rows
 (out/'query-output-check.json').write_text(json.dumps(dict(output_matches_backend=True,rows=rows,text_output_bytes=len(front.stdout),text_output_sha256=hashlib.sha256(front.stdout).hexdigest()),indent=2)+'\n')
