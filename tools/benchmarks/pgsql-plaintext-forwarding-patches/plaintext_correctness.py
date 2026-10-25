from pathlib import Path
import subprocess,hashlib,json

def verify(out,args,env,root,admin=None):
 direct=list(args);direct[direct.index('-p')+1]='5432'
 cases={
  'scalar':'SELECT 1;',
  'raw-copy-text':"/* mixed whitespace */ SELECT 'COPY', NULL::text, ''::text, E'a\\nb';",
  'rows':(root/'select42_4kb.sql').read_text(),
  'empty':'SELECT g FROM generate_series(1,0) AS g;',
  'large-message':"SELECT repeat('z',70000);",
  'many-rows':"SELECT g, repeat('x',701) FROM generate_series(1,2000) AS g;",
  'multiple-statements':'SELECT 1; SELECT 2;',
  'transaction':'BEGIN; SELECT 9; ROLLBACK;',
  'copy-out':'COPY (SELECT generate_series(1,3)) TO STDOUT;',
 }
 evidence=[]
 for name,sql in cases.items():
  opts=['-q','-A','-t','-v','ON_ERROR_STOP=1','-c',sql]
  back=subprocess.run(direct+opts,env=env,capture_output=True,check=True,timeout=20)
  front=subprocess.run(args+opts,env=env,capture_output=True,check=True,timeout=20)
  assert front.stdout==back.stdout,(name,front.stdout[:300],back.stdout[:300],front.stderr)
  evidence.append(dict(case=name,bytes=len(front.stdout),sha256=hashlib.sha256(front.stdout).hexdigest(),identical=True))
 for name,sql in [('error','SELECT 1/0;'),('error-after-rows','SELECT 1; SELECT 1/0;')]:
  front=subprocess.run(args+['-q','-A','-t','-v','ON_ERROR_STOP=1','-c',sql],env=env,capture_output=True,timeout=20)
  back=subprocess.run(direct+['-q','-A','-t','-v','ON_ERROR_STOP=1','-c',sql],env=env,capture_output=True,timeout=20)
  assert front.returncode!=0 and back.returncode!=0 and b'division by zero' in front.stderr and front.stdout==back.stdout,(name,front)
  evidence.append(dict(case=name,expected_error=True,stdout_identical=True))
 if admin is not None:
  name='pgsql-threshold_resultset_size'
  old=admin("SELECT variable_value FROM runtime_global_variables WHERE variable_name='"+name+"'")[0]['variable_value'];assert old.isdigit()
  try:
   admin("UPDATE global_variables SET variable_value='1024' WHERE variable_name='"+name+"'");admin('LOAD PGSQL VARIABLES TO RUNTIME')
   assert admin("SELECT variable_value FROM runtime_global_variables WHERE variable_name='"+name+"'")[0]['variable_value']=='1024'
   for case in ['large-message','many-rows']:
    opts=['-q','-A','-t','-v','ON_ERROR_STOP=1','-c',cases[case]]
    front=subprocess.run(args+opts,env=env,capture_output=True,check=True,timeout=20);back=subprocess.run(direct+opts,env=env,capture_output=True,check=True,timeout=20)
    assert front.stdout==back.stdout,case
    evidence.append(dict(case=case+'-low-threshold',bytes=len(front.stdout),sha256=hashlib.sha256(front.stdout).hexdigest(),identical=True,resultset_threshold=1024))
  finally:
   admin("UPDATE global_variables SET variable_value='"+old+"' WHERE variable_name='"+name+"'");admin('LOAD PGSQL VARIABLES TO RUNTIME')
   assert admin("SELECT variable_value FROM runtime_global_variables WHERE variable_name='"+name+"'")[0]['variable_value']==old
 (out/'correctness.json').write_text(json.dumps(evidence,indent=2)+'\n');print('PASS: scalar, rows, large/partial messages, COPY output, transactions, multiple results and errors match the backend.',flush=True)
