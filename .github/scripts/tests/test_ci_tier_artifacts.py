import copy,sys,unittest
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from ci_tier_artifacts import select_artifact, verify_binding, validate_binary, safe_members, resolve_producer, GitHubAPI

class ArtifactTests(unittest.TestCase):
 def test_exact_attempt_artifact(self):
  records=[{'id':1,'name':'ci-handoff-t1-a1-b2-a1-v40-normal-full','expired':False},
           {'id':2,'name':'ci-handoff-t1-a1-b2-a2-v40-asan-full','expired':False}]
  self.assertEqual(select_artifact(records,records[1]['name'])['id'],2)
  with self.assertRaises(ValueError):select_artifact(records,'wrong')
  records[1]['expired']=True
  with self.assertRaises(ValueError):select_artifact(records,records[1]['name'])
 def test_binding_cannot_change_source(self):
  p=dict(repository='sysown/proxysql',sha='a'*40,trigger_id=1,trigger_attempt=1)
  verify_binding(p,p)
  for field in p:
   bad=copy.deepcopy(p);bad[field]='wrong'
   with self.assertRaises(ValueError):verify_binding(bad,p)
 def test_binary_tier_checked(self):
  for tier,version in [('v30','3.0.12'),('v31','3.1.12'),('v40','4.0.12')]:validate_binary(tier,version)
  with self.assertRaises(ValueError):validate_binary('v30','4.0.12')
 def test_archive_paths(self):
  import tarfile
  good=tarfile.TarInfo('src/proxysql');safe_members([good])
  for name in ['../secret','/tmp/escape','src/../../secret']:
   with self.assertRaises(ValueError):safe_members([tarfile.TarInfo(name)])
  link=tarfile.TarInfo('test/afl_digest_test/c_tokenizer.cpp');link.type=tarfile.SYMTYPE;link.linkname='../../lib/c_tokenizer.cpp'
  safe_members([link])
  link=tarfile.TarInfo('src/link');link.type=tarfile.SYMTYPE;link.linkname='../../escape'
  with self.assertRaises(ValueError):safe_members([link])
 def test_registration_is_not_sha_search(self):
  class API:
   def pages(self,path,key):return [{'external_id':'ci-tier-origin:1:1','output':{'text':'{"build_id":2,"build_attempt":1,"trigger_id":1,"trigger_attempt":1,"repository":"sysown/proxysql","sha":"'+('a'*40)+'"}'}}]
  c=dict(repository='sysown/proxysql',sha='a'*40,trigger_id=1,trigger_attempt=1)
  self.assertEqual(resolve_producer(c,API())['build_id'],2)
  c['trigger_id']=3
  with self.assertRaises(ValueError):resolve_producer(c,API())
 def test_secondary_rate_limit_retries_without_falling_back(self):
  import subprocess
  from unittest.mock import patch
  replies=[subprocess.CompletedProcess([],1,b'',b'HTTP 429 secondary rate limit'),subprocess.CompletedProcess([],0,b'{"id":7}',b'')]
  with patch('ci_tier_artifacts.subprocess.run',side_effect=replies),patch('ci_tier_artifacts.time.sleep') as sleep:
   self.assertEqual(GitHubAPI('sysown/proxysql').request('repos/sysown/proxysql/check-runs')['id'],7)
   sleep.assert_called_once()

 def test_restore_checks_real_archive_and_binary_version(self):
  import io,json,subprocess,tarfile,tempfile,zipfile
  from ci_tier_artifacts import restore_handoff
  from ci_tier_plan import make_plan
  from unittest.mock import Mock
  ctx=dict(repository='sysown/proxysql',sha='a'*40,control_sha='b'*40,trigger_id=1,trigger_attempt=1,build_id=2,build_attempt=1)
  plan=make_plan(ctx,dict(tiers=['v30'],mode='asan'),{'consumers':[]});leg=plan['legs'][0]
  with tempfile.TemporaryDirectory() as folder:
   root=Path(folder);source=root/'source';(source/'src').mkdir(parents=True)
   binary=source/'src/proxysql';binary.write_text('#!/bin/sh\necho "ProxySQL version 3.0.12"\n');binary.chmod(0o755)
   meta=dict(execution_id=plan['execution_id'],sha=plan['sha'],tier='v30',mode='asan')
   (source/'src/ci-tier.json').write_text(json.dumps(meta))
   (source/'test/afl_digest_test').mkdir(parents=True)
   (source/'lib').mkdir();(source/'lib/c_tokenizer.cpp').write_text('fixture')
   (source/'test/afl_digest_test/c_tokenizer.cpp').symlink_to('../../lib/c_tokenizer.cpp')
   with tarfile.open(root/'full.tar','w') as tar:
    for folder_name in ['src','test','lib']:tar.add(source/folder_name,arcname=folder_name)
   payload=subprocess.check_output(['zstd','-q','-c',str(root/'full.tar')])
   data=io.BytesIO()
   with zipfile.ZipFile(data,'w') as archive:archive.writestr('cache_full.tar.zst',payload)
   api=Mock(repository='sysown/proxysql');api.artifacts.return_value=[dict(id=9,name=leg['artifact_name'],expired=False)];api.request.return_value=data.getvalue()
   restore_handoff(plan,leg,root/'restored',api)
   self.assertEqual((root/'restored/test/afl_digest_test/c_tokenizer.cpp').read_text(),'fixture')
   self.assertEqual(json.loads((root/'restored/src/ci-tier.json').read_text()),meta)
   wrong=dict(leg,artifact_name='wrong')
   with self.assertRaisesRegex(ValueError,'identity'):restore_handoff(plan,wrong,root/'wrong',api)

 def test_binary_version_uses_build_abi_when_host_loader_fails(self):
  import subprocess
  from unittest.mock import patch
  from ci_tier_artifacts import binary_version
  replies=[subprocess.CompletedProcess([],1,'','GLIBC_2.38 not found'),subprocess.CompletedProcess([],0,'ProxySQL version 4.0.12','')]
  with patch('ci_tier_artifacts.subprocess.run',side_effect=replies) as run:
   self.assertEqual(binary_version('/tmp/fixture'),'ProxySQL version 4.0.12')
   self.assertIn('proxysql/packaging:build-ubuntu24-v4.0.0',run.call_args.args[0])

if __name__=='__main__':unittest.main()
