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
 def test_handoff_filter_resolves_symlinks_from_their_directory(self):
  # CPython gh-107845 (Python < 3.10.13/3.11.5, e.g. ubuntu-22.04): the data filter resolved relative
  # symlink targets against the destination root; emulate that and check the fallback's own verdict
  import os,tarfile,tempfile
  from unittest.mock import patch
  from ci_tier_artifacts import handoff_filter
  real=tarfile.data_filter
  def buggy(member,dest_path):
   # only the old root-relative symlink check: the interpreter's own filter must not judge the target
   # (fixed interpreters reject or, since CVE-2025-4517, normalise it), so it sees a harmless one
   if not member.issym():return real(member,dest_path)
   root=os.path.realpath(dest_path);target=os.path.realpath(os.path.join(root,member.linkname))
   if os.path.commonpath([root,target])!=root:raise tarfile.LinkOutsideDestinationError(member,target)
   return real(member.replace(linkname='.',deep=False),dest_path).replace(linkname=member.linkname,deep=False)
  def link(name,target):
   member=tarfile.TarInfo(name);member.type=tarfile.SYMTYPE;member.linkname=target;return member
  with tempfile.TemporaryDirectory() as folder,patch('ci_tier_artifacts.tarfile.data_filter',side_effect=buggy):
   inside=handoff_filter(link('test/afl_digest_test/c_tokenizer.h','../../include/c_tokenizer.h'),folder)
   self.assertEqual(inside.linkname,'../../include/c_tokenizer.h')
   with self.assertRaises(tarfile.LinkOutsideDestinationError):handoff_filter(link('test/escape','../../outside'),folder)
   # a link already extracted is followed, as the fixed interpreters do
   os.makedirs(os.path.join(folder,'a/b'));os.symlink('/',os.path.join(folder,'a/b/up'))
   with self.assertRaises(tarfile.LinkOutsideDestinationError):handoff_filter(link('a/b/c/d/x','../../up/etc'),folder)
   # a link the old filter accepts (resolved from the root) that escapes through a link extracted earlier
   os.makedirs(os.path.join(folder,'p/q/r'));os.symlink('../../..',os.path.join(folder,'p/q/r/alias'))
   self.assertEqual(handoff_filter(link('p/q/r/alias2','../../..'),folder).linkname,'../../..')
   self.assertEqual(buggy(link('p/q/r/link','alias/../outside'),folder).linkname,'alias/../outside')
   with self.assertRaises(tarfile.LinkOutsideDestinationError):handoff_filter(link('p/q/r/link','alias/../outside'),folder)
  # and on this interpreter's own data filter
  with tempfile.TemporaryDirectory() as folder:
   os.makedirs(os.path.join(folder,'p/q/r'));os.symlink('../../..',os.path.join(folder,'p/q/r/alias'))
   with self.assertRaises(tarfile.LinkOutsideDestinationError):handoff_filter(link('p/q/r/link','alias/../outside'),folder)
   self.assertEqual(handoff_filter(link('test/afl_digest_test/c_tokenizer.h','../../include/c_tokenizer.h'),folder).linkname,'../../include/c_tokenizer.h')
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

 def test_rejected_rate_limited_write_can_retry_without_replaying_unknown_outcome(self):
  import subprocess
  from unittest.mock import patch
  replies=[subprocess.CompletedProcess([],1,b'',b'HTTP 429 secondary rate limit'),subprocess.CompletedProcess([],0,b'{"id":7}',b'')]
  with patch('ci_tier_artifacts.subprocess.run',side_effect=replies),patch('ci_tier_artifacts.time.sleep') as sleep:
   self.assertEqual(GitHubAPI('repo').request('check-runs','POST',{'name':'test'})['id'],7)
   sleep.assert_called_once_with(60)

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

 def test_download_timeout_and_network_errors_retry_only_reads(self):
  import subprocess
  from unittest.mock import patch
  success=subprocess.CompletedProcess([],0,b'payload',b'')
  failures=[subprocess.TimeoutExpired(['gh'],60),subprocess.CompletedProcess([],1,b'',b'connection reset by peer')]
  for failure in failures:
   with self.subTest(failure=type(failure).__name__),patch('ci_tier_artifacts.subprocess.run',side_effect=[failure,success]) as run,patch('ci_tier_artifacts.time.sleep'):
    self.assertEqual(GitHubAPI('repo').request('artifacts/1/zip',raw=True),b'payload')
    self.assertGreater(run.call_args.kwargs['timeout'],60)
  for method in ['POST','PATCH']:
   for failure in [*failures,subprocess.CompletedProcess([],1,b'',b'HTTP 503')]:
    with self.subTest(method=method),patch('ci_tier_artifacts.subprocess.run',side_effect=[failure,success]) as run,patch('ci_tier_artifacts.time.sleep'):
     with self.assertRaises(RuntimeError):GitHubAPI('repo').request('check-runs',method,payload={'name':'test'})
     self.assertEqual(run.call_count,1)
 def test_timeout_retries_are_bounded_and_do_not_expose_payload(self):
  import subprocess
  from unittest.mock import patch
  with patch('ci_tier_artifacts.subprocess.run',side_effect=subprocess.TimeoutExpired(['secret'],60,stderr=b'secret')) as run,patch('ci_tier_artifacts.time.sleep'):
   with self.assertRaisesRegex(RuntimeError,'timed out') as failure:GitHubAPI('repo').request('artifacts/1/zip',raw=True)
   self.assertNotIn('secret',str(failure.exception));self.assertEqual(run.call_count,6)

if __name__=='__main__':unittest.main()
