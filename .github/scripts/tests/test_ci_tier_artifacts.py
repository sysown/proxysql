import copy,sys,unittest
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from ci_tier_artifacts import select_artifact, verify_binding, validate_binary, safe_members, resolve_producer

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
  link=tarfile.TarInfo('src/link');link.type=tarfile.SYMTYPE;link.linkname='../../escape'
  with self.assertRaises(ValueError):safe_members([link])
 def test_registration_is_not_sha_search(self):
  class API:
   def pages(self,path,key):return [{'external_id':'ci-tier-origin:1:1','output':{'text':'{"build_id":2,"build_attempt":1,"trigger_id":1,"trigger_attempt":1,"repository":"sysown/proxysql","sha":"'+('a'*40)+'"}'}}]
  c=dict(repository='sysown/proxysql',sha='a'*40,trigger_id=1,trigger_attempt=1)
  self.assertEqual(resolve_producer(c,API())['build_id'],2)
  c['trigger_id']=3
  with self.assertRaises(ValueError):resolve_producer(c,API())
if __name__=='__main__':unittest.main()
