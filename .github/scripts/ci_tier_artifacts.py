#!/usr/bin/env python3
"""Run-scoped GitHub API and handoff operations. Never select by newest SHA."""
import io
import json
import os
from pathlib import Path, PurePosixPath
import subprocess
import tarfile
import tempfile
import time
import zipfile
from ci_tier_plan import validate_manifest, version_tuple

class GitHubAPI:
    def __init__(self, repository):
        self.repository=repository
    def request(self,path,method='GET',payload=None,raw=False):
        args=['gh','api',path,'--method',method]
        if payload is not None:args+=['--input','-']
        for attempt in range(6):
            result=subprocess.run(args,input=json.dumps(payload).encode() if payload is not None else None,
                                  capture_output=True,timeout=60)
            if not result.returncode:
                return result.stdout if raw else json.loads(result.stdout or b'{}')
            error=result.stderr.decode(errors='replace').lower()
            transient=any(marker in error for marker in ('rate limit','http 429','http 502','http 503','http 504'))
            if not transient or attempt==5:
                raise RuntimeError(f'GitHub API {method} {path}: exit {result.returncode}')
            time.sleep(60 if 'rate limit' in error or '429' in error else min(30,2**attempt))

    def pages(self,path,key):
        records=[]
        for page in range(1,1001):
            data=self.request(path+('&' if '?' in path else '?')+f'per_page=100&page={page}')
            batch=data[key] if key else data
            records.extend(batch)
            if len(batch)<100:return records
        raise RuntimeError('GitHub pagination limit exceeded')
    def artifacts(self,run_id):
        return self.pages(f'repos/{self.repository}/actions/runs/{int(run_id)}/artifacts','artifacts')
    def json_artifact(self,run_id,name,filename):
        artifact=select_artifact(self.artifacts(run_id),name)
        raw=self.request(f"repos/{self.repository}/actions/artifacts/{artifact['id']}/zip",raw=True)
        with zipfile.ZipFile(io.BytesIO(raw)) as archive:
            return json.loads(archive.read(filename))

def select_artifact(records,name):
    matches=[r for r in records if r['name']==name and not r.get('expired',False)]
    if len(matches)!=1:raise ValueError(f'expected one live artifact named {name}, found {len(matches)}')
    return matches[0]

def verify_binding(binding,context):
    for key in ('repository','sha','trigger_id','trigger_attempt'):
        if binding.get(key)!=context.get(key):raise ValueError('producer binding mismatch: '+key)

def resolve_producer(context,api):
    checks=api.pages(f"repos/{context['repository']}/commits/{context['sha']}/check-runs?filter=all",'check_runs')
    external=f"ci-tier-origin:{context['trigger_id']}:{context['trigger_attempt']}"
    matches=[c for c in checks if c.get('external_id')==external]
    if len(matches)!=1:raise ValueError('missing or ambiguous build registration for trigger execution')
    binding=json.loads(matches[0]['output']['text'])
    verify_binding(binding,context)
    return binding

def load_manifest(producer,api):
    eid='t{trigger_id}-a{trigger_attempt}-b{build_id}-a{build_attempt}'.format(**producer)
    plan=api.json_artifact(producer['build_id'],'ci-manifest-'+eid,'manifest.json')
    validate_manifest(plan);verify_binding(plan,producer)
    if plan['execution_id']!=eid:raise ValueError('producer attempt mismatch')
    return plan

def validate_binary(tier,version):
    expected={'v30':(3,0),'v31':(3,1),'v40':(4,0)}[tier]
    if version_tuple(version)[:2]!=expected:raise ValueError('restored binary does not match requested product tier')

def safe_members(members):
    for member in members:
        path=PurePosixPath(member.name)
        if path.is_absolute() or '..' in path.parts or member.isdev() or member.isfifo():
            raise ValueError('unsafe handoff archive member: '+member.name)
        if member.issym() or member.islnk():
            link=PurePosixPath(member.linkname)
            # Reject outward links; extraction also uses Python's data filter.
            if link.is_absolute() or '..' in link.parts:raise ValueError('unsafe handoff link')
    return members

def restore_handoff(manifest,leg,destination,api):
    validate_manifest(manifest)
    expected=next(x for x in manifest['legs'] if x['tier']==leg['tier'])
    if leg['artifact_name']!=expected['artifact_name']:raise ValueError('wrong handoff identity')
    record=select_artifact(api.artifacts(manifest['build_id']),expected['artifact_name'])
    if expected.get('artifact_id') and record['id']!=expected['artifact_id']:raise ValueError('handoff artifact replaced')
    with tempfile.TemporaryDirectory() as tmp:
        raw=api.request(f"repos/{api.repository}/actions/artifacts/{record['id']}/zip",raw=True)
        with zipfile.ZipFile(io.BytesIO(raw)) as archive:
            packed=Path(tmp)/'cache_full.tar.zst';packed.write_bytes(archive.read('cache_full.tar.zst'))
        tarpath=Path(tmp)/'full.tar'
        with tarpath.open('wb') as out:subprocess.run(['zstd','-d','-c',str(packed)],stdout=out,check=True)
        destination=Path(destination);destination.mkdir(parents=True,exist_ok=True)
        with tarfile.open(tarpath) as archive:
            archive.extractall(destination,members=safe_members(archive.getmembers()),filter='data')
    metadata=json.loads((destination/'src/ci-tier.json').read_text())
    for key,value in [('execution_id',manifest['execution_id']),('sha',manifest['sha']),('tier',leg['tier']),('mode',leg['mode'])]:
        if metadata.get(key)!=value:raise ValueError('restored metadata mismatch: '+key)
    result=subprocess.run([str(destination.resolve()/'src/proxysql'),'--version'],capture_output=True,text=True,check=True)
    validate_binary(leg['tier'],result.stdout+result.stderr)
