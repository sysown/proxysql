#!/usr/bin/env python3
"""Validate the paired tier catalogue, automatic routes and migrated coverage."""
import argparse
import json
from pathlib import Path
import re
import subprocess
import yaml
ROOT=Path(__file__).resolve().parents[3]

def version(value):
    match=re.search(r'(\d+)\.(\d+)\.(\d+)',value)
    if not match:raise ValueError('invalid version')
    return tuple(map(int,match.groups()))

def events(doc):return doc.get('on',doc.get(True,{})) or {}
def is_automatic(doc):return 'CI-trigger' in (events(doc).get('workflow_run') or {}).get('workflows',[])
def target(job):
    match=re.search(r'/workflows/([^/@]+)',job.get('uses',''))
    return match.group(1) if match else None

def validate_routes(rows,callers,engines,known_groups,migrated):
    errors=[];covered=set();identities=set()
    for row in rows:
        identity=(row['workflow'],row.get('instance','run'),row['job'])
        if identity in identities:errors.append('duplicate consumer '+str(identity))
        identities.add(identity)
        for group in row['groups']:
            if group not in known_groups:errors.append('unknown group '+group)
        if row['workflow']=='CI-builds' and row['job']=='tier-units':
            build=engines.get('ci-builds.yml',{})
            if not any('ci_tier_runtime.py units' in s.get('run','') for s in build.get('jobs',{}).get('builds',{}).get('steps',[])):
                errors.append('missing lower-tier unit execution')
            else:covered.update(row['groups'])
            continue
        caller=callers.get(row['workflow'])
        if not caller:errors.append('missing caller '+row['workflow']);continue
        if row['automatic']!=is_automatic(caller):errors.append('automatic/manual mismatch '+row['workflow'])
        start=target(caller['jobs'].get(row.get('instance','run'),{}));reachable=set()
        def walk(name):
            if not name or name in reachable:return
            reachable.add(name)
            if name not in engines:errors.append('missing reusable '+name);return
            for job in engines[name].get('jobs',{}).values():walk(target(job))
        walk(start)
        if row['file'] not in reachable or row['file'] not in engines:errors.append('unreachable consumer '+str(identity));continue
        body=engines[row['file']]
        if 'tier-context' not in body.get('jobs',{}):errors.append('missing tier context '+row['file'])
        if row['job'] not in body.get('jobs',{}):errors.append('missing consumer job '+str(identity))
        if row['automatic'] and is_automatic(caller) and set(row['tiers'])&{'v30','v31'}:covered.update(row['groups'])
    for group in sorted(migrated-covered):errors.append('lower-tier coverage lost: '+group)
    for name,body in engines.items():
        for jobid,job in body.get('jobs',{}).items():
            if any('ci_tier_runtime.py restore' in s.get('run','') or 'ci-builds-handoff-' in s.get('run','') for s in job.get('steps',[])):
                if not any(r['file']==name and r['job']==jobid for r in rows):errors.append('uncatalogued consumer '+name+'/'+jobid)
    return errors

def git(*args):return subprocess.check_output(['git',*args],cwd=ROOT,text=True)
def load_tree(ref):
    return {Path(p).name:yaml.safe_load(git('show',ref+':'+p)) for p in git('ls-tree','-r','--name-only',ref,'.github/workflows').splitlines() if p.endswith(('.yml','.yaml'))}

def main():
    parser=argparse.ArgumentParser();parser.add_argument('--callers-ref',default='HEAD');parser.add_argument('--engine-ref',default='origin/GH-Actions');args=parser.parse_args()
    callers={v['name']:v for v in load_tree(args.callers_ref).values()}
    engines=load_tree(args.engine_ref)
    rows=json.loads(git('show',args.engine_ref+':.github/ci-tier-consumers.json'))['consumers']
    groups=json.loads(git('show',args.callers_ref+':test/tap/groups/groups.json'))
    known={g for tags in groups.values() for g in tags if not g.startswith('@')}
    migrated=set(json.loads((ROOT/'test/infra/control/fixtures/pre-label-tier-groups.json').read_text()))
    errors=validate_routes(rows,callers,engines,known,migrated)
    for error in errors:print('ERROR:',error)
    if errors:return 1
    print(f'CI tier fanout OK: {len(rows)} consumers; {len(migrated)} migrated groups retain lower-tier routes')
    return 0
if __name__=='__main__':raise SystemExit(main())
