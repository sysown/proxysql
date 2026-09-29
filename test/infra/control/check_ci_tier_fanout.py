#!/usr/bin/env python3
"""Validate the paired tier catalogue, automatic routes and migrated coverage."""
import argparse
import json
from pathlib import Path
import re
import subprocess
import yaml
from ci_tier_conditions import condition_allows
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

def resolve(value,inputs):
    return re.sub(r'\$\{\{\s*inputs\.([a-zA-Z0-9_]+)\s*\}\}',lambda m:str(inputs.get(m[1],m[0])),str(value))

def selected_matrix(job, job_id, producer=False):
    needs=job.get('needs',[])
    needs=[needs] if isinstance(needs,str) else needs
    dependency='plan' if producer else 'tier-context'
    if dependency not in needs:return False
    matrix=job.get('strategy',{}).get('matrix')
    if producer:return matrix=='${{ fromJson(needs.plan.outputs.matrix) }}'
    if not isinstance(matrix,dict) or set(matrix)!={'include'}:return False
    expected="${{ fromJson(needs.tier-context.outputs.matrices)['"+job_id+"'] || fromJson('[{}]') }}"
    return re.sub(r'\s+','',str(matrix['include']))==re.sub(r'\s+','',expected)

def validate_routes(rows,callers,engines,known_groups,migrated):
    errors=[];covered={'v30':set(),'v31':set()};identities=set()
    def allowed(condition,tier,mode,inputs,job):
        try:return condition_allows(condition,tier,mode,inputs,job)
        except ValueError as error:
            message='cannot prove route condition: '+str(error)
            if message not in errors:errors.append(message)
            return False
    for row in rows:
        identity=(row['workflow'],row.get('instance','run'),row['job'])
        if identity in identities:errors.append('duplicate consumer '+str(identity))
        identities.add(identity)
        for group in row['groups']:
            if group not in known_groups:errors.append('unknown group '+group)
        caller=callers.get(row['workflow'])
        if not caller:errors.append('missing caller '+row['workflow']);continue
        if row['automatic']!=is_automatic(caller):errors.append('automatic/manual mismatch '+row['workflow'])
        start_job=caller['jobs'].get(row.get('instance','run'),{})
        routes=[]
        def walk(name,inputs,gates,ancestors):
            if not name or name in ancestors:return
            if name not in engines:errors.append('missing reusable '+name);return
            if name==row['file']:routes.append((inputs,gates))
            for job in engines[name].get('jobs',{}).values():
                nested={k:resolve(v,inputs) for k,v in job.get('with',{}).items()}
                walk(target(job),nested,gates+[(job.get('if'),inputs)],ancestors|{name})
        producer=row['workflow']=='CI-builds' and row['job']=='tier-units'
        if producer:
            body=engines.get('ci-builds.yml',{});job=body.get('jobs',{}).get('builds',{})
            if target(start_job)=='ci-builds.yml':routes=[(start_job.get('with',{}),[(start_job.get('if'),{})])]
        else:
            walk(target(start_job),start_job.get('with',{}),[(start_job.get('if'),{})],set())
            body=engines.get(row['file'],{});job=body.get('jobs',{}).get(row['job'],{})
            if 'tier-context' not in body.get('jobs',{}):errors.append('missing tier context '+row['file'])
        if not routes:errors.append('unreachable consumer '+str(identity));continue
        if not selected_matrix(job,row['job'],producer):
            errors.append('consumer matrix bypasses selected tiers: '+str(identity));continue
        required_groups=set(row['groups'])
        for tier in set(row['tiers'])&set(covered):
            per_mode=[]
            for mode in ['normal','asan']:
                wired=set()
                for inputs,gates in routes:
                    if not all(allowed(gate,tier,mode,values,row['job']) for gate,values in gates):continue
                    if not allowed(job.get('if'),tier,mode,inputs,row['job']):continue
                    for step in job.get('steps',[]):
                        run=resolve(step.get('run',''),inputs)
                        executed=('ci_tier_runtime.py units' in run if producer else
                                  'run-tests-isolated.bash' in run or 'unit-tests' in run)
                        if not executed or not allowed(step.get('if'),tier,mode,inputs,row['job']):continue
                        value=resolve(step.get('env',{}).get('TAP_GROUP',''),inputs)
                        if value:wired.add(value)
                        wired.update(re.findall(r"TAP_GROUP=[\"']?([a-zA-Z0-9_-]+)",run))
                per_mode.append(wired)
                missing=required_groups-wired
                if missing:errors.append('group not executed by '+str(identity)+' on '+tier+'/'+mode+': '+', '.join(sorted(missing)))
            if row['automatic'] and is_automatic(caller):
                covered[tier].update(required_groups.intersection(*per_mode))
    for tier in covered:
        for group in sorted(migrated-covered[tier]):errors.append('lower-tier coverage lost: '+tier+'/'+group)
    for name,body in engines.items():
        for jobid,job in body.get('jobs',{}).items():
            if any('ci_tier_runtime.py restore' in str(s.get('run','')) or 'ci-builds-handoff-' in str(s.get('run','')) for s in job.get('steps',[])):
                if not any(r['file']==name and r['job']==jobid for r in rows):errors.append('uncatalogued consumer '+name+'/'+jobid)
    return errors

def git(*args):return subprocess.check_output(['git',*args],cwd=ROOT,text=True)
def load_tree(ref):
    return {Path(p).name:yaml.safe_load(git('show',ref+':'+p)) for p in git('ls-tree','-r','--name-only',ref,'.github/workflows').splitlines() if p.endswith(('.yml','.yaml'))}

def main():
    parser=argparse.ArgumentParser();parser.add_argument('--callers-ref',default='HEAD');parser.add_argument('--engine-ref',default='origin/GH-Actions');args=parser.parse_args()
    callers={v['name']:v for filename,v in load_tree(args.callers_ref).items() if filename.startswith('CI-')}
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
