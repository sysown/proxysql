#!/usr/bin/env python3
"""GitHub Actions adapters for the tested tier contracts."""
import copy
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import time
from ci_tier_plan import resolve_selection, make_plan, consumer_matrix, applicable_tests, validate_manifest, check_key
from ci_tier_artifacts import binary_version, GitHubAPI, resolve_producer, load_manifest, select_artifact, restore_handoff, verify_binding
from ci_tier_checks import register, publish_result, reconcile, reporting_repository

ROOT=Path(__file__).resolve().parents[1]

def emit(**values):
    with open(os.environ['GITHUB_OUTPUT'],'a') as out:
        for key,value in values.items():
            out.write(key+'='+ (value if isinstance(value,str) else json.dumps(value,separators=(',',':')))+'\n')

def context():
    gh=json.loads(os.environ['GITHUB_JSON']);trigger=json.loads(os.environ.get('TRIGGER_JSON') or '{}')
    upstream=trigger.get('event',{}).get('workflow_run')
    origin=upstream or dict(id=int(gh['run_id']),run_attempt=int(gh['run_attempt']),head_sha=gh['sha'],event=gh['event_name'],pull_requests=[])
    return dict(repository=os.environ.get('SOURCE_REPOSITORY') or gh['repository'],sha=os.environ.get('SOURCE_SHA') or origin['head_sha'],
        event=origin['event'],pull_requests=origin.get('pull_requests',[]),trigger_id=int(origin['id']),trigger_attempt=int(origin.get('run_attempt',1)),
        build_id=int(gh['run_id']),build_attempt=int(gh['run_attempt']),control_sha=subprocess.check_output(['git','-C',str(ROOT.parent),'rev-parse','HEAD'],text=True).strip(),
        variables=json.loads(os.environ.get('CI_VARIABLES','{}')))

def read_plan():
    binding=json.loads(os.environ['CI_PLAN'])
    if 'checks' in binding:return binding
    plan=api_for(binding).json_artifact(binding['build_id'],'ci-plan-'+binding['execution_id'],'plan.json')
    validate_manifest(plan);verify_binding(plan,binding)
    if plan['execution_id']!=binding['execution_id']:raise ValueError('plan attempt mismatch')
    return plan
def api_for(plan):return GitHubAPI(plan['repository'],token=os.environ.get('SOURCE_ARTIFACTS_TOKEN') or None)
def reporting_api(plan):return GitHubAPI(reporting_repository(plan))
def plan_command():
    ctx=context();api=api_for(ctx);trusted=os.environ.get('TRUSTED')=='true'
    selection=resolve_selection(ctx,trusted,lambda number:api.request(f"repos/{ctx['repository']}/pulls/{number}"))
    plan=make_plan(ctx,selection,json.loads((ROOT/'ci-tier-consumers.json').read_text()) if trusted else {'consumers':[]})
    plan.pop('variables',None)
    if trusted:register(plan,api)
    Path('plan.json').write_text(json.dumps(plan))
    matrix=[]
    for leg in plan['legs']:
        check=next(c for c in plan['checks'] if c['workflow']=='CI-builds' and c['job']=='builds' and c['tier']==leg['tier'])
        matrix.append(dict(leg,dist='ubuntu24',type='-tap',check_key=check['key'],check_name=check['name']))
    binding={k:plan[k] for k in ('repository','sha','trigger_id','trigger_attempt','build_id','build_attempt','execution_id','control_sha')}
    emit(plan=binding,matrix={'include':matrix},execution_id=plan['execution_id'],control_sha=plan['control_sha'])

def stamp():
    plan=read_plan();leg=json.loads(os.environ['CI_LEG']);root=Path('proxysql')
    version=binary_version(root)
    from ci_tier_artifacts import validate_binary
    validate_binary(leg['tier'],version)
    groups=json.loads((root/'test/tap/groups/groups.json').read_text())
    applicable={c['key']:not c['groups'] or any(applicable_tests(groups,g,version) for g in c['groups']) for c in plan['checks'] if c['tier']==leg['tier']}
    all_groups={tag for tags in groups.values() for tag in tags if not tag.startswith('@')}
    applicable_groups=sorted(g for g in all_groups if applicable_tests(groups,g,version))
    metadata=dict(applicable_groups=applicable_groups,execution_id=plan['execution_id'],sha=plan['sha'],tier=leg['tier'],mode=leg['mode'],version=version,applicable=applicable)
    (root/'src/ci-tier.json').write_text(json.dumps(metadata))
    Path('metadata.json').write_text(json.dumps(metadata))

def finalize():
    plan=read_plan();api=api_for(plan)
    if os.environ.get('BUILD_RESULT')!='success':
        for check in plan['checks']:
            current=api.request(f"repos/{plan['repository']}/check-runs/{check['check_id']}")
            if current['status']!='completed':
                api.request(f"repos/{plan['repository']}/check-runs/{check['check_id']}",'PATCH',{'status':'completed','conclusion':'failure' if check['workflow']=='CI-builds' else 'skipped',
                    'output':{'title':'Build prerequisite failed','summary':'Test fanout was blocked; see the producer run.'}})
        reconcile(plan,api)
        raise RuntimeError('required producer job failed')
    for leg in plan['legs']:
        metadata=api.json_artifact(plan['build_id'],f"ci-leg-{plan['execution_id']}-{leg['tier']}",'metadata.json')
        if metadata['execution_id']!=plan['execution_id'] or metadata['sha']!=plan['sha']:raise ValueError('foreign build metadata')
        leg['artifact_id']=select_artifact(api.artifacts(plan['build_id']),leg['artifact_name'])['id']
        leg['version']=metadata['version']
        leg['applicable_groups']=metadata['applicable_groups']
        for check in plan['checks']:
            if check['tier']!=leg['tier']:continue
            check['applicable']=metadata['applicable'][check['key']]
            if not check['applicable']:
                api.request(f"repos/{plan['repository']}/check-runs/{check['check_id']}",'PATCH',{'status':'completed','conclusion':'neutral',
                    'output':{'title':'Not applicable','summary':'No tests in this group apply to the built product version.'}})
    # A failed-job rerun reuses its successful plan and any published handoffs.
    # Keep an existing final manifest immutable if only finalization is retried.
    name='ci-manifest-'+plan['execution_id']
    existing=[a for a in api.artifacts(plan['build_id']) if a['name']==name and not a.get('expired')]
    if existing:
        original=api.json_artifact(plan['build_id'],name,'manifest.json')
        validate_manifest(original);verify_binding(original,plan)
        plan=original
    Path('manifest.json').write_text(json.dumps(plan))
    emit(publish_manifest=not bool(existing))

def artifact_status():
    plan=read_plan();leg=json.loads(os.environ['CI_LEG'])
    names={a['name'] for a in api_for(plan).artifacts(plan['build_id']) if not a.get('expired')}
    emit(publish_metadata=f"ci-leg-{plan['execution_id']}-{leg['tier']}" not in names,
         publish_handoff=leg['artifact_name'] not in names)

def consumer_instance(manifest,workflow,instance,supplied):
    checks=[c for c in manifest['checks'] if c['workflow']==workflow]
    instances={c['cell'].get('ci_instance','run') for c in checks}
    if instance in instances or not instances:return instance
    from ci_tier_plan import parse_axis
    candidates=[]
    for candidate in instances:
        cells=[c['cell'] for c in checks if c['cell'].get('ci_instance','run')==candidate]
        axes={k for cell in cells for k in cell if k!='ci_instance'}
        if axes and all(supplied.get(k) and set(parse_axis(supplied[k]))=={cell[k] for cell in cells} for k in axes):
            candidates.append(candidate)
    if len(candidates)!=1:raise ValueError('ambiguous legacy consumer instance; pass consumer_id')
    return candidates[0]

def consumer():
    ctx=context();api=api_for(ctx);gh=json.loads(os.environ['GITHUB_JSON'])
    supplied=json.loads(os.environ.get('CONSUMER_INPUTS','{}'))
    instance=os.environ.get('CONSUMER_INSTANCE','run')
    # Old multi-instance callers lack consumer_id. Their stable input digest
    # separates binding uploads before their catalogue instance is resolved.
    suffix='-'+hashlib.sha256(json.dumps({k:v for k,v in supplied.items() if k!='trigger'},sort_keys=True).encode()).hexdigest()[:12] if instance=='run' and supplied else ''
    binding_name='ci-tier-binding-'+instance+suffix
    attempt=int(gh['run_attempt'])
    if attempt>1:
        producer=GitHubAPI(gh['repository']).json_artifact(int(gh['run_id']),binding_name,'binding.json')
        if ctx['event']!='workflow_dispatch':verify_binding(producer,ctx)
    elif os.environ.get('PRODUCER_RUN_ID'):
        run=int(os.environ['PRODUCER_RUN_ID']);build_attempt=int(os.environ.get('PRODUCER_ATTEMPT') or '1')
        names=[a['name'] for a in api.artifacts(run) if a['name'].startswith('ci-manifest-') and a['name'].endswith(f'-b{run}-a{build_attempt}')]
        if len(names)!=1:raise ValueError('manual dispatch requires an exact producer run and attempt with a manifest')
        producer=api.json_artifact(run,names[0],'manifest.json')
    else:
        if ctx['event']=='workflow_dispatch':raise ValueError('manual consumer dispatch requires producer_run_id and producer_attempt')
        producer=api.json_artifact(ctx['trigger_id'],f"ci-accepted-producer-a{ctx['trigger_attempt']}",'producer.json')
        verify_binding(producer,ctx)
    manifest=load_bound(producer)
    workflow=gh['workflow']
    manual=ctx['event']=='workflow_dispatch' or gh['repository']!=manifest['repository']
    if not manual:instance=consumer_instance(manifest,workflow,instance,supplied)
    jobs=sorted({c['job'] for c in manifest['checks'] if c['workflow']==workflow and c['cell'].get('ci_instance','run')==instance})
    override=producer.get('consumer_manifest')
    if not jobs or manual:
        if attempt>1 and not override:raise ValueError('rerun has no original consumer manifest')
        if not override:
            catalogue=json.loads((ROOT/'ci-tier-consumers.json').read_text())
            rows=[];seen=set()
            for item in catalogue['consumers']:
                if item['file']!=os.environ.get('CONSUMER_FILE') or item['job'] in seen:continue
                if supplied.get('tap_group') and supplied['tap_group'] not in item['groups']:continue
                row=copy.deepcopy(item);row.update(workflow=workflow,automatic=True,instance=instance)
                for axis in row.get('axes',{}):
                    if axis in supplied and supplied[axis]:
                        from ci_tier_plan import parse_axis
                        row['axes'][axis]=parse_axis(supplied[axis])
                rows.append(row);seen.add(item['job'])
            if not rows:raise ValueError('consumer not present in this producer plan or control catalogue')
            derived=make_plan(manifest,manifest['selection'],{'consumers':rows})
            manifest=copy.deepcopy(manifest)
            manifest['checks']=[c for c in derived['checks'] if c['workflow']!='CI-builds']
            if not manifest['checks']:raise ValueError('manual consumer has no applicable configurations')
            for check in manifest['checks']:
                leg=next(l for l in manifest['legs'] if l['tier']==check['tier'])
                check['applicable']=not check['groups'] or any(g in leg['applicable_groups'] for g in check['groups'])
            manifest['reporting']=dict(repository=gh['repository'],sha=gh['sha'] if gh['repository']!=manifest['repository'] else manifest['sha'],
                identity=manifest['execution_id']+':consumer:'+gh['repository']+':'+str(gh['run_id'])+':'+binding_name,
                name='CI / manual consumer '+workflow+' / '+instance)
            register(manifest,reporting_api(manifest),origin=False)
            override={'repository':gh['repository'],'run_id':int(gh['run_id']),'artifact':binding_name}
        jobs=sorted({c['job'] for c in manifest['checks'] if c['workflow']==workflow})
    matrices={job:consumer_matrix(manifest,workflow,job,instance) for job in jobs}
    binding={k:manifest[k] for k in ('repository','sha','trigger_id','trigger_attempt','build_id','build_attempt','execution_id','control_sha')}
    if override:binding['consumer_manifest']=override
    Path('binding.json').write_text(json.dumps(binding))
    Path('manifest.json').write_text(json.dumps(manifest))
    emit(matrices=matrices,binding=json.loads(Path('binding.json').read_text()),execution_id=manifest['execution_id'],
         control_sha=manifest['control_sha'],sha=manifest['sha'],binding_name=binding_name)

def load_bound(binding):
    override=binding.get('consumer_manifest')
    if override:
        plan=GitHubAPI(override['repository']).json_artifact(override['run_id'],override['artifact'],'manifest.json')
        validate_manifest(plan);verify_binding(plan,binding)
        return plan
    return load_manifest(binding,api_for(binding))

def bound_manifest():
    return load_bound(json.loads(os.environ['CI_BINDING']))

def result():
    plan=read_plan() if os.environ.get('CI_PLAN') else bound_manifest()
    key=os.environ['CHECK_KEY'];gh=json.loads(os.environ['GITHUB_JSON'])
    publish_result(plan,key,os.environ['CHECK_STATUS'],reporting_api(plan),gh['run_id'],gh['run_attempt'],run_repository=gh['repository'])

def restore():
    plan=bound_manifest();leg=json.loads(os.environ['CI_LEG']);restore_handoff(plan,leg,Path('proxysql'),api_for(plan))

def summary():
    plan=bound_manifest();reconcile(plan,reporting_api(plan))

def producer_lookup():
    # CI-trigger runs on the source event, before CI-builds can register itself.
    gh=json.loads(os.environ['GITHUB_JSON'])
    ctx=dict(repository=gh['repository'],sha=gh.get('event',{}).get('pull_request',{}).get('head',{}).get('sha') or gh['sha'],
             trigger_id=int(gh['run_id']),trigger_attempt=int(gh['run_attempt']))
    api=api_for(ctx);deadline=time.monotonic()+14400;errors_since=None
    while time.monotonic()<deadline:
        try:
            producer=resolve_producer(ctx,api);break
        except ValueError:
            # Setup can fail before a registration exists (for example a label API error).
            # The caller title carries the exact origin, so this is not a SHA lookup.
            runs=api.request(f"repos/{ctx['repository']}/actions/workflows/CI-builds.yml/runs?event=workflow_run&per_page=100")['workflow_runs']
            suffix=f" trigger={ctx['trigger_id']}/{ctx['trigger_attempt']}"
            candidates=[r for r in runs if r.get('display_title','').endswith(suffix)]
            if any(r['status']=='completed' and r['conclusion']!='success' for r in candidates):
                raise RuntimeError('producer failed before publishing a build registration')
            errors_since=None
            time.sleep(15)
        except RuntimeError:
            if errors_since is None:errors_since=time.monotonic()
            if time.monotonic()-errors_since>300:raise
            time.sleep(15)
    else:raise RuntimeError('timed out waiting for producer registration')
    while time.monotonic()<deadline:
        run=api.request(f"repos/{ctx['repository']}/actions/runs/{producer['build_id']}/attempts/{producer['build_attempt']}")
        if run['status']=='completed':
            if run['conclusion']!='success':raise RuntimeError('producer failed: '+str(run['conclusion']))
            Path('producer.json').write_text(json.dumps(producer))
            return
        time.sleep(30)
    raise RuntimeError('timed out waiting for producer completion')

def units():
    plan=read_plan();leg=json.loads(os.environ['CI_LEG']);gh=json.loads(os.environ['GITHUB_JSON'])
    check=next(c for c in plan['checks'] if c['job']=='tier-units' and c['tier']==leg['tier'])
    api=api_for(plan)
    publish_result(plan,check['key'],'in_progress',api,gh['run_id'],gh['run_attempt'])
    env=dict(os.environ,SKIP_PROXYSQL='1',TAP_GROUP='unit-tests-g1',INFRA_ID='ci-units-'+leg['tier'])
    result=subprocess.run(['test/infra/control/run-tests-isolated.bash'],cwd='proxysql',env=env)
    publish_result(plan,check['key'],'success' if result.returncode==0 else 'failure',api,gh['run_id'],gh['run_attempt'])
    if result.returncode:raise RuntimeError('lower-tier unit tests failed')

if __name__=='__main__':
    commands={'artifact-status':artifact_status,'plan':plan_command,'stamp':stamp,'finalize':finalize,'consumer':consumer,'result':result,'restore':restore,'summary':summary,'wait-build':producer_lookup,'units':units}
    commands[sys.argv[1]]()
