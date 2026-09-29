#!/usr/bin/env python3
"""GitHub Actions adapters for the tested tier contracts."""
import json
import os
from pathlib import Path
import subprocess
import sys
import time
from ci_tier_plan import resolve_selection, make_plan, consumer_matrix, applicable_tests, validate_manifest, check_key
from ci_tier_artifacts import GitHubAPI, resolve_producer, load_manifest, select_artifact, restore_handoff, verify_binding
from ci_tier_checks import register, publish_result, reconcile

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
def api_for(plan):return GitHubAPI(plan['repository'])
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
    version=subprocess.check_output([str(root.resolve()/'src/proxysql'),'--version'],text=True)
    from ci_tier_artifacts import validate_binary
    validate_binary(leg['tier'],version)
    groups=json.loads((root/'test/tap/groups/groups.json').read_text())
    applicable={c['key']:not c['groups'] or any(applicable_tests(groups,g,version) for g in c['groups']) for c in plan['checks'] if c['tier']==leg['tier']}
    metadata=dict(execution_id=plan['execution_id'],sha=plan['sha'],tier=leg['tier'],mode=leg['mode'],version=version,applicable=applicable)
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
        for check in plan['checks']:
            if check['tier']!=leg['tier']:continue
            check['applicable']=metadata['applicable'][check['key']]
            if not check['applicable']:
                api.request(f"repos/{plan['repository']}/check-runs/{check['check_id']}",'PATCH',{'status':'completed','conclusion':'neutral',
                    'output':{'title':'Not applicable','summary':'No tests in this group apply to the built product version.'}})
    Path('manifest.json').write_text(json.dumps(plan))

def consumer():
    ctx=context();api=api_for(ctx);gh=json.loads(os.environ['GITHUB_JSON'])
    binding_name='ci-tier-binding-'+os.environ.get('CONSUMER_INSTANCE','run')
    attempt=int(gh['run_attempt'])
    if attempt>1:
        producer=api.json_artifact(int(gh['run_id']),binding_name,'binding.json')
        if ctx['event']!='workflow_dispatch':verify_binding(producer,ctx)
    elif os.environ.get('PRODUCER_RUN_ID'):
        run=int(os.environ['PRODUCER_RUN_ID']);build_attempt=int(os.environ.get('PRODUCER_ATTEMPT') or '1')
        names=[a['name'] for a in api.artifacts(run) if a['name'].startswith('ci-manifest-') and a['name'].endswith(f'-b{run}-a{build_attempt}')]
        if len(names)!=1:raise ValueError('manual dispatch requires an exact producer run and attempt with a manifest')
        producer=api.json_artifact(run,names[0],'manifest.json')
    else:
        if ctx['event']=='workflow_dispatch':raise ValueError('manual consumer dispatch requires producer_run_id and producer_attempt')
        producer=resolve_producer(ctx,api)
    manifest=load_manifest(producer,api)
    workflow=gh['workflow'];instance=os.environ.get('CONSUMER_INSTANCE','run')
    jobs=sorted({c['job'] for c in manifest['checks'] if c['workflow']==workflow and c['cell'].get('ci_instance','run')==instance})
    matrices={job:consumer_matrix(manifest,workflow,job,instance) for job in jobs}
    Path('binding.json').write_text(json.dumps({k:manifest[k] for k in ('repository','sha','trigger_id','trigger_attempt','build_id','build_attempt','execution_id','control_sha')}))
    Path('manifest.json').write_text(json.dumps(manifest))
    emit(matrices=matrices,binding=json.loads(Path('binding.json').read_text()),execution_id=manifest['execution_id'],
         control_sha=manifest['control_sha'],sha=manifest['sha'],binding_name=binding_name)

def bound_manifest():
    binding=json.loads(os.environ['CI_BINDING']);return load_manifest(binding,api_for(binding))

def result():
    plan=read_plan() if os.environ.get('CI_PLAN') else bound_manifest()
    key=os.environ['CHECK_KEY'];gh=json.loads(os.environ['GITHUB_JSON'])
    publish_result(plan,key,os.environ['CHECK_STATUS'],api_for(plan),gh['run_id'],gh['run_attempt'])

def restore():
    plan=bound_manifest();leg=json.loads(os.environ['CI_LEG']);restore_handoff(plan,leg,Path('proxysql'),api_for(plan))

def summary():
    plan=bound_manifest();reconcile(plan,api_for(plan))

def producer_lookup():
    # CI-trigger runs on the source event, before CI-builds can register itself.
    gh=json.loads(os.environ['GITHUB_JSON'])
    ctx=dict(repository=gh['repository'],sha=gh.get('event',{}).get('pull_request',{}).get('head',{}).get('sha') or gh['sha'],
             trigger_id=int(gh['run_id']),trigger_attempt=int(gh['run_attempt']))
    api=api_for(ctx);deadline=time.monotonic()+14400;errors_since=None
    while time.monotonic()<deadline:
        try:
            producer=resolve_producer(ctx,api);break
        except ValueError:time.sleep(15)
        except RuntimeError:
            if errors_since is None:errors_since=time.monotonic()
            if time.monotonic()-errors_since>300:raise
            time.sleep(15)
    else:raise RuntimeError('timed out waiting for producer registration')
    while time.monotonic()<deadline:
        run=api.request(f"repos/{ctx['repository']}/actions/runs/{producer['build_id']}/attempts/{producer['build_attempt']}")
        if run['status']=='completed':
            if run['conclusion']!='success':raise RuntimeError('producer failed: '+str(run['conclusion']))
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
    commands={'plan':plan_command,'stamp':stamp,'finalize':finalize,'consumer':consumer,'result':result,'restore':restore,'summary':summary,'wait-build':producer_lookup,'units':units}
    commands[sys.argv[1]]()
