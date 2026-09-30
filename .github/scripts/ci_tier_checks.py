#!/usr/bin/env python3
"""Execution-scoped PR checks; aggregate writes belong to serialized finalizers."""
import json

def aggregate_state(manifest,observations):
    observed={r['key']:r for r in observations if r.get('execution_id')==manifest['execution_id']}
    required=[c for c in manifest['checks'] if c['required'] and c['applicable']]
    pending=0;failed=0;blocked=0
    for check in required:
        result=observed.get(check['key'],{})
        if result.get('status')!='completed':pending+=1
        elif result.get('conclusion')=='skipped':blocked+=1
        elif result.get('conclusion')!='success':failed+=1
    text=f'{len(required)-pending-failed-blocked}/{len(required)} passed; {pending} pending; {failed} failed; {blocked} blocked/skipped'
    if pending:return {'status':'in_progress','output':{'title':'Selected product tiers','summary':text}}
    return {'status':'completed','conclusion':'failure' if failed or blocked else 'success','output':{'title':'Selected product tiers','summary':text}}

def reporting_repository(plan):return plan.get('reporting',{}).get('repository',plan['repository'])
def scope(plan):return plan.get('reporting',{}).get('identity',plan['execution_id'])
def url(plan,run_id=None,repository=None):return f"https://github.com/{repository or plan['repository']}/actions/runs/{run_id or plan['build_id']}"

def register(plan,api,origin=True):
    path=f"repos/{reporting_repository(plan)}/check-runs"
    payload={'name':plan.get('reporting',{}).get('name','CI / selected tiers'),'head_sha':plan.get('reporting',{}).get('sha',plan['sha']),'status':'in_progress',
             'external_id':scope(plan)+':summary','details_url':url(plan),
             'output':{'title':'Selected product tiers','summary':', '.join(plan['selection']['tiers'])+' / '+plan['selection']['mode']}}
    plan['summary_check_id']=api.request(path,'POST',payload)['id']
    for check in plan['checks']:
        payload=dict(name=check['name'],head_sha=plan.get('reporting',{}).get('sha',plan['sha']),status='queued',
            external_id=scope(plan)+':'+check['key'],details_url=url(plan))
        if not check['applicable']:payload.update(status='completed',conclusion='neutral',output=dict(title='Not applicable',summary='No tests apply to this product version.'))
        check['check_id']=api.request(path,'POST',payload)['id']
    if not origin:return plan
    identity={k:plan[k] for k in ('repository','sha','trigger_id','trigger_attempt','build_id','build_attempt','execution_id','control_sha')}
    external=f"ci-tier-origin:{plan['trigger_id']}:{plan['trigger_attempt']}"
    checks=api.pages(f"repos/{plan['repository']}/commits/{plan['sha']}/check-runs?filter=all",'check_runs')
    existing=[c for c in checks if c.get('external_id')==external]
    if len(existing)>1:raise ValueError('ambiguous producer registration')
    payload=dict(name='CI / build registration',status='completed',conclusion='success',external_id=external,details_url=url(plan),
                 output={'title':'Build execution','summary':plan['execution_id'],'text':json.dumps(identity)})
    if existing:api.request(path+'/'+str(existing[0]['id']),'PATCH',payload)
    else:api.request(path,'POST',dict(payload,head_sha=plan['sha']))
    return plan

def publish_result(plan,key,status,api,run_id,attempt,run_repository=None):
    check=next(c for c in plan['checks'] if c['key']==key)
    path=f"repos/{reporting_repository(plan)}/check-runs/{check['check_id']}"
    run_repository=run_repository or reporting_repository(plan)
    current=api.request(f"repos/{run_repository}/actions/runs/{int(run_id)}")
    if int(current['run_attempt'])!=int(attempt):raise ValueError('refusing stale consumer attempt result')
    meta=dict(execution_id=plan['execution_id'],key=key,run_id=int(run_id),attempt=int(attempt),run_repository=run_repository)
    payload=dict(status='in_progress' if status=='in_progress' else 'completed',details_url=url(plan,run_id,run_repository),
        output={'title':check['name'],'summary':status,'text':json.dumps(meta)})
    if status!='in_progress':payload['conclusion']=status
    api.request(path,'PATCH',payload)
    if status=='in_progress':
        api.request(f"repos/{reporting_repository(plan)}/check-runs/{plan['summary_check_id']}",'PATCH',
                    {'status':'in_progress','output':{'title':'Selected product tiers','summary':'Execution in progress'}})

def observations(plan,api,verify_native=True):
    observed=[];runs={};jobs={}
    all_checks=api.pages(f"repos/{reporting_repository(plan)}/commits/{plan.get('reporting',{}).get('sha',plan['sha'])}/check-runs?filter=all",'check_runs')
    by_id={c['id']:c for c in all_checks}
    for check in plan['checks']:
        result=by_id.get(check['check_id'])
        if result is None:continue
        if result.get('external_id')!=scope(plan)+':'+check['key']:raise ValueError('foreign check identity')
        row=dict(result,key=check['key'],execution_id=plan['execution_id'])
        try:meta=json.loads(result.get('output',{}).get('text') or '{}')
        except ValueError:meta={}
        if verify_native and meta.get('run_id') and check.get('workflow')!='CI-builds':
            repo=meta.get('run_repository',reporting_repository(plan));rid=meta['run_id'];identity=(repo,rid)
            if identity not in runs:runs[identity]=api.request(f"repos/{repo}/actions/runs/{rid}")
            latest=runs[identity]['run_attempt']
            # Successful producer artifacts are immutable and accepted by the
            # trigger. A full producer rerun creates a different execution.
            if identity not in jobs:
                jobs[identity]=api.pages(f"repos/{repo}/actions/runs/{rid}/attempts/{latest}/jobs",'jobs')
            # Partial reruns retain cells absent from this attempt. Reusable jobs
            # have caller prefixes, so compare the complete explicit name suffix.
            rerun=[j for j in jobs[identity] if j['name']==check['name'] or j['name'].endswith(' / '+check['name'])]
            if rerun:
                if any(j['status']=='completed' and j.get('conclusion')!='success' for j in rerun):
                    row.update(status='completed',conclusion='failure')
                elif latest!=meta.get('attempt') or any(j['status']!='completed' for j in rerun):
                    row['status']='in_progress'
            elif latest==meta.get('attempt'):
                # A terminal custom check alone cannot prove the native job ran.
                row['status']='in_progress'
        observed.append(row)
    return observed

def execution_state(plan,api):
    state=aggregate_state(plan,observations(plan,api,verify_native=False))
    # Native validation is only needed at the success boundary. Avoid polling
    # every consumer run after each of hundreds of individual completions.
    if state.get('conclusion')=='success':state=aggregate_state(plan,observations(plan,api))
    return state

def reconcile(plan,api):
    path=f"repos/{reporting_repository(plan)}/check-runs/{plan['summary_check_id']}"
    state=execution_state(plan,api)
    # Checks PATCH has no compare-and-swap. Re-read after terminal publications
    # so a concurrent start cannot leave the reproduced stale green behind.
    # Starts also invalidate the summary; API/event visibility is not atomic.
    for _ in range(3):
        api.request(path,'PATCH',state)
        if state['status']!='completed':return state
        fresh=execution_state(plan,api)
        if fresh==state:return state
        state=fresh
    state={'status':'in_progress','output':{'title':'Selected product tiers','summary':'Results changed during reconciliation; awaiting the next finalizer'}}
    api.request(path,'PATCH',state)
    return state
