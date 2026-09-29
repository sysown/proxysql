#!/usr/bin/env python3
"""Execution-scoped PR checks; aggregate writes belong to serialized finalizers."""
import json

def aggregate_state(manifest,observations):
    observed={r['key']:r for r in observations if r.get('execution_id')==manifest['execution_id']}
    required=[c for c in manifest['checks'] if c['required'] and c['applicable']]
    pending=0;failed=0
    for check in required:
        result=observed.get(check['key'],{})
        if result.get('status')!='completed':pending+=1
        elif result.get('conclusion')!='success':failed+=1
    text=f'{len(required)-pending-failed}/{len(required)} passed; {pending} pending; {failed} failed'
    if pending:return {'status':'in_progress','output':{'title':'Selected product tiers','summary':text}}
    return {'status':'completed','conclusion':'failure' if failed else 'success','output':{'title':'Selected product tiers','summary':text}}

def url(plan,run_id=None):return f"https://github.com/{plan['repository']}/actions/runs/{run_id or plan['build_id']}"

def register(plan,api):
    path=f"repos/{plan['repository']}/check-runs"
    payload={'name':'CI / selected tiers','head_sha':plan['sha'],'status':'in_progress',
             'external_id':plan['execution_id']+':summary','details_url':url(plan),
             'output':{'title':'Selected product tiers','summary':', '.join(plan['selection']['tiers'])+' / '+plan['selection']['mode']}}
    plan['summary_check_id']=api.request(path,'POST',payload)['id']
    for check in plan['checks']:
        check['check_id']=api.request(path,'POST',dict(name=check['name'],head_sha=plan['sha'],status='queued',
            external_id=plan['execution_id']+':'+check['key'],details_url=url(plan)))['id']
    identity={k:plan[k] for k in ('repository','sha','trigger_id','trigger_attempt','build_id','build_attempt','execution_id','control_sha')}
    external=f"ci-tier-origin:{plan['trigger_id']}:{plan['trigger_attempt']}"
    checks=api.pages(f"repos/{plan['repository']}/commits/{plan['sha']}/check-runs?filter=all",'check_runs')
    existing=[c for c in checks if c.get('external_id')==external]
    if len(existing)>1:raise ValueError('ambiguous producer registration')
    payload=dict(name='CI / build execution',status='in_progress',external_id=external,details_url=url(plan),
                 output={'title':'Build execution','summary':plan['execution_id'],'text':json.dumps(identity)})
    if existing:api.request(path+'/'+str(existing[0]['id']),'PATCH',payload)
    else:api.request(path,'POST',dict(payload,head_sha=plan['sha']))
    return plan

def publish_result(plan,key,status,api,run_id,attempt):
    check=next(c for c in plan['checks'] if c['key']==key)
    path=f"repos/{plan['repository']}/check-runs/{check['check_id']}"
    current=api.request(f"repos/{plan['repository']}/actions/runs/{int(run_id)}")
    if int(current['run_attempt'])!=int(attempt):raise ValueError('refusing stale consumer attempt result')
    meta=dict(execution_id=plan['execution_id'],key=key,run_id=int(run_id),attempt=int(attempt))
    payload=dict(status='in_progress' if status=='in_progress' else 'completed',details_url=url(plan,run_id),
        output={'title':check['name'],'summary':status,'text':json.dumps(meta)})
    if status!='in_progress':payload['conclusion']=status
    api.request(path,'PATCH',payload)
    if status=='in_progress':
        api.request(f"repos/{plan['repository']}/check-runs/{plan['summary_check_id']}",'PATCH',
                    {'status':'in_progress','output':{'title':'Selected product tiers','summary':'Execution in progress'}})

def reconcile(plan,api):
    observed=[];runs={}
    all_checks=api.pages(f"repos/{plan['repository']}/commits/{plan['sha']}/check-runs?filter=all",'check_runs')
    by_id={c['id']:c for c in all_checks}
    for check in plan['checks']:
        result=by_id.get(check['check_id'])
        if result is None:continue
        if result.get('external_id')!=plan['execution_id']+':'+check['key']:raise ValueError('foreign check identity')
        row=dict(result,key=check['key'],execution_id=plan['execution_id'])
        try:meta=json.loads(result.get('output',{}).get('text') or '{}')
        except ValueError:meta={}
        if meta.get('run_id'):
            rid=meta['run_id']
            if rid not in runs:runs[rid]=api.request(f"repos/{plan['repository']}/actions/runs/{rid}")
            if runs[rid]['run_attempt']!=meta.get('attempt'):row['status']='in_progress'
        observed.append(row)
    state=aggregate_state(plan,observed)
    api.request(f"repos/{plan['repository']}/check-runs/{plan['summary_check_id']}",'PATCH',state)
    return state
