#!/usr/bin/env python3
"""Pure CI product configuration and execution identity contracts."""
import hashlib
import itertools
import json
import re

TIERS = {'v40': 'v4.0', 'v30': 'v3.0', 'v31': 'v3.1'}

def resolve_selection(context, trusted, fetch_pr):
    result = {'tiers': ['v40'], 'mode': 'normal', 'pr_number': None}
    if not trusted or context.get('event') != 'pull_request':
        return result
    prs = context.get('pull_requests', [])
    if len(prs) != 1 or not isinstance(prs[0].get('number'), int):
        raise ValueError('PR-backed execution requires one unambiguous PR association')
    result['pr_number'] = prs[0]['number']
    pr = fetch_pr(result['pr_number'])
    labels = {label['name'] for label in pr['labels']}
    result['tiers'] += [tier for tier, label in [('v30', 'ci:v3.0'), ('v31', 'ci:v3.1')] if label in labels]
    result['mode'] = 'asan' if 'ci:asan' in labels else 'normal'
    return result

def check_key(workflow, job, tier, cell):
    identity = json.dumps([workflow, job, tier, cell], sort_keys=True, separators=(',', ':'))
    return hashlib.sha256(identity.encode()).hexdigest()[:24]

def mode_label(tier, mode):
    return ('asan+gcov' if mode == 'asan' else 'coverage') if tier == 'v40' else ('asan' if mode == 'asan' else 'debug')

def make_plan(context, selection, catalogue):
    for field in ('trigger_id', 'trigger_attempt', 'build_id', 'build_attempt'):
        if not isinstance(context.get(field), int) or context[field] <= 0:
            raise ValueError('invalid execution identity: ' + field)
    for field in ('sha', 'control_sha'):
        if not re.fullmatch('[0-9a-f]{40}', context.get(field, '')):
            raise ValueError('invalid ' + field)
    if selection['mode'] not in ('normal', 'asan') or not selection['tiers'] or len(set(selection['tiers'])) != len(selection['tiers']):
        raise ValueError('invalid tier selection')
    eid = 't{trigger_id}-a{trigger_attempt}-b{build_id}-a{build_attempt}'.format(**context)
    plan = dict(context, schema=1, execution_id=eid, selection=selection, legs=[], checks=[])
    for tier in selection['tiers']:
        if tier not in TIERS:
            raise ValueError('invalid product tier')
        mode = selection['mode']
        leg = dict(tier=tier, mode=mode, coverage=tier == 'v40',
                   variant=f'ubuntu24-tap-{tier}-{mode}',
                   artifact_name=f'ci-handoff-{eid}-{tier}-{mode}-full')
        plan['legs'].append(leg)
        plan['checks'].append(dict(key=check_key('CI-builds','builds',tier,{}),workflow='CI-builds',job='builds',
            tier=tier,mode=mode,cell={},groups=[],required=True,applicable=True,
            name=f'CI-builds / builds ({TIERS[tier]}, {mode_label(tier,mode)})'))
        for consumer in catalogue['consumers']:
            if not consumer['automatic'] or tier not in consumer['tiers']:
                continue
            cells = consumer['cells']
            if consumer.get('axes'):
                axes = {k: json.loads(context.get('variables', {})[v['var']]) if isinstance(v,dict) else v for k,v in consumer['axes'].items()}
                if any(not isinstance(v,list) or not v for v in axes.values()):
                    raise ValueError('empty/invalid configured consumer matrix: '+consumer['workflow'])
                cells = [dict(zip(axes,values)) for values in itertools.product(*axes.values())]
            for cell in cells:
                cell = dict(cell)
                if 'instance' in consumer: cell['ci_instance'] = consumer['instance']
                info = ', '.join(str(v) for k,v in cell.items() if k not in ('testdist','ci_instance'))
                middle = (info + ', ') if info else ''
                plan['checks'].append(dict(key=check_key(consumer['workflow'],consumer['job'],tier,cell),
                    workflow=consumer['workflow'],job=consumer['job'],tier=tier,mode=mode,cell=cell,
                    groups=consumer['groups'],required=True,applicable=True,
                    name=f"{consumer['workflow']} / {consumer['job']} ({TIERS[tier]}, {middle}{mode_label(tier,mode)})"))
    return plan

def validate_manifest(plan):
    if plan.get('schema') != 1:
        raise ValueError('unsupported CI manifest schema')
    expected = 't{trigger_id}-a{trigger_attempt}-b{build_id}-a{build_attempt}'.format(**plan)
    if plan.get('execution_id') != expected:
        raise ValueError('manifest execution identity mismatch')
    if len({c['key'] for c in plan['checks']}) != len(plan['checks']):
        raise ValueError('duplicate logical check')
    for leg in plan['legs']:
        if leg['tier'] not in TIERS or leg['mode'] not in ('normal','asan'):
            raise ValueError('invalid manifest leg')
        if leg['artifact_name'] != f"ci-handoff-{expected}-{leg['tier']}-{leg['mode']}-full":
            raise ValueError('handoff identity mismatch')

def consumer_matrix(plan, workflow, job, instance=None):
    validate_manifest(plan)
    return [dict(c['cell'],tier=c['tier'],mode=c['mode'],coverage=c['tier']=='v40',
                 check_key=c['key'],check_name=c['name'],check_id=c.get('check_id',0),
                 execution_id=plan['execution_id'],build_id=plan['build_id'],build_attempt=plan['build_attempt'],
                 artifact_name=next(l['artifact_name'] for l in plan['legs'] if l['tier']==c['tier']))
            for c in plan['checks'] if c['workflow']==workflow and c['job']==job and c['applicable'] and (instance is None or c['cell'].get('ci_instance','run')==instance)]

def version_tuple(version):
    match=re.search(r'(\d+)\.(\d+)\.(\d+)',version)
    if not match:raise ValueError('invalid binary version')
    return tuple(map(int,match.groups()))

def applicable_tests(groups, group, version):
    limit=version_tuple(version)
    return sorted(name for name,tags in groups.items() if group in tags and
                  all(version_tuple(t.split(':',1)[1]) <= limit for t in tags if t.startswith('@proxysql_min_version:')))
