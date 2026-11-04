"""Stateful JSON tool API. Use: audit_control.py REQUEST.json (or - for stdin).

Use describe for available actions and next_action for grounded request templates.
No arbitrary command execution or dynamic attacks.
"""
from __future__ import annotations
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
from datetime import datetime, timezone
from contextlib import contextmanager

from audit_profiles import VERSION, PROFILES, profile
from audit_depth import measure_project, RISK_FACTORS, evaluate_high_only
from audit_report import validate, render, compare
from audit_contracts import HIGH_FIELDS, high_errors, validate_triage, candidate_records, all_candidates, text as nonempty
from audit_guidance import coverage_review, template, finding_draft

SCRIPT = Path(__file__).resolve().parent
TASKS = {
    'changed-review': ('references/self-review.md', 'Inspect changed auth/payment/upload/config paths; supply baseline and locations.'),
    'interfaces': ('references/api-audit.md', 'Inventory interfaces; record caller, object permission, input/output and rate limits. State unknown totals.'),
    'trust-review': ('references/advanced-risks.md', 'Trace input through authentication and trust boundaries to sensitive operations; explain applicability.'),
    'validation-plan': ('references/attack-testing.md', 'Record hypotheses and authorization/isolation evidence, or explicitly explain why no dynamic test ran.'),
    'second-pass': ('references/audit-prompts.md', 'Recheck critical paths using alternative abuse hypotheses; evidence must identify paths and first-pass assumptions.'),
    'high-evidence': ('references/report-format.md', 'Submit H1-H8 records with evidence or reasoned N/A; H6/H8 always required.'),
    'coverage': ('references/report-format.md', 'List reviewed_files and interfaces with id/file/reviewed. Explicitly attest interface_inventory_complete; counts are computed. Unknown totals keep this task blocked.'),
    'triage': ('references/risk-standards.md', 'Classify every candidate as confirmed, false-positive, manual-review or resolved; confirmed/resolved require linked findings, resolved also requires retest evidence.'),
}
EXCLUDED = {'.git', 'node_modules', 'vendor', '.venv', 'venv', '__pycache__', 'dist', 'build', 'target', '.next'}


def stamp():
    return datetime.now(timezone.utc).isoformat()


def outside(path, target):
    path = Path(path).resolve()
    if path == target or target in path.parents:
        raise ValueError('audit state/output must be outside target project')
    return path


def snapshot(target):
    """Content snapshot of included files, bounded at 50k files and 1GiB."""
    rows, omitted = [], []
    total_bytes = 0
    for root, dirs, files in os.walk(target, onerror=lambda e: omitted.append('unreadable directory')):
        for d in dirs:
            if d in EXCLUDED or (Path(root)/d).is_symlink():
                omitted.append(str((Path(root)/d).relative_to(target)))
        dirs[:] = sorted(d for d in dirs if d not in EXCLUDED and not (Path(root)/d).is_symlink())
        for name in sorted(files):
            p = Path(root)/name
            if p.is_symlink():
                omitted.append(str(p.relative_to(target))); continue
            try:
                st = p.stat()
                total_bytes += st.st_size
                if total_bytes > 1024**3:
                    raise ValueError('snapshot exceeds 1GiB; narrow target scope')
                digest = hashlib.sha256()
                with p.open('rb') as stream:
                    for chunk in iter(lambda: stream.read(1024 * 1024), b''):
                        digest.update(chunk)
                rows.append((p.relative_to(target).as_posix(), st.st_size, digest.hexdigest()))
            except OSError:
                omitted.append(str(p.relative_to(target)))
            if len(rows) >= 50000:
                raise ValueError('snapshot exceeds 50000 files; narrow target scope')
    # Detect HEAD changes even when working-tree metadata is unchanged.
    try:
        git = subprocess.run(['git','rev-parse','HEAD'], cwd=target, capture_output=True, timeout=5)
        head = git.stdout.decode('ascii', 'replace').strip() if git.returncode == 0 else None
    except (OSError, subprocess.TimeoutExpired):
        head = None
    digest = hashlib.sha256(json.dumps([rows, omitted, head], sort_keys=True).encode()).hexdigest()
    return dict(fingerprint=digest, files=len(rows), file_paths=[r[0] for r in rows], omitted=omitted, head=head,
                method='path-content-SHA256-and-HEAD; excluded trees are not tracked')


def inspect(target, params):
    manifests = []
    for root, dirs, files in os.walk(target):
        depth = len(Path(root).relative_to(target).parts)
        dirs[:] = sorted(d for d in dirs if d not in EXCLUDED and not (Path(root)/d).is_symlink()) if depth < params['manifest_depth'] else []
        for n in sorted(files):
            if n in ('package-lock.json','npm-shrinkwrap.json','requirements.txt','go.mod','Cargo.toml','composer.json'):
                manifests.append((Path(root)/n).relative_to(target).as_posix())
    return dict(metrics=measure_project(target), manifests=manifests,
                note='Manifest discovery is depth-limited. Routing/interface metrics are estimates.')


def build_plan(info, params, risks=None):
    checks = [dict(id='secrets', kind='tool', tool='secrets', status='pending'),
              dict(id='history', kind='tool', tool='history', status='pending'),
              dict(id='configuration', kind='tool', tool='configuration', status='pending')]
    for parent in sorted({str(Path(m).parent) for m in info['manifests']}):
        checks.append(dict(id='dependencies:' + parent, kind='tool', tool='dependencies', relative=parent, status='pending'))
    if not info['manifests']:
        checks.append(dict(id='dependency-scope', kind='review', status='pending',
            instruction='No supported manifest found; explain dependency scope or mark incomplete.'))
    checks += [dict(id=t, kind='review', status='pending', reference=TASKS[t][0], instruction=TASKS[t][1])
               for t in params['review_tasks'] + ['triage', 'coverage']]
    for c in checks:
        if c['id'] in ('trust-review','changed-review','second-pass'):
            c['instruction'] += ' Declared risk focus: ' + ', '.join(risks or ['not specified; record unknowns'])
    return checks


def save(path, state):
    state['updated_at'] = stamp()
    fd, tmp = tempfile.mkstemp(dir=path.parent, prefix='.audit-', suffix='.tmp')
    try:
        with os.fdopen(fd, 'w', encoding='utf-8') as f:
            json.dump(state, f, ensure_ascii=True, indent=2)
        os.replace(tmp, path)
    finally:
        if os.path.exists(tmp): os.unlink(tmp)


@contextmanager
def locked(path):
    lock = path.with_suffix(path.suffix + '.lock')
    fd = os.open(lock, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    try:
        os.write(fd, str(os.getpid()).encode()); os.close(fd)
        yield
    finally:
        lock.unlink()


def invoke(check, state):
    params, target = state['parameters'], state['target']
    kind = check['tool']
    if kind == 'secrets':
        cmd = [sys.executable, str(SCRIPT/'scan_secrets.py'), target, '--json', '--max-size-mb', str(params['file_limit_mb'])]
        timeout = params['scan_timeout']
    elif kind == 'history':
        cmd = [sys.executable, str(SCRIPT/'audit_history.py'), target, '--commits', str(params['history_commits']),
            '--timeout', str(params['history_timeout']), '--max-bytes', str(params['history_output_mb']*1_000_000)]
        timeout = params['history_timeout'] + 10
    else:
        cmd = [sys.executable, str(SCRIPT/'audit_worker.py'), kind,
            str(Path(target)/check.get('relative','.')), str(params['dependency_timeout'])]
        if kind == 'dependencies':cmd.append('true' if params['dependency_include_dev'] else 'false')
        timeout = params['dependency_timeout'] * 5 + 15 if kind == 'dependencies' else params['scan_timeout']
    with tempfile.TemporaryFile() as stdout, tempfile.TemporaryFile() as stderr:
        proc = subprocess.Popen(cmd, stdout=stdout, stderr=stderr, start_new_session=(os.name!='nt'))
        deadline = time.monotonic()+timeout
        limit = params['output_limit_mb']*1_000_000
        while proc.poll() is None:
            if time.monotonic()>deadline or stdout.tell()+stderr.tell()>limit:
                if os.name=='nt':
                    subprocess.run(['taskkill','/PID',str(proc.pid),'/T','/F'],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
                else:
                    import signal
                    os.killpg(proc.pid,signal.SIGKILL)
                proc.wait()
                return dict(execution='incomplete', assessment='unknown', reason='timeout or output limit')
            time.sleep(.05)
        if stdout.tell()>limit:
            return dict(execution='incomplete', assessment='unknown', reason='output limit')
        stdout.seek(0)
        try: data=json.loads(stdout.read(limit).decode('utf-8-sig'))
        except (ValueError, UnicodeError):
            return dict(execution='error', assessment='unknown', reason='invalid tool JSON; raw output omitted')
    if not isinstance(data, dict):
        return dict(execution='error', assessment='unknown', reason='unexpected output type')
    if kind in ('secrets','history'):
        candidates=data.get('hits',[])
        complete = proc.returncode in (0,1) and data.get('status','complete') == 'complete'
        coverage = data.get('coverage', 'bounded' if kind == 'history' else 'partial')
        return dict(execution='complete' if complete else 'incomplete', assessment='candidates' if candidates else 'no-candidates' if complete and coverage != 'partial' else 'unknown',
                    coverage=coverage, candidates=candidates, details=data)
    if kind=='dependencies':
        results=data.get('dependency_results',[])
        complete=proc.returncode==0 and bool(results) and all(r.get('execution')=='complete' for r in results)
        candidates=[c for r in results for c in r.get('candidates',[])]
        return dict(execution='complete' if complete else 'incomplete',
            assessment='candidates' if candidates else 'no-candidates' if complete else 'unknown',
            candidates=candidates,details=data)
    summary=data.get('summary',{})
    complete=proc.returncode==0 and summary.get('warn',1)==0
    return dict(execution='complete' if complete else 'incomplete', assessment='candidates' if summary.get('fail',0) else 'no-candidates' if complete else 'unknown', details=data)


def validate_review(item, review, state):
    if not isinstance(review,dict) or review.get('redaction_reviewed') is not True:
        raise ValueError('review requires redaction_reviewed=true')
    if review.get('status') not in ('done','not-applicable','blocked') or not isinstance(review.get('evidence'),str) or not review['evidence'].strip():
        raise ValueError('review requires status and nonempty redacted evidence/reason')
    if item['id'] in ('coverage','triage','high-evidence') and review['status']=='not-applicable':
        raise ValueError('this review always applies')
    if item['id']=='high-evidence' and review['status']=='done':
        errors=high_errors(review.get('high_only',{}), state.get('evidence_root'))
        if errors: raise ValueError('; '.join(errors))
    if item['id']=='second-pass' and review['status']=='done':
        items=review.get('analysis')
        if not isinstance(items,list) or not items or any(not isinstance(x,dict) or any(not nonempty(x.get(k)) for k in ('target','alternative_hypothesis','observation')) for x in items):
            raise ValueError('second-pass.analysis needs target/alternative_hypothesis/observation records')
    if item['id']=='coverage' and review['status']=='done':
        coverage_review(review,state)
    if not isinstance(review.get('findings',[]),list):raise ValueError('review.findings must be a list')
    for f in review.get('findings',[]):
        probe=dict(project='review',date='review',scope=['review'],limitations=[],depth='quick',
            coverage={'files':{'reviewed':0,'total':0},'interfaces':{'reviewed':0,'total':0}},
            checks=[{'status':'pass','evidence':'review'}],findings=[f],dynamic={'executed':False,'reason':'review'},redaction_reviewed=True)
        if validate(probe): raise ValueError('invalid finding: '+ '; '.join(validate(probe)))
    if item['id']=='triage' and review['status']=='done':validate_triage(review,state)


def finalize(state, output):
    if any(c['status'] not in ('done','not-applicable') for c in state['checks']):
        raise ValueError('unfinished/blocked checks; use status to see limitations')
    for c in state['checks']:
        if c['kind']=='review':validate_review(c,c['review'],state)
    coverage=next(c['review']['coverage'] for c in state['checks'] if c['id']=='coverage')
    findings=[]; limitations=[]; checks=[]
    for c in state['checks']:
        review=c.get('review',{})
        findings.extend(review.get('findings',[]))
        if c['kind']=='tool':
            r=c['result']
            status='pass' if r['execution']=='complete' and r['assessment']=='no-candidates' and r.get('coverage')!='partial' else 'fail' if r['assessment']=='candidates' else 'error'
            if status!='pass': limitations.append(c['id']+': '+r['execution']+'/'+r['assessment'])
            for skip in r.get('details',{}).get('skipped',[]):
                limitations.append(c['id'] + ': ' + skip['path'] + ' (' + skip['reason'] + ')')
            limitations.extend(c['id'] + ': ' + reason for reason in r.get('details',{}).get('limitations',[]))
        else: status='not-applicable' if c['status']=='not-applicable' else 'pass'
        checks.append(dict(status=status,evidence=c['id']+': '+review.get('evidence','see audit state result')))
    limitations += state['snapshot']['omitted']
    limitations += ['Content snapshot excludes listed trees; heuristic inventory; no unconditional release decision.']
    triage=next(c['review']['dispositions'] for c in state['checks'] if c['id']=='triage')
    candidates=[dict(c,disposition=triage[c['id']]) for c in all_candidates(state)]
    document=dict(project=Path(state['target']).name,date=stamp(),scope=[state['target']],limitations=limitations,
        depth=state['depth'],coverage=coverage,coverage_complete=False,checks=checks,findings=findings,
        dynamic={'executed':False,'reason':'Controller never executes dynamic attacks; external validation must be reported separately'},
        redaction_reviewed=True,conclusion='manual review required',parameters=state['parameters'],candidates=candidates,
        unresolved_candidates=[c for c in candidates if c['disposition']['status']=='manual-review'])
    if state['depth']=='comprehensive-high':
        document['high_only']=next(c['review']['high_only'] for c in state['checks'] if c['id']=='high-evidence')
    errors=validate(document)
    if errors:raise ValueError('; '.join(errors))
    output=outside(output,Path(state['target']))
    # Create both files exclusively; roll back JSON if Markdown cannot be created.
    jsonpath=output.with_suffix('.json'); mdpath=output.with_suffix('.md')
    if jsonpath.exists() or mdpath.exists():raise ValueError('output exists')
    with jsonpath.open('x',encoding='utf-8') as f:json.dump(document,f,ensure_ascii=True,indent=2)
    try:
        with mdpath.open('x',encoding='utf-8') as f:f.write(render(document))
    except Exception:
        jsonpath.unlink();raise
    return dict(json=str(jsonpath),markdown=str(mdpath))


def dispatch(request):
    validate_request(request)
    action=request.get('action')
    if action=='describe':
        return dict(version=VERSION,transport='JSON file or stdin; standard-library Python CLI',
            actions={
                'profiles':[], 'start':['state','target','depth=quick|low|high','risks=[]'],
                'inspect':['state'], 'plan':['state'], 'next_action':['state'], 'status':['state'],
                'progress':['state'], 'file_inventory':['state','offset=0','limit=100'],
                'review_template':['state','check_id'], 'finding_draft':['state','candidate_id'],
                'run_pending':['state','max_checks=3','allow_network=false'],
                'write_evidence':['state','h_id','items','summary','redaction_reviewed=true'],
                'run_check':['state','check_id','allow_network=false','retry=false'],
                'skip_check':['state','check_id','reason'],
                'record_review':['state','check_id','review'], 'refresh':['state'],
                'finalize':['state','output','redaction_reviewed=true'],
                'compare':['previous','current']},
            high_evidence_fields=HIGH_FIELDS,
            review_fields=['status=done|blocked|not-applicable','evidence','redaction_reviewed=true',
                'findings=[]','reviewed_files/interfaces/interface_inventory_complete (coverage task)',
                'dispositions keyed by candidate ID; confirmed/resolved need finding_id; resolved needs retest',
                'analysis: target/alternative_hypothesis/observation (second-pass)',
                'high_only: artifact/sha256/summary/items evidence objects (high-evidence)'])
    if action=='profiles':return dict(version=VERSION,profiles=PROFILES)
    if action=='compare':
        old=json.loads(Path(request['previous']).read_text(encoding='utf-8-sig'))
        new=json.loads(Path(request['current']).read_text(encoding='utf-8-sig'))
        if validate(old) or validate(new): raise ValueError('invalid comparison report')
        return compare(old,new)
    path=Path(request['state']).resolve()
    if not path.parent.is_dir():raise ValueError('state parent must exist')
    with locked(path):
        if action=='start':
            if path.exists():raise ValueError('state already exists')
            target=Path(request['target']).resolve()
            if not target.is_dir():raise ValueError('target must be a directory')
            outside(path,target)
            mode,params=profile(request.get('depth','low'))
            risks=request.get('risks',[])
            if not isinstance(risks,list) or set(risks)-set(RISK_FACTORS):raise ValueError('invalid risks')
            info=inspect(target,params)
            state=dict(version=VERSION,target=str(target),depth=mode,parameters=params,risks=risks,
                snapshot=snapshot(target),inspection=info,checks=build_plan(info,params,risks),created_at=stamp(),events=[],evidence_root=str(path.parent))
            save(path,state)
            return dict(state=str(path),depth=mode,parameters=params,checks=state['checks'])
        state=json.loads(path.read_text(encoding='utf-8-sig'))
        if state.get('version')!=VERSION:raise ValueError('state version mismatch; start a new audit')
        target=Path(state['target']);outside(path,target)
        if action=='progress':
            return dict(freshness='not-rechecked',updated_at=state['updated_at'],
                completed=sum(c['status'] in ('done','not-applicable') for c in state['checks']),total=len(state['checks']),
                pending=[c['id'] for c in state['checks'] if c['status'] not in ('done','not-applicable')])
        if action=='file_inventory':
            files=state['snapshot']['file_paths'];offset=request.get('offset',0);limit=request.get('limit',100)
            return dict(freshness='not-rechecked',snapshot=state['snapshot']['fingerprint'],total=len(files),
                files=files[offset:offset+limit],next_offset=offset+limit if offset+limit<len(files) else None)
        current=snapshot(target)
        stale=current['fingerprint']!=state['snapshot']['fingerprint']
        if action=='refresh':
            if stale:
                state['snapshot']=current;state['inspection']=inspect(target,state['parameters'])
                state['checks']=build_plan(state['inspection'],state['parameters'],state['risks'])
                state.pop('high_artifacts',None)
                state['events'].append(dict(at=stamp(),event='scope changed; all checks invalidated'))
                save(path,state)
            return dict(refreshed=stale,checks=state['checks'])
        if action=='status':return dict(stale=stale,checks=state['checks'],parameters=state['parameters'],snapshot=state['snapshot'])
        if stale:raise ValueError('target changed; refresh required; previous evidence cannot be reused automatically')
        if action=='inspect':return state['inspection']
        if action=='plan':return dict(checks=state['checks'],parameters=state['parameters'])
        if action=='review_template':return template(state,request['check_id'])
        if action=='finding_draft':return finding_draft(state,request['candidate_id'])
        if action=='write_evidence':
            key=request['h_id']; items=request['items']
            if request.get('redaction_reviewed') is not True:raise ValueError('evidence redaction review required')
            if not isinstance(items,list) or not items or any(not isinstance(row,dict) or any(not nonempty(row.get(k)) for k in HIGH_FIELDS[key]) for row in items):
                raise ValueError('items do not match '+key+' fields: '+', '.join(HIGH_FIELDS[key]))
            raw=json.dumps({key:items},ensure_ascii=True,indent=2).encode()
            if len(raw)>5*1024*1024:raise ValueError('evidence exceeds 5MiB')
            digest=hashlib.sha256(raw).hexdigest()
            name='evidence-'+key+'-'+digest+'.json'
            dest=outside(Path(state['evidence_root'])/name,target)
            try:
                with dest.open('xb') as stream:stream.write(raw)
            except FileExistsError:
                if dest.read_bytes()!=raw:raise ValueError('existing artifact mismatch')
            record={'status':'done','evidence':{'artifact':name,'sha256':digest,'summary':request['summary'],'items':items}}
            state.setdefault('high_artifacts',{})[key]=record
            for c in state['checks']:
                if c['id']=='high-evidence':c['status']='pending';c.pop('review',None)
            save(path,state)
            return record
        if action=='next_action':
            pending=next((c for c in state['checks'] if c['status'] in ('pending','blocked')),None)
            next_action=('run_check' if pending['kind']=='tool' else 'record_review') if pending else 'finalize'
            response=dict(next=pending,action=next_action)
            if pending:
                response['request']={'action':next_action,'state':str(path),'check_id':pending['id']}
                if pending['kind']=='review':
                    draft=template(state,pending['id']);response['request']['review']=draft['review'];response['context']=draft['context']
                elif pending['tool']=='dependencies':
                    response['request']['allow_network']=False
                    response['context']={'instruction':'Set allow_network=true only under existing authorization; otherwise skip_check with a reason.'}
            else:
                response['request']={'action':'finalize','state':str(path),
                    'output':str(path.parent/(path.stem+'-report')),'redaction_reviewed':False}
                response['context']={'instruction':'Review redaction and output location; explicitly set redaction_reviewed=true. Existing files are never overwritten.'}
            return response
        if action=='run_pending':
            completed=[];blocked=[]
            for check in state['checks']:
                if check['kind']!='tool' or check['status']=='done':continue
                if check['tool']=='dependencies' and request.get('allow_network') is not True:
                    blocked.append({'check_id':check['id'],'reason':'network authorization needed'});continue
                check['result']=candidate_records(check['id'],invoke(check,state));check['status']='done';check['updated_at']=stamp()
                for c in state['checks']:
                    if c['id']=='triage':c['status']='pending';c.pop('review',None)
                save(path,state)
                completed.append({'check_id':check['id'],'execution':check['result']['execution'],'assessment':check['result']['assessment'],'candidate_count':len(check['result']['candidates'])})
                if len(completed)>=request.get('max_checks',3):break
            return dict(completed=completed,blocked=blocked)
        if action=='finalize':
            if request.get('redaction_reviewed') is not True:raise ValueError('final redaction review required')
            return finalize(state,request['output'])
        if action not in ('run_check','skip_check','record_review'):raise ValueError('unknown action')
        item=next((c for c in state['checks'] if c['id']==request.get('check_id')),None)
        if item is None:raise ValueError('unknown check id')
        if action in ('run_check','skip_check'):
            if item['kind']!='tool':raise ValueError('requires AI review')
            if item['status']=='done' and not request.get('retry'):return item
            if action=='skip_check':
                if not isinstance(request.get('reason'),str) or not request['reason'].strip():raise ValueError('skip requires reason')
                item['result']=dict(execution='skipped',assessment='unknown',reason=request['reason'])
            elif item['tool']=='dependencies' and request.get('allow_network') is not True:
                raise ValueError('dependency check needs allow_network=true; may contact registries')
            else:item['result']=candidate_records(item['id'],invoke(item,state))
            item['status']='done'
            # New candidates invalidate previous triage.
            for c in state['checks']:
                if c['id']=='triage':c['status']='pending';c.pop('review',None)
        else:
            if item['kind']!='review':raise ValueError('cannot replace tool result with review')
            if item['id']=='triage' and any(c['kind']=='tool' and c['status']!='done' for c in state['checks']):raise ValueError('run tool checks before triage')
            review=request['review'];validate_review(item,review,state)
            item['review']=review;item['status']=review['status']
        item['updated_at']=stamp();save(path,state)
        return item


def main():
    try:
        text=sys.stdin.read() if len(sys.argv)<2 or sys.argv[1]=='-' else Path(sys.argv[1]).read_text(encoding='utf-8-sig')
        request=json.loads(text)
        if not isinstance(request,dict):raise ValueError('request must be object')
        result=dispatch(request)
        print(json.dumps(dict(ok=True,result=result),ensure_ascii=True));return 0
    except (ValueError,OSError,KeyError,TypeError,StopIteration) as e:
        print(json.dumps(dict(ok=False,error=str(e)),ensure_ascii=True));return 2


def validate_request(request):
    if not isinstance(request,dict):raise ValueError('request must be object')
    action=request.get('action')
    actions={'describe','profiles','start','inspect','plan','next_action','run_check','skip_check','record_review','status','refresh','finalize','compare','review_template','finding_draft','run_pending','write_evidence','progress','file_inventory'}
    if not isinstance(action,str) or action not in actions:raise ValueError('action: unsupported action')
    fields=[] if action in ('describe','profiles') else ['previous','current'] if action=='compare' else ['state']
    fields += {'start':['target'],'run_check':['check_id'],'skip_check':['check_id','reason'],'record_review':['check_id'],'review_template':['check_id'],'finding_draft':['candidate_id'],'finalize':['output'],'write_evidence':['h_id','summary']}.get(action,[])
    for field in fields:
        if not nonempty(request.get(field)):raise ValueError(field+': nonempty string required')
    for field in ('retry','allow_network','redaction_reviewed'):
        if field in request and type(request[field]) is not bool:raise ValueError(field+': boolean required')
    if 'max_checks' in request and (type(request['max_checks']) is not int or not 1<=request['max_checks']<=10):raise ValueError('max_checks: integer 1..10 required')
    if 'offset' in request and (type(request['offset']) is not int or request['offset']<0):raise ValueError('offset: nonnegative integer required')
    if 'limit' in request and (type(request['limit']) is not int or not 1<=request['limit']<=500):raise ValueError('limit: integer 1..500 required')
    if action=='record_review' and not isinstance(request.get('review'),dict):raise ValueError('review: object required')
    if action=='write_evidence' and request['h_id'] not in HIGH_FIELDS:raise ValueError('h_id: H1..H8 required')
    if action=='start':
        if not isinstance(request.get('depth','low'),str):raise ValueError('depth: string required')
        risks=request.get('risks',[])
        if not isinstance(risks,list) or any(not isinstance(r,str) or r not in RISK_FACTORS for r in risks):raise ValueError('risks: array of supported risk names required')


if __name__=='__main__':raise SystemExit(main())
