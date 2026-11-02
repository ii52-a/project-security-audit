"""Stateful JSON tool API. Use: audit_control.py REQUEST.json (or - for stdin).

Actions: describe, profiles, start, inspect, plan, next_action, run_check, skip_check, record_review,
status, refresh, finalize, compare. No arbitrary command execution or dynamic attacks.
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

SCRIPT = Path(__file__).resolve().parent
TASKS = {
    'changed-review': ('references/self-review.md', 'Inspect changed auth/payment/upload/config paths; supply baseline and locations.'),
    'interfaces': ('references/api-audit.md', 'Inventory interfaces; record caller, object permission, input/output and rate limits. State unknown totals.'),
    'trust-review': ('references/advanced-risks.md', 'Trace input through authentication and trust boundaries to sensitive operations; explain applicability.'),
    'validation-plan': ('references/attack-testing.md', 'Record hypotheses and authorization/isolation evidence, or explicitly explain why no dynamic test ran.'),
    'second-pass': ('references/audit-prompts.md', 'Recheck critical paths using alternative abuse hypotheses; evidence must identify paths and first-pass assumptions.'),
    'high-evidence': ('references/report-format.md', 'Submit H1-H8 records with evidence or reasoned N/A; H6/H8 always required.'),
    'coverage': ('references/report-format.md', 'Submit reviewed/total files and interfaces, omissions, and evidence index. Unknown totals remain limitations.'),
    'triage': ('references/risk-standards.md', 'Classify every automated candidate as confirmed, false-positive or manual-review; link finding IDs where appropriate.'),
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
    """Metadata snapshot, not a content integrity guarantee; bound at 50k files."""
    rows, omitted = [], []
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
                rows.append((p.relative_to(target).as_posix(), st.st_size, st.st_mtime_ns))
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
    return dict(fingerprint=digest, files=len(rows), omitted=omitted, head=head,
                method='path-size-mtime-ns-and-HEAD; excluded trees are not tracked')


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


def build_plan(info, params):
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
        return dict(execution='complete' if complete else 'incomplete', assessment='candidates' if candidates else 'no-candidates' if complete else 'unknown',
                    candidates=candidates, details=data)
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
        errors=evaluate_high_only(review.get('high_only',{}))['issues']
        if errors: raise ValueError('; '.join(errors))
    if item['id']=='coverage' and review['status']=='done':
        counts=review.get('coverage',{})
        for k in ('files','interfaces'):
            c=counts.get(k,{})
            if any(type(c.get(x)) is not int or c[x]<0 for x in ('reviewed','total')) or c['reviewed']>c['total']:
                raise ValueError('coverage requires valid reviewed/total counts; unknown totals must remain blocked')
    if item['id']=='triage' and review['status']=='done':
        expected={c['id'] for c in state['checks'] if c.get('result',{}).get('assessment')=='candidates'}
        dispositions=review.get('dispositions',{})
        if not expected.issubset(dispositions):
            raise ValueError('triage must address every check with candidates')
        for k in expected:
            d=dispositions[k]
            if not isinstance(d,dict) or d.get('status') not in ('confirmed','false-positive','manual-review') or not d.get('evidence'):
                raise ValueError('disposition needs status and evidence; account for every candidate in evidence')
    for f in review.get('findings',[]):
        probe=dict(project='review',date='review',scope=['review'],limitations=[],depth='quick',
            coverage={'files':{'reviewed':0,'total':0},'interfaces':{'reviewed':0,'total':0}},
            checks=[{'status':'pass','evidence':'review'}],findings=[f],dynamic={'executed':False,'reason':'review'},redaction_reviewed=True)
        if validate(probe): raise ValueError('invalid finding: '+ '; '.join(validate(probe)))


def finalize(state, output):
    if any(c['status'] not in ('done','not-applicable') for c in state['checks']):
        raise ValueError('unfinished/blocked checks; use status to see limitations')
    coverage=next(c['review']['coverage'] for c in state['checks'] if c['id']=='coverage')
    findings=[]; limitations=[]; checks=[]
    for c in state['checks']:
        review=c.get('review',{})
        findings.extend(review.get('findings',[]))
        if c['kind']=='tool':
            r=c['result']
            status='pass' if r['execution']=='complete' and r['assessment']=='no-candidates' else 'fail' if r['assessment']=='candidates' else 'error'
            if status!='pass': limitations.append(c['id']+': '+r['execution']+'/'+r['assessment'])
        else: status='not-applicable' if c['status']=='not-applicable' else 'pass'
        checks.append(dict(status=status,evidence=c['id']+': '+review.get('evidence','see audit state result')))
    limitations += state['snapshot']['omitted']
    limitations += ['Metadata snapshot and heuristic inventory; no unconditional release decision.']
    document=dict(project=Path(state['target']).name,date=stamp(),scope=[state['target']],limitations=limitations,
        depth=state['depth'],coverage=coverage,coverage_complete=False,checks=checks,findings=findings,
        dynamic={'executed':False,'reason':'Controller never executes dynamic attacks; external validation must be reported separately'},
        redaction_reviewed=True,conclusion='manual review required',parameters=state['parameters'])
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
    action=request.get('action')
    if action=='describe':
        return dict(version=VERSION,transport='JSON file or stdin; standard-library Python CLI',
            actions={
                'profiles':[], 'start':['state','target','depth=quick|low|high','risks=[]'],
                'inspect':['state'], 'plan':['state'], 'next_action':['state'], 'status':['state'],
                'run_check':['state','check_id','allow_network=false','retry=false'],
                'skip_check':['state','check_id','reason'],
                'record_review':['state','check_id','review'], 'refresh':['state'],
                'finalize':['state','output','redaction_reviewed=true'],
                'compare':['previous','current']},
            review_fields=['status=done|blocked|not-applicable','evidence','redaction_reviewed=true',
                'findings=[]','coverage (coverage task)','dispositions (triage task)','high_only (high-evidence task)'])
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
                snapshot=snapshot(target),inspection=info,checks=build_plan(info,params),created_at=stamp(),events=[])
            for c in state['checks']:
                if c['id'] in ('trust-review','changed-review','second-pass'):
                    c['instruction'] += ' Declared risk focus: ' + ', '.join(risks or ['not specified; record unknowns'])
            save(path,state)
            return dict(state=str(path),depth=mode,parameters=params,checks=state['checks'])
        state=json.loads(path.read_text(encoding='utf-8-sig'))
        if state.get('version')!=VERSION:raise ValueError('state version mismatch; start a new audit')
        target=Path(state['target']);outside(path,target)
        current=snapshot(target)
        stale=current['fingerprint']!=state['snapshot']['fingerprint']
        if action=='refresh':
            if stale:
                state['snapshot']=current;state['inspection']=inspect(target,state['parameters'])
                state['checks']=build_plan(state['inspection'],state['parameters'])
                state['events'].append(dict(at=stamp(),event='scope changed; all checks invalidated'))
                save(path,state)
            return dict(refreshed=stale,checks=state['checks'])
        if action=='status':return dict(stale=stale,checks=state['checks'],parameters=state['parameters'],snapshot=state['snapshot'])
        if stale:raise ValueError('target changed; refresh required; previous evidence cannot be reused automatically')
        if action=='inspect':return state['inspection']
        if action=='plan':return dict(checks=state['checks'],parameters=state['parameters'])
        if action=='next_action':
            pending=next((c for c in state['checks'] if c['status'] in ('pending','blocked')),None)
            return dict(next=pending,action=('run_check' if pending['kind']=='tool' else 'record_review') if pending else 'finalize')
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
            else:item['result']=invoke(item,state)
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


if __name__=='__main__':raise SystemExit(main())
