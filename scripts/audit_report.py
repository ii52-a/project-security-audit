"""Validate, render and compare redacted audit records. No external dependencies."""
import argparse
import json
from pathlib import Path
from audit_depth import evaluate_high_only


def validate(data):
    errors = []
    if not isinstance(data, dict):
        return ['report must be an object']
    for key in ('project', 'date', 'scope', 'limitations', 'depth', 'coverage', 'findings', 'checks', 'dynamic'):
        if key not in data:
            errors.append('missing ' + key)
    for key in ('project', 'date'):
        if not isinstance(data.get(key), str) or not data[key].strip():
            errors.append('empty ' + key)
    if not isinstance(data.get('scope'), list) or not data.get('scope'):
        errors.append('scope must be a nonempty list')
    if not isinstance(data.get('limitations'), list):
        errors.append('limitations must be a list')
    if data.get('depth') not in ('quick', 'comprehensive-low', 'comprehensive-high'):
        errors.append('invalid depth')
    findings = data.get('findings', [])
    if not isinstance(findings, list):
        return errors + ['findings must be a list']
    ids = set()
    for f in findings:
        if not isinstance(f, dict):
            errors.append('finding must be an object')
            continue
        for k in ('id', 'title', 'severity', 'confidence', 'status', 'location', 'evidence', 'remediation'):
            if not isinstance(f.get(k), str) or not f[k].strip():
                errors.append('finding requires nonempty ' + k)
        if str(f.get('id')) in ids:
            errors.append('duplicate finding ID')
        ids.add(str(f.get('id')))
        if f.get('severity') not in ('P0', 'P1', 'P2', 'P3'):
            errors.append('invalid severity')
        if f.get('confidence') not in ('high', 'medium', 'low'):
            errors.append('invalid confidence')
        if f.get('status') not in ('confirmed', 'suspected', 'not-reproduced', 'resolved'):
            errors.append('invalid evidence status')
    coverage = data.get('coverage', {})
    if not isinstance(coverage, dict):
        errors.append('coverage must be an object')
    else:
        for key in ('files', 'interfaces'):
            c = coverage.get(key, {})
            if not isinstance(c, dict) or any(type(c.get(k)) is not int or c[k] < 0 for k in ('reviewed', 'total')):
                errors.append('invalid coverage: ' + key)
            elif c['reviewed'] > c['total']:
                errors.append('coverage exceeds total')
    checks = data.get('checks')
    if not isinstance(checks, list) or not checks:
        errors.append('checks must be a nonempty list')
    else:
        for c in checks:
            if not isinstance(c, dict) or c.get('status') not in ('pass', 'fail', 'error', 'skipped', 'not-applicable') or not c.get('evidence'):
                errors.append('check requires status and evidence/reason')
    dynamic = data.get('dynamic', {})
    if not isinstance(dynamic, dict):
        errors.append('invalid dynamic record')
    elif dynamic.get('executed') is True:
        if data.get('depth') == 'quick':
            errors.append('quick forbids dynamic tests')
        for k in ('authorization', 'isolation', 'tests', 'cleanup'):
            if not dynamic.get(k):
                errors.append('dynamic testing requires ' + k)
        tests = dynamic.get('tests')
        if not isinstance(tests, list) or not tests:
            errors.append('dynamic tests must be a nonempty list')
        else:
            for test in tests:
                if not isinstance(test, dict) or any(not isinstance(test.get(k), str) or not test[k].strip() for k in ('id', 'plan', 'hypothesis', 'outcome', 'evidence')):
                    errors.append('each dynamic test needs id/plan/hypothesis/outcome/evidence')
        cleanup = dynamic.get('cleanup')
        if not isinstance(cleanup, dict) or cleanup.get('complete') is not True or not cleanup.get('evidence'):
            errors.append('cleanup must be complete with evidence')
    elif dynamic.get('executed') is not False or not dynamic.get('reason'):
        errors.append('dynamic skipped requires executed=false and reason')
    if data.get('depth') == 'comprehensive-high':
        high = data.get('high_only', {})
        if not isinstance(high, dict):
            errors.append('high_only must be an object')
        else:
            errors.extend(evaluate_high_only(high)['issues'])
    if data.get('redaction_reviewed') is not True:
        errors.append('human/agent redaction review required before persistence')
    if data.get('conclusion') == 'releasable':
        if data.get('depth') == 'quick' or data.get('coverage_complete') is not True or data.get('limitations'):
            errors.append('incomplete coverage cannot declare releasable')
        if any(isinstance(c, dict) and c.get('status') not in ('pass', 'not-applicable') for c in (checks if isinstance(checks, list) else [])):
            errors.append('unresolved checks block release')
        if any(isinstance(f, dict) and f.get('status') != 'resolved' for f in findings):
            errors.append('unresolved findings require remediation/review conclusion')
        if isinstance(coverage, dict):
            for counts in coverage.values():
                if isinstance(counts, dict) and counts.get('reviewed') != counts.get('total'):
                    errors.append('partial coverage blocks releasable conclusion')
    return errors


def compare(old, new):
    before = {f['id']: f for f in old['findings']}
    after = {f['id']: f for f in new['findings']}
    return dict(added=sorted(after.keys() - before.keys()),
                absent_requires_review=sorted(before.keys() - after.keys()),
                resolved=[k for k in after if k in before and after[k]['status'] == 'resolved' and before[k]['status'] != 'resolved'],
                changed=[k for k in after if k in before and after[k] != before[k]],
                scope_changed=old['scope'] != new['scope'])


def render(data):
    errors = validate(data)
    if errors:
        raise ValueError('; '.join(errors))
    lines = ['# Security Audit Report: ' + data['project'], '',
             'Date: ' + data['date'], 'Depth: ' + data['depth'], '',
             '## Scope and limitations', json.dumps({k: data[k] for k in ('scope', 'limitations', 'coverage')}, ensure_ascii=False),
             '', '## Conclusion', data.get('conclusion', 'manual review required'), '', '## Findings']
    for f in data['findings']:
        lines += ['', '### ' + f['id'] + ' [' + f['severity'] + '] ' + f['title']]
        lines += [k + ': ' + f[k] for k in ('status', 'confidence', 'location', 'evidence', 'remediation')]
    for key in ('parameters', 'checks', 'dynamic', 'high_only', 'score', 'roadmap', 'structure', 'performance'):
        if key in data:
            lines += ['', '## ' + key.title(), '```json', json.dumps(data[key], ensure_ascii=False, indent=2), '```']
    return '\n'.join(lines) + '\n'


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('record')
    p.add_argument('--render', metavar='OUTPUT')
    p.add_argument('--compare', metavar='PREVIOUS')
    a = p.parse_args()
    try:
        data = json.loads(Path(a.record).read_text(encoding='utf-8-sig'))
        errors = validate(data)
        if errors:
            print(json.dumps({'errors': errors})); return 1
        if a.compare:
            old = json.loads(Path(a.compare).read_text(encoding='utf-8-sig'))
            if validate(old):
                raise ValueError('previous report is invalid')
            print(json.dumps(compare(old, data), indent=2))
        elif a.render:
            with Path(a.render).open('x', encoding='utf-8') as out:
                out.write(render(data))
        else:
            print('VALID')
        return 0
    except (OSError, ValueError, TypeError) as e:
        print(json.dumps({'error': str(e)})); return 2


if __name__ == '__main__':
    raise SystemExit(main())
