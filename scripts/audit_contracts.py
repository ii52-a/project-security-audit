"""Typed evidence and candidate contracts. Checks structure, not truth of claims."""
import hashlib
import json
from pathlib import Path
import re

HIGH_FIELDS = {
    'H1': ('interface', 'caller', 'object_check', 'output', 'rate_limit'),
    'H2': ('boundary', 'identity', 'trust_check'),
    'H3': ('hypothesis', 'method', 'outcome'),
    'H4': ('component', 'version', 'advisory_check'),
    'H5': ('target', 'alternative_hypothesis', 'observation'),
    'H6': ('scope', 'coverage', 'evidence_index'),
    'H7': ('configuration', 'check', 'observation'),
    'H8': ('finding_ids', 'conclusion_check', 'remediation_check'),
}


def text(value):
    return isinstance(value, str) and bool(value.strip())


def high_errors(statuses, root=None):
    errors = []
    if not isinstance(statuses, dict):
        return ['high_only must be an object']
    for key, fields in HIGH_FIELDS.items():
        record = statuses.get(key)
        if not isinstance(record, dict):
            errors.append(key + ': missing structured record'); continue
        if record.get('status') == 'n/a' and key not in ('H6', 'H8') and text(record.get('reason')):
            continue
        evidence = record.get('evidence')
        if record.get('status') != 'done' or not isinstance(evidence, dict):
            errors.append(key + ': done requires structured evidence'); continue
        if not all(text(evidence.get(k)) for k in ('artifact', 'summary', 'sha256')) or not re.fullmatch('[0-9a-f]{64}', str(evidence.get('sha256', ''))):
            errors.append(key + ': artifact/summary/SHA256 required')
        items = evidence.get('items')
        if not isinstance(items, list) or not items or any(not isinstance(row, dict) or any(not text(row.get(k)) for k in fields) for row in items):
            errors.append(key + ': evidence items require ' + ', '.join(fields))
        if root is not None and text(evidence.get('artifact')):
            base = Path(root).resolve(); p = (base / evidence['artifact']).resolve()
            if p == base or base not in p.parents:
                errors.append(key + ': artifact must be inside evidence directory'); continue
            try:
                if p.stat().st_size > 5 * 1024 * 1024:
                    errors.append(key + ': artifact exceeds 5MiB'); continue
                raw = p.read_bytes()
                if hashlib.sha256(raw).hexdigest() != evidence.get('sha256'):
                    errors.append(key + ': artifact hash mismatch')
                artifact = json.loads(raw.decode('utf-8-sig'))
                if not isinstance(artifact, dict) or artifact.get(key) != items:
                    errors.append(key + ': artifact JSON must contain matching items under ' + key)
            except (OSError, ValueError, UnicodeError):
                errors.append(key + ': unreadable/invalid JSON artifact')
    return errors


def all_candidates(state):
    return [candidate for check in state['checks'] for candidate in check.get('result', {}).get('candidates', [])]


def validate_triage(review, state):
    candidates = all_candidates(state)
    expected = {c['id'] for c in candidates}
    dispositions = review.get('dispositions')
    if not isinstance(dispositions, dict) or set(dispositions) != expected:
        raise ValueError('review.dispositions must account for every candidate ID exactly')
    findings = [f for c in state['checks'] if c['id'] != 'triage' for f in c.get('review', {}).get('findings', [])] + review.get('findings', [])
    by_id = {f['id']: f for f in findings if isinstance(f, dict) and text(f.get('id'))}
    for key, disposition in dispositions.items():
        if not isinstance(disposition, dict) or disposition.get('status') not in ('confirmed', 'false-positive', 'manual-review', 'resolved') or not text(disposition.get('evidence')):
            raise ValueError('review.dispositions.' + key + ' requires status and evidence')
        if disposition['status'] in ('confirmed','resolved'):
            finding = by_id.get(disposition.get('finding_id'))
            if not finding or finding.get('status') != disposition['status']:
                raise ValueError(key + ' requires linked finding with matching status')
            if disposition['status']=='resolved':
                retest=disposition.get('retest')
                if not isinstance(retest,dict) or any(not text(retest.get(k)) for k in ('method','expected','observed','evidence')) or retest.get('passed') is not True:
                    raise ValueError('resolved candidate requires successful structured retest')


def candidate_records(check_id, result):
    records = result.get('candidates', [])
    if not records and result.get('assessment') == 'candidates':
        checks = result.get('details', {}).get('checks', [])
        for check in checks:
            if check.get('level') != 'FAIL' or check.get('check') == 'dependencies':
                continue  # aggregate duplicates the individual dependency results
            for location in check.get('details', []) or [check.get('message', 'candidate')]:
                records.append(dict(rule=check['check'], location=location))
    normalized = []; seen=set()
    for record in records:
        identity = {k: v for k, v in record.items() if k not in ('id', 'check_id', 'snippet', 'redacted')}
        digest = hashlib.sha256(json.dumps([check_id, identity], sort_keys=True).encode()).hexdigest()[:20]
        if digest not in seen:
            normalized.append(dict(record, id='C-' + digest, check_id=check_id)); seen.add(digest)
    result['candidates'] = normalized
    return result
