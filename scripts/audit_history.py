"""Bounded, read-only Git patch secret scan; never prints raw Git output."""
import argparse
import json
import subprocess
from pathlib import Path
from scan_secrets import RULES, RULE_SCOPE, fingerprint
import fnmatch


def scan_history(target, commits=200, timeout=60, max_bytes=20_000_000):
    if commits < 1 or timeout < 1 or max_bytes < 1:
        raise ValueError('limits must be positive')
    result = dict(status='complete', hits=[], commits_requested=commits,
                  commits_scanned=0, limitations=['Current HEAD ancestry only; added patch lines only; binary contents excluded'])
    # Stream to a temporary file, avoiding unbounded capture_output memory.
    import tempfile
    import time
    with tempfile.TemporaryFile() as output:
        try:
            proc = subprocess.Popen(['git', '-c', 'core.hooksPath=/dev/null', 'log',
                '--no-ext-diff', '--no-textconv', '--format=COMMIT:%H',
                '-p', '--unified=0', '--max-count=' + str(commits), 'HEAD', '--', '.'],
                cwd=target, stdout=output, stderr=subprocess.DEVNULL)
            deadline = time.monotonic() + timeout
            while proc.poll() is None:
                if time.monotonic() > deadline or output.tell() > max_bytes:
                    proc.kill()
                    proc.wait()
                    result['status'] = 'incomplete'
                    break
                time.sleep(.02)
            if proc.returncode != 0:
                result['status'] = 'incomplete'
            if output.tell() > max_bytes:
                result['status'] = 'incomplete'
            output.seek(0)
            text = output.read(max_bytes).decode('utf-8', 'replace')
        except OSError:
            result['status'] = 'not-executed'
            return result
    commit, path, line_no = '', '', 0
    import re
    for line in text.splitlines():
        if line.startswith('COMMIT:'):
            commit = line[7:]
            result['commits_scanned'] += 1
        elif line.startswith('+++ b/'):
            path = line[6:]
        elif line.startswith('@@'):
            match = re.search(r'\+(\d+)', line)
            line_no = int(match[1]) if match else 0
        elif line.startswith('+') and not line.startswith('+++'):
            for rule, regex, _ in RULES:
                if rule in RULE_SCOPE and not fnmatch.fnmatch(Path(path).name, RULE_SCOPE[rule]):
                    continue
                for match in regex.finditer(line[1:]):
                    result['hits'].append(dict(commit=commit, file=path, line=line_no, column=match.start()+1,
                        rule=rule, fingerprint=fingerprint(match[0]), snippet='[REDACTED]'))
            line_no += 1
    return result


if __name__ == '__main__':
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('target')
    p.add_argument('--commits', type=int, default=200)
    p.add_argument('--timeout', type=int, default=60)
    p.add_argument('--max-bytes', type=int, default=20_000_000)
    a = p.parse_args()
    try:
        r = scan_history(a.target, a.commits, a.timeout, a.max_bytes)
        print(json.dumps(r, ensure_ascii=True, indent=2))
        raise SystemExit(2 if r['status'] != 'complete' else 1 if r['hits'] else 0)
    except ValueError as e:
        p.error(str(e))
