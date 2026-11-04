import hashlib
import json
from pathlib import Path
from audit_contracts import HIGH_FIELDS


def high_record(key, root=None):
    items = [{field: 'Reviewed synthetic fixture: ' + field for field in HIGH_FIELDS[key]}]
    raw = json.dumps({key: items}).encode()
    if root is not None:
        (Path(root) / (key + '.json')).write_bytes(raw)
    return {'status': 'done', 'evidence': {'artifact': key + '.json',
        'sha256': hashlib.sha256(raw).hexdigest(), 'summary': 'Synthetic evidence record', 'items': items}}
