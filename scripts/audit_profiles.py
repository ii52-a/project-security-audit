"""Single source of truth for executable depth budgets and review requirements."""
from copy import deepcopy

VERSION = 'alpha1.5'
PROFILES = {
    'quick': dict(time_target_minutes=15, file_limit_mb=1, scan_timeout=60,
        history_commits=20, history_timeout=30, history_output_mb=5,
        dependency_timeout=60, output_limit_mb=10, manifest_depth=2,
        review_passes=1, review_scope='changed security-sensitive paths and exposed configuration',
        interface_scope='changed/new interfaces', dynamic='forbidden',
        review_tasks=['changed-review']),
    'comprehensive-low': dict(time_target_minutes=180, file_limit_mb=2, scan_timeout=180,
        history_commits=200, history_timeout=60, history_output_mb=20,
        dependency_timeout=120, output_limit_mb=25, manifest_depth=4,
        review_passes=1, review_scope='all identified entry points; trace high-risk paths to sinks',
        interface_scope='all identified interfaces; explicit unknowns', dynamic='authorized risk-prioritized only',
        review_tasks=['interfaces', 'trust-review', 'validation-plan']),
    'comprehensive-high': dict(time_target_minutes=300, file_limit_mb=5, scan_timeout=600,
        history_commits=1000, history_timeout=180, history_output_mb=50,
        dependency_timeout=300, output_limit_mb=60, manifest_depth=8,
        review_passes=2, review_scope='all critical trust boundaries plus independent second-pass reasoning',
        interface_scope='all identified interfaces plus caller/object authorization matrix',
        dynamic='authorized applicable critical hypotheses only',
        review_tasks=['interfaces', 'trust-review', 'validation-plan', 'second-pass', 'high-evidence']),
}


def profile(mode):
    mode = {'low':'comprehensive-low', 'high':'comprehensive-high'}.get(mode, mode)
    if mode not in PROFILES:
        raise ValueError('unknown depth')
    return mode, deepcopy(PROFILES[mode])
