"""Internal isolated adapter for existing quick-check functions."""
import json
from pathlib import Path
import sys
from self_check import Report, check_dependencies, check_git, check_debug, check_deployment

if __name__ == '__main__':
    kind,target,timeout=sys.argv[1:4]
    report=Report(Path(target))
    if kind=='dependencies':check_dependencies(report,Path(target),int(timeout),False,include_dev=len(sys.argv)<5 or sys.argv[4]=='true')
    elif kind=='configuration':
        check_git(report,Path(target),history_limit=0);check_debug(report,Path(target));check_deployment(report,Path(target))
    else:raise SystemExit(2)
    # Third-party text/path names can contain sensitive data; suppress detail transcripts.
    print(json.dumps(report.as_dict(),ensure_ascii=True))
