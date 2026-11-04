"""Dependency adapters with separate execution and finding states; no raw log persistence."""
import json


def incomplete(reason):
    return dict(execution='incomplete', assessment='unknown', candidates=[], reason=reason)


def candidate(tool, advisory, component='unknown', version='unknown', severity='unknown', **extra):
    return dict(tool=tool, rule='dependency-advisory', advisory_id=str(advisory),
                component=str(component), installed_version=str(version), severity=str(severity), **extra)


def parse(tool, code, output):
    try:
        if code not in (0, 1, 3):return incomplete('tool failed, timed out or unavailable')
        findings=[]
        if tool=='go':
            events=[];decoder=json.JSONDecoder();rest=output.strip()
            while rest:
                event,end=decoder.raw_decode(rest)
                if not isinstance(event,dict) or len(event)!=1:raise ValueError('invalid Go event')
                events.append(event);rest=rest[end:].lstrip()
            configs=[e['config'] for e in events if 'config' in e]
            if len(configs)!=1 or not isinstance(configs[0],dict) or not all(isinstance(configs[0].get(k),str) and configs[0][k] for k in ('scanner_name','protocol_version')):
                raise ValueError('invalid Go config')
            for e in events:
                if not set(e)<= {'config','progress','osv','finding'} or not isinstance(next(iter(e.values())),dict):raise ValueError('unsupported Go event')
                if 'finding' in e:
                    f=e['finding']
                    if not isinstance(f.get('osv'),str) or not isinstance(f.get('trace'),list) or any(not isinstance(x,dict) for x in f['trace']):raise ValueError('invalid Go finding')
                    trace=next((x for x in f['trace'] if x.get('module')), {})
                    findings.append(candidate(tool,f['osv'],trace.get('module','unknown'),trace.get('version','unknown')))
        else:
            data=json.loads(output)
            if tool=='npm':
                if not isinstance(data,dict) or data.get('error'):raise ValueError('npm error')
                counts=data.get('metadata',{}).get('vulnerabilities') if isinstance(data.get('metadata',{}),dict) else None
                if counts is not None:
                    if not isinstance(counts,dict) or any(type(counts.get(k)) is not int or counts[k]<0 for k in ('high','critical','total')) or counts['total']<counts['high']+counts['critical']:raise ValueError('invalid npm counts')
                advisories=data.get('advisories')
                vulns=data.get('vulnerabilities')
                if advisories is not None:
                    if not isinstance(advisories,dict):raise ValueError('invalid npm advisories')
                    for key,f in advisories.items():
                        if not isinstance(f,dict) or f.get('severity') not in ('info','low','moderate','high','critical'):raise ValueError('invalid npm advisory')
                        findings.append(candidate(tool,key,f.get('module_name','unknown'),f.get('version','unknown'),f['severity']))
                elif vulns is not None:
                    if not isinstance(vulns,dict):raise ValueError('invalid npm vulnerabilities')
                    for package,f in vulns.items():
                        if not isinstance(f,dict) or not isinstance(f.get('via'),list) or not isinstance(f.get('severity'),str):raise ValueError('invalid npm package record')
                        for via in f['via']:
                            if isinstance(via,dict):
                                if 'source' not in via:raise ValueError('missing advisory ID')
                                findings.append(candidate(tool,via['source'],package,f.get('version','unknown'),via.get('severity',f['severity']),affected_range=str(via.get('range','unknown'))))
                            elif isinstance(via,str):
                                findings.append(candidate(tool,'transitive:'+via,package,'unknown',f['severity'],detail_level='transitive-reference'))
                            else:raise ValueError('invalid npm via')
                elif counts is None:raise ValueError('missing npm results')
                if counts and counts['total'] and not findings:
                    # Summary-only output must remain visible, without invented advisory IDs.
                    severity='high' if counts['high'] or counts['critical'] else 'unknown'
                    findings.append(candidate(tool,'summary-only',severity=severity,count=counts['total'],detail_level='summary-requires-review'))
                if counts and counts['total']==0 and findings:raise ValueError('npm counts contradict records')
            elif tool=='cargo':
                v=data.get('vulnerabilities') if isinstance(data,dict) else None
                if not isinstance(v,dict) or not isinstance(v.get('list'),list):raise ValueError('invalid cargo list')
                if 'count' in v and (type(v['count']) is not int or v['count']!=len(v['list'])):raise ValueError('cargo count/list mismatch')
                if 'found' in v and (type(v['found']) is not bool or v['found']!=bool(v['list'])):raise ValueError('cargo found/list mismatch')
                for f in v['list']:
                    if not isinstance(f,dict) or not isinstance(f.get('advisory'),dict) or not isinstance(f['advisory'].get('id'),str) or not isinstance(f.get('package'),dict):raise ValueError('invalid cargo advisory')
                    findings.append(candidate(tool,f['advisory']['id'],f['package'].get('name','unknown'),f['package'].get('version','unknown')))
            elif tool=='pip':
                deps=data.get('dependencies') if isinstance(data,dict) else data
                if not isinstance(deps,list):raise ValueError('invalid pip dependencies')
                for f in deps:
                    if not isinstance(f,dict) or not isinstance(f.get('vulns'),list):raise ValueError('invalid pip record')
                    for v in f['vulns']:
                        if not isinstance(v,dict) or not isinstance(v.get('id'),str):raise ValueError('invalid pip advisory')
                        findings.append(candidate(tool,v['id'],f.get('name','unknown'),f.get('version','unknown')))
            elif tool=='composer':
                advisories=data.get('advisories') if isinstance(data,dict) else None
                if advisories==[]:advisories={}
                if not isinstance(advisories,dict):raise ValueError('unsupported Composer schema')
                for package,items in advisories.items():
                    if not isinstance(items,list):raise ValueError('invalid Composer entries')
                    for f in items:
                        if not isinstance(f,dict) or not isinstance(f.get('advisoryId') or f.get('cve'),str):raise ValueError('missing Composer advisory ID')
                        findings.append(candidate(tool,f.get('advisoryId') or f['cve'],package,f.get('version','unknown'),f.get('severity','unknown')))
            else:raise ValueError('unsupported tool')
        if code!=0 and not findings:return incomplete('nonzero exit without valid findings')
        return dict(execution='complete',assessment='candidates' if findings else 'no-candidates',candidates=findings)
    except (ValueError,TypeError,KeyError,AttributeError):
        return incomplete('unsupported, malformed or inconsistent tool JSON')


def run_audit(tool,target,timeout,run,which,include_dev=True):
    names={'npm':'npm','pip':'pip-audit','go':'govulncheck','cargo':'cargo','composer':'composer'}
    executable=which(names[tool])
    if not executable:return incomplete('tool unavailable: '+names[tool])
    arguments={'npm':['audit','--json']+([] if include_dev else ['--omit=dev']),
        'pip':['-r','requirements.txt','--format','json'],'go':['-json','./...'],
        'cargo':['audit','--json'],'composer':['audit','--format=json']}
    code,output=run([executable]+arguments[tool],target,timeout)
    result=parse(tool,code,output)
    result['tool']=tool
    return result


def legacy(result):
    if result['execution']!='complete':return 'WARN',result.get('reason','incomplete'),[]
    if not result['candidates']:return 'PASS','Dependency audit: no candidates',[]
    high=any(c['severity'] in ('high','critical') or c['tool']!='npm' for c in result['candidates'])
    return ('FAIL' if high else 'WARN'),'Dependency advisories require review',[]
