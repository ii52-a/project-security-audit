"""Grounded review forms and coverage arithmetic; never invents review completion."""
from audit_contracts import all_candidates, HIGH_FIELDS


def coverage_review(review,state):
    inventory=state['snapshot']['file_paths']
    reviewed=review.get('reviewed_files')
    if not isinstance(reviewed,list) or any(not isinstance(p,str) for p in reviewed) or len(set(reviewed))!=len(reviewed) or not set(reviewed)<=set(inventory):
        raise ValueError('reviewed_files: unique paths from snapshot.file_paths required')
    interfaces=review.get('interfaces')
    if not isinstance(interfaces,list):raise ValueError('interfaces: explicit inventory array required')
    ids=[]
    for row in interfaces:
        if not isinstance(row,dict) or not isinstance(row.get('id'),str) or not row['id'].strip() or row.get('file') not in inventory or type(row.get('reviewed')) is not bool:
            raise ValueError('each interface requires id, file from inventory, reviewed boolean')
        ids.append(row['id'])
    if len(set(ids))!=len(ids):raise ValueError('duplicate interface id')
    if review.get('interface_inventory_complete') is not True:
        raise ValueError('interface inventory incomplete: keep coverage blocked')
    estimate=state['inspection']['metrics']['interfaces_estimate']
    if len(interfaces)<estimate and not str(review.get('estimate_difference_reason','')).strip():
        raise ValueError('interface inventory below heuristic estimate; explain estimate_difference_reason')
    counts={'files':{'reviewed':len(reviewed),'total':len(inventory)},
        'interfaces':{'reviewed':sum(r['reviewed'] for r in interfaces),'total':len(interfaces)}}
    if 'coverage' in review and review['coverage']!=counts:raise ValueError('coverage conflicts with inventory-derived counts')
    review['coverage']=counts


def template(state,check_id):
    item=next((c for c in state['checks'] if c['id']==check_id),None)
    if item is None or item['kind']!='review':raise ValueError('review task required')
    review=dict(status='blocked',redaction_reviewed=False,evidence='',findings=[])
    context={'instruction':item.get('instruction',''), 'reference':item.get('reference','')}
    if check_id=='triage':
        candidates=all_candidates(state);context['candidates']=candidates
        review['dispositions']={c['id']:{'status':'manual-review','evidence':''} for c in candidates}
    elif check_id=='coverage':
        review.update(reviewed_files=[],interfaces=[],interface_inventory_complete=False)
        paths=state['snapshot']['file_paths']
        context.update(file_choices=paths[:100],file_choices_total=len(paths),
            more_files_action='file_inventory',interface_estimate=state['inspection']['metrics']['interfaces_estimate'])
    elif check_id=='second-pass':
        review['analysis']=[dict(target='',alternative_hypothesis='',observation='')]
    elif check_id=='high-evidence':
        review['high_only']={key:{'status':'pending','evidence':{'artifact':'','sha256':'','summary':'','items':[{k:'' for k in fields}]}} for key,fields in HIGH_FIELDS.items()}
        review['high_only'].update(state.get('high_artifacts',{}))
    return dict(check_id=check_id,review=review,context=context)


def finding_draft(state,candidate_id):
    c=next((c for c in all_candidates(state) if c['id']==candidate_id),None)
    if c is None:raise ValueError('unknown candidate ID')
    location=c.get('location') or (str(c['file'])+':'+str(c.get('line')) if c.get('file') else c.get('component','unknown'))
    return dict(candidate_id=candidate_id,source=c,review_required=['severity','confidence','evidence','remediation','status'],
        finding=dict(id='F-'+candidate_id[2:],title=c.get('rule','Candidate'),severity='',confidence='low',
            status='suspected',location=location,evidence='',remediation=''))
