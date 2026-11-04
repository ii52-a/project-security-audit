"""alpha1.7 regression and guided-workflow tests. No real network calls."""
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'scripts'))
import audit_control as ctl
import audit_contracts as contracts
import audit_report
import audit_history
import dependency_audit as deps
import self_check
import scan_secrets
from config_analysis import compose_environment,python_debug_lines


class V17Tests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.root=Path(self.tmp.name)
        self.target=self.root/'target';self.target.mkdir()
        (self.target/'app.py').write_text('print(1)\n')
        self.state=self.root/'state.json'
    def tearDown(self):self.tmp.cleanup()
    def call(self,action,**args):return ctl.dispatch(dict(action=action,state=str(self.state),**args))
    def start(self,depth='quick'):return self.call('start',target=str(self.target),depth=depth)

    def test_moderate_advisory_survives_adapter_to_candidate(self):
        (self.target/'package-lock.json').write_text('{}')
        payload={'metadata':{'vulnerabilities':{'high':0,'critical':0,'total':1}},
            'vulnerabilities':{'fixture-package':{'severity':'moderate','via':[{'source':123,'severity':'moderate','range':'<1.0'}]}}}
        report=self_check.Report(self.target)
        with patch.object(self_check.shutil,'which',return_value='npm'),patch.object(self_check,'run',return_value=(1,json.dumps(payload))):
            self_check.check_dependencies(report,self.target,5,False)
        data=report.as_dict()
        class Process:
            returncode=0
            def __init__(self,*args,**kw):kw['stdout'].write(json.dumps(data).encode())
            def poll(self):return 0
        state={'target':str(self.target),'parameters':ctl.profile('low')[1],'depth':'comprehensive-low'}
        with patch.object(ctl.subprocess,'Popen',Process):
            result=contracts.candidate_records('dependencies:.',ctl.invoke({'tool':'dependencies'},state))
        self.assertEqual(result['execution'],'complete')
        self.assertEqual(result['assessment'],'candidates')
        self.assertEqual(result['candidates'][0]['advisory_id'],'123')
        self.assertEqual(result['candidates'][0]['component'],'fixture-package')
        self.assertEqual(result['candidates'][0]['severity'],'moderate')

    def test_summary_only_is_not_lost_or_fabricated(self):
        r=deps.parse('npm',1,json.dumps({'metadata':{'vulnerabilities':{'high':0,'critical':0,'total':2}}}))
        self.assertEqual(r['candidates'][0]['count'],2)
        self.assertEqual(r['candidates'][0]['detail_level'],'summary-requires-review')

    def test_development_dependency_scope_is_machine_readable_and_applied(self):
        for depth,include in [('quick',False),('low',True),('high',True)]:
            with self.subTest(depth=depth):
                params=ctl.profile(depth)[1]
                self.assertEqual(params['dependency_include_dev'],include)
                def run(cmd,target,timeout):
                    self.assertEqual('--omit=dev' in cmd,not include)
                    return 0,'{"metadata":{"vulnerabilities":{"high":0,"critical":0,"total":0}}}'
                result=deps.run_audit('npm',self.target,1,run,lambda name:name,include_dev=include)
                self.assertEqual(result['assessment'],'no-candidates')

    def test_go_event_stream_and_cargo_consistency(self):
        self.assertEqual(deps.parse('go',0,'{"config":null}')['execution'],'incomplete')
        self.assertEqual(deps.parse('cargo',0,'{"vulnerabilities":{"found":true,"count":2,"list":[]}}')['execution'],'incomplete')
        config={'config':{'scanner_name':'govulncheck','protocol_version':'v1'}}
        finding={'finding':{'osv':'SYNTHETIC-1','trace':[{'module':'fixture','version':'v1'}]}}
        clean=deps.parse('go',0,json.dumps(config))
        found=deps.parse('go',3,json.dumps(config)+'\n'+json.dumps(finding))
        self.assertEqual(clean['assessment'],'no-candidates')
        self.assertEqual(found['candidates'][0]['advisory_id'],'SYNTHETIC-1')
        self.assertEqual(deps.parse('go',0,json.dumps(config)+' broken')['execution'],'incomplete')

    def test_ci_directories_scanned_git_excluded(self):
        for directory in ('.git','.github/workflows','.gitlab'):
            p=self.target/directory;p.mkdir(parents=True)
            (p/'deploy.yml').write_text('password: "A8qR6sT4uV2wX9zY"\n')
        r=scan_secrets.scan(self.target)
        self.assertEqual({h['file'] for h in r['hits']},{'.github/workflows/deploy.yml','.gitlab/deploy.yml'})

    def test_config_quoted_keys_and_subscript(self):
        for key in ('environment','"environment"',"'environment'"):
            values,unknown=compose_environment('services:\n  db:\n    '+key+':\n      POSTGRES_PASSWORD: password\n')
            self.assertEqual(values,[(4,'POSTGRES_PASSWORD','password')]);self.assertFalse(unknown)
        self.assertEqual(python_debug_lines('config = {}\nconfig["DEBUG"] = True\n'),{2})
        self.assertFalse(python_debug_lines('# config["DEBUG"] = True\n'))

    def test_repeated_history_secret_has_distinct_ids(self):
        def git(*args):subprocess.run(['git',*args],cwd=self.target,check=True,capture_output=True)
        git('init');git('config','user.name','Fixture');git('config','user.email','fixture@example.invalid')
        (self.target/'app.py').write_text('password="R8sT6uV4wX2yZ9qP"; password="R8sT6uV4wX2yZ9qP"\n')
        git('add','.');git('-c','commit.gpgsign=false','commit','-m','fixture')
        hits=audit_history.scan_history(self.target)['hits']
        r=contracts.candidate_records('history',dict(candidates=hits,assessment='candidates'))
        self.assertEqual(len(r['candidates']),2)
        self.assertEqual(len({c['id'] for c in r['candidates']}),2)

    def test_coverage_counts_derived_and_fabricated_zero_rejected(self):
        self.start()
        r={'status':'done','evidence':'Reviewed app.py','redaction_reviewed':True,
            'reviewed_files':['app.py'],'interfaces':[],'interface_inventory_complete':True}
        item=self.call('record_review',check_id='coverage',review=r)
        self.assertEqual(item['review']['coverage']['files'],{'reviewed':1,'total':1})
        r['coverage']={'files':{'reviewed':0,'total':0},'interfaces':{'reviewed':0,'total':0}}
        with self.assertRaises(ValueError):self.call('record_review',check_id='coverage',review=r)
        r.pop('coverage');r['reviewed_files']=['absent.py']
        with self.assertRaises(ValueError):self.call('record_review',check_id='coverage',review=r)

    def test_guidance_templates_and_batch_resume(self):
        self.start()
        next_item=self.call('next_action')
        self.assertEqual(next_item['request']['check_id'],'secrets')
        result={'execution':'complete','assessment':'no-candidates','candidates':[]}
        with patch.object(ctl,'invoke',return_value=result) as run:
            first=self.call('run_pending',max_checks=2)
            second=self.call('run_pending',max_checks=2)
            self.assertEqual(len(first['completed']),2);self.assertEqual(len(second['completed']),1)
            self.assertEqual(run.call_count,3)
        form=self.call('review_template',check_id='coverage')
        self.assertIn('app.py',form['context']['file_choices'])
        self.assertEqual(form['review']['status'],'blocked')
        self.assertFalse(form['review']['redaction_reviewed'])

    def test_batch_does_not_infer_network_permission(self):
        (self.target/'package-lock.json').write_text('{}');self.start()
        with patch.object(ctl,'invoke',return_value={'execution':'complete','assessment':'no-candidates','candidates':[]}):
            r=self.call('run_pending',max_checks=10)
        self.assertEqual(r['blocked'][0]['check_id'],'dependencies:.')

    def test_write_evidence_hashes_and_invalidates_on_scope_change(self):
        self.start('high')
        items=[{k:'Concrete fixture observation' for k in contracts.HIGH_FIELDS['H6']}]
        record=self.call('write_evidence',h_id='H6',items=items,summary='Fixture coverage',redaction_reviewed=True)
        self.assertTrue((self.root/record['evidence']['artifact']).exists())
        form=self.call('review_template',check_id='high-evidence')
        self.assertEqual(form['review']['high_only']['H6'],record)
        (self.target/'app.py').write_text('print(2)')
        self.call('refresh')
        self.assertEqual(self.call('review_template',check_id='high-evidence')['review']['high_only']['H6']['status'],'pending')

    def test_resolved_disposition_requires_retest(self):
        state={'checks':[{'id':'secrets','result':{'candidates':[{'id':'C-x'}]}}]}
        r={'findings':[{'id':'F1','status':'resolved'}],
            'dispositions':{'C-x':{'status':'resolved','evidence':'rotated synthetic credential','finding_id':'F1'}}}
        with self.assertRaises(ValueError):contracts.validate_triage(r,state)
        r['dispositions']['C-x']['retest']={'method':'local mock','expected':'rejected','observed':'rejected','evidence':'fixture transcript','passed':True}
        contracts.validate_triage(r,state)

    def test_progress_is_explicitly_unverified_without_rehash(self):
        self.start()
        with patch.object(ctl,'snapshot',side_effect=AssertionError('must not hash')):
            self.assertEqual(self.call('progress')['freshness'],'not-rechecked')
            self.assertEqual(self.call('file_inventory',offset=0,limit=1)['files'],['app.py'])

    def test_guided_flow_can_finalize_without_handwritten_ids_or_counts(self):
        (self.target/'app.py').write_text('password="A8qR6sT4uV2wX9zY"\n')
        self.start();self.call('run_pending',max_checks=3)
        while True:
            next_step=self.call('next_action')
            if next_step['action']=='finalize':break
            request=next_step['request'];review=request['review']
            review.update(status='done',evidence='Synthetic fixture reviewed; unresolved values retained',redaction_reviewed=True)
            if request['check_id']=='triage':
                for cid,d in review['dispositions'].items():
                    d['evidence']='Synthetic candidate retained for review'
                    draft=self.call('finding_draft',candidate_id=cid)
                    self.assertEqual(draft['candidate_id'],cid)
                    self.assertEqual(draft['finding']['status'],'suspected')
            if request['check_id']=='coverage':
                review.update(reviewed_files=next_step['context']['file_choices'],interfaces=[],interface_inventory_complete=True)
            ctl.dispatch(request)
        request=next_step['request']
        self.assertFalse(request['redaction_reviewed'])
        request['redaction_reviewed']=True
        out=ctl.dispatch(request)
        report=json.loads(Path(out['json']).read_text())
        self.assertEqual(report['coverage']['files'],{'reviewed':1,'total':1})
        self.assertTrue(report['unresolved_candidates'])
        self.assertEqual(report['conclusion'],'manual review required')

if __name__=='__main__':unittest.main()
