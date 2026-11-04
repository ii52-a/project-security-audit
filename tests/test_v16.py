"""Regressions for evaluation E01-E09; synthetic fixtures, no network."""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'scripts'))
import audit_control as ctl
import audit_report
import scan_secrets
import self_check
from audit_contracts import high_errors
from evidence_helpers import high_record


class EvaluationRegressions(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory()
        self.root=Path(self.temp.name);self.target=self.root/'app';self.target.mkdir()
        self.state=self.root/'state.json'
    def tearDown(self):self.temp.cleanup()
    def call(self,action,**kw):return ctl.dispatch(dict(action=action,state=str(self.state),**kw))
    def start(self,depth='quick'):
        return self.call('start',target=str(self.target),depth=depth,risks=['payment'])
    def write(self,name,text,encoding='utf-8'):
        p=self.target/name;p.parent.mkdir(exist_ok=True,parents=True);p.write_text(text,encoding=encoding)
        return p

    def test_E05_multi_value_placeholder_and_utf16(self):
        self.write('a.py','password="A7rT9uP3sV5wX8zQ"; password="B6qR8sT2uV4wX7yZ"\npassword="H7qExampleR9tV3sW6"\npassword="example"\n')
        self.write('b.py','password="C8rT6uP4sV2wX9zQ"\n','utf-16')
        self.write('c.py','password="D8rT6uP4sV2wX9zQ"\n','utf-32')
        r=scan_secrets.scan(self.target)
        self.assertEqual(len(r['hits']),5)
        self.assertNotIn('H7qExample',json.dumps(r))
        self.assertEqual(len({h['column'] for h in r['hits'] if h['file']=='a.py' and h['line']==1}),2)

    def test_E04_comment_docstring_and_compose_forms(self):
        self.write('app.py','# DEBUG = True\n"""DEBUG=True"""\nDEBUG=False\n')
        report=self_check.Report(self.target);self_check.check_debug(report,self.target)
        self.assertEqual(report.fail_count,0)
        self.write('app.py','DEBUG = True\n')
        report=self_check.Report(self.target);self_check.check_debug(report,self.target)
        self.assertEqual(report.fail_count,1)
        for env in ('      POSTGRES_PASSWORD: password','      - POSTGRES_PASSWORD=password','      - "POSTGRES_PASSWORD=password"'):
            self.write('compose.yml','services:\n  db:\n    environment:\n'+env+'\n')
            report=self_check.Report(self.target);self_check.check_deployment(report,self.target)
            self.assertTrue(any(c['check']=='deployment-compose' and c['level']=='FAIL' for c in report.checks),env)
        self.write('compose.yml','services:\n  db:\n    environment: {POSTGRES_PASSWORD: password}\n')
        report=self_check.Report(self.target);self_check.check_deployment(report,self.target)
        self.assertGreater(report.warn_count,0)

    def test_E03_malformed_outputs_not_pass(self):
        cases=[(self_check._dep_npm,{'metadata':{'vulnerabilities':{'unexpected':'schema'}}}),
            (self_check._dep_cargo,{'vulnerabilities':{'list':None}}),
            (self_check._dep_composer,{'advisories':[{'id':'synthetic'}]})]
        for fn,data in cases:
            with patch.object(self_check.shutil,'which',return_value='tool'),patch.object(self_check,'run',return_value=(0,json.dumps(data))):
                self.assertEqual(self_check._safe_dependency(fn,self.target,5)[0],'WARN')
        for fn,data in [(self_check._dep_cargo,{'vulnerabilities':{'list':[]}}),(self_check._dep_composer,{'advisories':{}})]:
            with patch.object(self_check.shutil,'which',return_value='tool'),patch.object(self_check,'run',return_value=(0,json.dumps(data))):
                self.assertEqual(self_check._safe_dependency(fn,self.target,5)[0],'PASS')

    def test_E07_E08_content_change_and_risk_refresh(self):
        p=self.write('app.py','value=1\n');self.start('low');st=p.stat()
        p.write_text('value=2\n');os.utime(p,ns=(st.st_atime_ns,st.st_mtime_ns))
        self.assertTrue(self.call('status')['stale'])
        result=self.call('refresh')
        self.assertIn('payment',next(c['instruction'] for c in result['checks'] if c['id']=='trust-review'))

    def test_E09_invalid_nested_input_returns_json(self):
        self.write('app.py','print(1)');self.start()
        malformed=[dict(coverage={'files':42,'interfaces':{}}),dict(findings=42),dict(high_only=42)]
        for data in malformed[:2]:
            req=dict(action='record_review',state=str(self.state),check_id='coverage',review=dict(status='done',evidence='reviewed',redaction_reviewed=True,**data))
            p=subprocess.run([sys.executable,ctl.__file__,'-'],input=json.dumps(req),text=True,capture_output=True)
            self.assertEqual(p.returncode,2)
            self.assertFalse(json.loads(p.stdout)['ok'])
            self.assertNotIn('Traceback',p.stderr)
        for req in ([],{'action':[]},{'action':'start','state':str(self.state),'target':str(self.target),'risks':[{}]}):
            p=subprocess.run([sys.executable,ctl.__file__,'-'],input=json.dumps(req),text=True,capture_output=True)
            self.assertFalse(json.loads(p.stdout)['ok'])

    def test_E02_high_artifact_structure_integrity(self):
        old={f'H{i}':{'status':'done','evidence':'checked'} for i in range(1,9)}
        self.assertTrue(high_errors(old,self.root))
        records={f'H{i}':high_record(f'H{i}',self.root) for i in range(1,9)}
        self.assertEqual(high_errors(records,self.root),[])
        (self.root/'H1.json').write_text('{}')
        self.assertTrue(high_errors(records,self.root))
        records['H1']=high_record('H1',self.root);records['H1']['evidence']['items']=[{'interface':'/x'}]
        self.assertTrue(high_errors(records,self.root))

    def complete_reviews(self,dispositions,findings=None):
        for c in self.call('plan')['checks']:
            if c['kind']=='tool':continue
            r=dict(status='done',evidence='Synthetic fixture reviewed',redaction_reviewed=True)
            if c['id']=='triage':r.update(dispositions=dispositions,findings=findings or [])
            if c['id']=='coverage':r.update(reviewed_files=self.call('status')['snapshot']['file_paths'],interfaces=[],interface_inventory_complete=True)
            self.call('record_review',check_id=c['id'],review=r)

    def test_E01_confirmed_requires_finding_and_manual_is_preserved(self):
        self.write('app.py','password="A7rT9uP3sV5wX8zQ"; password="B6qR8sT2uV4wX7yZ"')
        self.start();r=self.call('run_check',check_id='secrets')
        ids=[c['id'] for c in r['result']['candidates']];self.assertEqual(len(set(ids)),2)
        for cid in ('history','configuration'):self.call('skip_check',check_id=cid,reason='Synthetic test')
        dispositions={i:{'status':'confirmed','evidence':'source fixture'} for i in ids}
        with self.assertRaises(ValueError):self.complete_reviews(dispositions)
        finding=dict(id='F1',title='Synthetic credential',severity='P1',confidence='high',status='confirmed',location='app.py:1',evidence='redacted literal',remediation='use injected configuration')
        dispositions[ids[0]]['finding_id']='F1'
        dispositions[ids[1]]={'status':'manual-review','evidence':'needs separate review'}
        self.complete_reviews(dispositions,[finding])
        out=self.call('finalize',output=str(self.root/'report'),redaction_reviewed=True)
        doc=json.loads(Path(out['json']).read_text())
        self.assertEqual(len(doc['findings']),1)
        self.assertEqual(len(doc['candidates']),2)
        self.assertEqual(doc['unresolved_candidates'][0]['id'],ids[1])
        self.assertIn(ids[1],Path(out['markdown']).read_text())

    def test_E06_skipped_file_reaches_report(self):
        p=self.target/'large.py';p.write_bytes(b'\n'*(2*1024*1024))
        self.start();r=self.call('run_check',check_id='secrets')['result']
        self.assertEqual(r['coverage'],'partial');self.assertEqual(r['assessment'],'unknown')
        for cid in ('history','configuration'):self.call('skip_check',check_id=cid,reason='Synthetic test')
        self.complete_reviews({})
        out=self.call('finalize',output=str(self.root/'report'),redaction_reviewed=True)
        doc=json.loads(Path(out['json']).read_text())
        self.assertTrue(any('large.py' in s for s in doc['limitations']))
        self.assertEqual(doc['checks'][0]['status'],'error')

if __name__=='__main__':unittest.main()
