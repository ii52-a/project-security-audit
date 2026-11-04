import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'scripts'))
import audit_control as control
from evidence_helpers import high_record
from audit_profiles import profile


class ControllerTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory()
        self.root=Path(self.tmp.name);self.target=self.root/'project';self.target.mkdir()
        (self.target/'app.py').write_text('print(1)\n')
        self.state=self.root/'state.json'
    def tearDown(self):self.tmp.cleanup()
    def call(self,action,**kwargs):
        return control.dispatch(dict(action=action,state=str(self.state),**kwargs))
    def start(self,depth='quick'):
        return self.call('start',target=str(self.target),depth=depth)

    def test_profiles_are_distinct(self):
        q=profile('quick')[1];l=profile('low')[1];h=profile('high')[1]
        self.assertLess(q['history_commits'],l['history_commits'])
        self.assertLess(l['history_commits'],h['history_commits'])
        self.assertEqual(q['dynamic'],'forbidden')
        self.assertEqual(h['review_passes'],2)
        h['history_commits']=0
        self.assertEqual(profile('high')[1]['history_commits'],1000)

    def test_state_outside_target_and_no_overwrite(self):
        with self.assertRaises(ValueError):
            control.dispatch(dict(action='start',state=str(self.target/'s.json'),target=str(self.target)))
        self.start()
        with self.assertRaises(ValueError):self.start()

    def test_resume_idempotence_and_invalidation(self):
        self.start()
        self.assertEqual(self.call('next_action')['next']['id'],'secrets')
        r=self.call('run_check',check_id='secrets')
        self.assertEqual(r['result']['execution'],'complete')
        with patch.object(control,'invoke',side_effect=AssertionError('must not run again')):
            self.assertEqual(self.call('run_check',check_id='secrets'),r)
        (self.target/'new.py').write_text('changed')
        self.assertTrue(self.call('status')['stale'])
        with self.assertRaises(ValueError):self.call('next_action')
        self.assertTrue(self.call('refresh')['refreshed'])
        self.assertEqual(self.call('next_action')['next']['id'],'secrets')

    def test_manifest_depth_and_network_gate(self):
        deep=self.target/'a'/'b'/'c';deep.mkdir(parents=True)
        (deep/'requirements.txt').write_text('')
        q=control.inspect(self.target,profile('quick')[1]);h=control.inspect(self.target,profile('high')[1])
        self.assertEqual(q['manifests'],[])
        self.assertIn('a/b/c/requirements.txt',h['manifests'])
        self.start('high')
        with self.assertRaises(ValueError):self.call('run_check',check_id='dependencies:a/b/c')

    def test_high_requires_evidence(self):
        self.start('high')
        with self.assertRaises(ValueError):
            self.call('record_review',check_id='high-evidence',review=dict(status='done',evidence='done',redaction_reviewed=True))

    def test_finalize_end_to_end_no_release_claim(self):
        self.start()
        plan=self.call('plan')['checks']
        for c in plan:
            if c['kind']=='tool':self.call('run_check',check_id=c['id'])
        for c in plan:
            if c['kind']=='review':
                r=dict(status='done',evidence='Synthetic fixture reviewed; no applicable business interface',redaction_reviewed=True)
                if c['id']=='coverage':r.update(reviewed_files=self.call('status')['snapshot']['file_paths'],interfaces=[],interface_inventory_complete=True)
                if c['id']=='second-pass':r['analysis']=[{'target':'app.py','alternative_hypothesis':'hidden side effect','observation':'only print call'}]
                if c['id']=='triage':r['dispositions']={}
                self.call('record_review',check_id=c['id'],review=r)
        result=self.call('finalize',output=str(self.root/'report'),redaction_reviewed=True)
        doc=json.loads(Path(result['json']).read_text())
        self.assertEqual(doc['conclusion'],'manual review required')
        self.assertTrue(doc['limitations'])
        self.assertTrue(Path(result['markdown']).exists())
        with self.assertRaises(ValueError):self.call('finalize',output=str(self.root/'report'),redaction_reviewed=True)

    def test_cannot_skip_tools_or_triage(self):
        self.start()
        with self.assertRaises(ValueError):self.call('finalize',output=str(self.root/'report'),redaction_reviewed=True)
        with self.assertRaises(ValueError):
            self.call('record_review',check_id='secrets',review=dict(status='done',evidence='x',redaction_reviewed=True))
        with self.assertRaises(ValueError):
            self.call('record_review',check_id='triage',review=dict(status='done',evidence='x',redaction_reviewed=True))

    def test_skip_preserves_unknown_and_reason(self):
        self.start()
        with self.assertRaises(ValueError):self.call('skip_check',check_id='history',reason='')
        r=self.call('skip_check',check_id='history',reason='Git unavailable')
        self.assertEqual(r['result']['execution'],'skipped')
        self.assertEqual(r['result']['assessment'],'unknown')
        self.assertEqual(r['result']['reason'],'Git unavailable')

    def test_lock_prevents_parallel_state_write(self):
        self.start()
        with control.locked(self.state):
            with self.assertRaises(FileExistsError):self.call('refresh')

    def test_candidate_triage_requires_disposition(self):
        self.start()
        item={'id':'triage'}
        state={'checks':[{'id':'secrets','result':{'assessment':'candidates','candidates':[{'id':'C-fixture'}]}}]}
        review=dict(status='done',redaction_reviewed=True,evidence='reviewed')
        with self.assertRaises(ValueError):control.validate_review(item,review,state)
        review['dispositions']={'C-fixture':{'status':'manual-review','evidence':'candidate in app.py:1 needs verification'}}
        control.validate_review(item,review,state)

    def test_scanner_parameters_and_error_normalization(self):
        self.start()
        (self.target/'app.py').write_text('password="SyntheticSensitive123"')
        self.call('refresh')
        r=self.call('run_check',check_id='secrets')['result']
        self.assertEqual(r['assessment'],'candidates')
        self.assertNotIn('SyntheticSensitive123',json.dumps(r))
        self.assertEqual(r['details']['max_size_mb'],1)

    def test_high_finalization_has_evidence_and_skip_limits(self):
        self.start('high')
        for c in self.call('plan')['checks']:
            if c['kind']=='tool':self.call('skip_check',check_id=c['id'],reason='Synthetic offline test')
            else:
                r=dict(status='done',redaction_reviewed=True,evidence='Synthetic review evidence')
                if c['id']=='coverage':r.update(reviewed_files=self.call('status')['snapshot']['file_paths'],interfaces=[],interface_inventory_complete=True)
                if c['id']=='second-pass':r['analysis']=[{'target':'app.py','alternative_hypothesis':'hidden side effect','observation':'only print call'}]
                if c['id']=='triage':r['dispositions']={}
                if c['id']=='high-evidence':
                    r['high_only']={f'H{i}':{'status':'n/a','reason':'No such surface in synthetic fixture'} for i in range(1,9)}
                    for k in ('H6','H8'):r['high_only'][k]=high_record(k,self.root)
                self.call('record_review',check_id=c['id'],review=r)
        out=self.call('finalize',output=str(self.root/'high'),redaction_reviewed=True)
        doc=json.loads(Path(out['json']).read_text())
        self.assertIn('high_only',doc)
        self.assertEqual(doc['parameters']['history_commits'],1000)
        self.assertTrue(any('skipped' in x for x in doc['limitations']))

if __name__=='__main__':unittest.main()
