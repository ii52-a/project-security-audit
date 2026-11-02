import copy
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
import audit_depth as depth
import audit_history as history
import audit_report as report
import scan_secrets as scanner
import self_check


def record():
    return dict(project='synthetic', date='2026-11-02', scope=['src'], limitations=[],
        depth='comprehensive-low', coverage={'files':{'reviewed':1,'total':1},'interfaces':{'reviewed':0,'total':0}},
        checks=[{'status':'pass','evidence':'reviewed src/main.py'}], findings=[],
        dynamic={'executed':False,'reason':'static review only'}, redaction_reviewed=True,
        coverage_complete=True, conclusion='releasable')


class V14Tests(unittest.TestCase):
    def test_risk_over_size_and_user_override(self):
        m=dict(source_files=5000,source_loc=400000,interfaces_estimate=1,services_estimate=1)
        self.assertEqual(depth.recommend_depth(m)['recommended'],'comprehensive-low')
        self.assertEqual(depth.recommend_depth(m, risks=['payment'])['recommended'],'comprehensive-high')
        self.assertEqual(depth.recommend_depth(m, 'quick', ['payment'])['effective'],'quick')

    def test_reasoned_na_and_evidence(self):
        h={f'H{i}':{'status':'n/a','reason':'no such surface'} for i in range(1,9)}
        for k in ('H6','H8'):h[k]={'status':'done','evidence':'appendix'}
        self.assertTrue(depth.evaluate_high_only(h)['achieved'])
        del h['H1']['reason']
        self.assertFalse(depth.evaluate_high_only(h)['achieved'])

    def test_report_gates(self):
        r=record()
        self.assertEqual(report.validate(r),[])
        self.assertIn('Security Audit',report.render(r))
        for key,value in [('coverage_complete',False),('depth','quick'),('redaction_reviewed',False),('checks',[]),('project','')]:
            bad=copy.deepcopy(r);bad[key]=value
            self.assertTrue(report.validate(bad),key)
        r['dynamic']={'executed':True}
        self.assertTrue(report.validate(r))
        r=record();r['coverage']['files']['reviewed']=0
        self.assertTrue(report.validate(r))
        r=record();r['dynamic']={'executed':True,'authorization':'user request','isolation':'disposable local VM',
            'tests':[{'id':'ATK-1','plan':'mock-only','hypothesis':'object authorization bypass','outcome':'not reproduced','evidence':'redacted transcript'}],
            'cleanup':{'complete':True,'evidence':'no test accounts/listeners remain'}}
        self.assertFalse(report.validate(r))
        r['dynamic']['cleanup']['complete']=False
        self.assertTrue(report.validate(r))

    def test_disappeared_is_not_fixed(self):
        old=record();new=record()
        old['findings']=[{'id':'SEC-1','status':'confirmed'}]
        d=report.compare(old,new)
        self.assertEqual(d['absent_requires_review'],['SEC-1'])
        self.assertEqual(d['resolved'],[])

    def test_tools_do_not_pass_invalid_json_or_errors(self):
        for fn in (self_check._dep_npm,self_check._dep_pip,self_check._dep_govuln,self_check._dep_cargo,self_check._dep_composer):
            for payload in ('not json','{}','{"error":"offline"}'):
                with patch.object(self_check.shutil,'which',return_value='tool'), patch.object(self_check,'run',return_value=(0,payload)):
                    self.assertNotEqual(self_check._safe_dependency(fn,Path('.'),2)[0],'PASS',fn.__name__)
            for code in (124,126,127):
                with patch.object(self_check.shutil,'which',return_value='tool'), patch.object(self_check,'run',return_value=(code,'')):
                    self.assertNotEqual(self_check._safe_dependency(fn,Path('.'),2)[0],'PASS')

    def test_multiple_values_redacted_and_skips(self):
        with tempfile.TemporaryDirectory() as tmp:
            p=Path(tmp)
            (p/'a.py').write_text('password="SensitiveOne123"; password="SensitiveTwo456"',encoding='utf-8')
            (p/'excluded.lock').write_text('binary exclusion')
            result=scanner.scan(p)
            self.assertTrue(result['hits'])
            self.assertNotIn('Sensitive',json.dumps(result))
            self.assertTrue(result['skipped'])
            baseline=[{'file':'a.py','rule':'password-literal'}]
            self.assertTrue(scanner.scan(p,baseline=baseline)['hits'])

    def test_history_removed_secret_and_limit(self):
        with tempfile.TemporaryDirectory() as tmp:
            p=Path(tmp)
            def git(*args):
                subprocess.run(['git',*args],cwd=p,check=True,capture_output=True)
            git('init');git('config','user.email','test@example.invalid');git('config','user.name','Synthetic Test')
            (p/'a.py').write_text('password="HistoricalSecret123"\n')
            git('add','a.py');git('-c','commit.gpgsign=false','commit','-m','fixture')
            (p/'a.py').write_text('print(1)\n')
            git('add','a.py');git('-c','commit.gpgsign=false','commit','-m','remove')
            r=history.scan_history(p)
            self.assertEqual(r['status'],'complete')
            self.assertTrue(r['hits'])
            self.assertNotIn('HistoricalSecret123',json.dumps(r))
            self.assertFalse(history.scan_history(p,commits=1)['hits'])
            self.assertEqual(history.scan_history(p,max_bytes=1)['status'],'incomplete')

    def test_report_cli(self):
        with tempfile.TemporaryDirectory() as tmp:
            p=Path(tmp);j=p/'r.json';out=p/'r.md'
            j.write_text(json.dumps(record()))
            cmd=[sys.executable,report.__file__,str(j),'--render',str(out)]
            self.assertEqual(subprocess.run(cmd,capture_output=True).returncode,0)
            self.assertEqual(subprocess.run(cmd,capture_output=True).returncode,2)


if __name__=='__main__':unittest.main()
