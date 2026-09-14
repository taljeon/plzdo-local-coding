import json
from pathlib import Path
import tempfile
import unittest
from workflow_metrics import collect_run,export_runs

class MetricsTest(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name)/'run';self.root.mkdir()
        self.put('packet.json',{'id':'fixture'})
        self.put('result.json',{'state':'candidate_ready','duration_seconds':3,'provider_transitions':0,
                 'attempts':[{'provider':'local','number':1,'passed':True}]})
    def put(self,path,value):
        p=self.root/path;p.parent.mkdir(parents=True,exist_ok=True);p.write_text(json.dumps(value))
    def test_missing_is_unknown_and_zero_preserved(self):
        self.put('local-1/provider/response.json',{'prompt_eval_count':10,'prompt_eval_cached_count':0})
        row=collect_run(self.root)[0]
        self.assertEqual(row['cached_prompt_tokens'],0);self.assertIsNone(row['output_tokens'])
        self.assertIsNone(row['ttft_seconds']);self.assertTrue(row['first_attempt_passed'])
    def test_injected_not_counted_as_real_quality(self):
        self.put('result.json',{'state':'candidate_ready','fault_injection':True,
                 'attempts':[{'provider':'local','number':1,'passed':False},{'provider':'codex','number':1,'passed':True}]})
        self.assertTrue(all(r['first_attempt_passed'] is None for r in collect_run(self.root)))
    def test_export_has_no_prompt_and_refuses_overwrite(self):
        self.put('local-1/provider/process/summary.json',{'argv':['private prompt'],'duration_seconds':1})
        output=self.root.parent/'export';export_runs([self.root],output)
        self.assertNotIn('private prompt',(output/'metrics.json').read_text())
        with self.assertRaises(FileExistsError):export_runs([self.root],output)
    def test_boolean_or_negative_metrics_are_unknown(self):
        self.put('local-1/provider/response.json',{'prompt_eval_count':True,'prompt_eval_cached_count':-1})
        row=collect_run(self.root)[0]
        self.assertIsNone(row['prompt_tokens']);self.assertIsNone(row['cached_prompt_tokens'])
    def test_handoff_has_no_fabricated_provider_or_quality(self):
        self.put('packet.json',{'id':'compute','kind':'compute-analysis'})
        self.put('result.json',{'state':'handoff_required','attempts':[]})
        row=collect_run(self.root)[0]
        self.assertIsNone(row['provider']);self.assertIsNone(row['passed']);self.assertIsNone(row['first_attempt_passed'])
    def test_latest_effective_cleanup_wins_over_legacy_file(self):
        self.put('cleanup.json',{'passed':True})
        result=json.loads((self.root/'result.json').read_text());result['cleanup']={'passed':False}
        self.put('result.json',result)
        self.assertFalse(collect_run(self.root)[0]['cleanup_passed'])

if __name__=='__main__':unittest.main()
