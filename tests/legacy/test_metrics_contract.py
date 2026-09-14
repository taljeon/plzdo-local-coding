"""Frozen acceptance contract for the local-authored metric summary change."""
import ast
import inspect
import unittest
import generate_edits as target

class MetricsContract(unittest.TestCase):
    def metrics(self,data):
        self.assertTrue(hasattr(target,'response_metrics'),'Add the specified response_metrics helper')
        return target.response_metrics(data,123)

    def test_missing_cached_count_and_duration_are_unknown(self):
        value=self.metrics({'model':'test','done_reason':'stop','prompt_eval_count':100})
        self.assertIsNone(value['prompt_eval_cached_count'])
        self.assertIsNone(value['prompt_eval_duration_ns'])
        self.assertIsNone(value['ttft_seconds'])
        self.assertEqual(value['response_bytes'],123)
        self.assertEqual(value['prompt_eval_count'],100)

    def test_zero_is_a_measured_value(self):
        value=self.metrics({'prompt_eval_cached_count':0,'prompt_eval_duration':0})
        self.assertEqual(value['prompt_eval_cached_count'],0)
        self.assertEqual(value['prompt_eval_duration_ns'],0)

    def test_real_cached_count_and_durations_preserved(self):
        value=self.metrics({'model':'test','done_reason':'stop','prompt_eval_count':100,
           'prompt_eval_cached_count':61,'eval_count':8,'prompt_eval_duration':20,
           'total_duration':30,'load_duration':4,'eval_duration':6})
        self.assertEqual(value,{'model':'test','done_reason':'stop','prompt_eval_count':100,
           'prompt_eval_cached_count':61,'eval_count':8,'prompt_eval_duration_ns':20,
           'total_duration_ns':30,'load_duration_ns':4,'eval_duration_ns':6,
           'response_bytes':123,'ttft_seconds':None})

    def test_invalid_new_metrics_are_unknown(self):
        for invalid in [True,-1,1.5,'61',None]:
            value=self.metrics({'prompt_eval_cached_count':invalid,'prompt_eval_duration':invalid})
            self.assertIsNone(value['prompt_eval_cached_count'])
            self.assertIsNone(value['prompt_eval_duration_ns'])

    def test_worker_entry_uses_helper_not_unobserved_ttft(self):
        calls=[node for node in ast.walk(ast.parse(inspect.getsource(target._worker_main))) if isinstance(node,ast.Call)]
        self.assertTrue(any(isinstance(node.func,ast.Name) and node.func.id=='response_metrics' for node in calls))

if __name__=='__main__': unittest.main()
