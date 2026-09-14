"""Offline profile integration and process-supervision contracts; no model calls."""
import contextlib
import json
from pathlib import Path
import sys
import tempfile
import time
import unittest
from types import SimpleNamespace
from unittest.mock import Mock, patch

import ollama_engine as workflow
import workflow as controller
from engine_types import no_start_cleanup
from generation_profile import PROFILE_ID, HUIHUI_PROFILE_ID, resolve_profile
from workflow_artifacts import validate_artifact_packet
from run_bounded import run


class OfficialIntegrationTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        self.packet = {'kind': 'artifact-create', 'id': 'profile-fixture',
                       'objective': 'Create a small module.', 'allowed_paths': ['item.py'],
                       'generation_profile': HUIHUI_PROFILE_ID, 'authorityId': 'fixture',
                       'checks': [['python3', '-B', '-c', 'pass']]}

    def test_new_packet_does_not_synthesize_a_missing_profile(self):
        packet = {key: value for key, value in self.packet.items() if key != 'generation_profile'}
        with self.assertRaises(workflow.ContractError):
            validate_artifact_packet(packet)

    def test_profile_options_are_bound_and_drift_rejected(self):
        packet = validate_artifact_packet({**self.packet, 'generation_profile': HUIHUI_PROFILE_ID})
        self.assertEqual(packet['generation_profile'], resolve_profile(HUIHUI_PROFILE_ID))
        self.assertEqual(controller.packet_hash(packet), controller.packet_hash(validate_artifact_packet(packet)))
        packet['generation_profile']['options']['num_predict'] = 4096
        with self.assertRaises(workflow.ContractError):
            validate_artifact_packet(packet)

    def execute_local(self, profile=None, *, preflight_error=None, stop_reason=None, token_evidence=None,
                      stream_failure=None, collided_status=None, partial_response=None, child_opener=None):
        requested = {}
        expected_context = 81920 if profile else 65536
        ps_calls = 0

        def status(endpoint, **kwargs):
            nonlocal ps_calls
            if endpoint == 'version':
                return {'version': '0.33.3'}
            if endpoint == 'tags':
                return {'models': [{'name': workflow.MODEL, 'digest': workflow.DIGEST}]}
            ps_calls += 1
            return {'models': [] if ps_calls == 1 else [
                {'name': workflow.MODEL, 'digest': workflow.DIGEST, 'context_length': expected_context}]}

        def generate(argv, cwd, evidence, timeout, **kwargs):
            requested.update(argv=argv, timeout=timeout, kwargs=kwargs)
            request = json.loads((self.root / 'provider/request.json').read_text())
            requested['request'] = request
            if stop_reason:
                return {'cleanup': no_start_cleanup(), 'return_code': 126, 'duration_seconds': 1,
                        'supervisor_stop': True, 'stop_reason': stop_reason}
            if child_opener is not None:
                import generate_stream
                evidence.mkdir(parents=True)
                with (evidence / 'events.jsonl').open('w') as output:
                    with (contextlib.redirect_stdout(output), patch.object(sys, 'argv', argv[next(i for i, value in enumerate(argv) if value.endswith('generate_stream.py')):]),
                          patch.object(generate_stream.urllib.request, 'build_opener', return_value=child_opener)):
                        return_code = generate_stream._worker_main()
                return {'cleanup': no_start_cleanup(), 'return_code': return_code, 'duration_seconds': 1, 'supervisor_stop': False}
            if stream_failure:
                evidence.mkdir(parents=True)
                (evidence / 'events.jsonl').write_text(json.dumps(stream_failure))
                if collided_status is not None:
                    (self.root / 'provider/stream-status.json').write_text(collided_status)
                if partial_response is not None:
                    (self.root / 'provider/response.json').write_text(partial_response)
                return {'cleanup': no_start_cleanup(), 'return_code': 1, 'duration_seconds': 1, 'supervisor_stop': False}
            response = {
                'model': workflow.MODEL, 'done': True, 'done_reason': 'stop',
                'message': {'content': '{"edits": []}'},
            }
            response.update({'prompt_eval_count': 20, 'eval_count': 10} if token_evidence is None else token_evidence)
            (self.root / 'provider/response.json').write_text(json.dumps(response))
            return {'cleanup': no_start_cleanup(), 'return_code': 0, 'duration_seconds': 181, 'supervisor_stop': False}

        governor = Mock()
        governor.summary.return_value = {'fixture': True}
        if preflight_error:
            governor.preflight.side_effect = ValueError(preflight_error)
        with (patch.object(workflow, 'MANIFEST', SimpleNamespace(read_bytes=lambda: b'model')),
             patch.object(workflow, 'sha', return_value=workflow.DIGEST),
             patch.object(workflow, 'local_status', side_effect=status),
             patch.object(workflow, 'run', side_effect=generate) as launcher,
             patch('generation_health.GenerationHealth', return_value=governor)):
            try:
                result = workflow.local_edits('Implement the frozen task.', {'type': 'object'},
                    self.root / 'provider', 17, generation_profile=profile)
            except workflow.LocalGenerationError as exc:
                return requested, governor, launcher, exc
        return requested, governor, launcher, result

    def test_profile_generation_obeys_effective_invocation_deadline_and_supervisor(self):
        requested, governor, launcher, result = self.execute_local(resolve_profile(PROFILE_ID))
        self.assertEqual(result, {'edits': []})
        self.assertGreater(requested['timeout'], 0)
        self.assertLessEqual(requested['timeout'], 17)
        self.assertIs(requested['kwargs']['stop_check'], governor)
        self.assertIn('--profile', requested['argv'])
        self.assertTrue(any(arg.endswith('generate_stream.py') for arg in requested['argv']))
        self.assertEqual(requested['request']['options'], resolve_profile(PROFILE_ID)['options'])
        self.assertTrue(requested['request']['stream'])
        governor.preflight.assert_called_once()
        governor.close.assert_called_once()

    def test_legacy_generation_keeps_its_original_transport_and_timeout(self):
        requested, governor, launcher, result = self.execute_local()
        self.assertEqual(result, {'edits': []})
        self.assertGreater(requested['timeout'], 0)
        self.assertLessEqual(requested['timeout'], 17)
        self.assertNotIn('stop_check', requested['kwargs'])
        self.assertTrue(any(arg.endswith('generate_edits.py') for arg in requested['argv']))
        self.assertEqual(requested['request']['options']['num_predict'], 4096)
        self.assertFalse(requested['request']['stream'])
        governor.preflight.assert_not_called()

    def test_memory_preflight_failure_never_starts_generation(self):
        requested, governor, launcher, error = self.execute_local(resolve_profile(PROFILE_ID), preflight_error='fixture')
        self.assertIsInstance(error, workflow.LocalGenerationError)
        self.assertTrue(error.generation_hard_stop)
        self.assertEqual(error.generation_error_code, 'MEMORY_ADMISSION_FAILED')
        launcher.assert_not_called()

    def test_memory_abort_is_not_a_semantic_retry(self):
        requested, governor, launcher, error = self.execute_local(resolve_profile(PROFILE_ID), stop_reason='memory-pressure-critical')
        self.assertIsInstance(error, workflow.LocalGenerationError)
        self.assertTrue(error.generation_hard_stop)
        self.assertEqual(error.generation_error_code, 'MEMORY_PRESSURE')

    def test_input_budget_rejects_before_model_status_or_generation(self):
        with patch.object(workflow, 'local_status') as status, patch.object(workflow, 'run') as launcher:
            with self.assertRaises(workflow.LocalGenerationError) as failure:
                workflow.local_edits('x' * 20000, {'type': 'object'}, self.root / 'large', 30,
                                     generation_profile=resolve_profile(PROFILE_ID))
        self.assertTrue(failure.exception.generation_hard_stop)
        self.assertEqual(failure.exception.generation_error_code, 'INPUT_BUDGET_EXCEEDED')
        status.assert_not_called()
        launcher.assert_not_called()

    def test_bad_profile_has_its_own_code_before_status_or_generation(self):
        for index, profile in enumerate(('unknown-profile', {**resolve_profile(PROFILE_ID), 'extra': True})):
            with patch.object(workflow, 'local_status') as status, patch.object(workflow, 'run') as launcher:
                with self.assertRaises(workflow.LocalGenerationError) as failed:
                    workflow.local_edits('small', {'type': 'object'}, self.root / str(index), 30,
                                         generation_profile=profile)
            self.assertEqual(failed.exception.generation_error_code, 'PROFILE_BINDING_INVALID')
            self.assertTrue(failed.exception.generation_hard_stop)
            status.assert_not_called()
            launcher.assert_not_called()

    def test_late_status_collision_preserves_original_code_and_hard_stop(self):
        _, _, _, error = self.execute_local(resolve_profile(PROFILE_ID), stream_failure={
            'status': 'failed', 'error_code': 'MODEL_MISMATCH', 'status_write_failed': True},
            collided_status='operator-owned non-JSON data', partial_response='{"unfinished":')
        self.assertEqual(error.generation_error_code, 'MODEL_MISMATCH')
        self.assertTrue(error.status_write_failed)
        self.assertTrue(error.generation_hard_stop)
        self.assertEqual((self.root / 'provider/stream-status.json').read_text(), 'operator-owned non-JSON data')

    def test_http_failure_with_lost_status_is_hard_stop_not_next_provider_permission(self):
        _, _, _, error = self.execute_local(resolve_profile(PROFILE_ID), stream_failure={
            'status': 'failed', 'error_code': 'HTTP_TIMEOUT', 'status_write_failed': True})
        self.assertEqual(error.generation_error_code, 'HTTP_TIMEOUT')
        self.assertTrue(error.generation_hard_stop)

    def test_evidence_close_failure_preserves_code_and_hard_stop(self):
        _, _, _, error = self.execute_local(resolve_profile(PROFILE_ID), stream_failure={
            'status': 'failed', 'error_code': 'HTTP_ERROR', 'evidence_close_failed': True})
        self.assertEqual(error.generation_error_code, 'HTTP_ERROR')
        self.assertTrue(error.evidence_close_failed)
        self.assertFalse(error.status_write_failed)
        self.assertTrue(error.generation_hard_stop)

    def test_real_child_cli_failure_receipt_reaches_parent_without_losing_cause(self):
        import generate_stream
        from test_generate_stream import FakeHTTP
        calls = []
        destination = self.root / 'provider/stream-status.json'
        def open_response(request, timeout):
            calls.append(request)
            destination.write_bytes(b'existing evidence must survive')
            frame = {'model': 'incorrect-model', 'done': False,
                     'message': {'role': 'assistant', 'content': ''}}
            return FakeHTTP([(json.dumps(frame) + '\n').encode()])
        close = generate_stream.Evidence.close
        def close_failure(evidence):
            close(evidence)
            raise OSError('private close diagnostic must not escape')
        with patch.object(generate_stream.Evidence, 'close', close_failure):
            _, _, _, error = self.execute_local(resolve_profile(PROFILE_ID),
                child_opener=SimpleNamespace(open=open_response))
        self.assertEqual(error.generation_error_code, 'MODEL_MISMATCH')
        self.assertTrue(error.status_write_failed)
        self.assertTrue(error.evidence_close_failed)
        self.assertTrue(error.generation_hard_stop)
        self.assertNotIn('private close', str(error))
        self.assertEqual(len(calls), 1)
        self.assertEqual(destination.read_bytes(), b'existing evidence must survive')
        self.assertFalse((self.root / 'provider/response.json').exists())

    def test_http_error_without_evidence_failure_is_still_a_hard_stop(self):
        _, _, _, error = self.execute_local(resolve_profile(PROFILE_ID), stream_failure={
            'status': 'failed', 'error_code': 'HTTP_TIMEOUT'})
        self.assertEqual(error.generation_error_code, 'HTTP_TIMEOUT')
        self.assertFalse(error.status_write_failed)
        self.assertTrue(error.generation_hard_stop)

    def test_malformed_receipt_does_not_weaken_stop_gates(self):
        _, _, _, error = self.execute_local(resolve_profile(PROFILE_ID), stream_failure={
            'status': 'failed', 'error_code': 'HTTP_TIMEOUT', 'status_write_failed': 'true'})
        self.assertEqual(error.generation_error_code, 'GENERATION_DIAGNOSTIC_INVALID')
        self.assertTrue(error.generation_hard_stop)

    def test_failure_receipt_symlink_is_not_followed(self):
        (self.root / 'process').mkdir()
        outside = self.root / 'outside.json'
        outside.write_text('{"status":"failed","error_code":"HTTP_TIMEOUT"}')
        (self.root / 'process/events.jsonl').symlink_to(outside)
        with self.assertRaises(workflow.LocalGenerationError) as failed:
            workflow._profile_stream_failure(self.root)
        self.assertEqual(failed.exception.generation_error_code, 'GENERATION_DIAGNOSTIC_INVALID')
        self.assertTrue(failed.exception.generation_hard_stop)

    def test_legacy_status_only_failure_evidence_is_still_readable(self):
        (self.root / 'stream-status.json').write_text('{"status":"failed","error_code":"MODEL_MISMATCH"}')
        error = workflow._profile_stream_failure(self.root)
        self.assertEqual(error.generation_error_code, 'MODEL_MISMATCH')
        self.assertTrue(error.generation_hard_stop)

    def test_missing_or_nonfailed_status_is_not_permission_for_fallback(self):
        for status in (None, {}, {'status': 'complete', 'error_code': 'HTTP_TIMEOUT'},
                       {'status': 'failed'}, {'status': 'failed', 'error_code': None}):
            with patch.object(workflow, '_generation_failure_object', side_effect=[None, status]):
                with self.assertRaises(workflow.LocalGenerationError) as rejected:
                    workflow._profile_stream_failure(self.root)
            self.assertEqual(rejected.exception.generation_error_code, 'GENERATION_DIAGNOSTIC_INVALID')
            self.assertTrue(rejected.exception.generation_hard_stop)

    def test_missing_or_over_limit_token_report_cannot_pass(self):
        requested, governor, launcher, error = self.execute_local(resolve_profile(PROFILE_ID),
            token_evidence={'prompt_eval_count': True, 'eval_count': 65537})
        self.assertIsInstance(error, workflow.LocalGenerationError)
        self.assertEqual(error.generation_error_code, 'TOKEN_USAGE_INVALID')
        self.assertTrue(error.generation_hard_stop)

    def test_reported_prompt_must_leave_the_reserved_output_room(self):
        requested, governor, launcher, error = self.execute_local(resolve_profile(PROFILE_ID),
            token_evidence={'prompt_eval_count': 16000, 'eval_count': 10})
        self.assertIsInstance(error, workflow.LocalGenerationError)
        self.assertEqual(error.generation_error_code, 'INPUT_BUDGET_EXCEEDED')
        self.assertTrue(error.generation_hard_stop)


class SupervisorProcessTest(unittest.TestCase):
    def test_supervisor_stops_only_owned_process_group(self):
        with tempfile.TemporaryDirectory() as temporary:
            started = time.monotonic()
            result = run([sys.executable, '-B', '-c', 'import time; time.sleep(10)'], temporary,
                         Path(temporary) / 'evidence', 3,
                         stop_check=lambda: 'memory-pressure-critical' if time.monotonic() - started >= 0.1 else None)
            self.assertEqual(result['return_code'], 126)
            self.assertTrue(result['supervisor_stop'])
            self.assertEqual(result['stop_reason'], 'memory-pressure-critical')
            self.assertLess(result['duration_seconds'], 3)

    def test_invalid_or_failed_supervisor_fails_closed(self):
        def failed():
            raise RuntimeError('Private diagnostic should not be exported')
        for callback in (lambda: 4, failed):
            with self.subTest(callback=callback), tempfile.TemporaryDirectory() as temporary:
                result = run([sys.executable, '-B', '-c', 'import time; time.sleep(10)'], temporary,
                             Path(temporary) / 'evidence', 3, stop_check=callback)
                self.assertEqual(result['return_code'], 126)
                self.assertEqual(result['stop_reason'], 'supervision-error')
                self.assertNotIn('Private diagnostic', json.dumps(result))


if __name__ == '__main__':
    unittest.main()
