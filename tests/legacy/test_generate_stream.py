"""In-memory HTTP fixtures only: never contact Ollama or any model/provider."""
import copy
from contextlib import redirect_stdout
import hashlib
import io
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch
import urllib.error

import generate_stream as stream
from generation_profile import PROFILE_ID, detect_repetition, resolve_profile


class Clock:
    def __init__(self):
        self.value = 1000.0

    def __call__(self):
        return self.value


class FakeHTTP:
    def __init__(self, lines, clock=None, times=None):
        self.lines = iter(lines)
        self.clock, self.times = clock, iter(times) if times else None
        self.pending = b''
        self.closed = False

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.closed = True

    def readline(self, limit):
        if not self.pending:
            self.pending = next(self.lines, b'')
            if self.times:
                self.clock.value = next(self.times, self.clock.value)
        raw, self.pending = self.pending[:limit], self.pending[limit:]
        return raw


class FakeOpener:
    def __init__(self, response=None, error=None):
        self.response, self.error = response, error
        self.calls = []

    def open(self, request, timeout):
        self.calls.append((request, timeout))
        if self.error:
            raise self.error
        return self.response


class StreamTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name).resolve()
        self.profile = resolve_profile(PROFILE_ID)
        self.sequence = 0

    def request(self):
        result = {key: copy.deepcopy(self.profile[key]) for key in
                  ('model', 'options', 'stream', 'think', 'truncate', 'shift', 'keep_alive')}
        return {**result, 'messages': [{'role': 'user', 'content': 'Return the requested JSON.'}],
                'format': {'type': 'object'}}

    def frame(self, content='', done=False, **changes):
        value = {'model': self.profile['model'], 'message': {'role': 'assistant', 'content': content},
                 'done': done}
        if done:
            value.update(done_reason='stop', prompt_eval_count=100, prompt_eval_cached_count=60,
                         eval_count=5, eval_duration=10000000, total_duration=20000000)
        value.update(changes)
        return json.dumps(value, ensure_ascii=False).encode() + b'\n'

    def destination(self):
        self.sequence += 1
        directory = self.root / ('run-' + str(self.sequence))
        directory.mkdir()
        return directory / 'response.json'

    def generate(self, lines, *, request=None, clock=None, times=None, detector=detect_repetition,
                 destination=None, profile=None):
        destination = destination or self.destination()
        clock = clock or Clock()
        http = FakeHTTP(lines, clock, times)
        opener = FakeOpener(http)
        metrics = stream.run_generation(profile or self.profile, request or self.request(), destination,
                                         opener=opener, clock=clock, repetition_fn=detector)
        return destination, metrics, opener, http

    def assert_failure(self, lines, code, **kwargs):
        destination = self.destination()
        with self.assertRaises(stream.StreamFailure) as raised:
            self.generate(lines, destination=destination, **kwargs)
        self.assertEqual(raised.exception.code, code)
        self.assertFalse(destination.exists())
        status = json.loads((destination.parent / 'stream-status.json').read_text())
        self.assertEqual(status['status'], 'failed')
        self.assertEqual(status['error_code'], code)
        self.assertTrue((destination.parent / 'wire.jsonl').exists())
        return destination, status

    def test_normal_stream_merges_content_and_final_metrics(self):
        lines = [self.frame('{"edits":'), self.frame('[]}'), self.frame(done=True)]
        destination, metrics, opener, http = self.generate(lines)
        data = json.loads(destination.read_text())
        self.assertEqual(data['message']['content'], '{"edits":[]}')
        self.assertEqual(metrics['prompt_eval_cached_count'], 60)
        self.assertEqual(metrics['generation_profile_id'], PROFILE_ID)
        self.assertTrue(metrics['request_profile_match'])
        self.assertEqual(opener.calls[0][0].full_url, stream.ENDPOINT)
        self.assertEqual(opener.calls[0][1], 600)
        self.assertEqual(len(opener.calls), 1)
        self.assertTrue(http.closed)
        status = json.loads((destination.parent / 'stream-status.json').read_text())
        self.assertEqual(status['status'], 'complete')
        self.assertIsNone(status['error_code'])
        self.assertEqual(status['wire_bytes'], sum(map(len, lines)))

    def test_only_nonempty_content_sets_first_and_idle_clock(self):
        clock = Clock()
        lines = [self.frame(), self.frame('{'), self.frame(), self.frame('}'), self.frame(done=True)]
        destination, metrics, _, _ = self.generate(lines, clock=clock,
                                                   times=[1001, 1003, 1010, 1012, 1013])
        status = json.loads((destination.parent / 'stream-status.json').read_text())
        self.assertEqual(metrics['ttft_seconds'], 3)
        self.assertEqual(status['first_content_monotonic'], 1003)
        self.assertEqual(status['last_content_monotonic'], 1012)

    def test_progress_is_atomic_with_immediate_first_content_then_one_second_throttle(self):
        clock = Clock()
        lines = [self.frame('{'), self.frame(' '), self.frame(' '), self.frame(' '), self.frame('}'),
                 self.frame(done=True)]
        with patch.object(stream.os, 'replace', wraps=stream.os.replace) as replace:
            destination, _, _, _ = self.generate(lines, clock=clock,
                                                  times=[1000.1, 1000.2, 1001.1, 1001.2, 1002.2, 1002.3])
        self.assertEqual(replace.call_count, 3)
        status = json.loads((destination.parent / 'stream-status.json').read_text())
        self.assertEqual(status['progress_writes'], 4)  # initial, immediate first, two throttled replacements
        progress = json.loads((destination.parent / 'progress.json').read_text())
        self.assertEqual(progress['content_chars'], 5)
        self.assertEqual(progress['first_content_monotonic'], 1000.1)
        self.assertFalse(list(destination.parent.glob('.progress-*.tmp')))

    def test_fast_first_content_stall_uses_120_second_idle_not_600_second_prefill(self):
        from generation_health import GenerationHealth
        clock = Clock()
        destination = self.destination()
        evidence = stream.Evidence(destination, clock())
        self.addCleanup(evidence.close)
        healthy = {'pressure': 1, 'free_bytes': 8 * 1024 ** 3, 'file_backed_bytes': 1024 ** 3,
                   'compressed_physical_bytes': 0, 'compressed_logical_bytes': 0,
                   'swap_used_bytes': 0, 'swap_out_bytes': 0, 'page_out_bytes': 0}
        health = GenerationHealth(self.profile, evidence.progress_path,
                                  destination.parent / 'health.jsonl', sampler=lambda: healthy, clock=clock)
        self.addCleanup(health.close)
        health.preflight()
        clock.value = 1000.1
        evidence.update_content('{', clock())
        marker = json.loads(evidence.progress_path.read_text())
        self.assertEqual(marker['first_content_monotonic'], 1000.1)
        self.assertEqual(marker['last_content_monotonic'], 1000.1)
        self.assertEqual(marker['content_chars'], 1)
        self.assertEqual(evidence.progress_writes, 2)
        self.assertIsNone(health())
        clock.value = 1120.2
        self.assertEqual(health(), 'generation-content-stall')
        self.assertEqual(health.summary()['first_content_monotonic'], 1000.1)

    def test_empty_early_frame_does_not_publish_first_content(self):
        destination = self.destination()
        evidence = stream.Evidence(destination, 1000)
        self.addCleanup(evidence.close)
        evidence.update_content('', 1000.1)
        self.assertEqual(json.loads(evidence.progress_path.read_text()), {
            'first_content_monotonic': None, 'last_content_monotonic': None, 'content_chars': 0})
        self.assertEqual(evidence.progress_writes, 1)

    def test_external_progress_replacement_is_not_overwritten(self):
        destination = self.destination()
        evidence = stream.Evidence(destination, 1000)
        self.addCleanup(evidence.close)
        evidence.progress_path.write_text('external marker')
        with self.assertRaises(stream.StreamFailure) as raised:
            evidence.update_content('x', 1002)
        self.assertEqual(raised.exception.code, 'PROGRESS_CHANGED')
        self.assertEqual(evidence.progress_path.read_text(), 'external marker')

    def test_long_wire_over_old_2mib_limit_with_small_merged_response_succeeds(self):
        # Metadata-heavy frames may exceed the old whole-response limit while
        # the actual generated JSON content remains very small.
        header = self.frame('', created_at='2026-09-07T00:00:00Z', padding='x' * 200)
        count = (2 * 1024 * 1024 // len(header)) + 20
        destination, metrics, _, _ = self.generate([header] * count + [self.frame('{"value":42}'), self.frame(done=True)])
        self.assertGreater(metrics['wire_bytes'], 2 * 1024 * 1024)
        self.assertLess(destination.stat().st_size, 2 * 1024 * 1024)

    def test_repetition_checks_each_4096_character_boundary(self):
        payload = '{"code":"' + ('abcde' * 3000) + '"}'
        calls = []

        def detector(text, profile):
            calls.append(len(text))
            return None

        self.generate([self.frame(payload), self.frame(done=True)], detector=detector)
        self.assertEqual(calls, [4096, 8192, 12288])

    def test_pathological_repetition_fails_without_normal_response(self):
        unit = ('abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789' * 5)[:256]
        content = '{"code":"' + unit * 160 + '"}'
        lines = [self.frame(content[index:index + 2048]) for index in range(0, len(content), 2048)]
        self.assert_failure(lines + [self.frame(done=True)], 'REPETITION_DETECTED')

    def test_legitimate_boilerplate_is_not_repetition_failure(self):
        content = json.dumps({'lines': [f'    field_{index}: value_{index}' for index in range(2500)]})
        lines = [self.frame(content[index:index + 2048]) for index in range(0, len(content), 2048)]
        destination, _, _, _ = self.generate(lines + [self.frame(done=True)])
        self.assertEqual(len(json.loads(json.loads(destination.read_text())['message']['content'])['lines']), 2500)

    def test_missing_done_and_length_stop_are_failures(self):
        self.assert_failure([self.frame('{"ok":true}')], 'MISSING_DONE')
        self.assert_failure([self.frame('{}'), self.frame(done=True, done_reason='length')], 'STOP_REASON')

    def test_every_frame_rejects_model_remote_and_tool_drift(self):
        cases = [
            (self.frame('x', model='wrong-model'), 'MODEL_MISMATCH'),
            (self.frame('x', remote_host='https://example.invalid'), 'REMOTE_RESPONSE'),
            (self.frame('x', remote_model='other-model'), 'REMOTE_RESPONSE'),
            (self.frame(message={'role': 'assistant', 'content': '', 'tool_calls': [{'function': 'unexpected'}]}), 'TOOL_RESPONSE'),
            (self.frame('x', tool_calls=[{'function': 'unexpected'}]), 'TOOL_RESPONSE'),
            (self.frame(message={'role': 'assistant', 'content': '', 'tool_calls': {}}), 'INVALID_MESSAGE'),
        ]
        for line, code in cases:
            with self.subTest(code=code):
                self.assert_failure([self.frame('{'), line, self.frame('}'), self.frame(done=True)], code)

    def test_invalid_frames_and_content_never_create_response(self):
        cases = [
            ([b'\xff\n'], 'INVALID_UTF8'),
            ([b'{"model":"a","model":"b"}\n'], 'INVALID_FRAME_JSON'),
            ([b'not json\n'], 'INVALID_FRAME_JSON'),
            ([b'[]\n'], 'INVALID_FRAME'),
            ([self.frame(message=None)], 'INVALID_MESSAGE'),
            ([self.frame(message={'role': 'assistant', 'content': 1})], 'INVALID_MESSAGE'),
            ([self.frame(message={'role': 'assistant', 'content': '{}', 'thinking': 'unexpected'})], 'UNEXPECTED_THINKING'),
            ([self.frame('[1,2]'), self.frame(done=True)], 'INVALID_CONTENT_OBJECT'),
            ([self.frame('{"x":1,"x":2}'), self.frame(done=True)], 'INVALID_CONTENT_JSON'),
            ([self.frame('{"x":'), self.frame(done=True)], 'INVALID_CONTENT_JSON'),
            ([b'{"error":"do-not-print-sensitive-provider-error"}\n'], 'SERVER_ERROR'),
        ]
        for lines, code in cases:
            with self.subTest(code=code):
                destination, status = self.assert_failure(lines, code)
                self.assertNotIn('do-not-print-sensitive-provider-error', json.dumps(status))

    def test_post_done_frame_is_not_accepted(self):
        self.assert_failure([self.frame('{}'), self.frame(done=True), self.frame('unexpected')], 'AFTER_DONE')

    def test_frame_limit_preserves_bounded_wire_prefix(self):
        destination, status = self.assert_failure([b'x' * (self.profile['frame_limit'] + 10)], 'FRAME_LIMIT')
        self.assertEqual(status['wire_bytes'], self.profile['frame_limit'] + 1)
        self.assertEqual((destination.parent / 'wire.jsonl').stat().st_size, status['wire_bytes'])

    def consume_with_small_limits(self, lines, **limits):
        destination = self.destination()
        profile = {**self.profile, **limits}
        evidence = stream.Evidence(destination, 1000)
        evidence.wire_limit = profile['wire_limit']
        self.addCleanup(evidence.close)
        return destination, profile, evidence

    def test_wire_limit_never_grows_beyond_cap(self):
        lines = [self.frame('x')] * 10
        destination, profile, evidence = self.consume_with_small_limits(lines, wire_limit=500)
        with self.assertRaises(stream.StreamFailure) as raised:
            stream.consume_frames(lines, profile, evidence, clock=lambda: 1001)
        self.assertEqual(raised.exception.code, 'WIRE_LIMIT')
        self.assertEqual((destination.parent / 'wire.jsonl').stat().st_size, 500)

    def test_content_and_merged_envelope_have_separate_size_checks(self):
        cases = [
            ([self.frame('{"value":"' + 'x' * 300 + '"}'), self.frame(done=True)], 100),
            ([self.frame('{}'), self.frame(done=True, large_metadata='x' * 1000)], 500),
        ]
        for lines, limit in cases:
            destination, profile, evidence = self.consume_with_small_limits(lines, response_limit=limit)
            with self.subTest(limit=limit), self.assertRaises(stream.StreamFailure) as raised:
                stream.consume_frames(lines, profile, evidence, clock=lambda: 1001)
            self.assertEqual(raised.exception.code, 'RESPONSE_LIMIT')
            self.assertFalse(destination.exists())

    def test_generation_hard_deadline_fails_between_frames(self):
        self.assert_failure([self.frame('{}'), self.frame(done=True)], 'GENERATION_DEADLINE',
                            times=[4601], clock=Clock())

    def test_profile_request_flags_and_options_are_exact(self):
        cases = []
        for key, value in (('stream', False), ('think', True), ('truncate', True), ('shift', True),
                           ('keep_alive', 'forever'), ('model', 'qwen-cloud')):
            cases.append({**self.request(), key: value})
        changed = self.request()
        changed['options']['num_predict'] = 65535
        cases.append(changed)
        changed = self.request()
        changed['options']['seed'] = True
        cases.append(changed)
        for request in cases:
            with self.subTest(request=request), self.assertRaises(stream.StreamFailure):
                stream.validate_request(request, self.profile)
        for request in ({**self.request(), 'tools': []}, {**self.request(), 'format': 'json'},
                        {**self.request(), 'messages': [{'role': 'tool', 'content': 'x'}]}):
            with self.assertRaises(stream.StreamFailure):
                stream.validate_request(request, self.profile)

    def test_invalid_profile_or_request_makes_zero_http_calls(self):
        destination = self.destination()
        opener = FakeOpener()
        profile = copy.deepcopy(self.profile)
        profile['options']['temperature'] = 0
        with self.assertRaises(stream.StreamFailure):
            stream.run_generation(profile, self.request(), destination, opener=opener, clock=Clock())
        self.assertEqual(opener.calls, [])
        self.assertEqual(json.loads((destination.parent / 'stream-status.json').read_text())['error_code'], 'INVALID_PROFILE')

    def test_existing_files_are_never_overwritten(self):
        for filename in ('response.json', 'wire.jsonl', 'stream-status.json', 'progress.json'):
            destination = self.destination()
            existing = destination.parent / filename
            existing.write_bytes(b'operator data')
            opener = FakeOpener()
            with self.subTest(filename=filename), self.assertRaises(stream.StreamFailure) as raised:
                stream.run_generation(self.profile, self.request(), destination, opener=opener, clock=Clock())
            self.assertEqual(raised.exception.code, 'OUTPUT_EXISTS')
            self.assertIs(raised.exception.status_write_failed, False)
            self.assertEqual(existing.read_bytes(), b'operator data')
            self.assertEqual(opener.calls, [])

    def collision_opener(self, destination, *, lines=(), error=None):
        marker = b'{"status":"complete","fixture":"immutable previous record"}\n'
        status_path = destination.parent / 'stream-status.json'

        class LateCollisionOpener(FakeOpener):
            def open(self, request, timeout):
                with status_path.open('xb') as existing:
                    existing.write(marker)
                return super().open(request, timeout)

        return LateCollisionOpener(FakeHTTP(lines), error=error), marker

    def test_late_status_collision_preserves_primary_stream_error_and_marker(self):
        destination = self.destination()
        opener, marker = self.collision_opener(destination, lines=[self.frame('{}', model='wrong-model')])
        with self.assertRaises(stream.StreamFailure) as raised:
            stream.run_generation(self.profile, self.request(), destination, opener=opener, clock=Clock())
        self.assertEqual(raised.exception.code, 'MODEL_MISMATCH')
        self.assertIs(raised.exception.status_write_failed, True)
        self.assertEqual((destination.parent / 'stream-status.json').read_bytes(), marker)
        self.assertFalse(destination.exists())
        self.assertEqual(len(opener.calls), 1)

    def test_late_status_collision_preserves_http_interrupt_and_io_error_codes(self):
        cases = [
            (TimeoutError('private timeout detail'), 'HTTP_TIMEOUT'),
            (urllib.error.URLError('private transport detail'), 'HTTP_ERROR'),
            (urllib.error.URLError(TimeoutError('private nested detail')), 'HTTP_TIMEOUT'),
            (urllib.error.HTTPError(stream.ENDPOINT, 503, 'private HTTP detail', {}, None), 'HTTP_ERROR'),
            (KeyboardInterrupt(), 'INTERRUPTED'),
            (OSError('private stream I/O detail'), 'STREAM_IO_OR_CONTRACT_ERROR'),
        ]
        for error, code in cases:
            destination = self.destination()
            opener, marker = self.collision_opener(destination, error=error)
            with self.subTest(code=code), self.assertRaises(stream.StreamFailure) as raised:
                stream.run_generation(self.profile, self.request(), destination, opener=opener, clock=Clock())
            self.assertEqual(raised.exception.code, code)
            self.assertIs(raised.exception.status_write_failed, True)
            self.assertEqual((destination.parent / 'stream-status.json').read_bytes(), marker)
            self.assertFalse(destination.exists())
            self.assertEqual(len(opener.calls), 1)

    def test_failed_status_write_without_collision_also_preserves_primary_error(self):
        destination = self.destination()
        opener = FakeOpener(error=TimeoutError('private timeout detail'))
        with patch.object(stream.Evidence, 'finish', side_effect=PermissionError('private filesystem detail')) as finish:
            with self.assertRaises(stream.StreamFailure) as raised:
                stream.run_generation(self.profile, self.request(), destination, opener=opener, clock=Clock())
        self.assertEqual(raised.exception.code, 'HTTP_TIMEOUT')
        self.assertIs(raised.exception.status_write_failed, True)
        self.assertEqual(finish.call_count, 1)
        self.assertFalse(destination.exists())

    def close_failure(self):
        original_close = stream.Evidence.close

        def close_then_fail(evidence):
            original_close(evidence)
            raise OSError('private close failure detail')

        return close_then_fail

    def test_final_close_failure_preserves_primary_model_and_http_errors(self):
        cases = [
            (FakeOpener(FakeHTTP([self.frame('{}', model='wrong-model')])), 'MODEL_MISMATCH'),
            (FakeOpener(error=TimeoutError('private timeout detail')), 'HTTP_TIMEOUT'),
            (FakeOpener(error=KeyboardInterrupt()), 'INTERRUPTED'),
        ]
        for opener, code in cases:
            destination = self.destination()
            with patch.object(stream.Evidence, 'close', self.close_failure()):
                with self.subTest(code=code), self.assertRaises(stream.StreamFailure) as raised:
                    stream.run_generation(self.profile, self.request(), destination, opener=opener, clock=Clock())
            self.assertEqual(raised.exception.code, code)
            self.assertIs(raised.exception.status_write_failed, False)
            self.assertIs(raised.exception.evidence_close_failed, True)
            self.assertEqual(json.loads((destination.parent / 'stream-status.json').read_text())['error_code'], code)
            self.assertFalse(destination.exists())
            self.assertEqual(len(opener.calls), 1)

    def test_status_collision_and_close_failure_preserve_both_flags_and_original_bytes(self):
        destination = self.destination()
        opener, marker = self.collision_opener(destination, lines=[self.frame('{}', model='wrong-model')])
        with patch.object(stream.Evidence, 'close', self.close_failure()):
            with self.assertRaises(stream.StreamFailure) as raised:
                stream.run_generation(self.profile, self.request(), destination, opener=opener, clock=Clock())
        self.assertEqual(raised.exception.code, 'MODEL_MISMATCH')
        self.assertIs(raised.exception.status_write_failed, True)
        self.assertIs(raised.exception.evidence_close_failed, True)
        self.assertEqual((destination.parent / 'stream-status.json').read_bytes(), marker)
        self.assertFalse(destination.exists())

    def test_final_close_failure_prevents_otherwise_complete_response_from_succeeding(self):
        destination = self.destination()
        opener = FakeOpener(FakeHTTP([self.frame('{}'), self.frame(done=True)]))
        original_close = stream.Evidence.close
        status_before_close = []

        def close_then_fail(evidence):
            status_before_close.append(evidence.status_path.read_bytes())
            original_close(evidence)
            raise OSError('private close failure detail')

        with patch.object(stream.Evidence, 'close', close_then_fail):
            with self.assertRaises(stream.StreamFailure) as raised:
                stream.run_generation(self.profile, self.request(), destination, opener=opener, clock=Clock())
        self.assertEqual(raised.exception.code, 'STREAM_IO_OR_CONTRACT_ERROR')
        self.assertIs(raised.exception.evidence_close_failed, True)
        self.assertIs(raised.exception.status_write_failed, False)
        self.assertEqual((destination.parent / 'stream-status.json').read_bytes(), status_before_close[0])
        self.assertEqual(json.loads(destination.read_text())['message']['content'], '{}')

    def test_late_success_status_collision_never_returns_success_metrics(self):
        destination = self.destination()
        opener, marker = self.collision_opener(destination, lines=[self.frame('{}'), self.frame(done=True)])
        with self.assertRaises(stream.StreamFailure) as raised:
            stream.run_generation(self.profile, self.request(), destination, opener=opener, clock=Clock())
        self.assertEqual(raised.exception.code, 'STREAM_IO_OR_CONTRACT_ERROR')
        self.assertIs(raised.exception.status_write_failed, True)
        self.assertEqual((destination.parent / 'stream-status.json').read_bytes(), marker)
        # A complete response remains forensic evidence, not an accepted result:
        # the function raised and the parent must hard-stop on the failure flag.
        self.assertEqual(json.loads(destination.read_text())['message']['content'], '{}')
        self.assertEqual(len(opener.calls), 1)

    def test_cli_failure_receipt_keeps_original_code_and_only_adds_true_flag(self):
        for collision, close_fails in ((False, False), (True, False), (False, True), (True, True)):
            destination = self.destination()
            profile_path, request_path = destination.parent / 'profile.json', destination.parent / 'request.json'
            profile_path.write_text(json.dumps(self.profile))
            request_path.write_text(json.dumps(self.request()))
            lines = [self.frame('{}', model='wrong-model')]
            if collision:
                opener, marker = self.collision_opener(destination, lines=lines)
            else:
                opener = FakeOpener(FakeHTTP(lines))
            output = io.StringIO()
            with (patch.object(sys, 'argv', ['generate_stream.py', '--profile', str(profile_path),
                                            str(request_path), str(destination)]),
                  patch.object(stream.urllib.request, 'build_opener', return_value=opener),
                  patch.object(stream.Evidence, 'close', self.close_failure() if close_fails else stream.Evidence.close),
                  redirect_stdout(output)):
                code = stream._worker_main()
            self.assertEqual(code, 1)
            expected = {'status': 'failed', 'error_code': 'MODEL_MISMATCH'}
            if collision:
                expected['status_write_failed'] = True
                self.assertEqual((destination.parent / 'stream-status.json').read_bytes(), marker)
            if close_fails:
                expected['evidence_close_failed'] = True
            self.assertEqual(json.loads(output.getvalue()), expected)
            self.assertFalse(destination.exists())

    def test_cli_complete_content_but_failed_close_emits_only_failure_receipt(self):
        destination = self.destination()
        profile_path, request_path = destination.parent / 'profile.json', destination.parent / 'request.json'
        profile_path.write_text(json.dumps(self.profile))
        request_path.write_text(json.dumps(self.request()))
        opener = FakeOpener(FakeHTTP([self.frame('{}'), self.frame(done=True)]))
        output = io.StringIO()
        with (patch.object(sys, 'argv', ['generate_stream.py', '--profile', str(profile_path),
                                        str(request_path), str(destination)]),
              patch.object(stream.urllib.request, 'build_opener', return_value=opener),
              patch.object(stream.Evidence, 'close', self.close_failure()), redirect_stdout(output)):
            code = stream._worker_main()
        self.assertEqual(code, 1)
        self.assertEqual(json.loads(output.getvalue()), {
            'status': 'failed', 'error_code': 'STREAM_IO_OR_CONTRACT_ERROR', 'evidence_close_failed': True})
        self.assertNotIn('private close failure detail', output.getvalue())

    def test_symlink_output_is_not_followed(self):
        destination = self.destination()
        outside = self.root / 'outside.json'
        destination.symlink_to(outside)
        with self.assertRaises(stream.StreamFailure):
            stream.run_generation(self.profile, self.request(), destination, opener=FakeOpener(), clock=Clock())
        self.assertFalse(outside.exists())

    def test_http_timeout_error_and_no_retry(self):
        for error, code in ((TimeoutError('hidden exception text'), 'HTTP_TIMEOUT'),
                            (urllib.error.URLError('hidden transport text'), 'HTTP_ERROR')):
            destination = self.destination()
            opener = FakeOpener(error=error)
            with self.subTest(code=code), self.assertRaises(stream.StreamFailure) as raised:
                stream.run_generation(self.profile, self.request(), destination, opener=opener, clock=Clock())
            self.assertEqual(raised.exception.code, code)
            self.assertEqual(len(opener.calls), 1)
            self.assertNotIn('hidden', (destination.parent / 'stream-status.json').read_text())

    def test_transport_disables_environment_proxies_and_redirects(self):
        http = FakeHTTP([self.frame('{}'), self.frame(done=True)])
        opener = FakeOpener(http)
        with patch.object(stream.urllib.request, 'build_opener', return_value=opener) as factory:
            stream.run_generation(self.profile, self.request(), self.destination(), clock=Clock())
        handlers = factory.call_args.args
        self.assertEqual(handlers[0].proxies, {})
        self.assertIsInstance(handlers[1], stream.NoRedirect)
        self.assertIsNone(handlers[1].redirect_request(None, None, 302, '', {}, 'https://example.invalid'))

    def test_untrusted_metric_values_are_never_printed_as_content(self):
        _, metrics, _, _ = self.generate([self.frame('{}'), self.frame(done=True,
            prompt_eval_count='sensitive-output', eval_count=True, load_duration=-1)])
        self.assertIsNone(metrics['prompt_eval_count'])
        self.assertIsNone(metrics['eval_count'])
        self.assertIsNone(metrics['load_duration_ns'])
        self.assertNotIn('sensitive-output', json.dumps(metrics))


if __name__ == '__main__':
    unittest.main()
