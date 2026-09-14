"""Hui stream fixtures only: no Ollama, network, HN, candidate, or model calls."""
from contextlib import redirect_stdout
import io
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import generate_stream as stream
from generation_health import GenerationHealth
from generation_profile import HUIHUI_PROFILE_ID, LEGACY_PROFILE_ID, PREVIOUS_PROFILE_ID, PROFILE_ID, resolve_profile
import test_generate_stream as fixtures
from test_generation_health import sample


class HuiStreamTests(unittest.TestCase):
    request = fixtures.StreamTests.request
    frame = fixtures.StreamTests.frame
    destination = fixtures.StreamTests.destination
    generate = fixtures.StreamTests.generate
    assert_failure = fixtures.StreamTests.assert_failure
    collision_opener = fixtures.StreamTests.collision_opener
    close_failure = fixtures.StreamTests.close_failure
    # Exercise the unchanged immutable-error/close contracts under the new profile too.
    test_final_close_failure_preserves_primary_model_and_http_errors = (
        fixtures.StreamTests.test_final_close_failure_preserves_primary_model_and_http_errors)
    test_status_collision_and_close_failure_preserve_both_flags_and_original_bytes = (
        fixtures.StreamTests.test_status_collision_and_close_failure_preserve_both_flags_and_original_bytes)
    test_final_close_failure_prevents_otherwise_complete_response_from_succeeding = (
        fixtures.StreamTests.test_final_close_failure_prevents_otherwise_complete_response_from_succeeding)

    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()
        self.profile = resolve_profile(HUIHUI_PROFILE_ID)
        self.sequence = 0

    def thought(self, text, **changes):
        return self.frame(message={'role': 'assistant', 'thinking': text}, **changes)

    def test_thinking_has_separate_activity_and_never_enters_response_or_stdout(self):
        private = 'private fixture reasoning: 생각'
        output = io.StringIO()
        with redirect_stdout(output):
            destination, metrics, opener, http = self.generate(
                [self.thought(private), self.frame(), self.frame('{"ok":true}'),
                 self.frame(done=True, thinking=private, private_metadata=private)],
                clock=fixtures.Clock(), times=[1001, 1005, 1010, 1011])
        response = json.loads(destination.read_text())
        status = json.loads((destination.parent / 'stream-status.json').read_text())
        self.assertEqual(json.loads(response['message']['content']), {'ok': True})
        self.assertEqual(metrics['first_activity_seconds'], 1)
        self.assertEqual(metrics['first_content_seconds'], 10)
        self.assertEqual(status['first_activity_monotonic'], 1001)
        self.assertEqual(status['last_activity_monotonic'], 1010)
        self.assertEqual(status['first_content_monotonic'], 1010)
        self.assertEqual(status['thinking_chars'], len(private))
        self.assertEqual(status['thinking_bytes'], len(private.encode()))
        for text in (destination.read_text(), json.dumps(status), json.dumps(metrics), output.getvalue()):
            self.assertNotIn(private, text)
        self.assertIn(private.encode(), (destination.parent / 'wire.jsonl').read_bytes())
        self.assertEqual(opener.calls[0][1], 600)
        self.assertEqual(len(opener.calls), 1)
        self.assertTrue(http.closed)

    def test_first_activity_and_first_content_publish_immediately_then_throttle(self):
        evidence = stream.Evidence(self.destination(), 1000, thinking=True)
        self.addCleanup(evidence.close)
        evidence.update_activity('a', '', 1000.1)
        marker = json.loads(evidence.progress_path.read_text())
        self.assertEqual(marker['first_activity_monotonic'], 1000.1)
        self.assertIsNone(marker['first_content_monotonic'])
        self.assertEqual(evidence.progress_writes, 2)
        evidence.update_activity('b', '', 1000.2)
        self.assertEqual(evidence.progress_writes, 2)
        evidence.update_activity('c', '', 1001.1)
        evidence.update_activity('', '{', 1001.2)
        self.assertEqual(evidence.progress_writes, 4)
        marker = json.loads(evidence.progress_path.read_text())
        self.assertEqual(marker['first_content_monotonic'], 1001.2)
        self.assertEqual(marker['last_activity_monotonic'], 1001.2)
        self.assertEqual(marker['thinking_chars'], 3)
        self.assertEqual(marker['content_chars'], 1)

    def test_empty_wire_and_metadata_do_not_revive_activity(self):
        self.assert_failure([b'\n', self.frame(), self.thought('too late')], 'FIRST_ACTIVITY_STALL',
                            times=[1100, 1599, 1600], clock=fixtures.Clock())
        self.assert_failure([self.thought('first'), b'\n', self.thought('late')], 'ACTIVITY_STALL',
                            times=[1001, 1120, 1121], clock=fixtures.Clock())

    def test_thinking_can_continue_past_first_content_timeout_until_deadline(self):
        lines = [self.thought(str(index)) for index in range(7)]
        destination, metrics, _, _ = self.generate(lines + [self.frame('{}'), self.frame(done=True)],
            times=[1100, 1200, 1300, 1400, 1500, 1600, 1700, 1701, 1702], clock=fixtures.Clock())
        self.assertTrue(destination.exists())
        self.assertEqual(metrics['first_activity_seconds'], 100)
        self.assertEqual(metrics['first_content_seconds'], 701)
        self.assert_failure([self.thought('x')] * 36, 'GENERATION_DEADLINE',
                            times=list(range(1100, 4700, 100)), clock=fixtures.Clock())

    def test_hui_ascii_model_case_only_is_compatible(self):
        self.generate([self.frame('{}', model=self.profile['model'].lower()), self.frame(done=True)])
        self.assert_failure([self.frame('{}', model='other-model')], 'MODEL_MISMATCH')
        self.assert_failure([self.frame('{}', model=self.profile['model'] + 'é')], 'MODEL_MISMATCH')

    def test_invalid_thinking_and_incomplete_content_are_rejected(self):
        for value in (None, 1, True, [], {}):
            with self.subTest(value=value):
                self.assert_failure([self.thought(value)], 'INVALID_MESSAGE')
        self.assert_failure([self.thought('{"looks":"like content"}'), self.frame(done=True)], 'INVALID_CONTENT_JSON')
        self.assert_failure([self.thought('x'), self.frame('{}'), self.frame(done=True, done_reason='length')], 'STOP_REASON')
        self.assert_failure([self.thought('x', tool_calls=[{}])], 'TOOL_RESPONSE')
        self.assert_failure([self.thought('x', remote_host='remote')], 'REMOTE_RESPONSE')

    def test_thinking_limit_counts_utf8_bytes_and_does_not_publish_over_limit_progress(self):
        evidence = stream.Evidence(self.destination(), 1000, thinking=True)
        self.addCleanup(evidence.close)
        profile = {**self.profile, 'thinking_limit': 5}
        with self.assertRaises(stream.StreamFailure) as failure:
            stream.consume_frames([self.thought('생각')], profile, evidence, clock=lambda: 1001)
        self.assertEqual(failure.exception.code, 'THINKING_LIMIT')
        self.assertEqual(json.loads(evidence.progress_path.read_text())['thinking_bytes'], 0)

    def test_thinking_tail_is_bounded_and_checks_exact_boundaries(self):
        evidence = stream.Evidence(self.destination(), 1000, thinking=True)
        self.addCleanup(evidence.close)
        lengths = []
        text = 'private fixture thought ' * 2100
        lines = [self.thought(text[:17]), self.thought(text[17:]), self.frame('{}'), self.frame(done=True)]
        merged, _ = stream.consume_frames(lines, self.profile, evidence, clock=lambda: 1001,
            repetition_fn=lambda tail, profile: lengths.append(len(tail)))
        self.assertEqual(lengths, [min(index, 32768) for index in range(4096, len(text) + 1, 4096)])
        self.assertEqual(len(evidence.thinking_tail), 32768)
        self.assertEqual(merged['message']['content'], '{}')

    def test_existing_repetition_threshold_also_applies_to_thinking(self):
        unit = ('abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789' * 5)[:256]
        self.assert_failure([self.thought(unit * 160)], 'REPETITION_DETECTED')

    def test_hui_rejects_clock_regression(self):
        self.assert_failure([self.thought('first'), self.frame('{}')], 'CLOCK_INVALID',
                            times=[1002, 1001], clock=fixtures.Clock())

    def test_legacy_profiles_still_reject_thinking_and_keep_exact_marker_schema(self):
        for identifier in (LEGACY_PROFILE_ID, PREVIOUS_PROFILE_ID, PROFILE_ID):
            self.profile = resolve_profile(identifier)
            destination, status = self.assert_failure([self.thought('no')], 'INVALID_MESSAGE')
            self.assertNotIn('thinking_chars', status)
            self.assertEqual(set(json.loads((destination.parent / 'progress.json').read_text())),
                             {'first_content_monotonic', 'last_content_monotonic', 'content_chars'})
            self.assert_failure([self.frame(message={'role': 'assistant', 'content': '', 'thinking': 'no'})],
                                'UNEXPECTED_THINKING')

    def test_canonical_profile_is_resolved_before_initial_hui_marker(self):
        observed = []
        original = stream._publish_exclusive

        def publish(source, destination):
            observed.append(json.loads(Path(source).read_text()))
            original(source, destination)

        with patch.object(stream, '_publish_exclusive', side_effect=publish):
            self.generate([self.frame('{}'), self.frame(done=True)])
        self.assertIn('thinking_chars', observed[0])
        self.assertEqual(observed[0]['thinking_chars'], 0)
        bad = {**self.profile, 'think': False}
        _, status = self.assert_failure([], 'INVALID_PROFILE', profile=bad)
        self.assertFalse(status['profile_validated'])
        self.assertNotIn('thinking_chars', status)

    def test_initial_marker_is_invisible_while_empty_or_half_written(self):
        destination = self.destination()
        monitor = GenerationHealth(self.profile, destination.parent / 'progress.json',
                                   destination.parent / 'health.jsonl', sampler=sample, clock=lambda: 1000)
        self.addCleanup(monitor.close)
        monitor.preflight()
        original = stream.os.fdopen
        observations = []

        class SplitWrite:
            def __init__(self, target):
                self.target = target

            def __enter__(self):
                self.target.__enter__()
                return self

            def __exit__(self, *args):
                return self.target.__exit__(*args)

            def __getattr__(self, key):
                return getattr(self.target, key)

            def write(self, raw):
                for part in (b'', raw[:len(raw) // 2], raw[len(raw) // 2:]):
                    self.target.write(part)
                    self.target.flush()
                    observations.append((destination.parent.joinpath('progress.json').exists(), monitor()))
                return len(raw)

        def fdopen(descriptor, mode):
            target = original(descriptor, mode)
            return SplitWrite(target) if mode == 'wb' else target

        with patch.object(stream.os, 'fdopen', side_effect=fdopen):
            evidence = stream.Evidence(destination, 1000, thinking=True)
        self.addCleanup(evidence.close)
        self.assertEqual(observations, [(False, None)] * 3)
        self.assertIsNone(monitor())
        self.assertEqual(evidence.progress_path.stat().st_nlink, 1)
        self.assertFalse(list(destination.parent.glob('.progress-*.tmp')))

    def test_initial_atomic_publication_preserves_a_racing_existing_marker(self):
        destination = self.destination()
        original = stream._publish_exclusive

        def publish(source, target):
            with Path(target).open('xb') as output:
                output.write(b'external marker')
            original(source, target)

        with patch.object(stream, '_publish_exclusive', side_effect=publish), self.assertRaises(FileExistsError):
            stream.Evidence(destination, 1000, thinking=True)
        self.assertEqual((destination.parent / 'progress.json').read_bytes(), b'external marker')
        self.assertFalse(list(destination.parent.glob('.progress-*.tmp')))

    def test_progress_hardlink_is_not_replaced(self):
        evidence = stream.Evidence(self.destination(), 1000, thinking=True)
        self.addCleanup(evidence.close)
        linked = evidence.progress_path.parent / 'linked.json'
        os.link(evidence.progress_path, linked)
        original = evidence.progress_path.read_bytes()
        with self.assertRaises(stream.StreamFailure) as failure:
            evidence.update_activity('x', '', 1001)
        self.assertEqual(failure.exception.code, 'PROGRESS_CHANGED')
        self.assertEqual(evidence.progress_path.read_bytes(), original)


if __name__ == '__main__':
    unittest.main()
