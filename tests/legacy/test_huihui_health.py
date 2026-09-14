"""Hui supervision fixtures; all telemetry, clocks, and progress are local fakes."""
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock, patch

import generation_health as health
from generation_profile import HUIHUI_PROFILE_ID
from test_generation_health import GIB, MIB, sample


class HuiHealthTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()
        self.now = 0
        self.sampler = Mock(return_value=sample())
        self.sequence = 0
        self.monitor = self.new_monitor()

    def new_monitor(self):
        self.sequence += 1
        monitor = health.GenerationHealth(HUIHUI_PROFILE_ID, self.root / f'progress-{self.sequence}.json',
            self.root / f'trace-{self.sequence}.jsonl', sampler=self.sampler, clock=lambda: self.now)
        self.addCleanup(monitor.close)
        monitor.preflight()
        return monitor

    def marker(self, **updates):
        return {'first_activity_monotonic': None, 'last_activity_monotonic': None,
                'first_content_monotonic': None, 'last_content_monotonic': None,
                'thinking_chars': 0, 'thinking_bytes': 0, 'content_chars': 0, 'content_bytes': 0, **updates}

    def thinking(self, count, last, *, first=1, **updates):
        return self.marker(**{'first_activity_monotonic': first, 'last_activity_monotonic': last,
                              'thinking_chars': count, 'thinking_bytes': count, **updates})

    def publish(self, value, monitor=None):
        (monitor or self.monitor).progress_path.write_text(json.dumps(value))

    def test_first_activity_uses_idle_guard_before_any_content(self):
        self.now = 0.1
        self.publish(self.thinking(1, 0.1, first=0.1))
        self.assertIsNone(self.monitor())
        self.now = 120.2
        self.assertEqual(self.monitor(), 'generation-activity-stall')
        summary = self.monitor.summary()
        self.assertEqual(summary['first_activity_monotonic'], 0.1)
        self.assertIsNone(summary['first_content_monotonic'])

    def test_genuine_thinking_can_continue_until_absolute_deadline(self):
        for now in range(100, 3600, 100):
            self.now = now
            self.publish(self.thinking(now, now, first=100))
            self.assertIsNone(self.monitor())
        self.now = 3600
        self.publish(self.thinking(3600, 3600, first=100))
        self.assertEqual(self.monitor(), 'generation-deadline')

    def test_missing_initial_marker_is_bounded_but_disappearing_marker_is_invalid(self):
        self.now = 599
        self.assertIsNone(self.monitor())
        self.now = 600
        self.assertEqual(self.monitor(), 'generation-prefill-stall')
        other = self.new_monitor()
        self.publish(self.marker(), other)
        self.assertIsNone(other())
        other.progress_path.unlink()
        self.assertEqual(other(), 'generation-progress-invalid')

    def test_unchanged_thinking_and_changed_timestamp_is_fake_activity(self):
        self.now = 1
        self.publish(self.thinking(1, 1))
        self.assertIsNone(self.monitor())
        self.now = 2
        self.publish(self.thinking(1, 2))
        self.assertEqual(self.monitor(), 'generation-progress-invalid')

    def test_counter_and_timestamp_regressions_or_inconsistent_channels_are_invalid(self):
        invalid = [
            {'thinking_chars': 0, 'thinking_bytes': 0},
            {'thinking_bytes': 0}, {'thinking_bytes': 5},
            {'thinking_chars': True}, {'thinking_chars': 8388609, 'thinking_bytes': 8388609},
            {'last_activity_monotonic': 0.5}, {'first_activity_monotonic': 0.5},
            {'last_activity_monotonic': float('inf')}, {'last_activity_monotonic': 10 ** 1000},
            {'last_activity_monotonic': 3},
            {'content_chars': 1, 'content_bytes': 1, 'first_content_monotonic': 0.5, 'last_content_monotonic': 2},
            {'content_chars': 1, 'content_bytes': 1, 'first_content_monotonic': 2, 'last_content_monotonic': 3},
        ]
        for changes in invalid:
            with self.subTest(changes=changes):
                self.now = 0
                monitor = self.new_monitor()
                self.now = 1
                self.publish(self.thinking(1, 1), monitor)
                self.assertIsNone(monitor())
                self.now = 2
                self.publish({**self.thinking(1, 1), **changes}, monitor)
                self.assertEqual(monitor(), 'generation-progress-invalid')

    def test_content_and_thinking_counters_can_advance_independently(self):
        self.now = 1
        self.publish(self.thinking(10, 1))
        self.assertIsNone(self.monitor())
        self.now = 2
        self.publish(self.thinking(10, 2, first_content_monotonic=2, last_content_monotonic=2,
                                   content_chars=1, content_bytes=3))
        self.assertIsNone(self.monitor())
        self.now = 3
        self.publish(self.thinking(11, 3, first_content_monotonic=2, last_content_monotonic=2,
                                   content_chars=1, content_bytes=3))
        self.assertIsNone(self.monitor())
        self.assertEqual(self.monitor.summary()['last_content_monotonic'], 2)
        self.assertEqual(self.monitor.summary()['last_activity_monotonic'], 3)

    def test_increasing_chars_without_new_utf8_bytes_cannot_fake_activity(self):
        self.now = 1
        self.publish(self.thinking(1, 1, thinking_bytes=4))
        self.assertIsNone(self.monitor())
        self.now = 2
        self.publish(self.thinking(2, 2, thinking_bytes=4))
        self.assertEqual(self.monitor(), 'generation-progress-invalid')

    def test_content_only_activity_timestamps_must_match_content(self):
        self.now = 2
        self.publish(self.marker(first_activity_monotonic=1, last_activity_monotonic=2,
            first_content_monotonic=2, last_content_monotonic=2, content_chars=1, content_bytes=1))
        self.assertEqual(self.monitor(), 'generation-progress-invalid')

    def test_partial_empty_invalid_json_and_non_hui_schema_are_not_retried(self):
        values = [b'', b'{"thinking_chars":', b'not json', b'{"x":1,"x":2}',
                  json.dumps({'content_chars': 0, 'first_content_monotonic': None,
                              'last_content_monotonic': None}).encode()]
        for raw in values:
            monitor = self.new_monitor()
            monitor.progress_path.write_bytes(raw)
            with patch.object(monitor, '_read_progress_once', wraps=monitor._read_progress_once) as read:
                self.assertEqual(monitor(), 'generation-progress-invalid')
            self.assertEqual(read.call_count, 1)

    def replace_after_open(self, monitor, replacement, *, repeat=False):
        original = health.os.open
        calls = []

        def open_and_replace(path, flags, *args, **kwargs):
            descriptor = original(path, flags, *args, **kwargs)
            if Path(path) == monitor.progress_path:
                calls.append(descriptor)
                if repeat or len(calls) == 1:
                    replacement(monitor.progress_path, len(calls))
            return descriptor

        return patch.object(health.os, 'open', side_effect=open_and_replace), calls

    def test_open_then_atomic_replace_rereads_new_activity_without_false_idle_stop(self):
        self.now = 1
        self.publish(self.thinking(1, 1))
        self.assertIsNone(self.monitor())
        self.now = 121

        def replace(path, number):
            temporary = self.root / f'replacement-{number}.json'
            temporary.write_text(json.dumps(self.thinking(2, 121)))
            os.replace(temporary, path)

        context, calls = self.replace_after_open(self.monitor, replace)
        with context:
            self.assertIsNone(self.monitor())
        self.assertEqual(len(calls), 2)
        self.assertEqual(self.monitor.summary()['thinking_chars'], 2)
        self.assertEqual(self.monitor.summary()['last_activity_monotonic'], 121)
        self.assertEqual(self.monitor.summary()['progress_stale_reads'], 1)
        self.assertEqual(self.monitor.summary()['progress_reopens'], 1)

    def test_persistent_safe_replacement_contention_has_a_finite_failure(self):
        self.publish(self.marker())

        def replace(path, number):
            temporary = self.root / f'repeated-{number}.json'
            temporary.write_text(json.dumps(self.marker()))
            os.replace(temporary, path)

        context, calls = self.replace_after_open(self.monitor, replace, repeat=True)
        with context:
            self.assertEqual(self.monitor(), 'generation-progress-invalid')
        self.assertEqual(len(calls), health.PROGRESS_READ_ATTEMPTS)
        self.assertEqual(self.monitor.summary()['progress_reopens'], 2)
        self.assertEqual(self.monitor.summary()['progress_read_error'], 'atomic-replacement-contention')

    def test_unsafe_replacement_is_not_accepted_as_atomic_race(self):
        for kind in ('symlink', 'hardlink', 'missing', 'invalid-json', 'oversized', 'regression'):
            with self.subTest(kind=kind):
                self.now = 0
                monitor = self.new_monitor()
                self.now = 2
                self.publish(self.thinking(2, 2), monitor)
                self.assertIsNone(monitor())

                def replace(path, number):
                    temporary = path.with_name(path.name + '.new')
                    if kind == 'missing':
                        path.unlink()
                        return
                    if kind in ('symlink', 'hardlink'):
                        source = path.with_name(path.name + '.source')
                        source.write_text(json.dumps(self.thinking(2, 2)))
                        if kind == 'symlink':
                            temporary.symlink_to(source)
                        else:
                            os.link(source, temporary)
                    else:
                        temporary.write_text('invalid' if kind == 'invalid-json' else 'x' * 4097 if kind == 'oversized'
                                             else json.dumps(self.thinking(1, 1)))
                    os.replace(temporary, path)

                context, calls = self.replace_after_open(monitor, replace)
                with context:
                    self.assertEqual(monitor(), 'generation-progress-invalid')
                self.assertEqual(len(calls), 2 if kind in ('invalid-json', 'regression') else 1)
                self.assertEqual(monitor.summary()['thinking_chars'], 2)

    def test_linked_symlink_and_hardlink_markers_are_rejected_without_retry(self):
        for kind in ('symlink', 'hardlink'):
            monitor = self.new_monitor()
            source = monitor.progress_path.with_name(monitor.progress_path.name + '.source')
            source.write_text(json.dumps(self.marker()))
            if kind == 'symlink':
                monitor.progress_path.symlink_to(source)
            else:
                os.link(source, monitor.progress_path)
            with patch.object(monitor, '_read_progress_once', wraps=monitor._read_progress_once) as read:
                self.assertEqual(monitor(), 'generation-progress-invalid')
            self.assertEqual(read.call_count, 1)

    def test_v3_memory_policy_remains_active_and_compression_is_not_a_cap(self):
        self.sampler.return_value = sample(free_bytes=MIB, file_backed_bytes=5 * GIB,
                                           compressed_physical_bytes=45 * GIB, compressed_logical_bytes=60 * GIB)
        self.now = 2
        self.publish(self.thinking(1, 2, first=2))
        self.assertIsNone(self.monitor())
        self.assertEqual(self.monitor.summary()['latest_sample']['compressed_physical_bytes'], 45 * GIB)
        for now in range(4, 70, 2):
            self.now = now
            self.publish(self.thinking(now, now, first=2))
            growth = (now // 4) * 12 * MIB
            self.sampler.return_value = sample(pressure=2, swap_used_bytes=growth, swap_out_bytes=growth)
            reason = self.monitor()
            if reason:
                break
        self.assertEqual(reason, 'memory-pressure-deterioration')
        self.assertEqual(self.monitor.summary()['deterioration_trigger'], 'rolling-net-growth')

    def test_critical_pressure_and_three_lost_samples_still_stop_thinking(self):
        self.now = 2
        self.publish(self.thinking(1, 2, first=2))
        self.sampler.return_value = {'pressure': 4}
        self.assertEqual(self.monitor(), 'memory-pressure-critical')
        self.now = 0
        self.sampler.return_value = sample()
        monitor = self.new_monitor()
        self.sampler.side_effect = OSError('fixture telemetry unavailable')
        for now in (2, 4, 6):
            self.now = now
            self.publish(self.thinking(now, now, first=2), monitor)
            reason = monitor()
        self.assertEqual(reason, 'memory-telemetry-lost')


if __name__ == '__main__':
    unittest.main()
