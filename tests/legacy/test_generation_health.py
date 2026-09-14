import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import Mock, patch

import generation_health as health
from generation_profile import LEGACY_PROFILE_ID, PREVIOUS_PROFILE_ID, PROFILE_ID

MIB = 1024 * 1024
GIB = 1024 * MIB


def sample(**overrides):
    return {'pressure': 1, 'free_bytes': 8 * GIB, 'file_backed_bytes': 12 * GIB,
            'compressed_physical_bytes': GIB, 'compressed_logical_bytes': 2 * GIB,
            'swap_used_bytes': 0, 'swap_out_bytes': 0, 'page_out_bytes': 0, **overrides}


class NativeTelemetryTests(unittest.TestCase):
    def setUp(self):
        self.vm = ('Mach Virtual Memory Statistics: (page size of 16384 bytes)\n'
                   'Pages free: 262144.\nFile-backed pages: 524288.\n'
                   'Pages occupied by compressor: 1024.\nPages stored in compressor: 4096.\n'
                   'Swapouts: 8.\nPageouts: 9.\n')

    def test_native_units_and_compression_counters_are_distinct(self):
        result = health.parse_system_telemetry('1\n', 'total = 2.00G used = 128.00M free = 1920.00M', self.vm)
        self.assertEqual(result['free_bytes'], 4 * GIB)
        self.assertEqual(result['file_backed_bytes'], 8 * GIB)
        self.assertEqual(result['compressed_physical_bytes'], 16 * MIB)
        self.assertEqual(result['compressed_logical_bytes'], 64 * MIB)
        self.assertEqual(result['swap_used_bytes'], 128 * MIB)
        self.assertEqual(result['swap_out_bytes'], 8 * 16384)
        self.assertEqual(result['page_out_pages'], 9)

    def test_missing_unknown_or_malformed_telemetry_is_not_zero(self):
        for pressure, swap, vm in [('0', 'used = 0M', self.vm), ('1', 'not swap', self.vm),
                                    ('1', 'used = 0M', self.vm.replace('Pages free: 262144.\n', ''))]:
            with self.assertRaises(health.TelemetryError):
                health.parse_system_telemetry(pressure, swap, vm)

    def test_sampler_uses_fixed_bounded_native_commands_only(self):
        with patch.object(health.subprocess, 'run', side_effect=[Mock(stdout='1'), Mock(stdout='used = 0M'), Mock(stdout=self.vm)]) as run:
            self.assertEqual(health.sample_system()['pressure'], 1)
        self.assertEqual([call.args[0] for call in run.call_args_list], [
            ['/usr/sbin/sysctl', '-n', 'kern.memorystatus_vm_pressure_level'],
            ['/usr/sbin/sysctl', '-n', 'vm.swapusage'], ['/usr/bin/vm_stat']])
        self.assertTrue(all(call.kwargs['timeout'] == 2 for call in run.call_args_list))
        self.assertTrue(all(set(call.kwargs['env']) == {'PATH', 'LC_ALL'} for call in run.call_args_list))

    def test_critical_first_read_short_circuits_before_other_telemetry_can_fail(self):
        with patch.object(health.subprocess, 'run', side_effect=[Mock(stdout='4'), subprocess.TimeoutExpired('unused', 2)]) as run:
            with self.assertRaises(health.CriticalPressureObserved) as observed:
                health.sample_system()
        self.assertEqual(run.call_count, 1)
        self.assertEqual(observed.exception.partial, {'pressure': 4})


class GenerationHealthTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()
        self.now = 0.0
        self.sampler = Mock(return_value=sample())
        self.monitor = health.GenerationHealth(PROFILE_ID, self.root / 'progress.json', self.root / 'trace.jsonl',
                                               sampler=self.sampler, clock=lambda: self.now)
        self.addCleanup(self.monitor.close)

    def progress(self, first, last, chars):
        (self.root / 'progress.json').write_text(json.dumps({'first_content_monotonic': first,
            'last_content_monotonic': last, 'content_chars': chars}))

    def test_preflight_is_health_floor_not_peak_capacity_admission(self):
        self.sampler.return_value = sample(free_bytes=4 * GIB, swap_used_bytes=2 * GIB)
        metadata = self.monitor.preflight()
        self.assertTrue(metadata['passed'])
        self.assertFalse(metadata['target_peak_memory_prevalidated'])
        self.assertTrue(metadata['controlled_first_load_calibration_required'])
        self.assertEqual(metadata['telemetry']['swap_used_bytes'], 2 * GIB)
        with self.assertRaises(ValueError):
            self.monitor.preflight()

    def test_unknown_preflight_blocks_and_does_not_invent_baseline(self):
        self.sampler.side_effect = health.TelemetryError('unavailable')
        with self.assertRaises(health.HealthAdmissionError) as rejected:
            self.monitor.preflight()
        self.assertEqual(rejected.exception.reason, 'memory-telemetry-unavailable')
        self.assertIsNone(self.monitor.summary()['baseline'])
        self.assertFalse(self.monitor.summary()['admitted'])
        self.assertEqual(json.loads((self.root / 'trace.jsonl').read_text())['telemetry'], None)

    def test_warning_or_low_free_preflight_blocks(self):
        for index, values in enumerate((sample(pressure=2), sample(free_bytes=GIB, file_backed_bytes=GIB), sample(pressure=True))):
            monitor = health.GenerationHealth(PROFILE_ID, self.root / ('p' + str(index)), self.root / ('t' + str(index)),
                                               sampler=lambda values=values: values, clock=lambda: 0)
            with self.assertRaises(health.HealthAdmissionError):
                monitor.preflight()
            monitor.close()

    def test_v2_accepts_observed_low_free_with_file_backed_headroom_as_estimate(self):
        self.sampler.return_value = sample(free_bytes=95_682_560, file_backed_bytes=8_177_369_088,
                                           compressed_physical_bytes=24 * GIB, compressed_logical_bytes=48 * GIB)
        metadata = self.monitor.preflight()
        self.assertTrue(metadata['passed'])
        self.assertEqual(metadata['estimated_headroom_bytes'], 8_273_051_648)
        self.assertEqual(metadata['headroom_measurement'], 'free-plus-file-backed-estimate')
        self.assertFalse(metadata['headroom_is_immediately_available_ram'])
        self.assertFalse(metadata['headroom_is_model_fit_guarantee'])
        self.assertFalse(metadata['target_peak_memory_prevalidated'])

    def test_v1_still_rejects_same_low_physical_free_even_with_file_backed_pages(self):
        legacy = health.GenerationHealth(LEGACY_PROFILE_ID, self.root / 'legacy-progress', self.root / 'legacy-trace',
            sampler=lambda: sample(free_bytes=95_682_560, file_backed_bytes=8_177_369_088), clock=lambda: 0)
        with self.assertRaises(health.HealthAdmissionError) as rejected:
            legacy.preflight()
        self.assertEqual(rejected.exception.reason, 'memory-preflight-free-floor')
        legacy.close()

    def test_v2_critical_pressure_is_not_overridden_by_large_headroom(self):
        self.sampler.return_value = sample(pressure=4, free_bytes=32 * GIB, file_backed_bytes=24 * GIB)
        with self.assertRaises(health.HealthAdmissionError) as rejected:
            self.monitor.preflight()
        self.assertEqual(rejected.exception.reason, 'memory-pressure-critical')

    def test_native_partial_critical_preflight_is_immediate_and_not_fabricated(self):
        self.sampler.side_effect = health.CriticalPressureObserved()
        with self.assertRaises(health.HealthAdmissionError) as rejected:
            self.monitor.preflight()
        self.assertEqual(rejected.exception.reason, 'memory-pressure-critical')
        summary = self.monitor.summary()
        self.assertEqual(summary['latest_sample'], {'pressure': 4})
        self.assertFalse(summary['latest_sample_complete'])

    def test_partial_critical_sampler_dict_also_stops_without_waiting_for_missing_fields(self):
        self.monitor.preflight()
        self.now = 2
        self.sampler.return_value = {'pressure': 4}
        self.assertEqual(self.monitor(), 'memory-pressure-critical')
        self.assertEqual(self.monitor.summary()['latest_sample'], {'pressure': 4})

    def test_compression_and_reduced_free_after_loading_do_not_stop_healthy_run(self):
        self.monitor.preflight()
        self.sampler.return_value = sample(free_bytes=512 * MIB, compressed_physical_bytes=24 * GIB,
                                           compressed_logical_bytes=60 * GIB, swap_used_bytes=3 * GIB)
        for now in (2, 30, 100):
            self.now = now
            self.assertIsNone(self.monitor())

    def test_critical_full_or_partial_sample_stops_on_first_observation(self):
        self.monitor.preflight()
        self.now = 2
        self.sampler.return_value = sample(pressure=4)
        self.assertEqual(self.monitor(), 'memory-pressure-critical')
        self.assertEqual(self.monitor(), 'memory-pressure-critical')
        self.assertEqual(self.sampler.call_count, 2)
        second = health.GenerationHealth(PROFILE_ID, self.root / 'p2', self.root / 't2',
                                        sampler=Mock(side_effect=[sample(), health.CriticalPressureObserved()]), clock=lambda: self.now)
        second.preflight()
        self.now = 4
        self.assertEqual(second(), 'memory-pressure-critical')
        self.assertEqual(second.summary()['latest_sample'], {'pressure': 4})
        second.close()

    def test_sustained_warning_plus_growth_stops_only_after_sixty_seconds(self):
        self.monitor.preflight()
        for now in range(2, 64, 2):
            self.now = now
            self.sampler.return_value = sample(pressure=2, swap_used_bytes=(now // 2) * 6 * MIB)
            reason = self.monitor()
            if now < 62:
                self.assertIsNone(reason)
            else:
                self.assertEqual(reason, 'memory-pressure-deterioration')

    def test_warning_requires_three_successive_growth_samples_even_after_window(self):
        legacy = health.GenerationHealth(PREVIOUS_PROFILE_ID, self.root / 'v2-progress', self.root / 'v2-trace',
                                         sampler=self.sampler, clock=lambda: self.now)
        self.addCleanup(legacy.close)
        legacy.preflight()
        for now in range(2, 66, 2):
            self.now = now
            growth = max(0, (now - 58) // 2) * 64 * MIB
            self.sampler.return_value = sample(pressure=2, swap_out_bytes=growth)
            reason = legacy()
            self.assertEqual(reason, 'memory-pressure-deterioration' if now == 64 else None)

    def test_warning_compression_and_pageout_alone_are_not_swap_deterioration(self):
        self.monitor.preflight()
        for now in range(2, 124, 2):
            self.now = now
            self.sampler.return_value = sample(pressure=2, compressed_physical_bytes=20 * GIB,
                                               page_out_bytes=now * 20 * MIB)
            self.assertIsNone(self.monitor())

    def test_transient_warning_returns_to_normal_without_stopping(self):
        self.monitor.preflight()
        for now, pressure, growth in ((2, 2, 200 * MIB), (4, 2, 400 * MIB), (6, 1, 400 * MIB), (8, 2, 600 * MIB)):
            self.now = now
            self.sampler.return_value = sample(pressure=pressure, swap_used_bytes=growth)
            self.assertIsNone(self.monitor())

    def test_three_scheduled_telemetry_failures_stop_not_three_fast_polls(self):
        self.monitor.preflight()
        self.sampler.side_effect = health.TelemetryError('missing counters')
        for now in (2, 2.1, 2.2, 4):
            self.now = now
            self.assertIsNone(self.monitor())
        self.assertEqual(self.monitor.summary()['consecutive_telemetry_failures'], 2)
        self.now = 6
        self.assertEqual(self.monitor(), 'memory-telemetry-lost')
        self.assertFalse(self.monitor.summary()['latest_sample_complete'])

    def test_successful_telemetry_resets_transient_failure_count(self):
        self.monitor.preflight()
        for now, failed in ((2, True), (4, False), (6, True), (8, True), (10, False)):
            self.now = now
            self.sampler.side_effect = health.TelemetryError('unavailable') if failed else None
            self.assertIsNone(self.monitor())
        self.assertEqual(self.monitor.summary()['consecutive_telemetry_failures'], 0)

    def test_intermittent_missing_samples_cannot_reset_sustained_warning_epoch(self):
        legacy = health.GenerationHealth(PREVIOUS_PROFILE_ID, self.root / 'v2-progress', self.root / 'v2-trace',
                                         sampler=self.sampler, clock=lambda: self.now)
        self.addCleanup(legacy.close)
        legacy.preflight()
        stopped_at = None
        for now in range(2, 184, 2):
            self.now = now
            self.sampler.side_effect = health.TelemetryError('single missing sample') if now % 30 == 0 else None
            self.sampler.return_value = sample(pressure=2, swap_used_bytes=now * 10 * MIB)
            reason = legacy()
            if reason is not None:
                self.assertEqual(reason, 'memory-pressure-deterioration')
                stopped_at = now
                break
        # Missing samples at 30 and 60 do not establish normal pressure. Three
        # fresh growth samples after the second miss are observed at 62/64/66.
        self.assertEqual(stopped_at, 66)
        self.assertEqual(legacy.summary()['consecutive_telemetry_failures'], 0)

    def test_prefill_tolerates_missing_progress_until_six_hundred_seconds(self):
        self.monitor.preflight()
        self.now = 599
        self.assertIsNone(self.monitor())
        self.now = 600
        self.assertEqual(self.monitor(), 'generation-prefill-stall')

    def test_content_idle_uses_last_content_not_wire_or_metadata_activity(self):
        self.monitor.preflight()
        self.now = 10
        self.progress(10, 10, 100)
        self.assertIsNone(self.monitor())
        self.now = 129
        self.assertIsNone(self.monitor())
        self.now = 130
        self.assertEqual(self.monitor(), 'generation-content-stall')

    def test_healthy_long_progress_survives_idle_guards_until_absolute_deadline(self):
        self.monitor.preflight()
        for now in range(100, 3600, 100):
            self.now = now
            self.progress(100, now, now)
            self.assertIsNone(self.monitor())
        self.now = 3600
        self.progress(100, 3600, 3600)
        self.assertEqual(self.monitor(), 'generation-deadline')

    def test_progress_is_refreshed_after_slow_sampling_before_idle_decision(self):
        self.monitor.preflight()
        self.now = 10
        self.progress(10, 10, 1)
        self.assertIsNone(self.monitor())
        self.now = 129
        def slow_sample():
            self.now = 135
            self.progress(10, 135, 2)
            return sample()
        self.sampler.side_effect = slow_sample
        self.assertIsNone(self.monitor())

    def test_duplicate_progress_keys_and_fake_activity_are_rejected(self):
        self.monitor.preflight()
        self.now = 2
        (self.root / 'progress.json').write_text('{"content_chars":0,"content_chars":1}')
        self.assertEqual(self.monitor(), 'generation-progress-invalid')
        second = health.GenerationHealth(PROFILE_ID, self.root / 'other-progress', self.root / 'other-trace',
                                        sampler=lambda: sample(), clock=lambda: self.now)
        second.preflight()
        self.now = 3
        (self.root / 'other-progress').write_text(json.dumps({'first_content_monotonic': 3, 'last_content_monotonic': 3, 'content_chars': 1}))
        self.assertIsNone(second())
        self.now = 4
        (self.root / 'other-progress').write_text(json.dumps({'first_content_monotonic': 3, 'last_content_monotonic': 4, 'content_chars': 1}))
        self.assertEqual(second(), 'generation-progress-invalid')
        second.close()

    def test_trace_is_bounded_and_ignores_non_vm_sampler_fields(self):
        self.sampler.return_value = sample(private_process_data='never expose this')
        self.monitor.preflight()
        with patch.object(health, 'MAX_TRACE_RECORDS', 2):
            for now in (2, 4, 6):
                self.now = now
                self.assertIsNone(self.monitor())
        self.assertTrue(self.monitor.summary()['trace_truncated'])
        raw = (self.root / 'trace.jsonl').read_text()
        self.assertEqual(len(raw.splitlines()), 2)
        self.assertNotIn('private_process_data', raw)
        self.assertNotIn('never expose', raw)


class BurstGuardTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()
        self.now = 0.0
        self.sampler = Mock(return_value=sample())
        self.monitor = self.make_monitor(PROFILE_ID, 'v3')

    def make_monitor(self, profile, suffix):
        monitor = health.GenerationHealth(profile, self.root / (suffix + '-progress'), self.root / (suffix + '-trace'),
                                          sampler=self.sampler, clock=lambda: self.now)
        self.addCleanup(monitor.close)
        monitor.preflight()
        return monitor

    def observe(self, now, used=0, swapped=None, pressure=2, missing=False, monitor=None):
        self.now = now
        self.sampler.side_effect = health.TelemetryError('missing sample') if missing else None
        self.sampler.return_value = sample(pressure=pressure, swap_used_bytes=used,
                                           swap_out_bytes=used if swapped is None else swapped)
        return (monitor or self.monitor)()

    def test_grow_flat_stops_with_bounded_window_at_sixty_seconds_of_warning(self):
        for index in range(1, 32):
            reason = self.observe(index * 2, used=((index + 1) // 2) * 20 * MIB)
            self.assertEqual(reason, 'memory-pressure-deterioration' if index == 31 else None)
        result = self.monitor.summary()
        self.assertEqual(result['deterioration_trigger'], 'rolling-net-growth')
        self.assertEqual(result['burst_guard']['net_growth_bytes'], 300 * MIB)
        self.assertEqual(result['burst_guard']['growing_transitions'], 15)
        self.assertEqual(result['warning_history_limit'], 31)
        self.assertLessEqual(result['burst_guard']['valid_warning_observations'], 31)

    def test_v1_and_v2_keep_original_conjunctive_behavior_for_grow_flat(self):
        for profile, suffix in ((LEGACY_PROFILE_ID, 'v1'), (PREVIOUS_PROFILE_ID, 'v2')):
            self.now = 0
            self.sampler.return_value = sample()
            legacy = self.make_monitor(profile, suffix)
            for index in range(1, 92):
                self.assertIsNone(self.observe(index * 2, used=((index + 1) // 2) * 20 * MIB, monitor=legacy))
            self.assertNotIn('burst_guard', legacy.summary())
            self.assertEqual(legacy.summary()['latest_sample']['swap_used_bytes'], 920 * MIB)

    def test_below_threshold_used_and_swapout_are_not_double_counted(self):
        for now in range(2, 64, 2):
            used = 0 if now == 2 else 64 * MIB if now == 4 else 127 * MIB
            self.assertIsNone(self.observe(now, used))
        detail = self.monitor.summary()['burst_guard']
        self.assertEqual(detail['net_swap_used_bytes'], 127 * MIB)
        self.assertEqual(detail['net_swap_out_bytes'], 127 * MIB)
        self.assertEqual(detail['net_growth_bytes'], 127 * MIB)
        self.assertEqual(detail['growing_transitions'], 2)

    def test_single_jump_then_flat_never_meets_two_growth_transitions(self):
        for now in range(2, 184, 2):
            self.assertIsNone(self.observe(now, used=0 if now == 2 else 256 * MIB))
        self.assertEqual(self.monitor.summary()['burst_guard']['net_growth_bytes'], 0)
        self.assertEqual(self.monitor.summary()['burst_guard']['growing_transitions'], 0)

    def test_expired_predecessor_does_not_leave_a_fake_growth_flag(self):
        for now, amount in ((2, 0), (30, 10), (60, 138), (64, 138)):
            self.assertIsNone(self.observe(now, amount * MIB))
        detail = self.monitor.summary()['burst_guard']
        self.assertEqual(detail['valid_warning_observations'], 3)
        self.assertEqual(detail['net_growth_bytes'], 128 * MIB)
        self.assertEqual(detail['growing_transitions'], 1)
        self.assertEqual(detail['window_span_seconds'], 34)
        self.assertIsNone(self.observe(126, 138 * MIB))
        self.assertEqual(self.monitor.summary()['burst_guard']['valid_warning_observations'], 1)
        self.assertEqual(self.monitor.summary()['burst_guard']['net_growth_bytes'], 0)

    def test_normal_pressure_clears_epoch_and_window_before_new_warning(self):
        for now, amount, pressure in ((2, 0, 2), (4, 64, 2), (6, 128, 2), (8, 128, 1)):
            self.assertIsNone(self.observe(now, amount * MIB, pressure=pressure))
        self.assertEqual(self.monitor.summary()['burst_guard']['valid_warning_observations'], 0)
        for now in range(10, 72, 2):
            amount = 128 if now == 10 else 192 if now == 12 else 256
            self.assertEqual(self.observe(now, amount * MIB), 'memory-pressure-deterioration' if now == 70 else None)

    def test_missing_gap_creates_no_fake_transition_but_preserves_warning_history(self):
        self.assertIsNone(self.observe(2, 0))
        self.assertIsNone(self.observe(4, missing=True))
        for now in range(6, 64, 2):
            self.assertIsNone(self.observe(now, (128 if now == 6 else 192) * MIB))
        detail = self.monitor.summary()['burst_guard']
        self.assertEqual(detail['valid_warning_observations'], 30)
        self.assertEqual(detail['net_growth_bytes'], 192 * MIB)
        self.assertEqual(detail['growing_transitions'], 1)
        self.assertIsNone(self.observe(64, 192 * MIB))
        self.assertEqual(self.observe(66, 320 * MIB), 'memory-pressure-deterioration')
        self.assertEqual(self.monitor.summary()['deterioration_trigger'], 'rolling-net-growth')

    def test_old_cumulative_growth_is_not_substituted_for_recent_net_growth(self):
        for index in range(1, 300):
            self.assertIsNone(self.observe(index * 2, ((index + 1) // 2) * MIB))
        result = self.monitor.summary()
        self.assertGreaterEqual(result['max_warning_swap_growth_bytes'], 128 * MIB)
        self.assertLess(result['burst_guard']['net_growth_bytes'], 128 * MIB)
        self.assertLessEqual(result['burst_guard']['valid_warning_observations'], 31)


if __name__ == '__main__':
    unittest.main()
