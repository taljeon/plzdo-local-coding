import random
import string
import unittest

from generation_profile import LEGACY_PROFILE_ID, PREVIOUS_PROFILE_ID, PROFILE_ID, detect_repetition, input_budget, profile_sha256, resolve_profile


class GenerationProfileTests(unittest.TestCase):
    def test_preset_is_exact_and_returns_independent_copies(self):
        one, two = resolve_profile(PROFILE_ID), resolve_profile(PROFILE_ID)
        self.assertEqual(one['options'], {'num_ctx': 81920, 'num_predict': 65536, 'temperature': 0.7,
                                         'top_p': 0.8, 'top_k': 20, 'repeat_penalty': 1.05, 'seed': 42})
        self.assertEqual(resolve_profile(one), two)
        one['options']['num_ctx'] = 1
        self.assertEqual(resolve_profile(PROFILE_ID), two)
        self.assertEqual(profile_sha256(two), profile_sha256(PROFILE_ID))
        self.assertEqual(len(profile_sha256(two)), 64)

    def test_absent_unknown_and_mutated_profiles_are_rejected(self):
        bad = [None, True, 1, [], {}, 'legacy', 'qwen3-coder-official-v4']
        for key, value in [('stream', 1), ('generation_deadline', 3600.0), ('free_floor', True),
                           ('telemetry_failures', 4), ('extra', 'field')]:
            profile = resolve_profile(PROFILE_ID)
            profile[key] = value
            bad.append(profile)
        changed = resolve_profile(PROFILE_ID)
        changed['options']['top_k'] = 20.0
        bad.append(changed)
        for value in bad:
            with self.subTest(value_type=type(value)), self.assertRaises(ValueError):
                resolve_profile(value)

    def test_v1_hash_and_body_are_preserved_while_v2_is_version_specific(self):
        original = resolve_profile(LEGACY_PROFILE_ID)
        self.assertEqual(profile_sha256(original), 'eba813d02eaad342a0be89f0513068f8d65b4be94558736f6ac0c5967cd9fb2c')
        self.assertNotIn('headroom_measurement', original)
        current = resolve_profile(PREVIOUS_PROFILE_ID)
        self.assertEqual(PREVIOUS_PROFILE_ID, 'qwen3-coder-official-v2')
        self.assertEqual(current.pop('headroom_measurement'), 'free-plus-file-backed-estimate')
        current['id'] = LEGACY_PROFILE_ID
        self.assertEqual(current, original)
        self.assertNotEqual(profile_sha256(PREVIOUS_PROFILE_ID), profile_sha256(LEGACY_PROFILE_ID))
        self.assertEqual(resolve_profile(original), original)
        forged = {**original, 'headroom_measurement': 'free-plus-file-backed-estimate'}
        with self.assertRaises(ValueError):
            resolve_profile(forged)

    def test_all_versions_keep_budget_and_repetition_interfaces(self):
        for identifier in (LEGACY_PROFILE_ID, PREVIOUS_PROFILE_ID, PROFILE_ID):
            self.assertEqual(input_budget('hello', 'system', identifier)['reserved_output_tokens'], 65536)
            self.assertIsNone(detect_repetition('small valid output', identifier))

    def test_v3_only_adds_versioned_burst_policy_and_preserves_both_old_hashes(self):
        previous = resolve_profile(PREVIOUS_PROFILE_ID)
        self.assertEqual(profile_sha256(PREVIOUS_PROFILE_ID), '2fb0605b6f1d15a36e5a2363ee187104fe1d0fc3689998555af8dec0eae75c28')
        self.assertEqual(profile_sha256(LEGACY_PROFILE_ID), 'eba813d02eaad342a0be89f0513068f8d65b4be94558736f6ac0c5967cd9fb2c')
        current = resolve_profile(PROFILE_ID)
        self.assertEqual(PROFILE_ID, 'qwen3-coder-official-v3')
        self.assertEqual(current.pop('burst_guard_mode'), 'consecutive-or-rolling-net')
        self.assertEqual(current.pop('burst_window'), 60)
        self.assertEqual(current.pop('burst_min_growth_observations'), 2)
        current['id'] = PREVIOUS_PROFILE_ID
        self.assertEqual(current, previous)
        self.assertNotEqual(profile_sha256(PROFILE_ID), profile_sha256(PREVIOUS_PROFILE_ID))
        for key, value in [('burst_window', 60.0), ('burst_min_growth_observations', True),
                           ('burst_guard_mode', 'always-stop')]:
            changed = resolve_profile(PROFILE_ID)
            changed[key] = value
            with self.assertRaises(ValueError):
                resolve_profile(changed)

    def test_byte_budget_boundary_and_tokenizer_disclaimer(self):
        result = input_budget('a' * 14330, 'system', PROFILE_ID)
        self.assertEqual(result['assumed_total_tokens'], 81920)
        self.assertEqual(result['assumed_remaining_tokens'], 0)
        self.assertFalse(result['exact_tokenizer_measurement'])
        self.assertEqual(result['reserved_output_tokens'], 65536)
        with self.assertRaises(ValueError):
            input_budget('a' * 14331, 'system', PROFILE_ID)

    def test_budget_counts_utf8_bytes_and_rejects_invalid_text(self):
        result = input_budget('가' * 100, '😀', PROFILE_ID)
        self.assertEqual(result['prompt_utf8_bytes'], 300)
        self.assertEqual(result['system_utf8_bytes'], 4)
        for prompt, system in ((True, ''), ('', None), ('\ud800', '')):
            with self.assertRaises(ValueError):
                input_budget(prompt, system, PROFILE_ID)

    def test_repetition_requires_large_text_and_sixteen_substantial_cycles(self):
        generator = random.Random(42)
        unit = ''.join(generator.choice(string.ascii_letters + string.digits + '{}[]():,') for _ in range(512))
        prefix = 'unique lead-in text. ' * 1800
        self.assertIsNone(detect_repetition(unit * 16, PROFILE_ID))
        self.assertIsNone(detect_repetition(prefix + unit * 15, PROFILE_ID))
        self.assertEqual(detect_repetition(prefix + unit * 16, PROFILE_ID), 'repetition-tail-cycle')

    def test_repetition_ignores_braces_indentation_and_low_alphabet_scalars(self):
        for text in ('    }],\n' * 6000, '{"v":1111},\n' * 4000, '0123456789\n' * 4000):
            self.assertIsNone(detect_repetition(text, PROFILE_ID))

    def test_repetition_checks_only_contiguous_tail_not_earlier_repeats(self):
        generator = random.Random(9)
        unit = ''.join(generator.choice(string.ascii_letters + string.digits) for _ in range(2048))
        self.assertEqual(detect_repetition(unit * 16, PROFILE_ID), 'repetition-tail-cycle')
        tail = ''.join(generator.choice(string.ascii_letters + string.digits) for _ in range(32768))
        self.assertIsNone(detect_repetition(unit * 20 + tail, PROFILE_ID))


if __name__ == '__main__':
    unittest.main()
