"""Pinned, opt-in Qwen generation policy; legacy packets remain unchanged.

Byte budgeting below is a conservative assumption, not a tokenizer measurement.
Tail repetition detection is a bounded heuristic, not proof of a semantic bug.
"""
import hashlib
import json

LEGACY_PROFILE_ID = 'qwen3-coder-official-v1'
PREVIOUS_PROFILE_ID = 'qwen3-coder-official-v2'
PROFILE_ID = 'qwen3-coder-official-v3'
MODEL = 'qwen3-coder:30b-a3b-q4_K_M'
DIGEST = '06c1097efce0431c2045fe7b2e5108366e43bee1b4603a7aded8f21689e90bca'
HUIHUI_PROFILE_ID = 'huihui-qwen38-q6kl-v1'
HUIHUI_MODEL = 'huihui_ai/Qwen3.8-abliterated:27b-q6_K_L'
HUIHUI_DIGEST = '4fcc84fd9a3b60b00abd3c0d5243bed154e83f9dbfb349403a1adbf7fc5e51cf'
# New packet authors use this explicit profile. Missing-profile historical
# packets and PROFILE_ID retain their original Coder meaning and hashes.
DEFAULT_PROFILE_ID = HUIHUI_PROFILE_ID

_V1_CANONICAL_JSON = json.dumps({
    'id': LEGACY_PROFILE_ID, 'model': MODEL, 'model_digest': DIGEST,
    'options': {'num_ctx': 81920, 'num_predict': 65536, 'temperature': 0.7,
                'top_p': 0.8, 'top_k': 20, 'repeat_penalty': 1.05, 'seed': 42},
    'stream': True, 'think': False, 'truncate': False, 'shift': False, 'keep_alive': '5m',
    'generation_deadline': 3600, 'supervisor_grace': 30,
    'first_content_timeout': 600, 'content_idle_timeout': 120,
    'wire_limit': 64 * 1024 * 1024, 'response_limit': 2 * 1024 * 1024,
    'frame_limit': 1024 * 1024, 'progress_interval': 1,
    'memory_sample_interval': 2, 'warning_window': 60,
    'sustained_swap_growth': 128 * 1024 * 1024, 'successive_growth_samples': 3,
    'telemetry_failures': 3, 'free_floor': 4 * 1024 * 1024 * 1024,
    'template_reserve': 2048, 'repetition_min_chars': 32768,
    'repetition_min_unit': 256, 'repetition_max_unit': 2048,
    'repetition_cycles': 16, 'repetition_min_distinct': 16,
}, sort_keys=True, separators=(',', ':'), allow_nan=False)
_V2_CANONICAL_JSON = json.dumps({**json.loads(_V1_CANONICAL_JSON), 'id': PREVIOUS_PROFILE_ID,
    'headroom_measurement': 'free-plus-file-backed-estimate'},
    sort_keys=True, separators=(',', ':'), allow_nan=False)
_V3_CANONICAL_JSON = json.dumps({**json.loads(_V2_CANONICAL_JSON), 'id': PROFILE_ID,
    'burst_guard_mode': 'consecutive-or-rolling-net', 'burst_window': 60,
    'burst_min_growth_observations': 2},
    sort_keys=True, separators=(',', ':'), allow_nan=False)
_HUIHUI_CANONICAL_JSON = json.dumps({**json.loads(_V3_CANONICAL_JSON),
    'id': HUIHUI_PROFILE_ID, 'model': HUIHUI_MODEL, 'model_digest': HUIHUI_DIGEST,
    'options': {'num_ctx': 81920, 'num_predict': 65536, 'temperature': 1.0,
                'top_p': 0.95, 'top_k': 20, 'repeat_penalty': 1.0, 'seed': 42,
                'min_p': 0.0, 'presence_penalty': 0.0},
    'think': True, 'thinking_limit': 8 * 1024 * 1024,
    'activity_timeout_semantics': 'thinking-or-content'},
    sort_keys=True, separators=(',', ':'), allow_nan=False)
_VERSION_JSON = {LEGACY_PROFILE_ID: _V1_CANONICAL_JSON, PREVIOUS_PROFILE_ID: _V2_CANONICAL_JSON,
                 PROFILE_ID: _V3_CANONICAL_JSON, HUIHUI_PROFILE_ID: _HUIHUI_CANONICAL_JSON}


def resolve_profile(value):
    """Accept the versioned name or its exact, type-sensitive canonical dict."""
    if type(value) is str:
        if value not in _VERSION_JSON:
            raise ValueError('Unknown generation profile')
        encoded = _VERSION_JSON[value]
    elif type(value) is dict:
        identifier = value.get('id')
        if type(identifier) is not str or identifier not in _VERSION_JSON:
            raise ValueError('Unknown generation profile')
        try:
            encoded = json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False)
        except (TypeError, ValueError, RecursionError) as exc:
            raise ValueError('Generation profile must be canonical JSON') from exc
        if encoded != _VERSION_JSON[identifier]:
            raise ValueError('Mutated or noncanonical generation profile')
    else:
        raise ValueError('An explicit generation profile name or canonical dict is required')
    return json.loads(encoded)


def profile_sha256(profile):
    selected = resolve_profile(profile)
    return hashlib.sha256(_VERSION_JSON[selected['id']].encode('utf-8')).hexdigest()


def input_budget(prompt, system, profile):
    """Fail closed using input UTF-8 bytes as a token upper-bound assumption."""
    policy = resolve_profile(profile)
    if type(prompt) is not str or type(system) is not str:
        raise ValueError('Prompt and system message must be strings')
    try:
        prompt_bytes, system_bytes = len(prompt.encode('utf-8')), len(system.encode('utf-8'))
    except UnicodeError as exc:
        raise ValueError('Generation input must be valid UTF-8') from exc
    assumed_input = prompt_bytes + system_bytes
    total = assumed_input + policy['template_reserve'] + policy['options']['num_predict']
    context = policy['options']['num_ctx']
    if total > context:
        raise ValueError('Conservative input/context budget exceeded')
    return {
        'method': 'utf8-byte-upper-bound-assumption', 'exact_tokenizer_measurement': False,
        'prompt_utf8_bytes': prompt_bytes, 'system_utf8_bytes': system_bytes,
        'assumed_input_token_upper_bound': assumed_input,
        'assumed_template_reserve_tokens': policy['template_reserve'],
        'reserved_output_tokens': policy['options']['num_predict'], 'context_tokens': context,
        'assumed_total_tokens': total, 'assumed_remaining_tokens': context - total,
        'profile_sha256': profile_sha256(policy),
    }


def detect_repetition(text, profile):
    """Return a heuristic stop reason for a large, exact contiguous tail cycle.

    Callers invoke this only after another 4096 content characters. Work uses a
    bounded 32768-character suffix and at most 1793 candidate unit lengths.
    Braces/indentation and low-alphabet repeated scalar values are ignored.
    """
    policy = resolve_profile(profile)
    if type(text) is not str:
        raise ValueError('Repetition input must be text')
    if len(text) < policy['repetition_min_chars']:
        return None
    cycles = policy['repetition_cycles']
    tail = text[-policy['repetition_max_unit'] * cycles:]
    minimum_distinct = policy['repetition_min_distinct']
    if len({char for char in tail if not char.isspace()}) < minimum_distinct:
        return None
    for width in range(policy['repetition_min_unit'], policy['repetition_max_unit'] + 1):
        unit = tail[-width:]
        if tail[-2 * width:-width] != unit:
            continue
        if len({char for char in unit if not char.isspace()}) < minimum_distinct:
            continue
        if tail.endswith(unit * cycles):
            return 'repetition-tail-cycle'
    return None
