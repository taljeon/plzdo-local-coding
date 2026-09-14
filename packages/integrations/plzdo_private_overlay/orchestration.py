"""The fixed private composition consumes the public pipeline and one Kernel."""
from __future__ import annotations

from pathlib import Path

from local_coding.api import Kernel, Policy, run_pipeline, strict_json

from .engines import fixed_engines, ROLES, AGY_RULES_UNSET
from .transports import _bounded_read, require_active_session


CONFIG_SCHEMA = 'plzdo.private-config.v1'


def load_config(path):
    value = strict_json(_bounded_read(Path(path)))
    if (not isinstance(value, dict)
            or set(value) - {'schemaVersion', 'stateRoot', 'providerPins', 'codexModel',
                             'agyModel', 'agyGlobalRulesSha256'}
            or not {'schemaVersion', 'stateRoot', 'providerPins'} <= set(value)
            or value['schemaVersion'] != CONFIG_SCHEMA):
        raise ValueError('Invalid closed private configuration')
    if (not isinstance(value['stateRoot'], str) or not Path(value['stateRoot']).is_absolute()
            or Path(value['stateRoot']).resolve() != Path(value['stateRoot'])):
        raise ValueError('Private state root must be explicit and canonical')
    if 'codexModel' in value and not isinstance(value['codexModel'], str):
        raise ValueError('Explicit Codex model must be a string')
    if 'agyModel' in value and not isinstance(value['agyModel'], str):
        raise ValueError('Explicit AGY model must be a string')
    configured_engines(value)
    return value


def configured_engines(configuration):
    return fixed_engines(configuration['providerPins'], codex_model=configuration.get('codexModel'),
        agy_model=configuration.get('agyModel'),
        agy_global_rules_sha256=configuration.get('agyGlobalRulesSha256', AGY_RULES_UNSET))


def compose(configuration):
    """No registry JSON, runtime callbacks, HN fallback, or arbitrary imports."""
    engines = configured_engines(configuration)
    root = Path(__file__).resolve().parent
    files = tuple(sorted(root.glob('*.py'))) + tuple(sorted((root / 'schemas').glob('*.json')))
    order = tuple(name for name in ('ollama', 'codex-openai') if name in engines)
    policy = Policy(namespace='plzdo.overlay',
        engine_roles={name: ROLES[name] for name in engines},
        generation_order=order,
        generation_limits={name: 2 if name == 'ollama' else 1 for name in order},
        high_risk_engines=tuple(name for name in ('codex-openai',) if name in engines),
        admission_engines=tuple(name for name in ('grok-cli',) if name in engines),
        source_files=files)
    return Kernel(Path(configuration['stateRoot']), policy=policy, engines=engines)


def run_private(kernel, packet, *, run_name, resume=False):
    # The shared pipeline calls begin_run on this private Kernel from the outset.
    require_active_session()
    return run_pipeline(packet, run_name, resume=resume, kernel=kernel)
