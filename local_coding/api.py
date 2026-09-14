"""Small source-composed API used by the public CLI and private consumer.

Task/CLI input cannot select Python modules, Policy objects or arbitrary engines.
Importing this module does not create state or contact a model/provider.
"""
from ._bootstrap import engine_module

_types = engine_module("engine_types")
EngineIdentity = _types.EngineIdentity
EngineFailure = _types.EngineFailure
Work = _types.Work
WorkResult = _types.WorkResult
require_cleanup = _types.require_cleanup
no_start_cleanup = _types.no_start_cleanup
_state = engine_module("state_io")
canonical_bytes = _state.canonical_bytes
strict_json = _state.strict_json
Policy = engine_module("composition").Policy
PUBLIC_POLICY = engine_module("composition").PUBLIC_POLICY


run_bounded = engine_module("run_bounded").run


def run_pipeline(*args, **kwargs):
    return engine_module("workflow").run_pipeline(*args, **kwargs)


def validate_bundle(value):
    return engine_module("provider_common").validate_bundle(value)


def execute_owned_ollama(work, identity):
    return engine_module("ollama_engine").execute_owned_ollama(work, identity)


def ollama_implementation_sha256():
    return engine_module("ollama_engine").implementation_sha256()


def __getattr__(name):
    # One literal deferred type keeps policy-sensitive flat imports after the
    # caller's fixed composition is selected. This is not caller module loading.
    if name == "Kernel":
        return engine_module("kernel").Kernel
    raise AttributeError(name)
