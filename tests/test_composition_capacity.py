"""Private registry capacity changes neither public authority nor generation."""
import json
from pathlib import Path

import pytest

import composition
import contracts
from engine_types import EngineIdentity
from state_io import StateError


PRIVATE_ROLES = {
    "ollama": ("generate",),
    "codex-openai": ("generate", "design-review"),
    "claude": ("review",),
    "grok-cli": ("review",),
    "agy": ("review",),
}


def private_policy(roles=None):
    return composition.Policy(namespace="plzdo.overlay", engine_roles=PRIVATE_ROLES if roles is None else roles,
        generation_order=("ollama", "codex-openai"), generation_limits={"ollama": 2, "codex-openai": 1},
        high_risk_engines=("codex-openai",), admission_engines=("grok-cli",), source_files=(Path(__file__),))


class OfflineEngine:
    def __init__(self, identifier, roles):
        self._identity = EngineIdentity(identifier, roles, "a" * 64)

    def identity(self):
        return self._identity

    def execute(self, _work):
        raise AssertionError("Registry tests must not execute an engine")


def test_five_private_engines_register_without_extra_generation(tmp_path, monkeypatch):
    policy = private_policy()
    engines = {name: OfflineEngine(name, roles) for name, roles in PRIVATE_ROLES.items()}
    state = tmp_path.resolve() / "state"
    monkeypatch.setattr(composition, "_context", None)
    monkeypatch.setenv("LOCAL_CODING_STATE_ROOT", str(state))
    composition.configure(policy, engines, state)
    assert composition.current_policy() == policy
    assert set(composition.current_engine_pins(tuple(engines))) == set(PRIVATE_ROLES)
    assert composition.engine("agy", "review") is engines["agy"]
    with pytest.raises(StateError, match="fixed engine roles"):
        composition.engine("agy", "generate")

    previous = private_policy({name: roles for name, roles in PRIVATE_ROLES.items() if name != "agy"})
    task = {"kind": "artifact-create", "risk": "normal", "local_attempts": 2}
    assert policy.generation_plan(task, tuple(engines)) == previous.generation_plan(task, tuple(previous.engine_roles)) == [
        {"engineId": "ollama", "role": "generate", "ordinal": 1},
        {"engineId": "ollama", "role": "generate", "ordinal": 2},
        {"engineId": "codex-openai", "role": "generate", "ordinal": 3},
    ]
    assert policy.generation_plan({**task, "risk": "high"}, tuple(engines)) == [
        {"engineId": "codex-openai", "role": "generate", "ordinal": 1}]
    assert policy.generation_plan(task, ("agy",)) == []
    assert dict(policy.generation_limits) == {"ollama": 2, "codex-openai": 1}
    assert not state.exists()


@pytest.mark.parametrize("roles", [{"ollama": ("generate",), "agy": ("review",)}, PRIVATE_ROLES])
def test_public_composition_still_refuses_expansion(roles):
    with pytest.raises(StateError, match="Public composition cannot be expanded"):
        composition.Policy(engine_roles=roles)
    assert dict(composition.PUBLIC_POLICY.engine_roles) == {"ollama": ("generate",)}


def test_six_private_engines_are_still_refused():
    with pytest.raises(StateError, match="registry size"):
        private_policy({**PRIVATE_ROLES, "unapproved-extra": ("review",)})


def test_registry_capacity_does_not_widen_generation_slot_ceiling():
    policy = composition.Policy(namespace="plzdo.overlay",
        engine_roles={**PRIVATE_ROLES, "agy": ("generate",)},
        generation_order=("ollama", "codex-openai", "agy"),
        generation_limits={"ollama": 2, "codex-openai": 1, "agy": 1}, source_files=(Path(__file__),))
    with pytest.raises(StateError, match="Generation plan exceeds bounded composition"):
        policy.generation_plan({"kind": "artifact-create", "local_attempts": 2}, tuple(policy.engine_roles))


@pytest.mark.parametrize("kind,filename", [
    ("exact", "standalone-contract"), ("scope", "scoped-task"),
    ("parent-exact", "parent-delegation"), ("parent-scope", "parent-scoped-contract"),
])
def test_schema_capacity_is_derived_and_public_snapshots_are_unchanged(kind, filename):
    private = contracts.authority_schema(kind, private_policy())
    assert private["$defs"]["engines"]["maxItems"] == 5
    assert private["$defs"]["engines"]["items"]["enum"] == sorted(PRIVATE_ROLES)
    assert private["$defs"]["operations"]["maxItems"] == 6
    assert private["$defs"]["generationPlan"]["maxItems"] == 3
    public = contracts.authority_schema(kind, composition.PUBLIC_POLICY)
    stored = Path(contracts.__file__).parents[1] / "schemas" / (filename + ".schema.json")
    assert public == json.loads(stored.read_text())
    assert public["$defs"]["engines"]["maxItems"] == 1
    assert public["$defs"]["operations"]["maxItems"] == 1
    assert public["$defs"]["generationPlan"]["maxItems"] == 2
