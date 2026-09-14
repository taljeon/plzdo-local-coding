"""Focused v2 authority boundaries; only owned synthetic state and core reads."""
import copy
from datetime import timedelta
import inspect
import json
import os
from pathlib import Path
import subprocess
import sys

import jsonschema
import pytest

CORE = Path(__file__).resolve().parents[1].parent / 'plzdo'
sys.path.insert(0, str(CORE))

import composition
import contracts
import parent_authority as parent
import scope_authority as scope
from engine_types import EngineIdentity
from state_io import StateError, StateStore
from plzdo_local_code_adapter.cli import configure
from tests.adapter.fixtures import formalization, save_formalization


class OfflineEngine:
    implementation = "a" * 64

    def identity(self):
        return EngineIdentity("ollama", ("generate",), self.implementation)

    def execute(self, _work):
        raise AssertionError("Authority checks must not execute an engine")


@pytest.fixture
def env(tmp_path, monkeypatch):
    root = tmp_path.resolve()
    monkeypatch.setattr(composition, "_context", None)
    monkeypatch.setenv("LOCAL_CODING_STATE_ROOT", str(root / "state"))
    for key in ("META_HARNESS_AGENT_CONTEXT", "META_HARNESS_SCHEDULED_AUTOMATION", "META_HARNESS_HEARTBEAT_LANE", "CI"):
        monkeypatch.delenv(key, raising=False)
    engine = OfflineEngine()
    composition.configure(composition.PUBLIC_POLICY, {"ollama": engine}, root / "state")
    # Editing-time authority fixtures use a fixed policy; real source hashing is
    # checked separately, so another worker's source edit cannot race a fixture.
    monkeypatch.setattr(contracts, "policy_fingerprint", lambda: "f" * 64)
    return {"root": root, "state": root / "state", "engine": engine}


def packet(root_id="fixture-root", *, identifier="fixture-packet", attempts=2):
    from workflow import validate_task_packet
    return validate_task_packet({"kind": "artifact-create", "id": identifier, "authorityId": root_id,
        "objective": "Create bounded fixture text", "allowed_paths": ["output.txt", "extra.txt"],
        "generation_profile": scope.PROFILE_ID, "task_category": "product-development", "local_attempts": attempts,
        "validation_packs": [{"type": "text", "path": "output.txt", "required": ["fixture"]}]})


def draft(value=None, *, engines=None, calls=2):
    value = packet() if value is None else value
    return contracts.draft_contract(value["authorityId"], [value],
        expires_at=(contracts._now() + timedelta(hours=1)).isoformat(),
        max_live_integration_calls=calls, allowed_engines=["ollama"] if engines is None else engines)


def draft_scope(value=None):
    value = packet() if value is None else value
    return scope.draft_scope(value["authorityId"], {"schemaVersion": scope.SCOPE_VERSION,
        "templates": {"fixture": {"packet": value, "basePolicy": {"mode": "exact"}}}},
        expires_at=(contracts._now() + timedelta(hours=1)).isoformat(), max_live_integration_calls=2,
        allowed_engines=["ollama"], max_total_runs=2, max_children=3, max_runs_per_child=1)


def validator(kind, definition=None):
    schema = contracts.authority_schema(kind)
    if definition:
        schema = {"$schema": schema["$schema"], "$defs": schema["$defs"], "$ref": "#/$defs/" + definition}
    return jsonschema.Draft202012Validator(schema, format_checker=jsonschema.FormatChecker())


def test_exact_draft_approval_and_no_budget_reinitialization(env):
    value = packet()
    document = draft(value)
    validator("exact").validate(document)
    binding = document["execution"]["taskBindings"][value["id"]]
    assert binding["allowedOperations"] == [{"engineId": "ollama", "role": "generate"}]
    assert binding["generationAttemptPlan"] == [{"engineId": "ollama", "role": "generate", "ordinal": i} for i in (1, 2)]
    contracts.save_draft(env["state"], document)
    with pytest.raises(StateError, match="approved"):
        contracts.approved_contract(value, env["state"])
    sha = contracts.payload_sha256(document)
    approved = contracts.approve_contract(env["state"], document["id"], expected_payload_sha256=sha,
        approved_by="operator", confirmation="APPROVE " + document["id"] + " " + sha)
    assert contracts.approved_contract(value, env["state"]) == (approved, binding)
    before = (env["state"] / "ledgers" / (document["id"] + ".json")).read_bytes()
    with pytest.raises(StateError, match="durable state"):
        contracts.save_draft(env["state"], document)
    assert (env["state"] / "ledgers" / (document["id"] + ".json")).read_bytes() == before
    assert "backend" not in inspect.signature(contracts.approved_contract).parameters
    assert not hasattr(contracts, "_legacy_contract")


@pytest.mark.parametrize("mutation", [
    lambda d: d.update(schemaVersion="standalone-contract.v1"),
    lambda d: d.update(schemaVersion="plzdo.overlay.exact.v2"),
    lambda d: d["execution"].pop("enginePins"),
    lambda d: d["execution"].update(allowedProviders=["local"]),
    lambda d: d["execution"].update(allowedEngines=["codex"]),
    lambda d: d["execution"]["taskBindings"]["fixture-packet"].update(externalAiAllowed=True),
    lambda d: d["execution"]["taskBindings"]["fixture-packet"].update(allowedOperations=[{"engineId": "ollama", "role": "review"}]),
    lambda d: d["execution"]["taskBindings"]["fixture-packet"]["generationAttemptPlan"][0].update(ordinal=True),
    lambda d: d["execution"]["taskBindings"]["fixture-packet"]["generationAttemptPlan"].append({"engineId": "ollama", "role": "generate", "ordinal": 3}),
])
def test_legacy_unknown_roles_or_unapproved_slots_cannot_execute(env, mutation):
    document = draft()
    mutation(document)
    with pytest.raises(StateError):
        contracts.validate_contract(document)
    with pytest.raises(jsonschema.ValidationError):
        validator("exact").validate(document)


def test_engine_identity_is_rechecked_without_a_cache(env):
    document = draft()
    env["engine"].implementation = "b" * 64
    with pytest.raises(StateError, match="implementation identity changed"):
        contracts.validate_contract(document)
    contracts.validate_contract(document, check_freshness=False)


def test_exact_packet_recomputes_generation_plan(env):
    value = packet(attempts=1)
    document = draft(value)
    binding = document["execution"]["taskBindings"][value["id"]]
    binding["generationAttemptPlan"].append({"engineId": "ollama", "role": "generate", "ordinal": 2})
    with pytest.raises(StateError, match="generation-attempt"):
        contracts.binding_for_packet(document, value)


def test_zero_call_compute_binding_has_no_engines_or_operations(env):
    value = {"id": "fixture-compute", "authorityId": "fixture-root", "kind": "compute-analysis", "inputs": {"n": 3}}
    document = draft(value, engines=[], calls=0)
    binding = document["execution"]["taskBindings"][value["id"]]
    assert document["execution"]["enginePins"] == {}
    assert binding["allowedEngines"] == binding["allowedOperations"] == binding["generationAttemptPlan"] == []
    validator("exact").validate(document)
    with pytest.raises(StateError):
        draft(value, engines=["ollama"], calls=0)


def test_scope_child_stays_within_the_fixed_template_and_slots(env):
    document = draft_scope()
    validator("scope").validate(document)
    value = copy.deepcopy(document["execution"]["taskScope"]["templates"]["fixture"]["packet"])
    value.update(id="child-one", allowed_paths=["output.txt"])
    binding = scope._child(document, "fixture", value, admission=True)
    assert binding["allowedEngines"] == ["ollama"] and binding["maxRuns"] == 1
    for change in ({"allowed_paths": ["outside.txt"]}, {"local_attempts": 1}, {"authorityId": "different-root"},
                   {"external_ai_allowed": True}):
        with pytest.raises(StateError):
            scope._child(document, "fixture", {**value, **change}, admission=True)
    env["engine"].implementation = "b" * 64
    with pytest.raises(StateError, match="implementation identity changed"):
        scope.validate_scope(document)


def test_common_schemas_materialize_separate_closed_engine_sets(env):
    directory = Path(contracts.__file__).parents[1] / "schemas"
    common = json.loads((directory / "authority-common.schema.json").read_text())
    with pytest.raises(jsonschema.ValidationError):
        jsonschema.Draft202012Validator(common).validate(draft())
    for kind, name in (("exact", "standalone-contract"), ("scope", "scoped-task"),
                       ("parent-exact", "parent-delegation"), ("parent-scope", "parent-scoped-contract")):
        schema = contracts.authority_schema(kind)
        jsonschema.Draft202012Validator.check_schema(schema)
        assert schema == json.loads((directory / (name + ".schema.json")).read_text())
        assert schema["additionalProperties"] is False
        assert schema["$defs"]["engines"]["items"]["enum"] == ["ollama"]
    private = composition.Policy(namespace="plzdo.overlay", engine_roles={"ollama": ("generate",), "codex": ("generate", "review")},
        generation_order=("ollama", "codex"), generation_limits={"ollama": 2, "codex": 1},
        high_risk_engines=("codex",), source_files=(Path(__file__),))
    private_schema = contracts.authority_schema("exact", private)
    assert private_schema["properties"]["schemaVersion"]["const"] == "plzdo.overlay.exact.v2"
    assert private_schema["$defs"]["engines"]["items"]["enum"] == ["codex", "ollama"]
    with pytest.raises(jsonschema.ValidationError):
        jsonschema.Draft202012Validator(private_schema).validate(draft())


def parent_fixture(env):
    core_state, project = env["root"] / "core-state", env["root"] / "project"
    core_state.mkdir(mode=0o700)
    project.mkdir(mode=0o700)
    interpreter = Path(sys.executable).resolve()
    output = env["root"] / "pins"
    configure(core_root=CORE, core_python=interpreter, verifier_python=interpreter,
              state_root=core_state, project_root=project, project_id="fixture-project",
              formalization_id="fixture-goal", output=output)
    (core_state / "registry").mkdir()
    (core_state / "registry" / "registry.json").write_text(json.dumps({"schemaVersion": "plzdo-local.registry.v1", "projects": [{
        "id": "fixture-project", "aliases": [], "domain": "software", "area": "tooling", "path": str(project),
        "repositoryId": None, "state": "active"}]}))
    verifier = json.loads((output / "verifier.json").read_text())
    sha = parent.digest(verifier)
    parent.trust_verifier(env["state"], verifier, expected_descriptor_sha256=sha,
                          confirmation="TRUST PARENT VERIFIER " + sha)
    return {"parent_reference": json.loads((output / "parent-reference.json").read_text()), "verifier": verifier,
            "expires_at": (contracts._now() + timedelta(hours=1)).isoformat(),
            "max_live_integration_calls": 2, "allowed_engines": ["ollama"]}


def test_real_fixed_parent_prepare_adopt_and_revocation(env):
    options = parent_fixture(env)
    request = parent.prepare_request(env["state"], packet(), **options)
    assert parent.marker(request) == "plzdo-delegation:v2:" + request["requestSha256"]
    assert request["packet"]["authorityId"] == request["id"]
    validator("parent-exact", "request").validate(request)
    assert parent.prepare_request(env["state"], packet(), **options) == request
    save_formalization(request, formalization(request))
    document = parent.adopt_request(env["state"], request["id"], expected_request_sha256=request["requestSha256"])
    validator("parent-exact").validate(document)
    assert parent.adopt_request(env["state"], request["id"], expected_request_sha256=request["requestSha256"]) == document
    observations = []
    with StateStore(env["state"]) as store, store.locked():
        assert parent.current_delegated_contract(store, document, observations=observations) == document
    assert len(observations) == 1 and observations[0]["atomicLease"] is False
    parent.validate_authority_observation(observations[0], document, fresh=True)
    before = (env["state"] / "ledgers" / (request["id"] + ".json")).read_bytes()
    save_formalization(request, formalization(request, status="draft"))
    with pytest.raises(StateError):
        contracts.approved_contract(request["packet"], env["state"])
    assert (env["state"] / "ledgers" / (request["id"] + ".json")).read_bytes() == before


def test_caller_pinned_fake_verifier_is_rejected_even_with_exact_confirmation(env, monkeypatch):
    options = parent_fixture(env)
    forged = env["root"] / "forged.py"
    forged.write_text('raise RuntimeError("must not run")\n')
    for field in ("python", "entrypoint"):
        verifier = copy.deepcopy(options["verifier"])
        verifier[field] = parent.file_identity(forged)
        sha = parent.digest(verifier)
        monkeypatch.setattr(parent, "_process", lambda *_: pytest.fail("Caller code executed"))
        with pytest.raises(StateError, match="Fixed public"):
            parent.trust_verifier(env["root"] / ("other-" + field), verifier,
                expected_descriptor_sha256=sha, confirmation="TRUST PARENT VERIFIER " + sha)


def test_old_wire_and_changed_engine_pin_fail_before_parent_process(env, monkeypatch):
    options = parent_fixture(env)
    request = parent.prepare_request(env["state"], packet(), **options)
    monkeypatch.setattr(parent, "_process", lambda *_: pytest.fail("Invalid authority started a process"))
    changed = copy.deepcopy(request)
    changed["schemaVersion"] = "local-coding.parent-request.v1"
    changed["requestSha256"] = parent.request_sha256(changed)
    with StateStore(env["state"]) as store, store.locked():
        with pytest.raises(StateError):
            parent.verify_parent(changed, store)
        env["engine"].implementation = "b" * 64
        with pytest.raises(StateError, match="implementation identity changed"):
            parent.verify_parent(request, store)


def test_parent_scope_wire_and_projection_keep_json_types_distinct(env):
    options = parent_fixture(env)
    value = packet()
    value["facts"] = {"number": 1}
    request = parent.prepare_scope_request(env["state"], {"schemaVersion": scope.SCOPE_VERSION,
        "templates": {"fixture": {"packet": value, "basePolicy": {"mode": "exact"}}}},
        **options, max_total_runs=2, max_children=3)
    validator("parent-scope", "request").validate(request)
    assert parent.marker(request) == "plzdo-scope-delegation:v2:" + request["requestSha256"]
    document = {"schemaVersion": parent.SCOPE_CONTRACT_VERSION, "id": request["id"], "status": "delegated",
        "adoptedAt": contracts._now().isoformat(), "expiresAt": request["expiresAt"],
        "policyFingerprint": request["policyFingerprint"], "execution": copy.deepcopy(request["execution"]),
        "request": copy.deepcopy(request), "parentApprovalHash": "a" * 64,
        "parentCreatedAt": request["preparedAt"], "parentApprovedAt": request["preparedAt"]}
    parent._validate_document(document, request)
    document["execution"]["taskScope"]["templates"]["fixture"]["packet"]["facts"]["number"] = True
    with pytest.raises(StateError, match="projection drift"):
        parent._validate_document(document, request)


def test_historical_parent_reader_does_not_require_current_parent_or_engine(env, monkeypatch):
    options = parent_fixture(env)
    request = parent.prepare_request(env["state"], packet(), **options)
    save_formalization(request, formalization(request))
    document = parent.adopt_request(env["state"], request["id"], expected_request_sha256=request["requestSha256"])
    (env["state"] / "parent-verifier" / "trust.json").unlink()
    Path(options["parent_reference"]["project"]["path"]).rename(env["root"] / "preserved-parent-project")
    monkeypatch.setattr(contracts, "_now", lambda: contracts._timestamp(document["expiresAt"]) + timedelta(hours=1))
    monkeypatch.setattr(contracts, "policy_fingerprint", lambda: pytest.fail("Historical read inspected current policy"))
    monkeypatch.setattr(contracts, "current_engine_pins", lambda *_: pytest.fail("Historical read inspected engine source"))
    monkeypatch.setattr(parent, "_process", lambda *_: pytest.fail("Historical read launched parent verifier"))
    with StateStore(env["state"]) as store, store.locked():
        assert parent.historical_delegated_contract(store, document) == document
        with pytest.raises(StateError):
            parent.current_delegated_contract(store, document)


def test_policy_reads_reject_symlinks_and_hardlinks(env):
    path = env["root"] / "source.py"
    path.write_text("value = 1\n")
    assert contracts._policy_bytes(path) == b"value = 1\n"
    link = env["root"] / "link.py"
    link.symlink_to(path)
    with pytest.raises(StateError):
        contracts._policy_bytes(link)
    link.unlink()
    os.link(path, link)
    with pytest.raises(StateError):
        contracts._policy_bytes(path)


def test_prepared_snapshot_confirmation_must_be_boolean(env):
    import ledger
    snapshot = {"preparedIdDigest": "a" * 64, "inputSha256": "b" * 64, "schemaSha256": "c" * 64,
        "expiresAt": (contracts._now() + timedelta(hours=1)).isoformat(), "facts": {"confirmationVerified": True}}
    ledger.validate_snapshot(snapshot, "b" * 64, "c" * 64, fresh=True)
    snapshot["facts"]["confirmationVerified"] = 1
    with pytest.raises(StateError, match="binding mismatch"):
        ledger.validate_snapshot(snapshot, "b" * 64, "c" * 64, fresh=True)


def test_scope_git_history_still_rejects_reverted_outside_changes(env):
    repository = env["root"] / "repository"
    repository.mkdir()

    def git(*args):
        return subprocess.run(["git", "-c", "core.hooksPath=/dev/null", "-c", "user.name=Offline fixture",
            "-c", "user.email=fixture@example.com", *args], cwd=repository,
            capture_output=True, text=True, check=True).stdout.strip()

    def commit(path, content):
        (repository / path).write_text(content)
        git("add", path)
        git("commit", "-qm", "owned fixture change")
        return git("rev-parse", "HEAD")

    git("init", "-q", "-b", "work")
    for name in ("app.py", "verify.py", "outside.txt"):
        (repository / name).write_text("fixture = 1\n")
    git("add", ".")
    git("commit", "-qm", "owned fixture baseline")
    anchor = git("rev-parse", "HEAD")
    from workflow import validate_task_packet
    value = validate_task_packet({"kind": "repo-edit", "id": "fixture-packet", "authorityId": "fixture-root",
        "repository": str(repository), "base_revision": anchor, "objective": "Change fixture source",
        "allowed_paths": ["app.py"], "checks": [[sys.executable, "verify.py"]],
        "task_category": "product-development", "generation_profile": scope.PROFILE_ID})
    document = draft_scope(value)
    template = document["execution"]["taskScope"]["templates"]["fixture"]
    template["basePolicy"] = {"mode": "descendant-within-scope", "ref": "refs/heads/work", "anchor": anchor}
    scope.validate_scope(document)
    revision = commit("app.py", "fixture = 2\n")
    child = {**value, "id": "child-one", "base_revision": revision}
    assert scope._child(document, "fixture", child, admission=True)["baseRevision"] == revision
    scope.save_scope_draft(env["state"], document)
    sha = contracts.payload_sha256(document)
    document = scope.approve_scope(env["state"], document["id"], expected_payload_sha256=sha,
        approved_by="operator", confirmation="APPROVE " + document["id"] + " " + sha)
    admitted = scope.admit_child(env["state"], document["id"], "fixture", child)
    commit("outside.txt", "fixture = 2\n")
    reverted = commit("outside.txt", "fixture = 1\n")
    assert git("diff", "--name-only", anchor, reverted) == "app.py"
    with pytest.raises(StateError, match="outside its approved template"):
        scope._child(document, "fixture", {**child, "base_revision": reverted}, admission=True)
    repository.rename(env["root"] / "preserved-repository")
    scope.validate_scope(document, check_freshness=False, historical=True)
    with StateStore(env["state"]) as store, store.locked():
        assert scope.scope_children(store, document, historical=True)[child["id"]] == admitted
        with pytest.raises(StateError):
            scope.scope_children(store, document)
