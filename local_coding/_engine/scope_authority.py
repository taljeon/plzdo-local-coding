"""Opt-in scope grants and immutable AI-admitted children of one root ledger.

The catalog is authority data, not a collection of synthetic operator approvals.
All catalog readers run under the caller's StateStore lock. No function here
applies edits, updates Git refs, executes checks, or contacts a provider.
"""
import copy
import os
from pathlib import Path, PurePosixPath
import posixpath
import re
import selectors
import shutil
import subprocess
import time
import unicodedata

import contracts
from state_io import StateError, StateStore, canonical_bytes, require, strict_json


SCHEMA_VERSION = contracts.POLICY.schema_version("scope")
PARENT_VERSION = contracts.POLICY.schema_version("parent-scope")
SCOPE_VERSION = "plzdo.task-scope.v2"
CATALOG_VERSION = "plzdo.scoped-children.v2"
PROFILE_ID = "huihui-qwen38-q6kl-v1"
MAX_PACKET_BYTES = 128 * 1024
_SHA = re.compile(r"(?:[a-f0-9]{40}|[a-f0-9]{64})\Z")
_MUTABLE = frozenset(("id", "objective", "design", "allowed_paths", "base_revision"))


def _same(left, right):
    return canonical_bytes(left) == canonical_bytes(right)


def _active():
    from provider_common import require_active_session
    require_active_session()


def _git(repository, *arguments, allow_not_ancestor=False):
    """Bounded read-only builtins with no inherited Git overrides/replacements."""
    executable = shutil.which("git", path=os.defpath)
    require(executable is not None, "Git is unavailable for scope verification")
    environment = {"PATH": os.defpath, "LANG": "C", "LC_ALL": "C",
                   "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": "/dev/null",
                   "GIT_TERMINAL_PROMPT": "0", "GIT_NO_REPLACE_OBJECTS": "1",
                   "GIT_GRAFT_FILE": "/dev/null",
                   "GIT_OPTIONAL_LOCKS": "0", "GIT_NO_LAZY_FETCH": "1",
                   "GIT_ALLOW_PROTOCOL": ""}
    command = [executable, "--no-pager", "--no-replace-objects", "-c", "core.hooksPath=/dev/null",
               "-c", "core.fsmonitor=false", "-c", "core.pager=cat",
               "-c", "protocol.allow=never", "-c", "log.showSignature=false",
               "-c", "gpg.program=/usr/bin/false", "-c", "gpg.ssh.program=/usr/bin/false",
               "-c", "gpg.x509.program=/usr/bin/false", *arguments]
    process = None
    try:
        process = subprocess.Popen(command, cwd=repository, env=environment,
                                   stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                   stderr=subprocess.PIPE)
        output, errors = bytearray(), bytearray()
        deadline = time.monotonic() + 15
        with selectors.DefaultSelector() as selector:
            selector.register(process.stdout, selectors.EVENT_READ, output)
            selector.register(process.stderr, selectors.EVENT_READ, errors)
            while selector.get_map():
                require(time.monotonic() < deadline, "Scope Git verification timed out")
                for key, _ in selector.select(min(0.1, max(0, deadline - time.monotonic()))):
                    block = os.read(key.fileobj.fileno(), 65536)
                    if not block:
                        selector.unregister(key.fileobj)
                    else:
                        key.data.extend(block)
                        require(len(output) + len(errors) <= 1024 * 1024,
                                "Scope Git verification exceeds output budget")
        code = process.wait(timeout=max(0.01, deadline - time.monotonic()))
        require(code == 0 or (allow_not_ancestor and code == 1), "Scope Git verification failed")
        return code, bytes(output)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise StateError("Scope Git verification unavailable") from exc
    finally:
        if process is not None:
            if process.poll() is None:
                process.kill()
            process.wait()
            process.stdout.close()
            process.stderr.close()


def _repo(packet):
    path = packet.get("repository")
    require(isinstance(path, str) and Path(path).is_absolute(), "Invalid scoped repository")
    repository = Path(path)
    require(repository.is_dir() and repository.resolve() == repository,
            "Scoped repository must remain canonical")
    require(_git(repository, "rev-parse", "--show-toplevel")[1].decode().rstrip("\n") == path,
            "Scoped repository must remain its Git root")
    return repository


def _commit(repository, value):
    require(isinstance(value, str) and _SHA.fullmatch(value), "Exact scoped commit required")
    require(_git(repository, "rev-parse", "--verify", value + "^{commit}")[1].decode().strip() == value,
            "Scoped commit is unavailable")


def _check_guards(packet, *, allowed_paths=None):
    """Conservatively protect explicit check inputs and standard test/config files.

    Arbitrary check-program dependency analysis is intentionally not claimed.
    The root operator must review custom check commands and their dependencies.
    """
    if packet.get("kind", "repo-edit") != "repo-edit":
        return
    repository = PurePosixPath(packet["repository"])
    guards = set(packet.get("context_files", []))
    for argv in packet["checks"] + packet.get("regression_checks", []):
        for argument in argv:
            token = argument.partition("=")[2] if argument.startswith("-") and "=" in argument else argument
            token = posixpath.normpath(token.split("::", 1)[0])
            path = PurePosixPath(token)
            if path.is_absolute():
                try:
                    token = path.relative_to(repository).as_posix()
                except ValueError:
                    continue
            while token.startswith("./"):
                token = token[2:]
            if token and not token.startswith("-"):
                guards.add(token.rstrip("/"))
        if "-m" in argv:
            index = argv.index("-m") + 1
            if index < len(argv) and re.fullmatch(r"[A-Za-z_]\w*(?:\.[A-Za-z_]\w*)*", argv[index]):
                module = argv[index].replace(".", "/")
                guards.update((module + ".py", module))
    folded = lambda value: unicodedata.normalize("NFC", value).casefold()
    guards = {folded(guard) for guard in guards}
    for path in packet["allowed_paths"] if allowed_paths is None else allowed_paths:
        pieces = PurePosixPath(path).parts
        name = pieces[-1].lower()
        conventional = (any(part.lower() in {"test", "tests", "__tests__"} for part in pieces[:-1])
                        or name.startswith("test_") or name.endswith("_test.py")
                        or re.search(r"\.(?:test|spec)\.[a-z0-9]+$", name)
                        or name in {"conftest.py", "pytest.ini", "tox.ini", "pyproject.toml", "setup.cfg"})
        key = folded(path)
        require(not conventional and not any(guard in {"", "."} or key == guard
                or key.startswith(guard + "/") for guard in guards),
                "Scoped paths cannot edit context or immutable check files")


def _normalize_packet(packet):
    require(isinstance(packet, dict) and len(canonical_bytes(packet)) <= MAX_PACKET_BYTES,
            "Scoped packet exceeds byte budget or is invalid")
    from workflow import validate_task_packet
    try:
        result = validate_task_packet(copy.deepcopy(packet))
    except (ValueError, RuntimeError, OSError) as exc:
        raise StateError("Invalid scoped task packet: " + str(exc)) from exc
    require(result.get("kind", "repo-edit") in ("repo-edit", "artifact-create"),
            "Scope supports product repo-edit or artifact-create only")
    require(result.get("task_category") == "product-development",
            "Scope requires explicit product-development category")
    require(isinstance(result.get("generation_profile"), dict)
            and result["generation_profile"].get("id") == PROFILE_ID,
            "New scopes require the explicit Huihui generation profile")
    require(len(canonical_bytes(result)) <= MAX_PACKET_BYTES, "Normalized scoped packet exceeds byte budget")
    _check_guards(result)
    return result


def normalize_scope(scope, root_id, *, bind_root=False):
    """Normalize draft templates; parent preparation may explicitly bind its ID."""
    contracts._identifier(root_id)
    require(isinstance(scope, dict) and set(scope) == {"schemaVersion", "templates"}
            and scope["schemaVersion"] == SCOPE_VERSION, "Invalid task scope fields")
    canonical_bytes(scope)
    templates = scope["templates"]
    require(isinstance(templates, dict) and 1 <= len(templates) <= 16, "Invalid scope template count")
    result = copy.deepcopy(scope)
    for template_id, template in result["templates"].items():
        contracts._identifier(template_id)
        require(isinstance(template, dict) and set(template) == {"packet", "basePolicy"},
                "Invalid scope template fields")
        require(isinstance(template["packet"], dict), "Invalid scope template packet")
        if bind_root:
            template["packet"]["authorityId"] = root_id
        template["packet"] = _normalize_packet(template["packet"])
        require(template["packet"].get("authorityId") == root_id, "Scope template root id mismatch")
    # A second template cannot make another template's check/context editable.
    packets = [template["packet"] for template in result["templates"].values()]
    for packet in packets:
        if packet.get("kind", "repo-edit") == "repo-edit":
            editable = set().union(*(set(other["allowed_paths"]) for other in packets
                if other.get("repository") == packet["repository"]))
            _check_guards(packet, allowed_paths=editable)
    return result


def _base_policy(template, packet, *, admission=False):
    policy, approved = template["basePolicy"], template["packet"]
    require(isinstance(policy, dict), "Invalid scoped base policy")
    mode = policy.get("mode")
    if mode == "exact":
        require(set(policy) == {"mode"}, "Invalid exact base policy")
    else:
        require(mode == "descendant-within-scope" and set(policy) == {"mode", "ref", "anchor"},
                "Invalid descendant base policy")
        require(approved.get("kind", "repo-edit") == "repo-edit", "Artifact scopes require exact base policy")
    if approved.get("kind", "repo-edit") == "artifact-create":
        return
    require(packet["repository"] == approved["repository"], "Scoped repository changed")
    repository = _repo(packet)
    _commit(repository, packet["base_revision"])
    if mode == "exact":
        require(packet["base_revision"] == approved["base_revision"], "Exact scoped base revision changed")
        return
    reference = policy["ref"]
    require(_git(repository, "rev-parse", "--is-shallow-repository")[1].strip() == b"false",
            "Descendant scopes require complete, non-shallow repository history")
    require(isinstance(reference, str) and reference.startswith("refs/heads/")
            and len(reference) <= 240, "Scoped ref must be a full local branch ref")
    _git(repository, "check-ref-format", reference)
    anchor = policy["anchor"]
    _commit(repository, anchor)
    require(approved["base_revision"] == anchor, "Scope template base must equal its descendant anchor")
    require(_git(repository, "merge-base", "--is-ancestor", anchor, packet["base_revision"],
                 allow_not_ancestor=True)[0] == 0, "Scoped base is not descended from its anchor")
    changed = _git(repository, "diff", "--no-ext-diff", "--no-textconv", "--no-renames", "--ignore-submodules=none",
                   "--name-only", "-z", anchor, packet["base_revision"], "--")[1]
    # Check every intervening commit, including both sides of merge commits.
    # Endpoint-only diff would allow an out-of-scope edit followed by a revert.
    touched = _git(repository, "log", "--format=", "--no-show-signature", "--no-ext-diff", "--no-textconv",
                   "--no-renames", "--ignore-submodules=none", "-m", "--name-only", "-z",
                   anchor + ".." + packet["base_revision"], "--")[1]
    try:
        paths = set(filter(None, (changed + touched).decode("utf-8", "strict").split("\0")))
    except UnicodeError as exc:
        raise StateError("Scoped revision contains unsupported path encoding") from exc
    require(paths <= set(approved["allowed_paths"]), "Scoped revision changes paths outside its approved template")
    if admission:
        current = _git(repository, "rev-parse", "--verify", reference + "^{commit}")[1].decode().strip()
        require(current == packet["base_revision"], "Scoped admission base does not match the pinned branch ref")


def _historical_scope(value, root_id):
    """Bound stored scope data without consulting a current target or checker."""
    require(isinstance(value, dict) and set(value) == {"schemaVersion", "templates"}
            and value["schemaVersion"] == SCOPE_VERSION, "Invalid historical task scope")
    templates = value["templates"]
    require(isinstance(templates, dict) and 1 <= len(templates) <= 16, "Invalid historical scope templates")
    for identifier, template in templates.items():
        contracts._identifier(identifier)
        require(isinstance(template, dict) and set(template) == {"packet", "basePolicy"},
                "Invalid historical template fields")
        packet, policy = template["packet"], template["basePolicy"]
        require(isinstance(packet, dict) and len(canonical_bytes(packet)) <= MAX_PACKET_BYTES
                and packet.get("authorityId") == root_id
                and packet.get("kind", "repo-edit") in ("repo-edit", "artifact-create"),
                "Invalid historical template packet")
        contracts._identifier(packet.get("id"))
        require(isinstance(policy, dict), "Invalid historical base policy")
        if policy.get("mode") == "exact":
            require(set(policy) == {"mode"}, "Invalid historical exact base policy")
        else:
            require(set(policy) == {"mode", "ref", "anchor"} and policy["mode"] == "descendant-within-scope"
                    and packet.get("kind", "repo-edit") == "repo-edit"
                    and isinstance(policy["ref"], str) and policy["ref"].startswith("refs/heads/")
                    and len(policy["ref"]) <= 240 and isinstance(policy["anchor"], str)
                    and _SHA.fullmatch(policy["anchor"]) and packet.get("base_revision") == policy["anchor"],
                    "Invalid historical descendant base policy")
    return copy.deepcopy(value)


def validate_execution(execution, root_id, check_freshness=True, *, historical=False):
    """Structural validation also rechecks immutable commit/path policy, not ref tips."""
    fields = {"allowedEngines", "enginePins", "maxLiveIntegrationCalls", "maxTotalRuns", "maxChildren",
              "maxRunsPerChild", "taskScope"}
    require(isinstance(execution, dict) and fields <= set(execution)
            <= fields | {"previewAuthorization"}, "Invalid scoped execution fields")
    contracts._engines(execution["allowedEngines"])
    contracts.validate_engine_pins(execution, check_freshness=check_freshness)
    contracts._integer(execution["maxLiveIntegrationCalls"], 0, 10000, "scope engine budget")
    contracts._integer(execution["maxTotalRuns"], 1, 10000, "scope total runs")
    contracts._integer(execution["maxChildren"], 1, 32, "scope maximum children")
    contracts._integer(execution["maxRunsPerChild"], 1, 1000, "scope child runs")
    require(bool(execution["allowedEngines"]) == (execution["maxLiveIntegrationCalls"] > 0),
            "Scope engine capabilities and budget are inconsistent")
    require(not historical or not check_freshness, "Historical scope cannot authorize a new call")
    normalized = (_historical_scope(execution["taskScope"], root_id) if historical
                  else normalize_scope(execution["taskScope"], root_id))
    require(_same(normalized, execution["taskScope"]), "Scope templates must be normalized before approval")
    packets, bindings = [], {}
    for template_id, template in normalized["templates"].items():
        packet = template["packet"]
        if not historical:
            _base_policy(template, packet)
        bindings[template_id] = contracts._packet_binding(
            packet, execution["allowedEngines"], execution["maxRunsPerChild"])
        packets.append(packet)
    if "previewAuthorization" in execution:
        contracts.validate_preview_authorization(execution["previewAuthorization"],
                                                  bindings=bindings, packets=None if historical else packets)
    canonical_bytes(execution)
    return execution


def draft_scope(contract_id, scope, *, expires_at, max_live_integration_calls,
                allowed_engines, max_total_runs, max_children, max_runs_per_child=1,
                preview_authorization=None):
    _active()
    execution = {"allowedEngines": copy.deepcopy(allowed_engines),
                 "enginePins": contracts.current_engine_pins(allowed_engines),
                 "maxLiveIntegrationCalls": max_live_integration_calls,
                 "maxTotalRuns": max_total_runs, "maxChildren": max_children,
                 "maxRunsPerChild": max_runs_per_child,
                 "taskScope": normalize_scope(scope, contract_id)}
    if preview_authorization is not None:
        execution["previewAuthorization"] = copy.deepcopy(preview_authorization)
    document = {"schemaVersion": SCHEMA_VERSION, "id": contract_id,
                "createdAt": contracts._now().isoformat(), "expiresAt": expires_at,
                "policyFingerprint": contracts.policy_fingerprint(), "execution": execution,
                "status": "draft", "approvalHash": None, "approvedBy": None, "approvedAt": None}
    return validate_scope(document)


def validate_scope(document, *, require_approved=False, check_freshness=True, historical=False):
    fields = {"schemaVersion", "id", "createdAt", "expiresAt", "policyFingerprint",
              "execution", "status", "approvalHash", "approvedBy", "approvedAt"}
    require(isinstance(document, dict) and set(document) == fields
            and document["schemaVersion"] == SCHEMA_VERSION, "Invalid scoped contract fields")
    contracts._identifier(document["id"])
    created, expires = contracts._timestamp(document["createdAt"]), contracts._timestamp(document["expiresAt"])
    require(created < expires, "Scope expiry must follow creation")
    require(isinstance(document["policyFingerprint"], str)
            and contracts.SHA256.fullmatch(document["policyFingerprint"]), "Invalid scope policy fingerprint")
    require(not historical or (not require_approved and not check_freshness),
            "Historical scope cannot authorize a new call")
    validate_execution(document["execution"], document["id"], check_freshness, historical=historical)
    require(document["status"] in ("draft", "approved", "revoked", "completed"), "Invalid scope status")
    if document["status"] == "draft":
        require(all(document[key] is None for key in ("approvalHash", "approvedBy", "approvedAt")),
                "Draft scope cannot contain approval")
    else:
        require(document["approvalHash"] == contracts.payload_sha256(document), "Scope approval payload hash mismatch")
        require(document["approvedBy"] in ("operator", "human", "user"), "Invalid scope approval actor")
        approved = contracts._timestamp(document["approvedAt"])
        require(created <= approved < expires, "Scope approval outside lifetime")
        if check_freshness:
            require(approved <= contracts._now(), "Scope approval is in the future")
    if require_approved:
        require(document["status"] == "approved", "Scope is not active/approved")
    if check_freshness:
        require(created <= contracts._now() < expires, "Scope is expired or not yet valid")
        require(document["policyFingerprint"] == contracts.policy_fingerprint(), "Scope policy fingerprint is stale")
    canonical_bytes(document)
    return document


def empty_catalog(document):
    """For exclusive standalone save or parent adoption, never for budget reset."""
    require(document.get("schemaVersion") in (SCHEMA_VERSION, PARENT_VERSION), "Expected scoped root")
    return {"schemaVersion": CATALOG_VERSION, "rootId": document["id"],
            "rootPayloadSha256": contracts.payload_sha256(document), "children": {}}


def save_scope_draft(state_root, document):
    _active()
    from ledger import initial_ledger
    validate_scope(document)
    require(document["status"] == "draft", "Only draft scopes can be created")
    name = document["id"] + ".json"
    with StateStore(state_root, create=True) as store, store.locked():
        for directory in ("contracts", "ledgers", "scoped-children"):
            store.directory(directory, create=True)
            require(store.read_bytes(directory, name, missing_ok=True) is None,
                    "Scoped root already has durable state; never reset its budget")
        store.write_json("scoped-children", name, empty_catalog(document), expected_bytes=None)
        store.write_json("ledgers", name, initial_ledger(document), expected_bytes=None)
        store.write_json("contracts", name, document, expected_bytes=None)
    return copy.deepcopy(document)


def _child(document, template_id, packet, *, admission=False, historical=False):
    contracts._identifier(template_id)
    templates = document["execution"]["taskScope"]["templates"]
    require(template_id in templates, "Unknown scope template")
    require(not historical or not admission, "Historical children cannot be newly admitted")
    if historical:
        require(isinstance(packet, dict) and len(canonical_bytes(packet)) <= MAX_PACKET_BYTES,
                "Invalid historical child packet")
        contracts._paths(packet.get("allowed_paths"))
    normalized = packet if historical else _normalize_packet(packet)
    require(_same(normalized, packet), "Admitted scoped packet normalization drift")
    require(packet.get("authorityId") == document["id"], "Scoped child root id mismatch")
    template = templates[template_id]
    approved = template["packet"]
    fixed = lambda value: {key: item for key, item in value.items() if key not in _MUTABLE}
    require(_same(fixed(packet), fixed(approved)), "Scoped child changes immutable template policy")
    require(set(packet["allowed_paths"]) <= set(approved["allowed_paths"]),
            "Scoped child paths exceed its approved template")
    if not historical:
        _base_policy(template, packet, admission=admission)
    binding = contracts._packet_binding(packet, document["execution"]["allowedEngines"],
                                        document["execution"]["maxRunsPerChild"])
    if "previewAuthorization" in document["execution"]:
        contracts.validate_preview_authorization(document["execution"]["previewAuthorization"],
                                                  bindings={packet["id"]: binding}, packets=None if historical else [packet])
    return binding


def scope_children(store, document, *, historical=False):
    """Locked structural reader. Parent verifier calls this: do not recurse to it."""
    require(isinstance(document, dict) and document.get("schemaVersion") in (SCHEMA_VERSION, PARENT_VERSION),
            "Expected a scoped root")
    if document["schemaVersion"] == SCHEMA_VERSION:
        validate_scope(document, check_freshness=False, historical=historical)
    else:
        validate_execution(document["execution"], document["id"], check_freshness=False, historical=historical)
    catalog = store.read_json("scoped-children", document["id"] + ".json")
    require(isinstance(catalog, dict) and set(catalog) == {
        "schemaVersion", "rootId", "rootPayloadSha256", "children"}
        and catalog["schemaVersion"] == CATALOG_VERSION and catalog["rootId"] == document["id"]
        and catalog["rootPayloadSha256"] == contracts.payload_sha256(document), "Scoped catalog root binding mismatch")
    children = catalog["children"]
    require(isinstance(children, dict) and len(children) <= document["execution"]["maxChildren"],
            "Scoped child count exceeds root allowance")
    require(not children or document["status"] != "draft", "Draft scope cannot contain admitted children")
    for child_id, entry in children.items():
        contracts._identifier(child_id)
        require(isinstance(entry, dict) and set(entry) == {"templateId", "packet", "binding", "admittedAt"},
                "Invalid scoped child fields")
        require(isinstance(entry["packet"], dict) and entry["packet"].get("id") == child_id,
                "Scoped child catalog id mismatch")
        actual = _child(document, entry["templateId"], entry["packet"], historical=historical)
        require(_same(entry["binding"], actual), "Scoped child binding drift")
        admitted = contracts._timestamp(entry["admittedAt"])
        require(admitted < contracts._timestamp(document["expiresAt"])
                and (historical or admitted <= contracts._now()),
                "Scoped admission timestamp outside lifetime")
        lower = document.get("approvedAt") or document.get("adoptedAt") or document.get("createdAt")
        if lower is not None:
            require(contracts._timestamp(lower) <= admitted, "Scoped admission predates root approval")
    canonical_bytes(catalog)
    return copy.deepcopy(children)


def approve_scope(state_root, contract_id, *, expected_payload_sha256, approved_by, confirmation):
    _active()
    from ledger import validate_ledger
    contracts._identifier(contract_id)
    require(approved_by in ("operator", "human", "user"), "Explicit scope operator approval required")
    require(isinstance(expected_payload_sha256, str) and contracts.SHA256.fullmatch(expected_payload_sha256),
            "Expected scope payload hash required")
    require(confirmation == "APPROVE " + contract_id + " " + expected_payload_sha256,
            "Exact reviewed-scope confirmation required")
    with StateStore(state_root) as store, store.locked():
        name = contract_id + ".json"
        previous = store.read_bytes("contracts", name)
        document = validate_scope(strict_json(previous))
        require(document["id"] == contract_id, "Scoped root filename/id mismatch")
        require(contracts.payload_sha256(document) == expected_payload_sha256, "Scope changed since review")
        children = scope_children(store, document)
        validate_ledger(store.read_json("ledgers", name), document,
                        bindings={key: entry["binding"] for key, entry in children.items()})
        if document["status"] == "approved":
            return document
        require(document["status"] == "draft", "Only a fresh scope draft may be approved")
        document.update(status="approved", approvalHash=expected_payload_sha256,
                        approvedBy=approved_by, approvedAt=contracts._now().isoformat())
        validate_scope(document, require_approved=True)
        store.write_json("contracts", name, document, expected_bytes=previous)
        return document


def current_scope(store, document, binding=None, packet=None, *, observations=None):
    """Revalidate root, catalog and exact child before each reservation; lock held."""
    _active()
    require(isinstance(document, dict), "Expected a scoped root")
    if document.get("schemaVersion") == PARENT_VERSION:
        from parent_authority import current_delegated_contract
        current = current_delegated_contract(store, document, observations=observations)
    else:
        validate_scope(document, require_approved=True)
        current = validate_scope(store.read_json("contracts", document["id"] + ".json"), require_approved=True)
        require(_same(current, document), "Scoped root changed since authority load")
    children = scope_children(store, current)
    bindings = {key: entry["binding"] for key, entry in children.items()}
    if packet is not None:
        require(isinstance(packet, dict) and packet.get("id") in children, "Scoped child has not been admitted")
        entry = children[packet["id"]]
        require(_same(entry["packet"], packet), "Admitted scoped packet drift")
        require(binding is None or _same(entry["binding"], binding), "Supplied scoped binding drift")
    else:
        require(binding is None, "Scoped binding requires its exact packet")
    return current, bindings


def admit_child(state_root, contract_id, template_id, packet):
    """One locked admission, no fresh approval and no independent child budget."""
    _active()
    from ledger import validate_ledger
    contracts._identifier(contract_id)
    normalized = _normalize_packet(packet)
    with StateStore(state_root) as store, store.locked():
        name = contract_id + ".json"
        document = store.read_json("contracts", name)
        require(isinstance(document, dict) and document.get("id") == contract_id,
                "Scoped root filename/id mismatch")
        document, bindings = current_scope(store, document)
        previous = store.read_bytes("scoped-children", name)
        catalog = strict_json(previous)
        children = catalog["children"]
        validate_ledger(store.read_json("ledgers", name), document, bindings=bindings)
        existing = children.get(normalized["id"])
        if existing is not None:
            require(existing["templateId"] == template_id and _same(existing["packet"], normalized),
                    "Scoped child id already has a different immutable binding")
            return copy.deepcopy(existing)
        require(len(children) < document["execution"]["maxChildren"], "Scoped child allowance exhausted")
        binding = _child(document, template_id, normalized, admission=True)
        admitted = contracts._now()
        require(admitted < contracts._timestamp(document["expiresAt"]), "Scope expired during child admission")
        entry = {"templateId": template_id, "packet": normalized, "binding": binding,
                 "admittedAt": admitted.isoformat()}
        children[normalized["id"]] = entry
        canonical_bytes(catalog)
        store.write_json("scoped-children", name, catalog, expected_bytes=previous)
        return copy.deepcopy(entry)
