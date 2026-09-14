"""Explicit standalone approvals with the historical normalized packet hash.

Preparation only returns/saves a draft. Approval is a distinct operator action
requiring the exact reviewed payload hash and confirmation. These local records
are auditable operator assertions, not cryptographic identity attestations.
"""
import copy
from datetime import datetime, timezone
import hashlib
import os
from pathlib import Path, PurePosixPath
import re
import stat

from composition import current_policy, current_engine_pins, policy_data

from state_io import (StateError, StateStore, canonical_bytes, digest, require,
                      strict_json)


ContractError = StateError
POLICY = current_policy()
SCHEMA_VERSION = POLICY.schema_version("exact")
SCOPE_VERSION = POLICY.schema_version("scope")
PARENT_VERSIONS = (POLICY.schema_version("parent-exact"), POLICY.schema_version("parent-scope"))
IDENTIFIER = re.compile(r"[A-Za-z0-9][A-Za-z0-9_-]{0,119}\Z")
SHA256 = re.compile(r"[a-f0-9]{64}\Z")


def packet_hash(packet):
    """Do not normalize profiles or inject fields here; callers already did so."""
    return digest(packet)


def _identifier(value):
    require(isinstance(value, str) and IDENTIFIER.fullmatch(value), "Invalid contract/packet id")
    return value


def _timestamp(value):
    require(isinstance(value, str) and re.fullmatch(
        r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?(?:Z|\+00:00)", value),
        "Timestamp must be explicit UTC ISO-8601")
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ContractError("Invalid timestamp") from exc


def _now():
    return datetime.now(timezone.utc)


def _integer(value, minimum, maximum, label):
    require(type(value) is int and minimum <= value <= maximum, "Invalid " + label)


def _policy_bytes(path):
    """Read a bounded fixed source/schema through a stable no-follow descriptor."""
    try:
        require(path.resolve(strict=True) == path, "Authority policy path changed")
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        with os.fdopen(fd, "rb") as source:
            before = os.fstat(source.fileno())
            require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1
                    and before.st_uid in (0, os.getuid()) and not before.st_mode & 0o022
                    and before.st_size <= 1024 * 1024, "Unsafe authority policy input")
            data = source.read(1024 * 1024 + 1)
            after, current = os.fstat(source.fileno()), path.lstat()
            identity = lambda value: (value.st_dev, value.st_ino, value.st_size, value.st_mtime_ns, value.st_ctime_ns)
            require(len(data) == before.st_size and identity(before) == identity(after) == identity(current),
                    "Authority policy input changed during inspection")
        return data
    except OSError as exc:
        raise ContractError("Authority policy input unavailable") from exc


def policy_fingerprint():
    """Bind authority, permission/check sources and verified runtime manifest bytes."""
    require(POLICY == current_policy(), "Authority modules must follow the fixed process composition")
    from host_paths import permission_policy_fingerprint, runtime_policy_fingerprint
    try:
        runtime = runtime_policy_fingerprint()
        permissions = permission_policy_fingerprint()
    except (ValueError, OSError) as exc:
        raise ContractError("Runtime or permission policy verification failed") from exc
    require(runtime is None or (isinstance(runtime, str) and SHA256.fullmatch(runtime)),
            "Invalid verified runtime policy fingerprint")
    require(isinstance(permissions, str) and SHA256.fullmatch(permissions),
            "Invalid permission policy fingerprint")
    closure = {}
    for name in ("contracts.py", "state_io.py", "ledger.py", "parent_authority.py", "scope_authority.py",
                 "composition.py", "engine_types.py"):
        path = Path(__file__).absolute().parent / name
        closure[name] = hashlib.sha256(_policy_bytes(path)).hexdigest()
    schema_root = Path(__file__).absolute().parent.parent / "schemas"
    for index, path in enumerate(schema_root.glob("*.json")):
        require(index < 32, "Authority schema closure exceeds file limit")
        closure["schemas/" + path.name] = hashlib.sha256(_policy_bytes(path)).hexdigest()
    require("schemas/parent-delegation.schema.json" in closure, "Parent authority schema is missing")
    return digest({"composition": policy_data(), "source": closure,
                   "runtimePolicySha256": runtime, "permissionPolicySha256": permissions})


def canonical_approval_payload(document):
    return {key: copy.deepcopy(document[key]) for key in (
        "schemaVersion", "id", "createdAt", "expiresAt", "policyFingerprint", "execution")}


def payload_sha256(document):
    require(isinstance(document, dict), "Invalid authority document")
    if document.get("schemaVersion") in PARENT_VERSIONS:
        return digest(document)
    require(document.get("schemaVersion") in (SCHEMA_VERSION, SCOPE_VERSION),
            "Unsupported concrete authority version")
    return digest(canonical_approval_payload(document))


def authority_identity(document):
    """One pinned identity for standalone, delegated, and advisory child bindings."""
    if document.get("schemaVersion") in PARENT_VERSIONS:
        return payload_sha256(document)
    value = document.get("approvalHash")
    require(isinstance(value, str) and SHA256.fullmatch(value), "Missing parent authority identity")
    return value


def _engines(value):
    require(POLICY == current_policy(), "Authority modules must follow the fixed process composition")
    require(isinstance(value, list) and all(isinstance(item, str) and item in POLICY.engine_roles for item in value)
            and len(set(value)) == len(value), "Invalid allowedEngines capability")


def validate_engine_pins(execution, *, check_freshness=True):
    selected = execution["allowedEngines"]
    _engines(selected)
    pins = execution.get("enginePins")
    require(isinstance(pins, dict) and set(pins) == set(selected), "Engine pins must match allowedEngines")
    for engine_id, pin in pins.items():
        require(isinstance(pin, dict) and set(pin) == {"implementationSha256", "roles"},
                "Invalid engine identity fields")
        require(isinstance(pin["implementationSha256"], str) and SHA256.fullmatch(pin["implementationSha256"]),
                "Invalid engine implementation digest")
        roles = pin["roles"]
        require(isinstance(roles, list) and all(isinstance(role, str) for role in roles)
                and len(roles) == len(set(roles)) and set(roles) == set(POLICY.engine_roles[engine_id]),
                "Engine roles differ from the fixed composition")
    if check_freshness:
        require(pins == current_engine_pins(selected), "Engine implementation identity changed")
    return pins


def _paths(value):
    require(isinstance(value, list) and 0 < len(value) <= 64, "Invalid bound output paths")
    for path in value:
        require(isinstance(path, str) and path and "\\" not in path
                and not PurePosixPath(path).is_absolute() and ".." not in PurePosixPath(path).parts
                and str(PurePosixPath(path)) == path and path != ".", "Invalid bound output path")
    require(len(set(value)) == len(value), "Duplicate bound output path")


def _binding_shape(binding, capabilities):
    require(isinstance(binding, dict), "Invalid task binding")
    kind = binding.get("kind")
    required = {"packetSha256", "kind", "maxRuns", "allowedEngines", "allowedOperations", "generationAttemptPlan"}
    if kind == "repo-edit":
        required |= {"repository", "baseRevision"}
    elif kind == "artifact-create":
        required |= {"baseline", "allowedPaths"}
    else:
        require(kind == "compute-analysis", "Invalid bound packet kind")
    require(set(binding) == required, "Unknown or missing task binding fields")
    require(isinstance(binding["packetSha256"], str) and SHA256.fullmatch(binding["packetSha256"]),
            "Invalid bound packet hash")
    _integer(binding["maxRuns"], 1, 1000, "packet maxRuns")
    _engines(binding["allowedEngines"])
    require(set(binding["allowedEngines"]) <= set(capabilities), "Binding exceeds engine capabilities")
    require(binding["allowedOperations"] == POLICY.operations(binding["allowedEngines"]),
            "Binding operations differ from the fixed composition")
    plan = binding["generationAttemptPlan"]
    require(isinstance(plan, list) and len(plan) <= sum(POLICY.generation_limits.values()),
            "Invalid generation attempt plan")
    observed = []
    counts = {}
    for ordinal, slot in enumerate(plan, 1):
        require(isinstance(slot, dict) and set(slot) == {"engineId", "role", "ordinal"},
                "Invalid generation slot fields")
        engine_id = slot["engineId"]
        require(engine_id in binding["allowedEngines"] and engine_id in POLICY.generation_limits
                and slot["role"] == "generate"
                and "generate" in POLICY.engine_roles[engine_id], "Generation slot exceeds engine capability")
        counts[engine_id] = counts.get(engine_id, 0) + 1
        require(type(slot["ordinal"]) is int and slot["ordinal"] == ordinal
                and counts[engine_id] <= POLICY.generation_limits[engine_id], "Invalid generation slot ordinal")
        observed.append(engine_id)
    require(any(observed == [engine_id for engine_id in order for _ in range(counts.get(engine_id, 0))]
                for order in (POLICY.generation_order, POLICY.high_risk_engines)),
            "Generation attempt order differs from the fixed composition")
    if kind == "compute-analysis":
        require(not binding["allowedEngines"] and not plan, "Compute handoff cannot authorize engine calls")
    elif kind == "repo-edit":
        path = binding["repository"]
        require(isinstance(path, str) and Path(path).is_absolute() and ".." not in Path(path).parts,
                "Invalid bound repository")
        require(isinstance(binding["baseRevision"], str)
                and re.fullmatch(r"(?:[a-f0-9]{40}|[a-f0-9]{64})", binding["baseRevision"]),
                "Invalid bound base revision")
    else:
        require(binding["baseline"] == "empty", "Artifact baseline must be empty")
        _paths(binding["allowedPaths"])


def validate_preview_authorization(value, *, bindings=None, packets=None):
    """Validate the one optional generated-artifact preview capability."""
    require(isinstance(value, dict) and set(value) == {
        "approved", "bind", "source", "requireStopBeforeFinalize", "maxLifetimeSeconds", "maxSessionsPerRun"},
        "Invalid preview authorization fields")
    require(value["approved"] is True and value["bind"] == "127.0.0.1"
            and value["source"] == "exact-generated-artifact-allowlist-only"
            and value["requireStopBeforeFinalize"] is True, "Unsupported preview authorization")
    _integer(value["maxLifetimeSeconds"], 1, 300, "preview lifetime")
    _integer(value["maxSessionsPerRun"], 1, 3, "preview session limit")
    if bindings is not None:
        require(isinstance(bindings, dict) and bindings and all(
            isinstance(binding, dict) and binding.get("kind") == "artifact-create"
            and binding.get("baseline") == "empty" for binding in bindings.values()),
            "Preview authorization requires artifact-create bindings only")
    if packets is not None:
        require(isinstance(packets, list) and packets, "Preview authorization needs managed artifact packets")
        from workflow_validation import validate_packs
        for packet in packets:
            require(isinstance(packet, dict) and packet.get("kind") == "artifact-create",
                    "Preview authorization requires artifact-create packets only")
            packs = validate_packs(packet.get("validation_packs", []), packet.get("allowed_paths"))
            browser_packs = [pack for pack in packs if pack["type"] == "html-browser"]
            require(browser_packs and all(pack.get("driver") == "managed" for pack in browser_packs),
                    "Preview authorization requires explicit managed-browser validation")
    canonical_bytes(value)
    return value


def validate_execution(execution, *, one_packet=False, check_freshness=True):
    fields = {"maxLiveIntegrationCalls", "allowedEngines", "enginePins", "taskBindings"}
    require(isinstance(execution, dict) and fields <= set(execution)
            <= fields | {"previewAuthorization"}, "Invalid execution capability fields")
    _integer(execution["maxLiveIntegrationCalls"], 0, 10000, "engine call budget")
    _engines(execution["allowedEngines"])
    require(bool(execution["allowedEngines"]) == (execution["maxLiveIntegrationCalls"] > 0),
            "Engine capabilities and call budget are inconsistent")
    validate_engine_pins(execution, check_freshness=check_freshness)
    bindings = execution["taskBindings"]
    require(isinstance(bindings, dict) and 0 < len(bindings) <= (1 if one_packet else 1000),
            "Invalid taskBindings")
    for packet_id, binding in bindings.items():
        _identifier(packet_id)
        _binding_shape(binding, execution["allowedEngines"])
    require(set(execution["allowedEngines"]) == set().union(
        *(set(item["allowedEngines"]) for item in bindings.values())),
        "Contract contains unbound engine capabilities")
    if "previewAuthorization" in execution:
        validate_preview_authorization(execution["previewAuthorization"], bindings=bindings)
    canonical_bytes(execution)
    return execution


def validate_contract(document, *, require_approved=False, check_freshness=True):
    fields = {"schemaVersion", "id", "createdAt", "expiresAt", "policyFingerprint",
              "execution", "status", "approvalHash", "approvedBy", "approvedAt"}
    require(isinstance(document, dict) and set(document) == fields, "Invalid standalone contract fields")
    require(document["schemaVersion"] == SCHEMA_VERSION, "Unsupported standalone contract version")
    _identifier(document["id"])
    created = _timestamp(document["createdAt"])
    expires = _timestamp(document["expiresAt"])
    require(created < expires, "Contract expiry must follow creation")
    require(isinstance(document["policyFingerprint"], str)
            and SHA256.fullmatch(document["policyFingerprint"]), "Invalid policy fingerprint")
    validate_execution(document["execution"], check_freshness=check_freshness)
    status = document["status"]
    require(status in ("draft", "approved", "revoked", "completed"), "Invalid contract status")
    if status == "draft":
        require(all(document[key] is None for key in ("approvalHash", "approvedBy", "approvedAt")),
                "Draft cannot contain approval")
    else:
        require(document["approvalHash"] == payload_sha256(document), "Approval payload hash mismatch")
        require(document["approvedBy"] in ("operator", "human", "user"), "Invalid approval actor")
        approved = _timestamp(document["approvedAt"])
        require(created <= approved < expires, "Approval timestamp is outside contract lifetime")
        if check_freshness:
            require(approved <= _now(), "Approval timestamp is in the future")
    if require_approved:
        require(status == "approved", "Contract is not active/approved")
    if check_freshness:
        require(created <= _now() < expires, "Contract is expired or not yet valid")
        require(document["policyFingerprint"] == policy_fingerprint(), "Contract policy fingerprint is stale")
    canonical_bytes(document)
    return document


def _packet_binding(packet, engine_ids, runs):
    require(isinstance(packet, dict), "Packet must be normalized before binding")
    _identifier(packet.get("id"))
    kind = packet.get("kind", "repo-edit")
    selected = [] if kind == "compute-analysis" else list(engine_ids)
    _engines(selected)
    result = {"packetSha256": packet_hash(packet), "kind": kind, "maxRuns": runs,
              "allowedEngines": selected, "allowedOperations": POLICY.operations(selected),
              "generationAttemptPlan": POLICY.generation_plan(packet, selected)}
    if kind == "repo-edit":
        result.update(repository=packet.get("repository"), baseRevision=packet.get("base_revision"))
    elif kind == "artifact-create":
        result.update(baseline="empty", allowedPaths=copy.deepcopy(packet.get("allowed_paths")))
    _binding_shape(result, engine_ids)
    return result


def draft_contract(contract_id, packets, *, expires_at, max_live_integration_calls,
                   allowed_engines, max_runs=1, preview_authorization=None):
    """Build a reviewable draft. packets must already be engine-normalized."""
    _identifier(contract_id)
    require(isinstance(packets, list) and packets, "Draft needs normalized packets")
    _engines(allowed_engines)
    _integer(max_runs, 1, 1000, "packet maxRuns")
    bindings = {}
    for packet in packets:
        require(packet.get("authorityId") == contract_id, "Packet contract id mismatch")
        require(packet.get("id") not in bindings, "Duplicate packet binding")
        bindings[packet["id"]] = _packet_binding(packet, allowed_engines, max_runs)
    document = {
        "schemaVersion": SCHEMA_VERSION, "id": contract_id, "createdAt": _now().isoformat(),
        "expiresAt": expires_at, "policyFingerprint": policy_fingerprint(),
        "execution": {"maxLiveIntegrationCalls": max_live_integration_calls,
                      "allowedEngines": list(allowed_engines),
                      "enginePins": current_engine_pins(allowed_engines), "taskBindings": bindings},
        "status": "draft", "approvalHash": None, "approvedBy": None, "approvedAt": None,
    }
    if preview_authorization is not None:
        validate_preview_authorization(preview_authorization, bindings=bindings, packets=packets)
        document["execution"]["previewAuthorization"] = copy.deepcopy(preview_authorization)
    return validate_contract(document)


def save_draft(state_root, document):
    """Exclusive contract+ledger initialization. Partial initialization fails closed."""
    from ledger import initial_ledger
    validate_contract(document)
    require(document["status"] == "draft", "Only an unapproved draft can be created")
    name = document["id"] + ".json"
    with StateStore(state_root, create=True) as store, store.locked():
        store.directory("contracts", create=True)
        store.directory("ledgers", create=True)
        require(store.read_bytes("contracts", name, missing_ok=True) is None
                and store.read_bytes("ledgers", name, missing_ok=True) is None,
                "Contract id already has durable state; never reset its budget")
        store.write_json("ledgers", name, initial_ledger(document), expected_bytes=None)
        store.write_json("contracts", name, document, expected_bytes=None)
    return copy.deepcopy(document)


def load_contract(state_root, contract_id):
    _identifier(contract_id)
    with StateStore(state_root) as store, store.locked():
        document = store.read_json("contracts", contract_id + ".json")
        if isinstance(document, dict) and document.get("schemaVersion") in PARENT_VERSIONS:
            from parent_authority import current_delegated_contract
            document = current_delegated_contract(store, document)
        elif isinstance(document, dict) and document.get("schemaVersion") == SCOPE_VERSION:
            from scope_authority import validate_scope
            document = validate_scope(document)
        else:
            document = validate_contract(document)
        require(document["id"] == contract_id, "Contract filename/id mismatch")
        return document


def approve_contract(state_root, contract_id, *, expected_payload_sha256, approved_by,
                     confirmation):
    from ledger import validate_ledger
    _identifier(contract_id)
    require(approved_by in ("operator", "human", "user"), "Explicit operator approval required")
    require(isinstance(expected_payload_sha256, str) and SHA256.fullmatch(expected_payload_sha256),
            "Expected approval payload hash is required")
    require(confirmation == "APPROVE " + contract_id + " " + expected_payload_sha256,
            "Exact reviewed-contract confirmation is required")
    with StateStore(state_root) as store, store.locked():
        name = contract_id + ".json"
        previous = store.read_bytes("contracts", name)
        document = validate_contract(strict_json(previous))
        require(document["id"] == contract_id, "Contract filename/id mismatch")
        require(document["status"] == "draft", "Only a fresh draft may be approved")
        require(payload_sha256(document) == expected_payload_sha256, "Contract changed since review")
        validate_ledger(store.read_json("ledgers", name), document)
        document.update(status="approved", approvalHash=expected_payload_sha256,
                        approvedBy=approved_by, approvedAt=_now().isoformat())
        validate_contract(document, require_approved=True)
        store.write_json("contracts", name, document, expected_bytes=previous)
        return document


def binding_for_packet(document, packet):
    require(isinstance(packet, dict) and packet.get("authorityId") == document["id"],
            "Packet contract id mismatch")
    _identifier(packet.get("id"))
    binding = document["execution"].get("taskBindings", {}).get(packet["id"])
    require(isinstance(binding, dict) and binding.get("packetSha256") == packet_hash(packet),
            "Packet drift: contract binding mismatch")
    kind = packet.get("kind", "repo-edit")
    if kind == "repo-edit":
        require(binding.get("repository") == packet.get("repository")
                and binding.get("baseRevision") == packet.get("base_revision"),
                "Packet drift: source binding mismatch")
    else:
        require(binding.get("kind") == kind, "Packet drift: kind binding mismatch")
        if kind == "artifact-create":
            require(binding.get("baseline") == "empty"
                    and binding.get("allowedPaths") == packet.get("allowed_paths"),
                    "Packet drift: output binding mismatch")
    _binding_shape(binding, document["execution"]["allowedEngines"])
    require(binding == _packet_binding(packet, binding["allowedEngines"], binding["maxRuns"]),
            "Packet operation or generation-attempt binding mismatch")
    if "previewAuthorization" in document["execution"]:
        validate_preview_authorization(document["execution"]["previewAuthorization"],
                                       bindings=document["execution"]["taskBindings"], packets=[packet])
    return binding


def approved_contract(packet, state_root):
    contract_id = _identifier(packet.get("authorityId"))
    with StateStore(state_root) as store, store.locked():
        document = store.read_json("contracts", contract_id + ".json")
        if isinstance(document, dict) and document.get("schemaVersion") in (
                SCOPE_VERSION, PARENT_VERSIONS[1]):
            from scope_authority import current_scope
            document, bindings = current_scope(store, document, packet=packet)
            require(document["id"] == contract_id, "Contract filename/id mismatch")
            from ledger import validate_ledger
            validate_ledger(store.read_json("ledgers", contract_id + ".json"), document, bindings=bindings)
            return document, bindings[packet["id"]]
        if isinstance(document, dict) and document.get("schemaVersion") == PARENT_VERSIONS[0]:
            from parent_authority import current_delegated_contract
            document = current_delegated_contract(store, document, packet=packet)
        else:
            document = validate_contract(document, require_approved=True)
        require(document["id"] == contract_id, "Contract filename/id mismatch")
        binding = binding_for_packet(document, packet)
        from ledger import validate_ledger
        validate_ledger(store.read_json("ledgers", contract_id + ".json"), document)
        return document, binding


def authority_schema(kind, policy=None):
    """Materialize one closed structural contract from source-owned policy.

    No schema grants execution authority. The normal Python validators still
    enforce fresh pins, packet identity, policy ordering, and the locked ledger.
    Inline shared definitions keep validation offline without URI resolvers.
    """
    from composition import Policy
    selected = current_policy() if policy is None else policy
    require(isinstance(selected, Policy), "Source-owned schema Policy required")
    version = selected.schema_version(kind)
    path = Path(__file__).absolute().parent.parent / "schemas" / "authority-common.schema.json"
    shared = strict_json(_policy_bytes(path))
    definitions = copy.deepcopy(shared["$defs"])
    ref = lambda name: {"$ref": "#/$defs/" + name}

    def integer(minimum, maximum):
        return {"type": "integer", "minimum": minimum, "maximum": maximum}

    def closed(properties, optional=()):
        return {"type": "object", "additionalProperties": False,
                "required": [name for name in properties if name not in optional], "properties": properties}

    identifiers = sorted(selected.engine_roles)
    maximum = sum(selected.generation_limits.values())
    definitions["engines"] = {"type": "array", "uniqueItems": True,
        "maxItems": len(identifiers), "items": {"enum": identifiers}}
    definitions["enginePins"] = closed({engine_id: closed({
        "implementationSha256": ref("sha256"), "roles": {"const": list(selected.engine_roles[engine_id])}})
        for engine_id in identifiers}, optional=identifiers)
    definitions["operations"] = {"type": "array", "uniqueItems": True,
        "maxItems": sum(len(roles) for roles in selected.engine_roles.values()),
        "items": {"oneOf": [closed({"engineId": {"const": row["engineId"]}, "role": {"const": row["role"]}})
                             for row in selected.operations(identifiers)]}}
    definitions["generationPlan"] = {"type": "array", "maxItems": maximum, "items": False,
        "prefixItems": [{"oneOf": [closed({"engineId": {"const": engine_id}, "role": {"const": "generate"},
                                            "ordinal": {"const": index}})
                                    for engine_id in selected.generation_order]}
                        for index in range(1, maximum + 1)]}
    if not maximum:
        definitions["generationPlan"].pop("prefixItems")
    else:
        definitions["generationPlan"]["allOf"] = [{"contains": {
            "type": "object", "required": ["engineId"], "properties": {"engineId": {"const": engine_id}}},
            "minContains": 0, "maxContains": limit} for engine_id, limit in selected.generation_limits.items()]
    common_binding = {"packetSha256": ref("sha256"), "kind": {}, "maxRuns": integer(1, 1000),
        "allowedEngines": ref("engines"), "allowedOperations": ref("operations"),
        "generationAttemptPlan": ref("generationPlan")}
    bindings = []
    for packet_kind, target in (("repo-edit", {"repository": ref("path"), "baseRevision": ref("commit")}),
                                ("artifact-create", {"baseline": {"const": "empty"}, "allowedPaths": {
                                    "type": "array", "minItems": 1, "maxItems": 64, "uniqueItems": True,
                                    "items": {"type": "string", "minLength": 1}}}), ("compute-analysis", {})):
        fields = {**copy.deepcopy(common_binding), "kind": {"const": packet_kind}, **target}
        if packet_kind == "compute-analysis":
            fields.update({name: {"const": []} for name in ("allowedEngines", "allowedOperations", "generationAttemptPlan")})
        bindings.append(closed(fields))
    definitions["binding"] = {"oneOf": bindings}
    scoped = kind in ("scope", "parent-scope")
    execution = {"maxLiveIntegrationCalls": integer(0, 10000), "allowedEngines": ref("engines"),
        "enginePins": ref("enginePins"), "previewAuthorization": ref("previewAuthorization")}
    if scoped:
        execution.update(maxTotalRuns=integer(1, 10000), maxChildren=integer(1, 32),
                         maxRunsPerChild=integer(1, 1000), taskScope=ref("taskScope"))
    else:
        execution["taskBindings"] = {"type": "object", "minProperties": 1,
            "maxProperties": 1 if kind == "parent-exact" else 1000,
            "propertyNames": ref("id"), "additionalProperties": ref("binding")}
    definitions["execution"] = closed(execution, optional=("previewAuthorization",))
    definitions["execution"]["allOf"] = [{
        "if": {"properties": {"maxLiveIntegrationCalls": {"const": 0}}},
        "then": {"properties": {"allowedEngines": {"const": []}, "enginePins": {"const": {}}}},
        "else": {"properties": {"allowedEngines": {"minItems": 1}, "enginePins": {"minProperties": 1}}}}]
    for engine_id in identifiers:
        definitions["execution"]["allOf"].append({
            "if": {"properties": {"allowedEngines": {"contains": {"const": engine_id}}}},
            "then": {"properties": {"enginePins": {"required": [engine_id]}}},
            "else": {"properties": {"enginePins": {"not": {"required": [engine_id]}}}}})
    if not scoped:
        definitions["execution"]["allOf"].append({
            "if": {"required": ["previewAuthorization"]}, "then": {"properties": {
                "taskBindings": {"additionalProperties": {"properties": {"kind": {"const": "artifact-create"}}}}}}})
    request = {"schemaVersion": {"const": "plzdo.parent-scope-request.v2" if scoped else "plzdo.parent-request.v2"},
        "id": ref("id"), "preparedAt": ref("timestamp"), "expiresAt": ref("timestamp"),
        "runtimeState": ref("directory"), "policyFingerprint": ref("sha256"), "parentReference": ref("parent"),
        "verifier": ref("verifier"), "execution": ref("execution"), "requestSha256": ref("sha256")}
    if not scoped:
        request["packet"] = {"type": "object"}
    definitions["request"] = closed(request)
    definitions["verifierInput"] = closed({"protocol": {"const": "plzdo.parent-verifier-input.v2"},
        "operation": {"enum": ["prepare", "verify"]}, "request": ref("request")})
    fields = {"schemaVersion": {"const": version}, "id": ref("id"), "expiresAt": ref("timestamp"),
              "policyFingerprint": ref("sha256"), "execution": ref("execution")}
    if kind.startswith("parent-"):
        fields.update(status={"const": "delegated"}, adoptedAt=ref("timestamp"), request=ref("request"),
                      parentApprovalHash=ref("sha256"), parentCreatedAt=ref("timestamp"), parentApprovedAt=ref("timestamp"))
        result = closed(fields)
    else:
        fields.update(createdAt=ref("timestamp"), status={"enum": ["draft", "approved", "revoked", "completed"]},
            approvalHash={"oneOf": [{"type": "null"}, ref("sha256")]}, approvedBy={"enum": [None, "operator", "human", "user"]},
            approvedAt={"oneOf": [{"type": "null"}, ref("timestamp")]})
        result = closed(fields)
        result["allOf"] = [{"if": {"properties": {"status": {"const": "draft"}}},
            "then": {"properties": {name: {"type": "null"} for name in ("approvalHash", "approvedBy", "approvedAt")}},
            "else": {"properties": {"approvalHash": ref("sha256"), "approvedAt": ref("timestamp"),
                                     "approvedBy": {"enum": ["operator", "human", "user"]}}}}]
    return {"$schema": "https://json-schema.org/draft/2020-12/schema", "$id": "urn:" + version,
            "description": "Closed structural contract. Runtime additionally verifies fresh authority, engine and packet pins, attempt policy and the locked ledger.",
            **result, "$defs": definitions}
