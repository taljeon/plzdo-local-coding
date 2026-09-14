# PlzDo integrations

`plzdo-integrations` is an optional package for an explicit user-owned AI integration composition. It depends on the matching `plzdo==0.3.0` core/adapter and `plzdo-local-runtime==0.3.0` distributions. It retains the `plzdo_private_overlay` Python module and `plzdo-private` command so existing interfaces and authority formats remain stable.

The command owns its private approvals from the start and calls the runtime's shared pipeline, checks, cleanup and ledger. Each approved root has one ledger for all its calls. Installing the package does not configure accounts, select provider binaries, grant execution, or add external engines to the public command. An existing public root cannot be continued as private authority.

This composition deliberately uses the user's own local execution trust and external provider accounts. It does not establish the public Ollama isolation boundary. The optional runtime and integration packages require Python 3.11+; the core's lower Python requirement is independent. The current runtime/integration support target is macOS.

Internal and company use follows the governing workspace and organizational policy. Local LLM use is optional and does not authorize an external provider. Choose separate policy-approved configuration and state; never automatically import personal configuration, credentials, grants or ledgers. A policy that requires OS-enforced isolation must use a verified isolation path rather than treating this user-owned trust composition as proof of isolation.

| Engine | Role |
| --- | --- |
| `ollama` | Pinned Hui Qwen generation through the existing personal-local transport |
| `codex-openai` | Structured generation and design review |
| `claude` | Advisory Opus review |
| `grok-cli` | Advisory review after separate foreground APPROVE and SEND |
| `agy` | Advisory Gemini 3.8 review through pinned Google Antigravity CLI |

The personal Ollama path reports `trust=personal-local` and `isolation_verified=false`. It trusts the existing loopback server on the user's Mac, checks the pinned Hui profile/model and Ollama version, and unloads only its owned generation. The public Ollama entry continues to require an enforced isolation profile. No model download, daemon reconfiguration, scheduler, provider discovery or target apply is part of installation.

## Configuration and commands

Use the [source installation commands](../../README.md#install-from-source) from
this repository's main README. They install the matching core, runtime and this
optional package together. No release wheelhouse or PyPI publication of these
three packages is required. External provider software and authentication remain
operator-managed and are not installed by these commands.

For local-only use, set `providerPins` to `{}` and permit only `ollama` in the
task draft. For external-only work, configure and permit the desired external
engine within its existing role. Each selected engine must be explicitly
allowed; unconfigured providers and implicit cloud fallback are unavailable.

Use a fresh prefix when moving from the former `plzdo-private-overlay` distribution. Both names install the same module and command, so they must not be co-installed in one prefix. Preserve the previous environment until the new one has been verified. Editable installs and mixing packages from unrelated prefixes are unsupported.

Use the packaged shell entry so Python starts with `-I -S -B`. `--help` and `--version` need no provider configuration. The loader uses exact package locations; it never adds the complete site-packages directory to Python's import path. Config, state and provider pins use explicit canonical paths. A regular convenience wrapper may invoke the actual packaged launcher; a lone launcher symlink in a different directory does not provide its companion files.

A configuration is a small private JSON file matching `plzdo_private_overlay/schemas/config.schema.json`:

```json
{
  "schemaVersion": "plzdo.private-config.v1",
  "stateRoot": "/absolute/new-private-state",
  "providerPins": {
    "codex-openai": {"path": "/absolute/canonical/codex", "sha256": "<64 lowercase hex characters>"},
    "claude": {"path": "/absolute/canonical/claude", "sha256": "<64 lowercase hex characters>"},
    "grok-cli": {"path": "/absolute/canonical/grok", "sha256": "<64 lowercase hex characters>"}
  },
  "codexModel": "<explicit cloud model>"
}
```

Include only the external engines needed by this composition. Omitting `codexModel` preserves the existing CLI model default; it does not read the user's general Codex configuration. Executable pins and explicit model choices are bound into engine identity. A changed implementation/configuration requires a fresh approval.

Private identity also binds both actual launcher files. Their logical hash names stay the same across source and installed layouts; changed, ambiguous or symlinked launchers refuse validation.

`schema --kind` emits the configured private concrete schema through the shared schema API. Its private namespace and closed engine/role set come from this package's fixed composition; common definitions remain owned by the public runtime.

The command supports these bounded steps after the matching installation is verified:

```sh
plzdo-private --config /absolute/private.json identity
plzdo-private --config /absolute/private.json schema --kind exact
plzdo-private --config /absolute/private.json draft \
  --id private-task --packet /absolute/task.json \
  --expires-at '<timezone-aware expiry>' --max-live-calls 3 \
  --allow-engine ollama --allow-engine codex-openai
plzdo-private --config /absolute/private.json approve \
  --id private-task --payload-sha256 '<hash shown by draft>' \
  --confirm 'APPROVE private-task <hash shown by draft>'
plzdo-private --config /absolute/private.json run --packet /absolute/task.json --name first-run
```

Use a fresh task with `authorityId` and the explicit pinned Hui `generation_profile`. Historical `hn_formalization` grants and completed budgets are rejected. `draft` saves an unapproved contract and prints the exact payload hash for review. Normal generation can use the approved Ollama slots followed by at most one approved Codex slot. Unknown, authority, scope, identity and cleanup failures stop execution. Only a verified candidate may be reported ready.

Private delegation uses the fixed PlzDo adapter. Create its verifier descriptor and parent reference with the public adapter's configuration command, using the same interpreter as the private launcher. `trust-verifier --verifier FILE --descriptor-sha256 HASH --confirm 'TRUST PARENT VERIFIER HASH'` records that setup without approving a parent or a task.

`parent-prepare --packet FILE --parent-reference FILE --verifier FILE` takes the same explicit expiry, call/run and `--allow-engine` limits as `draft`. It prints the exact request, its normalized packet, and the marker for the normal PlzDo parent approval. After that parent is actually approved, `parent-adopt --id ID --request-sha256 HASH` adopts the saved request. Parent snapshots report `atomic_lease=false`; repeating adoption preserves consumed state, and an unapproved or revoked parent refuses adoption.

For bounded child templates, `scope-draft --id ID --scope FILE` and `parent-prepare-scope --scope FILE ...` also require `--max-total-runs` and `--max-children`; `--max-runs-per-child` defaults to one. `scope-approve` uses the same exact hash/confirmation form as `approve`. `scope-admit --id ROOT --template TEMPLATE --packet FILE` binds a child to existing root authority and returns its normalized packet. It creates no independent child budget. Use the returned packet for subsequent runs. Both standalone and delegated roots use the private namespace and the shared ledger implementation.

Draft and prepare commands accept browser permission only through `--allow-managed-preview` together with explicit `--preview-max-lifetime-seconds` and `--preview-max-sessions` limits.

`review` reserves one explicitly allowed Codex, Claude, or AGY review outside the generation plan. `grok-prepare` saves bounded exact bytes without reserving a call. `grok-approve` performs a fresh artifact/authority check, requires the exact foreground APPROVE phrase and reserves one global call plus its unique preparation claim. `grok-send` requires a new foreground SEND phrase and consumes that reservation's single child claim before dispatch. `grok-import` reads the captured answer only after matching the admission, durable dispatch/completion and unchanged cleanup evidence. Failure, timeout or missing output never causes an automatic retry or refund. Evidence-publication failure after debit remains consumed.

Native AGY review uses the same `review --engine agy` reservation and dispatch. Add its exact binary pin under `providerPins.agy`, an explicit resolved `agyModel` such as `gemini-3.8-flash-high`, and `agyGlobalRulesSha256`. The latter is the SHA-256 of the exact operator-reviewed generic global rules; JSON `null` requires the global file to be absent. Omitting this field does not mean absence. The fixed native binary is Google Antigravity CLI 1.2.2 for Darwin ARM64, SHA-256 `cabadc15a61944372bede1fdff186701c17467dd9d718e97dc79283055d3c101`. No SDK, Gemini CLI, API-key/Vertex route, fallback model, or additional generation slot is enabled.

AGY automatically reads the current OS account's `.gemini/GEMINI.md`. Its admitted hash and the metadata snapshot of native configuration are bound into engine identity and private approval. The adapter never copies or changes global rules or credentials. It rejects global rules that contain an automatic `@file` reference, unexpected rules, and nonempty shared or legacy hooks, MCP, plugins, agents, skills, commands, extensions, or extra-context sources. Configuration accepts only a narrow set of visual/personal-auth-type fields, known model display names overridden by the explicit CLI model, and an empty native `trustedWorkspaces` list or the exact current-user home entry. Permission grants, extra file access, command callbacks, custom routing, and paid-credit settings are rejected. This trust record is admitted native security state; its serialized semantics are not fully documented and it does not authorize adding the home directory as a workspace. The snapshot records hashes and file metadata, never rule/settings contents. [Native global context](https://antigravity.google/docs/cli/gcli-migration/), [Workspace trust](https://antigravity.google/docs/cli/getting-started/)

Each AGY call selects `--new-project` with an empty owned temporary workspace outside the account home. Capture and authority files remain outside that workspace. The adapter uses `--disable-slash-commands --sandbox`, an exact model flag and bounded print timeout, with no continuation or additional directories. It omits `--mode plan`: native 1.2.2 reports that this flag has no effect while slash expansion is disabled. Native project/session persistence and fixed host metadata follow the pinned CLI/account defaults. Existing project contents are not inspected or attached. [Native projects](https://antigravity.google/docs/cli/projects/)

The provider prompt deterministically appends the fixed review JSON Schema and JSON-only/no-tool/no-finish instructions to the approved Work prompt. Evidence records the original Work-byte hash, actual provider-prompt hash and byte count, fixed schema hash, and source-owned transform identifier. The native `--json-schema` option is omitted. The normal text response must parse as one JSON object, pass the host's fixed review validator, and canonically match the captured response fragments. Native schema/structured-output fields and every tool call, including finish tools, are rejected. Changing this transport changes engine identity and requires fresh explicit approval; historical grants, failed reservations and execution evidence remain consumed and unchanged.

The child receives the documented `AGY_CLI_DISABLE_AUTO_UPDATE=true` override so its pinned installation stays fixed. Existing task-origin markers are preserved unchanged after active-session admission. No shell profile or global environment is modified. [Native updater opt-out](https://antigravity.google/docs/cli/troubleshooting/)

The native CLI may advertise tools. The terminal sandbox does not establish a no-tools process boundary. The adapter rejects every observed tool/subagent event, permission or retry diagnostic, changed workspace/configuration, mismatched model/conversation, and any result other than one complete successful review validated by the host. Captured output is bounded and bad complete events request early termination through the shared supervisor. Before/after snapshots establish observed stability, not an atomic proof of every file the native process read. There is one bounded CLI launch per reservation, with no adapter retry/refund. The pinned CLI's internal API retry behavior has no documented disable flag; underlying API attempt counts are not claimed. [Headless events and permissions](https://antigravity.google/docs/cli/headless/)

Every provider response is a proposal or advisory evidence. External transports use their source-owned tool controls and bounded output/time; AGY's observed-tool rejection is described above. Their cleanup proof covers the initial POSIX process group; detached descendants are not claimed to be isolated. Missing cleanup receipts fail closed.

The Work deadline is fixed when Work is created and includes identity checks, context preparation, provider execution and final verification. Grok preparation uses `/usr/bin/git` with a fixed environment and owned temporary working directory. Each Git step uses the shared process supervisor, preserves cleanup evidence outside the admitted-prompt directory, and consumes the same remaining deadline. Grok execution receives at most 1,800 seconds of the remaining time, preserving the existing Grok admission runner's ceiling; Codex, Claude and AGY retain their 180-second ceilings. The shared transport records the provider cap and effective remaining time before dispatch. It checks its per-file output bounds during execution and again after process exit before accepting success. These are polling and final acceptance checks, not a byte-exact capture cap.

Grok's `plain` stdout carries the final answer and does not expose ongoing reasoning. Empty captured stdout therefore does not establish model inactivity, an authentication failure, or an upstream timeout. Diagnose a failed run from the exact native session's timestamps and phase metadata before proposing another call; do not store reasoning text or upload a trace for that diagnosis. A host deadline failure remains consumed and requires separately authorized follow-up work. Longer execution time does not create new reservations, change the configured model/effort, or grant additional tools.

For a contract that explicitly permits generated-file browser validation, `preview --name RUN` serves the approved files in the foreground. Record the actual browser observations and stop that owned server with Ctrl-C. `finish-browser --name RUN --observation /absolute/observation.json` verifies the stopped receipt and connection refusal before accepting the observation. A pending observation or an elapsed TTL alone does not make a candidate ready.

## Source preview status

The package exactly requires `plzdo==0.3.0` and `plzdo-local-runtime==0.3.0`.
The maintainer confirmed publication rights and selected [MIT](LICENSE).
The source-install recipe uses the root `constraints.txt`; no release wheelhouse
is supplied. `dependency-status.json` retains its compatibility field names and
records the source tag, not execution permission or a certified binary release.
The doctor's legacy pending artifact field does not prevent source-installed
commands; each actual task still needs its own approval.

This package does not install or authenticate provider software. Provider setup and live acceptance require their own explicit inputs and execution scope. Existing personal acceptance is a regression reference, not public isolation or compatibility evidence.

The private HN backend returns `HN_BACKEND_PROTOCOL_UNSUPPORTED` before reading any records. The inspected HN source exposes a v1 formalization contract without the required v2 snapshot protocol. HN code, live state and historical allowances stay untouched.

## Source development

Keep the two checkouts in this layout:

```text
workspace/
  plzdo/                         # core and read-only parent adapter
  plzdo-local-coding/             # the single runtime source
    local_coding/
    packages/integrations/
      plzdo_private_overlay/
      tests/
      bin/
```

The source-mode loader admits only this fixed layout. An installed loader uses its own prefix and does not search sibling repositories. Source tests can use their installed development dependencies; the isolated packaged CLI requires its declared dependency closure, so use the installed wheel layout for CLI acceptance.

From the runtime checkout, with pytest and the declared test dependencies already available:

```sh
python3 -B -m pytest packages/integrations/tests -q -p no:cacheprovider
```

These tests exercise the real runtime/core APIs with fake providers, role/config closure, exact input binding, explicit cleanup, preparation replay identity and the unsupported HN boundary. The foreground-confirmation tests create owned synthetic PTYs with dummy hashes. They do not invoke a provider or create live approval authority. Final package/install and publication gates apply to the frozen release artifacts.

Historical private benchmark reports and development patches are not part of this source distribution. No identity cache or skipped authority check was added.
