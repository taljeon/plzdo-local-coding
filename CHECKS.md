# Local runtime verification

Use Python 3.11+ with the declared JSON Schema dependencies and pytest already
available. This development gate does not install tools, contact model services,
run real provider CLIs, launch a real browser or execute the real Codex sandbox.
Parent-authority checks pin the running interpreter. Use a safe regular
executable in an owned prefix; when the system executable has unsuitable
permissions, run the gate with an owned copy of those exact interpreter bytes.
The gate does not establish support for arbitrary venv or pipx layouts.

Run focused files while editing. Once the relevant source is stable, the complete
current runtime suite uses the sibling source layout in [README.md](README.md):

```sh
PLZDO_RUNTIME_CORE_ROOT=/absolute/workspace/plzdo \
PLZDO_RUNTIME_PYTHON=/path/to/python3 sh scripts/verify-harness.sh
```

The core path must equal the canonical sibling `plzdo` directory. Omit
`PLZDO_RUNTIME_CORE_ROOT` to use that same fixed path; it cannot select another
checkout. Missing or symlinked core packages stop the gate before pytest runs.
The wrapper reports the exact core path and Python/pytest versions, disables
automatic pytest plugins and bytecode/cache writes, supplies only the explicit
source roots, and creates a new private temporary state. It
preserves that owned scratch for diagnosis. It never imports historical grants
or runs as part of normal CLI startup.

All test files remaining under `tests/`, including `tests/legacy/`, are current
supported tests. The latter name records their lineage, not v1 execution support.
Retired APIs and their replacements are listed in
[the migration record](docs/test-adaptations.md). A test-count increase or a
historical pass is not an acceptance requirement or fresh evidence.

The suite includes tiny owned subprocesses and synthetic process, browser and
provider fixtures. Those fixtures are not live Ollama/server-isolation or native
browser attestations. `scripts/verify-real-sandbox.py` remains a separate opt-in
probe using synthetic files and a reviewed exact Python prefix; it is not called
by this gate and was not executed for the migration's focused test passes.

Source launcher smoke is dependency-free:

```sh
bin/plzdo-local-code --version
bin/plzdo-local-code doctor
bin/plzdo-local-code --help
```

For this source preview, check the root README's source-install commands once
when the packaging/layout changes. Use one temporary directory on the current
Mac, leaving the personal installation unchanged. Verify help/version/doctor,
local-only identity/schema and the installed checker path. This is a short
installation check, not a new runtime environment project or a live-model test.

Run the existing runtime and integration regressions once on final code; use
focused tests for a subsequent relevant fix. Do not repeat unchanged full suites
or require another Mac, a new native backend, a wheelhouse release, or live
calls to every provider. Source/archive privacy, actual notices and explicit
publication approval still apply.
