This add-on lets you use the AI coding tools you choose with PlzDo.
It keeps proposed code changes and their checks together so you can review the result before using it.
You can choose an AI model on your own computer, an external AI service, or both, and set up only what you need.

# PlzDo local coding and optional integrations

Use an existing local Ollama model, explicitly selected external AI tools, or
both through PlzDo's shared candidate/check/cleanup pipeline. The standalone
[PlzDo harness](https://github.com/taljeon/plzdo) remains usable without this
repository or a model account.

This source preview is intended for a developer who trusts their own operating
system account, installed Ollama server and selected provider tools. It is not
an OS isolation product. Company and shared work must follow that environment's
data and tool policy; personal configuration and approvals must not be imported
automatically.

## Install from source

Use macOS with Python 3.12 and Git for the recipe below. The packages declare
Python 3.11+; other Python versions, machines and installer layouts are outside
this preview's installation check. Ollama and external provider software are
installed and authenticated separately, only when selected.

Keep the two source checkouts side by side. From their parent directory:

```sh
git clone --branch v0.3.0 https://github.com/taljeon/plzdo.git
git clone --branch v0.3.0 https://github.com/taljeon/plzdo-local-coding.git
python3.12 -m venv --copies .venv
.venv/bin/python3 -m pip install setuptools==80.9.0
(cd plzdo && ../.venv/bin/python3 setup.py bdist_wheel)
.venv/bin/python3 -m pip install --no-build-isolation \
  -c plzdo-local-coding/constraints.txt \
  ./plzdo/dist/plzdo-0.3.0-py3-none-any.whl \
  ./plzdo-local-coding ./plzdo-local-coding/packages/integrations
.venv/bin/plzdo-private doctor
```

Python packages install into `.venv`; source build files stay in the checkouts.
The core wheel is built locally because the published core v0.3.0 has a local
build-helper import that fails in a plain PEP517 source install. This recipe
uses its existing setup entry without changing the published core.

Use a fresh directory if a previous
environment contains `plzdo-private-overlay`: that older distribution and
`plzdo-integrations` own the same module/command and must not be co-installed.
There is no release wheelhouse to download and no PyPI release is required for
the three local source packages. `constraints.txt` records the dependency
versions used by this preview. A company may provide those dependencies through
its own approved channel.

## Select the features you use

The operational entrypoint for the existing user-owned composition is
`plzdo-private`. Its name describes private settings and authority, not a
requirement that this source repository be private.

| Configuration | Available work |
| --- | --- |
| `providerPins: {}` and a task allowing only `ollama` | Local generation; no cloud fallback |
| Selected external pins and a task allowing those engines | External work within each engine's supported role; no Ollama generation is required |
| Local and external engines explicitly allowed | Existing generation/fallback/review combinations |

Start with this local-only configuration and replace `stateRoot` with a new
absolute directory owned by your account:

```json
{
  "schemaVersion": "plzdo.private-config.v1",
  "stateRoot": "/absolute/path/to/plzdo-state",
  "providerPins": {}
}
```

Save it as `local.json`, then inspect the selected configuration:

```sh
.venv/bin/plzdo-private --config /absolute/path/to/local.json identity
.venv/bin/plzdo-private --config /absolute/path/to/local.json schema --kind exact
```

These commands do not authorize generation. A task must subsequently be drafted
and explicitly approved with its allowed engines, exact inputs and call limits.
See [configuration, roles and task commands](packages/integrations/README.md).
Ollama provides generation; Codex provides generation and review; Claude, Grok
and AGY provide their existing review paths. Unconfigured external tools are
not selected automatically.

Local generation keeps the existing Ollama 0.33.3 and
`huihui-qwen38-q6kl-v1` profile/model requirement. Missing or changed tools/models
fail with a diagnostic; installation does not download a model or reconfigure
the daemon. Outputs become checked candidates, never automatic writes to the
original project. Local execution does not make data already sent to a separate
cloud coding agent local.

## Boundaries and validation

The strict public command `plzdo-local-code` retains
`ISOLATION_PROFILE_UNSUPPORTED` for live generation. Its guard is not redirected
to the personal path. The `plzdo-private` path explicitly reports
`personal-local` trust and no verified OS isolation.

New native/UDS execution, replacement Qwen rendering/parsing and GPU isolation
experiments are not included. The preview uses the existing transports and
keeps profile, role, approval, no-refund and cleanup checks. Prior live evidence,
current offline checks and the tested installation are distinct; see
[feature status](docs/feature-status.md) and [checks](CHECKS.md).

Source doctor/help/version checks and the regression suite require no provider
call. For development, use the sibling layout above and the commands in
`CHECKS.md`. Contributions should include a small synthetic reproduction and
the relevant test result; do not attach credentials or raw private logs.

## License

The runtime and optional integration source are distributed under the
[MIT license](LICENSE), with the maintainer's confirmed publication rights.
Existing notices are retained. Dependencies, separately installed models and
provider tools keep their own licenses and service terms; their binaries,
credentials and private state are not included. See [provenance](docs/provenance.md).
