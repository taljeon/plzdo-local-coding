# Local runtime contribution boundary

Follow the latest operator request, README.md, CHECKS.md and the repository's
documented fixed interfaces. Preserve historical source, evidence, state,
grants and operational HN/automation outside the current task.

The runtime depends on the public PlzDo core/adapter. Core and adapter never
import or launch runtime. Public composition is fixed to Ollama; a separate
private consumer may reuse the same library under its own concrete authority.
Do not add plugin discovery, caller-selected modules, provider CLI commands or
legacy authority migration to the public CLI.

Keep exact profile bytes, immutable candidate/check rules, owned cleanup,
FD/lock/hash-chain state and generation-slot accounting. Unknown failures stop.
Owned cleanup precedes checks. Immutable attempt completion precedes retry or
reported success.
Authority, process, sandbox and reservation changes require independent review.

Use CHECKS.md. Focused offline tests come first; full suites and packaging gates
follow source freeze. No real models, provider jobs, downloads, account/config
changes, target apply or publication occur in ordinary checks. The public
Ollama isolation environment is unsupported until separately implemented and
verified. Historical and synthetic evidence cannot satisfy that live gate.

Preserve the runtime and integration MIT notices and the provenance of any new
third-party contribution. Publication remains an explicit operator action and
does not grant model execution or import personal authority.
