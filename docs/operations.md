# Runtime 0.3.0 operations

Install a reviewed candidate into a dedicated Python 3.11+ environment. `plzdo` selects core and adapter only; `plzdo[local]` additionally selects the matching runtime. Version 0.3.0 here is an unpublished candidate. Use the reviewed wheelhouse for offline installation; these docs do not claim a published package exists.

Use the isolated `plzdo-local-code` launcher. It fixes the package prefix and starts Python with `-I -S -B`; ordinary `python -m`, editable layouts and arbitrary search paths are not equivalent.

```sh
plzdo-local-code doctor
plzdo-local-code --state-root /absolute/path/to/dedicated-state contract draft \
  --id example --packet /absolute/path/to/packet.json \
  --expires-at 2030-01-01T00:00:00Z --max-calls 2 --engine ollama
```

Use a real bounded expiry appropriate to the task, review the returned payload hash, and approve that exact hash with `contract approve --id ... --expected-sha256 ... --confirm 'APPROVE <id> <hash>'`. Approval is reused within the same unchanged task; routine implementation/check phases do not require another operator approval.

`run --packet ... --name ...` uses a new run name. `retry` uses the same original name after a verified retry condition; it does not reset budget. `status --id ...` inspects durable authority and evidence and grants no execution. `status --run ...` inspects an owned run. `validate` and `route` make no engine calls. `metrics` exports only bounded usage and outcome summaries.

Public `doctor` reports discovery, not live acceptance. The current public engine refuses `ISOLATION_PROFILE_UNSUPPORTED`; neither approval nor installing Ollama overrides the missing server-isolation proof. The separately installed private personal composition provides its own disclosed execution policy.

`delegation` prepares and adopts the exact v2 parent request after fixed adapter trust is configured. `scope` supports an explicitly bounded root and admitted children without inventing new child budgets. These commands do not grant legacy-HN or automatic scheduling access.

For an explicitly approved managed preview, run `preview --run <owned-run-path> --ttl-seconds 300` in the foreground. Use Ctrl-C to stop it, then `finish-browser --run ... --observations ...` after coordinator observations are saved. A startup URL or pending observation is not completion. Finalization validates stopped evidence and connection refusal.

Do not copy old grants or edit consumed ledgers to recover. Preserve a failed run and its receipts. A genuinely new task needs its own reviewed authority; the old budget remains consumed. Engine source/config changes require new matching approval pins.

See [technical design](technical-design.md), [current checks](../CHECKS.md) and [historical evidence](historical-evidence.md).
