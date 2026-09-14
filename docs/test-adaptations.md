# Current v2 tests and preserved lineage

The completed `approval-autonomy-20260913/runtime-candidate` baseline remains
unchanged. This successor intentionally updates its copied fixtures for v2.
[The inventory](test-retirement-inventory.json) records prior test bytes, retained
suites, adapted suites and explicit retirement reasons. It is an inventory of
source changes, not a report that every final gate has already passed.

The normal development entry is `scripts/verify-harness.sh`, selecting every
remaining test under `tests/`. There is no skip list concealing retired imports.
`tests/legacy` contains maintained inherited assertions; its directory name does
not enable old packets, grants, routes, budgets or model defaults.

## Retained behavior

- Candidate and artifact tests retain exact paths, Git isolation, full-payload
  validation before writes, original-target refusal, ownership/no-follow receipt
  checks, UTF-8/Unicode behavior, byte limits and no-overwrite assertions. Fixtures
  now use `authorityId` and an explicit Hui profile. Old permission and Codex
  attempt fields are tested as unknown inputs, not silently translated.
- Stream, profile and health tests retain wire evidence, content/thinking limits,
  status collisions, close failures, memory/stall/deadline behavior and all four
  historical profile hashes. Transport imports now select `ollama_engine`.
  New Work deadlines cap invocation time while profile bytes remain unchanged.
- Node/Python and pack tests retain exact file grants, no directory/network/write
  expansion, startup failure classification, source immutability and frozen
  closure tamper detection. Synthetic summaries now explicitly record cleanup.
  The staged closure includes the neutral JSON, engine-value and error helpers.
- Known fixed-parser data errors remain failed assertions. Unknown report errors,
  missing receipts, bootstrap errors and failed cleanup stop further generation.
  Tests do not manufacture a successful receipt when execution is unknown.
- Preview tests retain exact frozen assets, request/CSP rules, timestamp bounds,
  actual-closure checks, interrupted-proof reuse and conflicting-proof refusal.
  Their v2 fixtures carry an original pending receipt and a Kernel interface;
  terminal receipts close the same reservation before ready/retry is published.
- Metrics remain read-only and prompt-free. Missing values and absent cleanup
  stay unknown. Historical fault labels do not become real quality observations.

## Replaced or retired behavior

- Public provider adapters, Grok admission commands, scheduler/automation lanes,
  pilot configuration and prototype edit/check wrappers were removed. Their tests
  are not executable public compatibility promises. Private provider behavior is
  verified in the separate overlay's tests using the public shared library.
- V1 standalone/parent/scope/backend and CLI fixture suites were replaced by
  `test_v2_authority.py`, `test_v2_kernel.py`, current shared pipeline/browser
  tests and fixed-prefix launcher tests. No completed grants or budgets are reused.
- Old `local_fn`/`codex_fn`/`checks_fn` controller and injected-failover fixtures
  were replaced by typed fixed-engine and Kernel fixtures. Public packets cannot
  select those callbacks or request a provider transition.
- Profile-less public execution, public Codex fallback, active legacy-HN backend
  selection and implicit retry for an arbitrary HTTP/provider failure are not
  preserved behaviors. The closed benign structured-output retry set is explicit.
- The existing compute-analysis shape remains a validated zero-provider handoff.
  Its tests cannot claim a calculation was performed or authorize code generation.

New focused tests add explicit engine immutability, no-start refusal, owned
process/model cleanup, deadline enforcement, single-slot browser finalization,
source-prefix isolation, package/resource identity and unsupported public
inference checks. Model/Ollama, native browser and real-sandbox proof remain
separate scopes; no synthetic pass is reported as one of those proofs.
