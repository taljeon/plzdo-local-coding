# One root grant, bounded autonomous children

This is an explicit new protocol, not a migration of existing exact contracts.
The coordinator reads the project's actual instructions, identifies a supported
product-code step and proposes fixed templates and budgets. A root grant covers
only those templates. The runtime verifies and records each child; it does not
ask the operator again merely because the child has a new ID or worker.

## Three product configurations

| Configuration | Root authority | Normal progress |
|---|---|---|
| PlzDo core only | Project instructions and existing valid formalization where required | Coordinator plans, verifies and advances the same goal; no runtime needed |
| Runtime only | `scope draft` then exact `scope approve` | `scope admit`, normal `run`/`retry` under the public local composition |
| PlzDo + runtime | `delegation prepare-scope`, normal parent formalization approval, `delegation adopt` | Same `scope admit` and engine, without an additional standalone approval |

Core Quick/Plan rules do not bypass the adapter's approved-parent requirement.
Normal phase completion is not whole-goal completion. Keep the goal active until
all its criteria and evidence are satisfied. Reuse a valid exact parent and fixed
verifier; do not rename/reapprove/reprepare to reset spent allowances.

## Scope format and commands

`plzdo-local-code scope --help` and `plzdo-local-code delegation --help` expose the CLI.
The interchange schema is `schemas/scoped-task.schema.json`; engine validation
is stricter than structural JSON validation.

A scope has `schemaVersion: plzdo.task-scope.v2` and `templates`. Each named
template has a normal product `packet` and `basePolicy: {"mode":"exact"}`. The
CLI binds template `authorityId` to the reviewed root ID before hashing.
Choose all limits explicitly: `--max-calls`, `--max-total-runs`, `--max-children`,
`--max-runs-per-child`, `--expires-at`, and each allowed `--engine`.

Standalone: draft the scope, review its returned payload/hash, then use the exact
`APPROVE <root-id> <hash>` confirmation through `scope approve`. This records an
operator assertion only when a real user instruction/policy authorizes it; an AI
must not impersonate a new operator decision. Duplicate valid root approval is
byte-stable. Existing `contract draft/approve` exact packets remain supported.

Connected: reuse the configured trusted verifier, prepare a new scope request,
and include its returned `plzdo-scope-delegation:v2:<hash>` marker in the
parent's evidence contract. Complete normal PlzDo parent approval and adopt that
exact request. The adapter remains read-only and owns no second ledger.

For each child, call `scope admit --id <root-id> --template <template-id> --packet
<child.json>`. The returned normalized `child.packet` is the exact input to the
existing engine. Preserve it as task-owned input. No new operator approval is
created. Admission itself makes no provider call and consumes no run reservation.

Children may change only ID, objective, design, a nonempty subset of approved
output paths, and base revision under its explicit policy. Everything else is
fixed: context, checks, regression checks, validation packs, facts, profile,
attempt/time limits, task category and approved engine roles. Scope supports
repo-edit and artifact-create product work, with the explicit pinned Huihui
profile. It is not a coding-test route, free-form task engine or semantic proof
that a new objective still serves the user's goal; the coordinator owns that
judgment and quality review.

## Revision policy

`exact` is the default and admits only the template's existing commit. Optional
`descendant-within-scope` fixes `anchor` to that template's commit and a full
local `ref` such as `refs/heads/work`. A child must name that ref's current full
commit at admission. Its ancestry and all intervening changed paths must remain
within the approved editable paths, including reverted edits. Later ref movement
does not rewrite an already admitted child; its exact commit stays pinned.

The runtime neither applies nor commits those changes to the original repository.
An independently authorized target workflow may advance the approved branch. A
new repository, branch policy, validation rule or outside-scope change requires
new authority, not a hidden template update.

## Budgets and failure behavior

One root ledger counts total runs and all provider reservations across children;
each child also has its existing run cap. A Grok child send stays under its one
already debited provider reservation. Renaming children/workers cannot refill
these limits. `maxChildren` is at most 32; there are at most 16 templates and each
normalized packet is at most 128 KiB. State retains the existing 8 MiB bound.
Partial initialization or interrupted provider reservations fail closed with no
refund. Identical child admission returns the original binding/time; changed
content under the same ID is rejected.

Before each reservation, the runtime rechecks active root authority, exact child,
immutable policy/code, catalog and ledger. The connected mode also rechecks the
parent's identity, hash, status and approval time. These are local record
snapshots, not signatures or atomic cross-process cancellation leases.

Permission failures are not new cloud permission. A company local-model ban
does not authorize cloud transmission; provider capability and project data
policy must separately allow it. Scheduled contexts cannot use foreground scope
grants. Existing separately authorized automation retains its original workflow.

P5 original-target apply and Grok's exact `SEND` consent remain separate existing
boundaries. This version does not combine old `APPROVE` with new send authority,
auto-apply candidates, launch a scheduler or silently transmit extra data.

## Verification limits

Scope guards protect context and explicit/conventional check files, and freeze
check commands and validation packs. They do not discover every dependency of
arbitrary custom check programs; review those dependencies when choosing a root
template. The runtime's immutable candidate/check sandbox remains mandatory.
Offline synthetic tests demonstrate admission, denial, concurrent budget debit
and parent integration. They are not live provider quality, another-Mac support
or a measured human-interruption/latency benchmark.
