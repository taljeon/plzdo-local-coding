# Runtime 0.3.0 design

This document replaces the P2 design for this candidate. Historical tests and live observations are recorded separately; they do not prove this version is operational.

## Distribution and imports

The public monorepo produces `plzdo` (core and fixed parent adapter) and `plzdo-local-runtime`. The core has no runtime dependency by default; `plzdo[local]` selects exactly `plzdo-local-runtime==0.3.0`. Runtime requires exactly `plzdo==0.3.0`. This optional installation relationship is distinct from code imports: runtime may use core, while core and adapter never import runtime.

Public commands compose only the Ollama engine. A separate private product can use the narrow Python API to compose its source-owned engines and `plzdo.overlay` contracts. That API is trusted in-process reuse, not a sandbox against a hostile Python caller. No task field, environment variable, module name, entry point, or callback can install an engine through the public CLI.

## Reused execution

`workflow` retains candidate creation, structured proposals, immutable scope/check verification, and explicit cleanup. `engine_types` supplies frozen `EngineIdentity`, `Work`, `WorkResult`, and typed failures. Work carries canonical prompt/schema/profile bytes, a bounded deadline, one dedicated evidence destination, and the reservation identity. It carries no target-apply or ledger object.

`Kernel` fixes one composition and state root per process before state-dependent helpers are imported. It validates the exact task, authority, implementation pins and source policy at each new reservation/dispatch. `ledger` reuses the existing owned-file store, lock, compare-and-replace writes and hash chain. A new process is required to change composition or state root.

## Authority and accounting

The four closed contracts are `plzdo.local.exact.v2`, `.scope.v2`, `.parent-exact.v2` and `.parent-scope.v2`; private compositions generate separately closed `plzdo.overlay` versions from the same schema builder. Shared definitions alone never authorize execution. Legacy contracts, consumed budgets and admissions are not migrated implicitly.

Each task binds exact engine roles and generation slots. Public ordinary work has at most two Ollama slots and stops on success. Private composition can choose its bounded route according to task risk, including a direct external generation route. Limits are ceilings, not instructions to spend every call.

`maxLiveIntegrationCalls` is the total cumulative call ceiling for the task, not a simultaneous-call limit. One root ledger records run reservations, generation/review debits, optional unique child-send claims, once-only dispatch claims, engine receipts and attempt outcomes. A crash never refunds or creates another allowance. A retry needs the prior exact slot's immutable retry outcome, explicit completed cleanup, and remaining approved budget. Unknown errors, identity changes and infrastructure failures stop. A pending browser observation grants no retry. Final browser evidence can supersede its original pending receipt once; it cannot rewrite history.

New calls require current active authority. Historical status and terminal receipt persistence validate stored structure, identities and evidence without granting a new call; cleanup evidence can therefore be captured after expiry. Local chains detect corruption, not an operator who can rewrite all owned state.

The fixed adapter verifies a fresh parent snapshot. Each new ledger action records the validated observation. `atomicLease=false`: this is a current observation, not an atomic transaction with the core. Parent revocation after dispatch cannot unsend a call. No cache or skipped check pretends to solve that race.

## Execution limits

Candidate checks use the existing bounded offline checker. Engine cleanup receipts distinguish no-start from owned-start work. The POSIX process-group runner proves closure of its original group; it is not a general proof about every detached descendant.

A public owned-Ollama server egress profile has not been established on the current macOS environment. Public dispatch refuses `ISOLATION_PROFILE_UNSUPPORTED` before endpoint/model access. An environment or JSON claim is not isolation proof. Private personal transport explicitly makes no G6 server-isolation claim.

Managed browser previews serve only approved generated assets on loopback, run in the foreground with a bounded lifetime, and require Ctrl-C/termination plus a stopped receipt and observed connection refusal before finalization. Coordinator browser observations are advisory evidence, not a signed native attestation.

## Verification frequency

Editing uses focused boundary checks. A frozen release candidate gets the complete current offline suite, artifact inventory, leak review, wheel/sdist build and isolated installation matrix. These suites do not execute on ordinary startup or each model call. Runtime keeps fresh authority/identity checks, locking, input bounds, cleanup and the actual task's acceptance checks. Measure that cost before considering an optimization; preserve the boundary when removing duplicate work.
