# Runtime candidate requirements

- The public CLI accepts only the fixed local composition and v2 concrete authority. External generation, review transports, private HN and schedulers are outside this distribution.
- Core-only installation works without the runtime or inference dependencies. Local installation is explicit and exact-version coupled.
- Product generation uses an explicit pinned Hui profile. Coding-test work stays in its existing coordinating task. Compute-analysis is a zero-call handoff.
- A task binds its target, allowed output paths, engine roles and maximum run/call budget. Successful generation stops immediately. Only a known recoverable failure with closed cleanup can consume a subsequent slot.
- Existing generation, checks, health handling and owned cleanup remain bounded. Candidate acceptance never means target application or publication.
- One root ledger debits before dispatch and never refunds crash-consumed authority. Child sends cannot create a new global allowance. Stored evidence remains inspectable after authority expires.
- Parent approval is a recorded non-atomic snapshot; unsupported or changed authority refuses new execution.
- Unsupported public server isolation refuses explicitly. License/right review and live server-egress proof remain separate public-release gates.
