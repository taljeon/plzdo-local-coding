# Optional integration contribution boundary

Follow the runtime repository's ../../AGENTS.md and ../../CHECKS.md, then this
package's instructions. This package owns the explicit user-owned integration
composition, external generation/review transports and parent-verifier integration.

Keep the `plzdo_private_overlay` module and `plzdo-private` command. Reuse the
runtime's existing Kernel, pipeline, ledger, checks and owned cleanup. Do not
copy runtime code, add provider discovery to the public entry, or transition an
existing public root into private authority. Provider responses remain advisory
or proposed content; they do not approve or apply changes.

The source layout is this package under `plzdo-local-coding/packages/integrations`,
with core/adapter in a sibling `plzdo` checkout. Installed dependencies must share
the launcher's canonical installation prefix. Source-layout adaptation does not
authorize imports from arbitrary caller-selected paths.

Preserve role restrictions, generation order, exact hashes, foreground Grok
confirmation, explicit AGY context admission, deadlines and no-refund accounting.
Ordinary tests use synthetic fixtures and fake providers; live model/provider,
account, installation, target-apply and publication actions require their separate
governing scope. Authority/process changes require independent review.

The maintainer confirmed publication rights and selected MIT for this package.
Preserve its LICENSE and any future third-party notices. The private authority
namespace remains separate from public authority despite source publication.
Other workers may own adjacent repositories or modules; do not revert their work.
