# Runtime context

This candidate implements the public local/private overlay separation after the P2/P3 extraction work. It preserves bounded generation, immutable task checks and owned cleanup while moving external transports into a separate private composition. It is an optional extension to the provider-free PlzDo core, not a second core or a mandatory model dependency.

Use the current technical design and requirements. Earlier candidate plans and observations are provenance only. Existing private HN operations, automations and source checkouts are unchanged by this candidate.
