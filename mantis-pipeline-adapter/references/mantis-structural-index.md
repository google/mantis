# Reference Blueprint: mantis-structural-index Skill

This is a **reference pointer** that documents the real
`mantis-structural-index` skill. For the complete specification — including
System Goal, Command Definition, Input/Output Contract, Instructions, data
structures (manifest schema, SQLite schema, cache key computation, canonical
symbol IDs), query interface, and safety invariants — see the single source of
truth:

**→
[../../mantis-structural-index/SKILL.md](../../mantis-structural-index/SKILL.md)**

Builders should read that file directly. This blueprint does not duplicate the
spec. If implementation details are needed that are not in the SKILL.md, they
should be added to the SKILL.md first, then referenced here.

## Key Architecture (summary)

The structural index is a content-addressed semantic-unit index with:

- Manifest-based atomic publishing (`manifest.json`) — written LAST as the
  atomic commit point
- SQLite serving store (`catalog.sqlite`) with bidirectional indexes
- Capability-based per-partition backend selection (6 tiers)
- Canonical symbol IDs (scoped, overload-aware, corpus-qualified)
- Bounded query interface with pagination and coverage metadata
- Baseline plus delta overlay architecture (CI baseline + local overlay)
- Deterministic partial coverage (priority queue, no discovery-order truncation)

See the SKILL.md for full details.

Safety guardrails are defined in the canonical
[../../mantis-structural-index/SKILL.md](../../mantis-structural-index/SKILL.md)
under `## Safety`.
