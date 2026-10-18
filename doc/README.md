# ProxySQL documentation guide

## Architecture

Start with the [architecture entry point](architecture.md). The refreshed source-grounded
collection retains the existing architecture's breadth and adds current module relationships,
protocol/tier qualifications and source references:

- [Overview](ai-generated/architecture/ARCHITECTURE-OVERVIEW.md).
- [Traffic runtime](ai-generated/architecture/RUNTIME-ARCHITECTURE.md).
- [Backend resources and monitoring](ai-generated/architecture/BACKEND-MANAGEMENT.md).
- [Administration, synchronization and statistics](ai-generated/architecture/ADMINISTRATION-AND-STATISTICS.md).
- [Visual architecture](ai-generated/architecture/VISUAL-GUIDE.md).
- [Project layout and composition](ai-generated/architecture/PROJECT-LAYOUT.md).

Each document states the investigated source baseline and verification scope. A source-verified
implementation detail is distinct from a maintainer-approved product contract. The
[`ai-generated/` directory name](ai-generated/DOCUMENTATION-INDEX.md) does not establish the
accuracy or currency of every document it contains.

## Product and development references

- [Product invariants](agents/invariants.md): guarantees changes must preserve.
- [Agent guidance](agents/README.md): repository conventions and known failure patterns.
- [Domain terminology](../GLOSSARY.md): resolved architectural vocabulary.
- [Test infrastructure](../test/infra/README.md): supported isolated provisioning/test execution.
- [CI architecture](GH-Actions/README.md): authoritative workflow architecture.
- [DuckDB documentation](duckdb/index.md): plugin tutorial and reference.
- `internal/`: focused implementation guides and investigation evidence.
- `release_notes/`: release history.
- [Repository README](../README.md), [installation](../INSTALL.md) and [FAQ](../FAQ.md).

## Historical exploration guides

The September 2025 [test pipeline](ai-generated/architecture/TEST-PIPELINE.md),
[release pipeline](ai-generated/architecture/RELEASE-PIPELINE.md) and
[enhancement ideas](ai-generated/architecture/ENHANCEMENT-OPPORTUNITIES.md) remain historical
exploration material. Their commands, counts, workflow descriptions and proposed extensions
have not been refreshed by the runtime-architecture investigation. Use the current CI/test
references above for execution. Proposed enhancement ideas are not current architecture or
approved work.

When updating documentation, preserve useful module and flow coverage, verify claims against
the owning source, and identify current behavior separately from intended design. Avoid stale
file counts, artifact sizes, fixed thread counts or deployment defaults without a scoped source.
