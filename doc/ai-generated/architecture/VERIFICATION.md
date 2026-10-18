# Architecture investigation and verification record

Date: 2026-10-18. Source baseline: `f8ada9117`. Working branch:
`docs/invariants-expansion`. This record concerns the architecture documentation refresh;
it is not a runtime release certification or ratification of new architecture contracts.

## Delivered coverage

| Document | Investigation scope |
| --- | --- |
| [Overview](ARCHITECTURE-OVERVIEW.md) | Product modules and their collaborations, with explicit Statistics and full Query Processor scope; Cluster under administration |
| [Runtime](RUNTIME-ARCHITECTURE.md) | Protocols/transport, workers/sessions, identity and front/backend authentication, query policy consumers, state virtualization, statements/portals, caching, alternate modes, errors/retries/cancellation |
| [Backend management](BACKEND-MANAGEMENT.md) | Resource ownership, selection/compatibility, local/shared accounting, capacity/waiting, release/reset/destruction, monitoring/topology, DNS/GTID/locality/discovery and published datasets |
| [Administration/statistics](ADMINISTRATION-AND-STATISTICS.md) | Configuration/SQLite transitions, bootstrap, runtime installation, Cluster modes, scheduler/interfaces, statistics producers/projections/history, logs/events, Prometheus and TSDB |
| [Visual guide](VISUAL-GUIDE.md) | Responsibility, execution, data/state, protocol, pooling, statistics, synchronization, lifecycle and composition views |
| [Layout](PROJECT-LAYOUT.md) | Source ownership, core/plugin build graph, tier implications, dependency roles and current test/CI references |

The existing September 2025 overview, layout and visual guide supplied the breadth baseline.
They were refreshed rather than treating an abstract four-box map as sufficient architecture.
Historical test/release pipeline and enhancement-proposal documents are labelled as such;
their detailed workflows were not accuracy-audited by this investigation.

## Substantive source review

Research followed implementation owners and their consumers, not just class names or public
field declarations. Independent cross-reviews checked the synthesis against subsystem source.
Important corrections incorporated during those reviews include:

- Exclusive backend assignment precedes authentication/state synchronization; readiness for
  execution is separate from ownership of the connection object.
- Rule-hit production/aggregation belongs to Query Processor paths; Session supplies other
  completion measurements and event logging.
- Runtime-only Cluster server pulls can install HGM directly, with MEMORY materialization
  only where required for configured persistence.
- Query-event circular-buffer history export is separate from event/audit file output.
- Legacy historical pool/status/cache sampling uses producer APIs directly; materialized
  current SQL tables are not a mandatory intermediate.
- Direct monitor Prometheus refresh and PostgreSQL monitor SQL-counter coverage differ.
- Shared policy outputs and similarly named methods do not establish protocol parity;
  unconsumed policy fields and inactive inherited GTID paths are explicitly qualified.
- Shipped plugin schemas/hooks are distinguished from reserved/removed interfaces and
  provider seams without a located in-tree installer.

The chapters cite source paths, named interfaces, line anchors, tests where relevant, and
selected history. Tests cited as evidence were read, not reported as executed.

## Mechanical and visual checks

- Verified local documentation/source targets, numeric line bounds and linked Markdown headings.
- Canonicalized case-sensitive source paths against Git's tracked names, avoiding macOS-only aliases.
- Checked code-fence balance, Markdown table structure and `git diff --check`.
- Rendered all 25 Mermaid diagrams in the six refreshed architecture documents to SVG using
  Mermaid CLI and local Chrome. Rendered representative module, acquisition and statistics
  diagrams to PNG and visually inspected them.
- Kept generated render outputs and tool dependencies in a temporary workspace, outside the repository.
- Verified changes are documentation/agent guidance on the dedicated branch; no production
  source or test implementation was changed by this refresh.

## Limits and remaining design work

PR preparation applied the three findings from the
[independent diagram review](../../internal/architecture-diagram-review.md): explicit local-cache
hits and release alternatives, runtime-owner history export, and core-protocol listener scope.
All 25 diagrams were rendered again after these changes. The GenAI query-hook description was
also corrected to identify its actual denial capability and disabled/unavailable behavior.

The [documentation-tree coverage audit](../../internal/architecture-coverage-audit.md) identifies
important remaining trust, state-replay, pool-measurement, migration and optional-service gaps.
Closing diagram findings is not a claim that those coverage gaps are closed.

Final local-reference checks cover all 27 changed Markdown files, including new evidence notes.
All new/changed links passed. Five unchanged historical references remain in the explicitly
historical enhancement/release guides: two missing exploration targets and three placeholder
`link` destinations. These are not links introduced by this refresh.

Source inspection establishes implementation evidence, not all intended guarantees or correctness
of every reachable execution. No database integration tests, protocol compatibility suites,
builds or benchmarks were run for this documentation-only change. Link/render checks validate
document structure, not behavioral truth by themselves.

The overview and chapters preserve explicit maintainer questions about configuration visibility,
startup dependency intent, degradation/admission policy, accepted coupling and extension lifetime.
Those questions can now be discussed against concrete module/state/flow descriptions. They were
not silently converted into new product invariants or production-code changes.
