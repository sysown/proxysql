# Architecture documentation baseline review

Reviewed 2026-10-18 on `docs/invariants-expansion`. This is a documentation comparison,
not a ratified architecture and not a full accuracy audit of the older documentation.

## Baseline

Use the existing architecture collection as the coverage baseline:

- [Architecture overview](../ai-generated/architecture/ARCHITECTURE-OVERVIEW.md): module inventory,
  protocol families, security, query policy, configuration, backend management and metrics.
- [Project layout](../ai-generated/architecture/PROJECT-LAYOUT.md): system composition,
  module relationships, source organization, configuration and deployment views.
- [Visual guide](../ai-generated/architecture/VISUAL-GUIDE.md): system, class, schema, flow,
  protocol-sequence, execution, pooling and deployment views.

The older overview, layout and visual guide were read and have now been refreshed, together
with three detailed subsystem chapters. The older test/release pipeline and enhancement-ideas
documents remain explicitly labelled historical; they were not accuracy-audited in this runtime
architecture investigation. The older material's unverified status called for verification,
not replacement by a narrower map.

## Coverage and revision map

| Baseline area | Material to retain | Verification/update work |
| --- | --- | --- |
| System composition | Clients, protocol entry points, core services, databases, statistics and backends in one view | Correct arrows to distinguish execution calls, policy outputs and stored representations. Separate configured listeners from universal port claims. |
| Protocol families | MySQL/PostgreSQL modules and shared base/template structure | Update actual class/interface names and PostgreSQL backend-driver choices. Feature parity must be checked at consumers. |
| Workers and sessions | Worker sets, session ownership and protocol state machines | Use actual execution contexts; avoid a generic accept-thread/worker-handoff model without tracing it. |
| Backend management | Hostgroups, server eligibility, pooling, multiplexing, topology and consistency constraints | Preserve this as a major subsystem, including monitor collaboration and local/shared pool paths. Do not depict server statuses as a required linear sequence. |
| Query Processor | Analysis/digests, rule matching, flags, rewrite, routing, cache and mirror policy | Retain breadth and distinguish policy generation from session enforcement. Expand execution controls, firewall and statistics. |
| Authentication/security | Frontend flow, wire mechanisms, TLS, credential caches and account policy | Verify current mechanisms, transport requirements and tiers. Add distinct backend identity/provider flows and current passthrough behavior. |
| Prepared statements | Statement metadata, protocol sequences and resource lifetime | Retain as an explicit runtime responsibility; distinguish protocol-specific statement/portal behavior. |
| Query cache | Dedicated module, result storage, expiration and interaction with policy | Verify actual key generation and eligibility rather than inheriting the overview's digest-key assertion. |
| Configuration | MEMORY, DISK and RUNTIME; bootstrap inputs and administrative operations | Distinguish configuration file, persistent SQLite, editable tables, runtime owners and published projections. |
| Cluster | Configuration synchronization, checksums, peer metadata and published resultsets | Place under configuration/administration. Refresh current datasets/extensions; preserve separation from client execution. |
| Statistics | Named Statistics module, SQL surfaces, metrics, runtime measurements | Expand module-owned sampling/history, producer-owned counters, Admin projections, digests, events/audit, metrics export and optional TSDB. |
| Monitoring | Probes, task scheduling, observations and hostgroup actions | Verify each protocol/topology's implementation rather than implying one universal work queue. |
| Deployment | Client/backend topology and external interfaces | Retain deployment context; distinguish configuration synchronization from availability/traffic failover supplied by other deployment mechanisms. |
| Build/composition | Core sources, dependencies, artifacts and optional capabilities | Refresh current tiers and plugin composition; remove stale counts, sizes and development commands. Keep detailed build/testing instructions in their authoritative guides. |
| Lifecycle | Startup and module dependencies | Add verified readiness, partial-failure, reload and draining relationships without letting recent lifecycle changes dominate the product architecture. |

## Source-backed corrections already established

These are specific findings from the current investigation, not an accuracy claim for all
other older statements:

- Protocol workers use ordinary `poll()` paths and conditional idle `epoll` paths. Libev is
  used elsewhere; it is not a complete description of traffic-worker execution.
- Runtime owners publish configuration through different mechanisms. Thread variables and
  query rules have separate version/refresh points.
- Query Processor output is consumed by Session. A diagram showing the processor as the
  direct owner of pool/cache execution obscures that distinction.
- PostgreSQL currently ignores mirror policy outputs; shared policy fields do not prove parity.
- `ProxySQL_Statistics` sampling/history, Admin live statistics projections, runtime producers,
  loggers and metrics export are cooperating but distinct responsibilities.
- Plugin-owned schemas/hooks have shipped consumers. Removed server-module machinery and its
  rejecting ABI stub must be distinguished from those supported extension paths.

Evidence: [state](architecture-state-evidence.md),
[execution/lifecycle](architecture-execution-evidence.md),
[query/authentication](architecture-query-auth-evidence.md), and
[statistics](architecture-statistics-evidence.md).

## Working method

Retain useful baseline sections and diagrams, verify their claims, update stale parts and add
missing current capabilities. Use module relationships and end-to-end flows to explain how the
product works. Add ownership and invariants to that model rather than substituting abstract
responsibility labels for the module architecture. Mark unverified claims and intent questions
at their actual location; do not declare the whole refreshed architecture verified merely because
its links resolve or its Markdown passes checks.
