# ProxySQL architecture

The architecture reference is the refreshed collection under
[`doc/ai-generated/architecture/`](ai-generated/architecture/ARCHITECTURE-OVERVIEW.md).
It updates the module/flow descriptions against source baseline `f8ada9117` on 2026-10-18;
the linked coverage audit records omissions and depth limits. The directory name is historical; each document states its
verification scope. Source-backed description is not automatic maintainer ratification
of every observed mechanism, nor a claim that runtime tests passed.

## Read by architectural responsibility

| Reference | Questions it answers |
| --- | --- |
| [Architecture overview](ai-generated/architecture/ARCHITECTURE-OVERVIEW.md) | What are the product's modules, responsibilities and principal collaborations? |
| [Runtime architecture](ai-generated/architecture/RUNTIME-ARCHITECTURE.md) | How do protocols, sessions, authentication, query policy, statements, caching and error handling execute? |
| [Backend management](ai-generated/architecture/BACKEND-MANAGEMENT.md) | Who selects backends, owns connections, controls reuse/capacity and applies monitoring/topology information? |
| [Administration and statistics](ai-generated/architecture/ADMINISTRATION-AND-STATISTICS.md) | How do configuration, Cluster synchronization, SQL management, statistics, history, logs and metrics relate? |
| [Visual guide](ai-generated/architecture/VISUAL-GUIDE.md) | What are the actual responsibility, execution, state and sequence relationships? |
| [Project layout](ai-generated/architecture/PROJECT-LAYOUT.md) | Where do those responsibilities live, and how do build tiers and artifacts compose them? |
| [Verification record](ai-generated/architecture/VERIFICATION.md) | What was investigated and checked, what did independent review correct, and what remains unverified? |

Cluster configuration synchronization is part of configuration administration. The traffic
runtime has substantial protocol, identity, query-policy, execution and resource-management
subsystems. Statistics includes the concrete `ProxySQL_Statistics` module and cooperating
producer/projection/export modules. Lifecycle and optional extensions are additional views
across these responsibilities, not substitutes for the module architecture.

## Architecture, contracts and source evidence

- [Product invariants](agents/invariants.md) are maintainer-agreed guarantees changes must preserve.
- [Glossary](../GLOSSARY.md) records resolved domain terminology.
- The detailed chapters cite source owners and execution consumers, including protocol/tier
  qualifications. An interface declaration alone does not establish an implemented capability.
- [Baseline comparison](internal/architecture-baseline-review.md) records the coverage retained
  from the earlier architecture and the initial verification/update targets.
- [Independent diagram review](internal/architecture-diagram-review.md) records findings and
  their corrections; [coverage audit](internal/architecture-coverage-audit.md) identifies
  important specialist contracts still requiring architectural treatment.
- [State evidence](internal/architecture-state-evidence.md),
  [execution/lifecycle evidence](internal/architecture-execution-evidence.md),
  [query/authentication evidence](internal/architecture-query-auth-evidence.md) and
  [statistics evidence](internal/architecture-statistics-evidence.md) preserve investigation notes.

Read the relevant architecture chapter before implementing or reviewing its area. Follow cited
owners and consumers for the actual path being changed. Separate verified behavior, intended
contracts and known deviations; do not assume every existing mechanism must be preserved or
that a cleaner-looking diagram proves a defect.

## Maintainer decisions still needed

The source investigation identifies concrete intent questions:

1. What worker-observation/consistency guarantees are promised across independently published
   configuration families?
2. Which observed startup relationships are required dependencies, and which are incidental order?
3. Which capability failures must prevent traffic admission versus permit degraded operation?
4. Which cross-area accesses are supported services versus implementation debt?
5. What draining/lifetime contract applies to each supported extension/provider interface?

These questions do not block documenting the verified architecture. New normative guarantees
or production changes require their appropriate maintainer decision and evidence.
