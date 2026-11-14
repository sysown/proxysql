# Shared hostgroup TCP forwarding implementation plan

> For agentic workers: use superpowers:subagent-driven-development; root coordinates OpenCode DeepSeek v4.1 Flash and owns integration/verification.

**Goal:** Map TCP routes to actual MySQL/PostgreSQL HGM connections with unified accounting and always-destroy lifecycle.

**Architecture:** Native epoll relay consumes a core-independent provider, adapted to a borrowed ABI18 core service that registers actual protocol connection objects in existing ConnectionsUsed lists.

**Tech stack:** C++17, existing HGM/monitor/SQLite/plugin services, Python loopback tests/benchmarks.

**Spec:** docs/superpowers/specs/2026-11-11-tcp-hostgroup-mapping-design.md

## Global constraints

- User approved mapping, unified existing counters/limits/status and fast-forward-like always-destroy lifecycle; OFFLINE_HARD alone forces close.
- Preserve static mode and the existing five table definitions; add a sixth mapping pair.
- No SQL/authentication/protocol framing on the native path, no reuse, blocking DNS, worker callbacks retained by core, commits/pushes or donor dependency writes.
- Independent OpenCode workers use isolated existing managed worktrees and opencode-go/deepseek-v4.1-flash. Root integrates scoped reviewed files.

## Review focus

- Pending/queued objects count in the actual HGM, every unwind destroys once, native sockets have one owner.
- HGM TLS policy and lock ordering are valid on acceptor/epoll workers; no fake SQL session.
- OFFLINE_HARD closes idle/pending streams without reroute; old backend identity survives removal and TCP remapping.
- Old persistent TCP rows survive bootstrap; six-table copies are atomic and derived source state is not persisted.
- Stats reflect actual bytes/outcomes, lifecycle stops callers before HGM teardown, ABI17 prefix and v3 behavior survive.

### Task 1: Core HGM raw connection service

- [x] Add frozen service implementation and ABI18 getter/live/phase-B stubs with compatible ABI17 prefix tests.
- [x] Reuse real selection/in-use protocol objects, policy TLS/throttles/DNS cache and existing counters/errors; always destroy safely without protocol state.
- [x] Add failing then passing targeted HGM/service tests and run chassis lifecycle/ABI regressions.
- [x] Build matching release core with read-only donor dependencies and publish immutable manifest/artifact.

### Task 2: Engine provider and Admin mapping integration

- [x] Add HostgroupMapping/provider interfaces, validation and RAII Accepted/Flow ownership; preserve static paths.
- [x] Integrate connect outcomes, HGM wire-byte accounting and periodic OFFLINE_HARD checks without static-ID interference.
- [x] Register sixth table pair/runtime projection and six-table parsing/copy/persistence; retain old DDL.
- [x] Adapter/descriptor release/debug build, meaningful engine/provider/Admin tests, user-guide updates.

### Task 3: Independent composed tests and benchmarks

- [x] Implement daemon tests for both HGM modes and actual monitoring role changes with task-owned fixtures.
- [x] Validate shared Used/Free/limits/counters/errors/bytes, opaque/TLS, SOFT/HARD, pending/removal/remap/restart.
- [x] Run existing adversarial regressions and identical direct/static/mapped MySQL/mapped PG/HAProxy benchmark workloads.
- [x] Publish raw JSON, Markdown and HTML reports with precise full-daemon scope and source/artifact hashes.

### Task 4: Root integration and final review

- [x] Review complete scoped changes and integrate into original without overwriting unrelated work.
- [x] Independently verify targeted engine/Admin/core/composed daemon behavior and release/debug ABI/export/build compatibility.
- [x] Independent final concurrency/lifetime/accounting review, repair reproduced defects and rerun affected checks.
- [x] Refresh HTML reports/index/user guide, record source/test manifests and remaining limitations, report completion without commits.

## Final verification

Implementation and integration completed on 2026-11-11. OpenCode workers used
`opencode-go/deepseek-v4.1-flash`; root owned the design, scoped integration,
independent review and final checks. No commits or pushes were made.

- Engine: 85 cases / 1,382 checks; Admin: 333 assertions; raw HGM service: 100
  assertions. ABI: 73; core lifecycle: 98; listener reservations: 54; managed
  configuration: 13. Release/debug builds and Engine ASan/UBSan/leak checks pass.
- Final composed suite: 12 mapped daemon cases / 154 checks and 44 adversarial
  scenarios pass. Both MySQL and PostgreSQL monitor role changes are exercised;
  PostgreSQL uses a controlled wire fixture, rather than physical replication.
- Root additionally verified five existing static daemon cases, six shutdown
  paths with live mapped connections, and mapped STOP/START for both protocols.
- Independent final concurrency/lifetime/accounting review is clean. It exposed
  and verified fixes for late OFFLINE_HARD during retirement and native
  comparative-latency policy. Atomic destruction returns the final HARD state
  before the Engine decides whether it can retry.
- Five-mode full-daemon benchmark completed with exact backend byte/connection
  reconciliation and mapped HGM byte reconciliation; Used/Free drain to zero.
  Measurements are short loopback runs with Python clients, not production
  capacity estimates. See [the report](../../benchmarks/2026-11-11-tcp-hostgroup-mapping-daemon.md).

Final manifests and raw verification logs are retained under
`/tmp/native-tcp-hgm/`. The reproducible tools live in
`plugins/tcp_proxy/tests/`; the [configuration guide](../../../doc/tcp-proxy-plugin.md)
and [HTML report index](../../tcp-proxy-reports.html) describe usage and results.
