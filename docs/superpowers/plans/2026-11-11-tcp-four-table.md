# Four-table TCP configuration implementation plan

> **For agentic workers:** use subagent-driven-development for coordinated OpenCode workers; root owns design, source review and final integration.

**Goal:** Remove standalone TCP backend management and expose only mandatory mappings to existing hostgroup managers.

**Architecture:** Four-table Admin configuration drives the existing native relay and ABI18/V2 backend provider. An early generic core schema check prevents destructive upgrades; an explicit plugin-owned offline converter upgrades saved mappings transactionally.

**Tech Stack:** C++17, SQLite, native sockets, Python test/migration tools, existing HGM services.

**Spec:** docs/superpowers/specs/2026-11-11-tcp-four-table-design.md

## Global constraints

- Mandatory MYSQL/PGSQL mappings; preserve real HGM counters/limits, no reuse, always destroy, OFFLINE_HARD sole force-close authority.
- Exactly four config tables; preserve listener/rule/settings columns and TCP commands/aliases. Source server persistence remains separate.
- No new plugin ABI; immutable core raw service and ownership fence remain intact.
- Preserve uncommitted original work; isolated existing managed worktrees; OpenCode model opencode-go/deepseek-v4.1-flash; no commits/pushes or donor writes.
- Runtime config application and persistence copies are atomic. Legacy DBs never silently lose rows.

## Review focus

- Preflight must run before exact-DDL materialization, including --no-start and STOP/START paths, and inspect every registered persistent plugin table first.
- Converter backup/locking/revalidation/rollback preserve old data on every rejected layout or failure; SQL strings/comments survive unchanged.
- Removing static state must preserve socket ownership, late HARD destruction fence, pending cancellation and no-retry-after-forwarding behavior.
- Tests must replace backend fixtures for relay cases; delete only obsolete standalone policy/health assertions with an explicit retirement list.
- All current examples and tools must use four tables; old benchmark measurements are historical and never relabeled as new runs.

### Task 1: Early schema protection and offline converter

**Files:** core generic plugin schema helper/call site and focused unit tests; plugins/tcp_proxy/tools/migrate_tcp_config.py and focused Python tests. Do not edit production Engine/Admin plugin files.

**Interfaces:** consumes registered ProxySQL_PluginTableDef config definitions and SQLite3DB. Produces bool preflight result plus actionable error, invoked before bootstrap table construction. Converter exact tcp_hostgroups DDL is frozen in spec; CLI --database FILE --check/--apply.

- [x] Add failing core preflight tests: missing/current accepted, later mismatch leaves earlier tables unchanged, malformed SQL/error fails closed.
- [x] Implement generic preflight and early call path; verify non-v4 remains unchanged.
- [x] Add failing converter tests for mapped merge, comments/binary-safe text, static/unmapped/dangling/unknown rejection, backup collision, missing DB, rollback and idempotency.
- [x] Implement explicit transactional offline conversion and tests; compare exact DDL to frozen spec/plugin definition.
- [x] Run focused tests, rebuild matching release core using existing read-only donor dependencies, publish scoped immutable files and hashes.

### Task 2: Unified mandatory-mapping plugin

**Files:** plugins/tcp_proxy/include/*.h, src/*.cpp, Makefile, tests/Makefile, tests/Makefile.admin, tests/engine_unit.cpp, tests/admin_unit.cpp. Delete obsolete health.cpp/selection.cpp if no remaining responsibility. Do not edit tools, core or integration Python/harness files.

**Interfaces:** Hostgroup has exactly hostgroup_id/source_protocol/source_hostgroup/comment; Config has settings/hostgroups/listeners/rules. Snapshot retains global/listener/rule data, no server data. BackendConnection/Provider and core service remain unchanged. Authoritative DDL from spec.

- [x] Add failing tests for new hostgroup mapping definition, provider requirement, invalid/missing destinations and four-table schema/transactions.
- [x] Remove static config/runtime/selection/health path and merge mappings into hostgroups; preserve native relay lifecycle and exact accounting/fences.
- [x] Register four persistent pairs/projections; remove server views/metrics and all ignored knobs; enforce service availability for configured hostgroups.
- [x] Adapt relay test fixtures to injected test backend providers, retain mapped race/ownership coverage, record retired obsolete cases.
- [x] Run Engine/Admin targeted suites, release/debug plugin builds, sanitizers; publish immutable source/binaries and scoped diff.

### Task 3: Composed validation, tools and documentation

**Files:** plugins/tcp_proxy/tests integration Python, harness and Makefile.integration/README.integration.md; doc/tcp-proxy-plugin.md; plugins/tcp_proxy/README.md; new dated benchmark reports. Root refreshes HTML/index and plan/ledger. Consume final Core/Engine artifacts; no product edits without reporting defect.

- [x] Adapt daemon fixtures, harness and applicable adversarial scenarios to four-table product configuration; document retired static-only scenarios.
- [x] Add real-daemon preflight refusal before data loss, converter/startup, four-table persistence, shared source mappings and removed schema/metrics checks.
- [x] Run both-protocol real-daemon lifecycle/accounting/status/monitor tests and relevant relay adversarial cases against final matching immutable artifacts.
- [x] Run measured direct/MySQL/PgSQL/HAProxy short benchmark with byte/counter reconciliation and source/artifact provenance; no static mode.
- [x] Rewrite current configuration guide and integration commands, preserving historical reports as historical.

### Task 4: Root integration and review

- [x] Compare all scoped changes to saved original baseline; independently review core/data migration and plugin lifetime changes; dispatch whole-change review.
- [x] Integrate only reviewed scoped files, including deletions, preserving unrelated work and editable modes; force fresh artifact builds as needed.
- [x] Independently verify relevant Engine/Admin/migration and composed-daemon cases in original checkout; resolve material findings and rerun affected checks.
- [x] Refresh current HTML guide/index/design/plan/benchmark and legacy guide compatibility copy; check files, anchors and docs-only HTTP serving.
- [x] Save final manifest/ledger and report completion with limitations and no commits.

## Final verification

Completed on 2026-11-11. OpenCode `opencode-go/deepseek-v4.1-flash` handled
implementation, test tools, composed testing and the benchmark; root owned the
architecture, integration, source review and independent verification.

- Engine: 65 cases / 1,029 checks, including ASan/UBSan/leak checks. The 21
  retired cases test deleted standalone policy/health/server-stat behavior;
  pending-generation, generic relay and mapped ownership/HARD tests remain.
- Admin: 354 assertions. Core schema preflight: 51 assertions. Converter: 21
  tests with actual legacy fixtures and actual plugin DDL. Release/debug
  plugins build and export only the descriptor. Affected non-v4 core units
  also pass syntax checks; no full non-v4 link is claimed.
- Composed daemon: all five Admin cases and all 15 mapped cases pass, including
  86 portable upgrade checks. All 36 applicable socket adversarial scenarios
  pass; eight obsolete local selection/health scenarios are explicitly retired.
  Final component hashes/build flags exactly match that tested Engine binary.
  MySQL monitoring uses a task-owned mysqld; PostgreSQL monitoring uses a
  controlled wire-protocol fixture, rather than physical replica promotion.
- Root independently rebuilt the original plugin and reran Engine/Admin and
  converter checks. Live tests using actual old-daemon DBs verify refusal
  before data changes, safe conversion, both protocol HGM limits shared by two
  TCP groups, Used/Free drain, fresh connections and saved restart. Seven actual
  core metadata/control probes verify the fail-closed preflight. The root-built
  DSO also passes binary relay/HARD closure against the final host.
- The single measured four-mode benchmark completes with independently
  recomputed exact backend bytes/connections and HGM byte/connection outcomes;
  mapped Used/Free return to zero. These are short local loopback measurements,
  not production capacity estimates. See [the benchmark](../../benchmarks/2026-11-11-tcp-four-table-daemon.md).
- Independent source/spec and code-quality review is clean; reproduced schema
  identity/fail-open defects were fixed and retested. Final evidence and source
  manifests are retained under `/tmp/tcp-four-table/`.

The [configuration guide](../../../doc/tcp-proxy-plugin.md) describes the four
remaining tables and explicit offline upgrade. The [HTML report index](../../tcp-proxy-reports.html)
links current reports and clearly labeled historical snapshots. Changes remain
uncommitted; existing unrelated edits and old measured Markdown/JSON reports
are preserved.
