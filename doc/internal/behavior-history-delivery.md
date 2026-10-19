# Twelve-month behavior review: delivery and operator tools

Status: awaiting maintainer answers. Source/history review on 2026-10-19, BASE `70228332135431229940279e49b6db186c6e4241` to END `9516441f7bd6fdb93f255f1881db19ca9ee56778`. No package upgrades, builds or runtime probes were executed. All links are pinned except the explicitly identified upstream systemd macro reference.

This stream screened build/dependency/packaging/workflow/tool changes. Product-tier runtime semantics are reviewed with their subsystem owners. CI/test/documentation changes are inventoried but are not represented as application behavior changes merely because a workflow or test file changed.

## Questions

### DE01 — RPM upgrades stop forcing a service restart

**Activation / integration:** January 2026; RHEL/SUSE packaging paths; actual macro expansion depends on the target distribution.

**Before:** The RPM scriptlets stopped ProxySQL in preun even on upgrade and started it again in postun/posttrans. Initial installation also explicitly enabled the service.

**After:** The specs use systemd_post and systemd_preun; explicit postun/posttrans restart hooks are commented out. Under the standard systemd macros, preun removal handling runs for uninstall, not upgrade, and restart is a separate macro not invoked here.

**Observable effect:** An RPM upgrade no longer requests the former stop/start cycle through these scriptlets. A running service can continue using the old process until a restart is requested elsewhere. This is source/macro reasoning; no package upgrade was executed, and downstream distro hooks must be checked per target.

**Question:** Should RPM upgrades leave restart timing under operator/distribution control?

**Answer:** A: retain no forced upgrade restart; B: automatically restart the service on upgrade

**Evidence:** [068736500](https://github.com/sysown/proxysql/commit/068736500); [docker/images/proxysql/rhel-compliant/rpmmacros/rpmbuild/SPECS/proxysql.spec:47](https://github.com/sysown/proxysql/blob/9516441f7bd6fdb93f255f1881db19ca9ee56778/docker/images/proxysql/rhel-compliant/rpmmacros/rpmbuild/SPECS/proxysql.spec#L47); [docker/images/proxysql/suse-compliant/rpmmacros/rpmbuild/SPECS/proxysql.spec:47](https://github.com/sysown/proxysql/blob/9516441f7bd6fdb93f255f1881db19ca9ee56778/docker/images/proxysql/suse-compliant/rpmmacros/rpmbuild/SPECS/proxysql.spec#L47); [upstream systemd macro definitions](https://github.com/systemd/systemd/blob/main/src/rpm/macros.systemd.in).

### DE02 — Ordinary Darwin/FreeBSD builds gain ClickHouse capability

**Activation / integration:** October 2026; ordinary make/debug on Darwin and FreeBSD, all product tiers.

**Before:** Darwin/FreeBSD selected the legacy build path; the ordinary Linux build already compiled ClickHouse support. The same unqualified make target did not produce the same feature composition across these platforms.

**After:** The top-level build exports PROXYSQLCLICKHOUSE=1 by default and routes ordinary builds through the common path on these platforms. The runtime ClickHouse service remains conditional on the existing clickhouse_server enable flag, which defaults false.

**Observable effect:** An ordinary macOS/FreeBSD build can now support the ClickHouse service without a special ClickHouse build target. This adds compiled capability; it does not by itself enable or bind a listener.

**Question:** Should normal Darwin/FreeBSD builds include ClickHouse capability by default?

**Answer:** Yes / No

**Evidence:** [d7ce280a3](https://github.com/sysown/proxysql/commit/d7ce280a3); [Makefile:112](https://github.com/sysown/proxysql/blob/9516441f7bd6fdb93f255f1881db19ca9ee56778/Makefile#L112); [src/main.cpp:1978](https://github.com/sysown/proxysql/blob/9516441f7bd6fdb93f255f1881db19ca9ee56778/src/main.cpp#L1978); [lib/ProxySQL_GloVars.cpp:270](https://github.com/sysown/proxysql/blob/9516441f7bd6fdb93f255f1881db19ca9ee56778/lib/ProxySQL_GloVars.cpp#L270).

### DE03 — The PostgreSQL user synchronizer disables individually missing roles

**Activation / integration:** August 2026; opt-in operator-managed sample, not a core auto-started service.

**Before:** No repository-provided role-verifier synchronizer owned these user rows. Operators or external automation chose user creation/revocation behavior.

**After:** The sample owns profile-marked rows and defaults missing_role_action to disable. After a successful validated nonempty snapshot, a previously managed active username absent from the source becomes inactive. The source allowlist excludes non-login/superuser/expired/null-verifier roles; keep is configurable. Empty snapshots have the separate DE06 guard.

**Observable effect:** Removing one role from the source allowlist, or letting it expire, can disable that profile-owned ProxySQL account on the next successful run, rather than merely stop refreshing its password.

**Question:** Should disable be the default for individually missing managed roles?

**Answer:** A: disable, as implemented; B: keep the previous account active unless explicitly configured to disable

**Evidence:** [811bedbef](https://github.com/sysown/proxysql/commit/811bedbef); [tools/pgsql_user_sync/proxysql_pgsql_user_sync.py:64](https://github.com/sysown/proxysql/blob/9516441f7bd6fdb93f255f1881db19ca9ee56778/tools/pgsql_user_sync/proxysql_pgsql_user_sync.py#L64); [tools/pgsql_user_sync/proxysql_pgsql_user_sync.py:631](https://github.com/sysown/proxysql/blob/9516441f7bd6fdb93f255f1881db19ca9ee56778/tools/pgsql_user_sync/proxysql_pgsql_user_sync.py#L631); [tools/pgsql_user_sync/create_source_function.sql:1](https://github.com/sysown/proxysql/blob/9516441f7bd6fdb93f255f1881db19ca9ee56778/tools/pgsql_user_sync/create_source_function.sql#L1).

### DE04 — The synchronizer persists successful user loads by default

**Activation / integration:** August 2026; opt-in PostgreSQL user synchronizer; save_to_disk defaults true.

**Before:** The sample and its persistence default did not exist. Core LOAD and SAVE remained separate explicit operations.

**After:** When its plan requires loading, the sample writes editable users, issues LOAD PGSQL USERS TO RUNTIME, then SAVE PGSQL USERS TO DISK by default. --no-save-to-disk/save_to_disk=false leaves persistence elsewhere. A save failure reports partial while the new runtime remains active.

**Observable effect:** Running the sample with its defaults changes future-start credentials as well as current runtime credentials; it is not a runtime-only refresh unless configured that way.

**Question:** What should the synchronizer default be for disk persistence?

**Answer:** A: automatically SAVE after successful LOAD; B: persist only when explicitly opted in

**Evidence:** [811bedbef](https://github.com/sysown/proxysql/commit/811bedbef); [tools/pgsql_user_sync/proxysql_pgsql_user_sync.py:67](https://github.com/sysown/proxysql/blob/9516441f7bd6fdb93f255f1881db19ca9ee56778/tools/pgsql_user_sync/proxysql_pgsql_user_sync.py#L67); [tools/pgsql_user_sync/proxysql_pgsql_user_sync.py:877](https://github.com/sysown/proxysql/blob/9516441f7bd6fdb93f255f1881db19ca9ee56778/tools/pgsql_user_sync/proxysql_pgsql_user_sync.py#L877); [tools/pgsql_user_sync/proxysql_pgsql_user_sync.py:900](https://github.com/sysown/proxysql/blob/9516441f7bd6fdb93f255f1881db19ca9ee56778/tools/pgsql_user_sync/proxysql_pgsql_user_sync.py#L900).

### DE05 — The drift guard covers backend user policy before a global LOAD

**Activation / integration:** August 2026; opt-in PostgreSQL user synchronizer; all profiles.

**Before:** There was no bundled synchronizer with a cross-user MEMORY/RUNTIME consistency admission check.

**After:** Before writing/loading, it fetches main/runtime snapshots with `WHERE backend=1` and compares their backend halves, normalizing `frontend=0` for the comparison. Detected divergence in an unmanaged backend row aborts the plan; a different-profile ownership conflict also aborts it. Frontend-only rows and frontend-eligibility changes are outside this guard, while the later `LOAD PGSQL USERS TO RUNTIME` publishes both namespaces globally.

**Observable effect:** An unrelated staged backend-password change can block credential refresh. An unrelated frontend-only staged edit can instead pass the guard and become active through the global LOAD. The current check is not a guarantee that all unrelated user edits remain unpublished.

**Question:** Which unrelated pending user edits should block the synchronizer before its global LOAD?

**Answer:** A: detected backend-half drift only, as implemented; B: all frontend/backend user-policy drift, requiring a broader guard

**Evidence:** [811bedbef](https://github.com/sysown/proxysql/commit/811bedbef); [snapshot filters:807](https://github.com/sysown/proxysql/blob/9516441f7bd6fdb93f255f1881db19ca9ee56778/tools/pgsql_user_sync/proxysql_pgsql_user_sync.py#L807); [comparison:531](https://github.com/sysown/proxysql/blob/9516441f7bd6fdb93f255f1881db19ca9ee56778/tools/pgsql_user_sync/proxysql_pgsql_user_sync.py#L531); [global refresh:7144](https://github.com/sysown/proxysql/blob/9516441f7bd6fdb93f255f1881db19ca9ee56778/lib/ProxySQL_Admin.cpp#L7144); [all active users:7429](https://github.com/sysown/proxysql/blob/9516441f7bd6fdb93f255f1881db19ca9ee56778/lib/ProxySQL_Admin.cpp#L7429); [namespace flags:7504](https://github.com/sysown/proxysql/blob/9516441f7bd6fdb93f255f1881db19ca9ee56778/lib/ProxySQL_Admin.cpp#L7504).

### DE06 — An empty authoritative role snapshot is rejected by default

**Activation / integration:** August 2026; opt-in PostgreSQL user synchronizer; allow_empty_snapshot defaults false.

**Before:** No bundled importer interpreted an empty role snapshot as either authoritative revocation or a guarded failure.

**After:** Validation rejects an empty snapshot unless explicitly permitted. Thus individually missing roles can be disabled under DE03, but removal of the last eligible role does not by default disable the whole managed set.

**Observable effect:** A deliberately emptied allowlist and an unexpectedly empty source result have the same default refusal boundary. Operators must opt in before an empty result can drive mass disabling.

**Question:** Should empty snapshots require explicit permission?

**Answer:** A: refuse by default, as implemented; B: accept a successfully fetched empty snapshot as authoritative by default

**Evidence:** [811bedbef](https://github.com/sysown/proxysql/commit/811bedbef); [tools/pgsql_user_sync/proxysql_pgsql_user_sync.py:66](https://github.com/sysown/proxysql/blob/9516441f7bd6fdb93f255f1881db19ca9ee56778/tools/pgsql_user_sync/proxysql_pgsql_user_sync.py#L66); [tools/pgsql_user_sync/proxysql_pgsql_user_sync.py:426](https://github.com/sysown/proxysql/blob/9516441f7bd6fdb93f255f1881db19ca9ee56778/tools/pgsql_user_sync/proxysql_pgsql_user_sync.py#L426).

### DE07 — Importer failures may leave partially edited MEMORY rows

**Activation / integration:** August 2026; opt-in PostgreSQL user synchronizer; source validation precedes all writes.

**Before:** No bundled multi-user synchronizer had a repair-on-next-run contract.

**After:** The sample performs Admin row writes through autocommit operations. A mid-write failure can leave part of the plan in main.pgsql_users while runtime is unchanged. No global LOAD is attempted until all planned writes succeed; later runs compare main/runtime and repair owned drift. A later SAVE failure instead leaves the successful runtime active.

**Observable effect:** If the second of several user updates fails, some editable credentials can already be new even though traffic still uses the previous runtime. The tool reports failure/partial rather than rolling the entire operation back.

**Question:** Should failed batches leave owned MEMORY changes for resumable reconciliation?

**Answer:** A: retain the explicit partial/repair-on-next-run behavior; B: require restoration of the prior editable state before reporting a failed batch

**Evidence:** [811bedbef](https://github.com/sysown/proxysql/commit/811bedbef); [tools/pgsql_user_sync/proxysql_pgsql_user_sync.py:836](https://github.com/sysown/proxysql/blob/9516441f7bd6fdb93f255f1881db19ca9ee56778/tools/pgsql_user_sync/proxysql_pgsql_user_sync.py#L836); [tools/pgsql_user_sync/proxysql_pgsql_user_sync.py:900](https://github.com/sysown/proxysql/blob/9516441f7bd6fdb93f255f1881db19ca9ee56778/tools/pgsql_user_sync/proxysql_pgsql_user_sync.py#L900).

## Changes already decided or classified without new policy questions

* **Vendored OpenSSL:** all tiers now use the pinned, statically linked OpenSSL core rather than a selectable system installation. Plugins resolve that process-owned runtime. This changes the dependency/update boundary, but [maintainer-authored #6115](https://github.com/sysown/proxysql/issues/6115) explicitly fixed those decisions, including no system mode and no FIPS claim. They are not reopened. The later [#6213 integration](https://github.com/sysown/proxysql/commit/9ed59e93b) removes Git LFS for vendored archives; a normal clone contains the sources. TLS trust/cipher behavior is reviewed in authentication.
* **Tier composition:** the year introduces the Stable/Innovative/v4 hierarchy, automatic flag propagation, plugin packaging and generic per-tier Linux tarballs. Build availability is distinct from runtime selection: building a plugin does not mean it is loaded. This review does not propose weakening I-2 or treating general correctness fixes as innovative-only.
* **Build correctness:** C++17/platform support, PIC/static linkage, dependencies’ page-size configuration, runtime-package dependency repairs, header/flag invalidation and archive cleanup address build/run correctness. Temporary MAKEOPT and OpenSSL-bundling changes were reverted/replaced; those intermediate mechanisms are not the END policy.
* **Regex/dependency upgrades:** PCRE2/RE2 and ParserSQL changes are inventoried here; externally visible query-rule/parser semantics are in the traffic and existing SET reviews. Merely replacing a tarball is not evidence that every upstream behavior changed in ProxySQL.
* **CI:** the mainline callers now contain tier/skip/artifact identity/runner/cancellation changes, while many reusable job bodies live on the separate GH-Actions branch. This range reviews the callers and local harness, not twelve months of that other branch or actual released artifacts. Labels and docs are not proof of executed test coverage. Nightly simulator defaults and tier choices are visible in the callers; independent unit/sanitizer paths have their own scope.
* **Auxiliary scripts:** release-note generation, lint/coverage tools, test harness orchestration and MCP discovery examples are screened as support/engineering interfaces. MCP service semantics are reviewed in AI services; documentation examples alone do not establish an executed service capability.
* **Shared foundation helpers:** oversized/null Unix socket paths now fail before unlink/bind instead of being truncated; core-dump/diagnostic formatting is bounded; fork/exec descriptor handling is repaired. CIDR matching, PostgreSQL startup escaping and digest-clock conversion are traced in their consuming traffic/statistics paths. Header friend declarations alone are not counted as a running WebUI feature. These source repairs do not create an intent choice to retain unsafe behavior.

## Integration screening coverage

The queue contains cross-stream integrations because build/dependency changes often accompany runtime changes. Source-traced operator questions above are distinguished from path/diff screening and delegated runtime analysis; this is not a claim of a full code review of every CI or dependency line.

| Integration | Date | Disposition |
| --- | --- | --- |
| [c6cbce34b](https://github.com/sysown/proxysql/commit/c6cbce34b15c85ed388f7df5437e515559265354) | 2025-10-20 | Build/support integration with production slices reviewed in traffic/backend/admin/auth/extensions |
| [5018cb66d](https://github.com/sysown/proxysql/commit/5018cb66d9620518ea949d39ab2b219e21f1d36a) | 2025-10-20 | Build/support integration with production slices reviewed in traffic/backend/admin/auth/extensions |
| [eb10eff1e](https://github.com/sysown/proxysql/commit/eb10eff1e1b6ae8221ebcede1c18254a3da18035) | 2025-10-22 | Build/support integration with production slices reviewed in traffic/backend/admin/auth/extensions |
| [08014501e](https://github.com/sysown/proxysql/commit/08014501e1458eb48a94754cc5ccd4e06f9ca184) | 2025-10-24 | Dependency/platform/package changes screened; runtime effects belong to named subsystem streams |
| [a308d26cd](https://github.com/sysown/proxysql/commit/a308d26cd011e9cbdc90cc52a2b3acec3c0b5e0b) | 2025-10-24 | Dependency/platform/package changes screened; runtime effects belong to named subsystem streams |
| [f1426ff99](https://github.com/sysown/proxysql/commit/f1426ff99e6a473a7dfe3a87d3833b86e8dca3f9) | 2025-10-27 | Dependency/platform/package changes screened; runtime effects belong to named subsystem streams |
| [dfd46fee4](https://github.com/sysown/proxysql/commit/dfd46fee4b6dce6867eeb693c0e2a727d6707a65) | 2025-11-04 | Build/support integration with production slices reviewed in traffic/backend/admin/auth/extensions |
| [3db9c0df5](https://github.com/sysown/proxysql/commit/3db9c0df5d891852ce21e6688112376d137381c7) | 2025-11-11 | Dependency/platform/package changes screened; runtime effects belong to named subsystem streams |
| [29a6b8576](https://github.com/sysown/proxysql/commit/29a6b8576a6c382e8bdafc5802b35ddb5667598f) | 2025-11-20 | Build/support integration with production slices reviewed in traffic/backend/admin/auth/extensions |
| [05ab128c4](https://github.com/sysown/proxysql/commit/05ab128c4ad59558b5ba0e1b037f3de07b2f5b61) | 2025-11-25 | Build/support integration with production slices reviewed in traffic/backend/admin/auth/extensions |
| [5d2d26d74](https://github.com/sysown/proxysql/commit/5d2d26d74e8c0eaa3dbf1860ee771d868f9b9bbc) | 2025-12-01 | Dependency/platform/package changes screened; runtime effects belong to named subsystem streams |
| [3c4e09fec](https://github.com/sysown/proxysql/commit/3c4e09fec0bb4261121f53d07c1bc520189486c7) | 2025-12-06 | Dependency/platform/package changes screened; runtime effects belong to named subsystem streams |
| [6534a152b](https://github.com/sysown/proxysql/commit/6534a152b2939c2a99d44afda6e04f118049b5ea) | 2025-12-06 | CI/test/harness/documentation changes; not inferred to change production semantics |
| [efd87ae4d](https://github.com/sysown/proxysql/commit/efd87ae4d4cbf14a9818ba846f0b13af26bc10f7) | 2025-12-19 | Build/support integration with production slices reviewed in traffic/backend/admin/auth/extensions |
| [0b85700e2](https://github.com/sysown/proxysql/commit/0b85700e22f1a886b8f8843168ce67b5052b0b1f) | 2025-12-20 | Build/support integration with production slices reviewed in traffic/backend/admin/auth/extensions |
| [8b6625630](https://github.com/sysown/proxysql/commit/8b66256308d3798529a2050b38af3cf15a6860e1) | 2025-12-23 | Dependency/platform/package changes screened; runtime effects belong to named subsystem streams |
| [4cf85d3ff](https://github.com/sysown/proxysql/commit/4cf85d3ff5b62a084a6c3275ca75b067388a099f) | 2025-12-24 | Dependency/platform/package changes screened; runtime effects belong to named subsystem streams |
| [b2bf3e262](https://github.com/sysown/proxysql/commit/b2bf3e262faceabb2bcdbfb5d09cebcf52f0fdea) | 2025-12-24 | Operator/support/lint/release/example tooling; no additional product-policy question found in screen |
| [96af0fd22](https://github.com/sysown/proxysql/commit/96af0fd22ed756a5a075c78f7a0874e6cb90bd8f) | 2025-12-24 | Dependency/platform/package changes screened; runtime effects belong to named subsystem streams |
| [2d1140581](https://github.com/sysown/proxysql/commit/2d1140581d80eff3158214b2163db31601044089) | 2025-12-25 | Build/support integration with production slices reviewed in traffic/backend/admin/auth/extensions |
| [e6cbdcad7](https://github.com/sysown/proxysql/commit/e6cbdcad7f8de61c62afd8606684b6381978d76c) | 2026-01-09 | Build/support integration with production slices reviewed in traffic/backend/admin/auth/extensions |
| [c6ed5b96c](https://github.com/sysown/proxysql/commit/c6ed5b96cdf5a63d69f5d87c3488496e569bf9b3) | 2026-01-12 | Build/support integration with production slices reviewed in traffic/backend/admin/auth/extensions |
| [068736500](https://github.com/sysown/proxysql/commit/068736500314986d3827cae1eb4c7ee9e6136f13) | 2026-01-12 | RPM lifecycle scriptlets; DE01 |
| [a8e759c97](https://github.com/sysown/proxysql/commit/a8e759c9707850cae1e68010961ff53d614578fc) | 2026-01-12 | Dependency/platform/package changes screened; runtime effects belong to named subsystem streams |
| [9f377eec4](https://github.com/sysown/proxysql/commit/9f377eec4ed13325143d1dd9751f670ccd9e0bd7) | 2026-01-16 | Dependency/platform/package changes screened; runtime effects belong to named subsystem streams |
| [3bcb9e0bd](https://github.com/sysown/proxysql/commit/3bcb9e0bd584cb9cac0257592400605fea49f484) | 2026-01-16 | Build/support integration with production slices reviewed in traffic/backend/admin/auth/extensions |
| [2637d28f3](https://github.com/sysown/proxysql/commit/2637d28f365b1e765875dabfb2a0af4c96a906e5) | 2026-01-16 | Build/support integration with production slices reviewed in traffic/backend/admin/auth/extensions |
| [69ea21ef4](https://github.com/sysown/proxysql/commit/69ea21ef417b5c2cc737dbc08a0f4e61189cab86) | 2026-02-03 | Dependency/platform/package changes screened; runtime effects belong to named subsystem streams |
| [052436332](https://github.com/sysown/proxysql/commit/0524363322d4ebdc2e6473d0a9059a5556cc0e73) | 2026-02-05 | Dependency/platform/package changes screened; runtime effects belong to named subsystem streams |
| [a360dc22a](https://github.com/sysown/proxysql/commit/a360dc22aed7de67d7349886b936a25d94a3c2a5) | 2026-02-06 | Dependency/platform/package changes screened; runtime effects belong to named subsystem streams |
| [8655f398e](https://github.com/sysown/proxysql/commit/8655f398e137535177fde46bfa5fb6e0891f194b) | 2026-02-07 | Dependency/platform/package changes screened; runtime effects belong to named subsystem streams |
| [bcbbab88a](https://github.com/sysown/proxysql/commit/bcbbab88a9ec1c6bde8e2923fa28c7b402ea83da) | 2026-02-07 | Dependency/platform/package changes screened; runtime effects belong to named subsystem streams |
| [11251a9ad](https://github.com/sysown/proxysql/commit/11251a9ad942bfda5db59f21608393ba15f2d7f5) | 2026-02-09 | Dependency/platform/package changes screened; runtime effects belong to named subsystem streams |
| [0e605f417](https://github.com/sysown/proxysql/commit/0e605f41704652b47a76c19a930e581cb0fc8583) | 2026-02-09 | CI/test/harness/documentation changes; not inferred to change production semantics |
| [3b578db4b](https://github.com/sysown/proxysql/commit/3b578db4bf767b29ad25b71c500eeaff200749cd) | 2026-02-15 | Dependency/platform/package changes screened; runtime effects belong to named subsystem streams |
| [10ff1322b](https://github.com/sysown/proxysql/commit/10ff1322ba16401c94a819f355b4a1f35749d9d7) | 2026-02-17 | Build/support integration with production slices reviewed in traffic/backend/admin/auth/extensions |
| [bad7ce40c](https://github.com/sysown/proxysql/commit/bad7ce40c5598b1d229e4fcd37499e04a2d7243a) | 2026-02-18 | Build/support integration with production slices reviewed in traffic/backend/admin/auth/extensions |
| [9e157d2aa](https://github.com/sysown/proxysql/commit/9e157d2aa37868ce96fd2f793e687b41901f6c50) | 2026-02-19 | Build/support integration with production slices reviewed in traffic/backend/admin/auth/extensions |
| [b64f2e561](https://github.com/sysown/proxysql/commit/b64f2e56149fbc10a85ff55ca29928b958f44fe5) | 2026-02-20 | Build/support integration with production slices reviewed in traffic/backend/admin/auth/extensions |
| [d683dd7b8](https://github.com/sysown/proxysql/commit/d683dd7b8b4ac1fffd723d30ff811e49952909fd) | 2026-02-25 | Build/support integration with production slices reviewed in traffic/backend/admin/auth/extensions |
| [d3af6c11b](https://github.com/sysown/proxysql/commit/d3af6c11bf6682d94bcd6825f26942f631bb9474) | 2026-03-06 | Dependency/platform/package changes screened; runtime effects belong to named subsystem streams |
| [c60f390b4](https://github.com/sysown/proxysql/commit/c60f390b447b758bb592130872b073cee47c86c7) | 2026-03-06 | Build/support integration with production slices reviewed in traffic/backend/admin/auth/extensions |
| [d3f7d2da4](https://github.com/sysown/proxysql/commit/d3f7d2da4c225cc82ae3f4df83229dfd8cb3843d) | 2026-03-07 | Dependency/platform/package changes screened; runtime effects belong to named subsystem streams |
| [8a1a942d6](https://github.com/sysown/proxysql/commit/8a1a942d659ded6b01b8bf375760813faf80a01f) | 2026-03-09 | Operator/support/lint/release/example tooling; no additional product-policy question found in screen |
| [eb2bb39da](https://github.com/sysown/proxysql/commit/eb2bb39da5bb3b9c7cca50b5dba060c776bbd605) | 2026-03-10 | Dependency/platform/package changes screened; runtime effects belong to named subsystem streams |
| [458ef0197](https://github.com/sysown/proxysql/commit/458ef01970eb30b67b7ff57c4108b9e177a1cf19) | 2026-03-19 | Dependency/platform/package changes screened; runtime effects belong to named subsystem streams |
| [1a0dea6da](https://github.com/sysown/proxysql/commit/1a0dea6da05c29a741978de1012c9313129e6467) | 2026-03-20 | Build/support integration with production slices reviewed in traffic/backend/admin/auth/extensions |
| [540fa174b](https://github.com/sysown/proxysql/commit/540fa174b4160a47b53ae734776b65e663d325e3) | 2026-03-20 | Build/support integration with production slices reviewed in traffic/backend/admin/auth/extensions |
| [7918e1737](https://github.com/sysown/proxysql/commit/7918e1737d940ad4929b50359be9bddb73fd0702) | 2026-03-20 | Dependency/platform/package changes screened; runtime effects belong to named subsystem streams |
| [0e955cd4b](https://github.com/sysown/proxysql/commit/0e955cd4bcd12cfb684bb07abb458533d819a03e) | 2026-03-20 | Dependency/platform/package changes screened; runtime effects belong to named subsystem streams |
| [9b482eb07](https://github.com/sysown/proxysql/commit/9b482eb076dcb4a634a2fd63228a35f35e0a667e) | 2026-03-21 | CI/test/harness/documentation changes; not inferred to change production semantics |
| [16529445b](https://github.com/sysown/proxysql/commit/16529445bf2c98e7473effd2bad54139c3042cad) | 2026-03-22 | Build/support integration with production slices reviewed in traffic/backend/admin/auth/extensions |
| [6e84e42ca](https://github.com/sysown/proxysql/commit/6e84e42cae65263dfa988a75d6d104166aa8368d) | 2026-03-23 | CI/test/harness/documentation changes; not inferred to change production semantics |
| [d1c86b141](https://github.com/sysown/proxysql/commit/d1c86b141f997f34d93c25480567bdbb687112e6) | 2026-03-23 | CI/test/harness/documentation changes; not inferred to change production semantics |
| [e067683f4](https://github.com/sysown/proxysql/commit/e067683f4e022ac96f37716d413c2c97404a5c11) | 2026-03-31 | Build/support integration with production slices reviewed in traffic/backend/admin/auth/extensions |
| [d0625dc24](https://github.com/sysown/proxysql/commit/d0625dc243296b99c199203982aa508078580447) | 2026-03-31 | Build/support integration with production slices reviewed in traffic/backend/admin/auth/extensions |
| [d7a26b79e](https://github.com/sysown/proxysql/commit/d7a26b79e936557e2d198148ce6d09111210d651) | 2026-04-05 | CI/test/harness/documentation changes; not inferred to change production semantics |
| [8579f4dc7](https://github.com/sysown/proxysql/commit/8579f4dc7fc7cfb25b39ac47a5fbce12ef37a089) | 2026-04-08 | Dependency/platform/package changes screened; runtime effects belong to named subsystem streams |
| [f713d78e4](https://github.com/sysown/proxysql/commit/f713d78e4136fd36cc85d24ccd1e1c7f1ceb75e9) | 2026-04-09 | Build/support integration with production slices reviewed in traffic/backend/admin/auth/extensions |
| [1a8e4ed91](https://github.com/sysown/proxysql/commit/1a8e4ed91882c8b0645360c92ca668c7bf3e765b) | 2026-04-09 | Dependency/platform/package changes screened; runtime effects belong to named subsystem streams |
| [7f14beedc](https://github.com/sysown/proxysql/commit/7f14beedc15d6d48fc510c6d393743b530630f65) | 2026-04-09 | Build/support integration with production slices reviewed in traffic/backend/admin/auth/extensions |
| [29a95af03](https://github.com/sysown/proxysql/commit/29a95af031b67d8d595688803dcf6c3bdde0d558) | 2026-04-09 | Build/support integration with production slices reviewed in traffic/backend/admin/auth/extensions |
| [669ab9149](https://github.com/sysown/proxysql/commit/669ab914948f03b10c1ded21a4361d283cd9652d) | 2026-04-10 | Dependency/platform/package changes screened; runtime effects belong to named subsystem streams |
| [904807cf9](https://github.com/sysown/proxysql/commit/904807cf90d86613ebc842da78234f3676642840) | 2026-04-10 | CI/test/harness/documentation changes; not inferred to change production semantics |
| [e0fded870](https://github.com/sysown/proxysql/commit/e0fded870d6353aca1e0138f133a71421d71ba33) | 2026-04-11 | CI/test/harness/documentation changes; not inferred to change production semantics |
| [e3e769f37](https://github.com/sysown/proxysql/commit/e3e769f3726940ecdf4b257b5829d62d4049ea2e) | 2026-04-11 | CI/test/harness/documentation changes; not inferred to change production semantics |
| [da0e67b58](https://github.com/sysown/proxysql/commit/da0e67b587b12a9538c0d5a09295d14225049931) | 2026-04-12 | CI/test/harness/documentation changes; not inferred to change production semantics |
| [c678ae40d](https://github.com/sysown/proxysql/commit/c678ae40d7ddc0a8ecd08f72a7fea18d572a7bfb) | 2026-04-12 | Dependency/platform/package changes screened; runtime effects belong to named subsystem streams |
| [6cab7bd13](https://github.com/sysown/proxysql/commit/6cab7bd13b06bc12bed928bfc9eddab050bb382d) | 2026-04-13 | Build/support integration with production slices reviewed in traffic/backend/admin/auth/extensions |
| [c75e222ce](https://github.com/sysown/proxysql/commit/c75e222ce5f465840e97665316cfcf75bff2a63a) | 2026-04-13 | Build/support integration with production slices reviewed in traffic/backend/admin/auth/extensions |
| [c05302b95](https://github.com/sysown/proxysql/commit/c05302b95458d9b58470bf78155f243225a97f01) | 2026-04-14 | CI/test/harness/documentation changes; not inferred to change production semantics |
| [824588d19](https://github.com/sysown/proxysql/commit/824588d1983f850a941496683d82838b216d5c4c) | 2026-04-14 | Dependency/platform/package changes screened; runtime effects belong to named subsystem streams |
| [17a54193c](https://github.com/sysown/proxysql/commit/17a54193cc352ab721e959d8d3326f4373e338ed) | 2026-04-17 | Build/support integration with production slices reviewed in traffic/backend/admin/auth/extensions |
| [dbb40a30b](https://github.com/sysown/proxysql/commit/dbb40a30baec7d23568ebe2d2b228737d31dfcba) | 2026-04-19 | Dependency/platform/package changes screened; runtime effects belong to named subsystem streams |
| [872479aeb](https://github.com/sysown/proxysql/commit/872479aebae81bf7b4505477c7857786554c39aa) | 2026-04-19 | CI/test/harness/documentation changes; not inferred to change production semantics |
| [795b56a1e](https://github.com/sysown/proxysql/commit/795b56a1e5ed6811360e24e226a59de657b2cbb9) | 2026-04-22 | Build/support integration with production slices reviewed in traffic/backend/admin/auth/extensions |
| [8c9ed94b5](https://github.com/sysown/proxysql/commit/8c9ed94b5316cdcd6b245983687922c5162711ad) | 2026-04-22 | Operator/support/lint/release/example tooling; no additional product-policy question found in screen |
| [9727871a1](https://github.com/sysown/proxysql/commit/9727871a16875f57319b1b782a5054171bafdada) | 2026-04-22 | Operator/support/lint/release/example tooling; no additional product-policy question found in screen |
| [7ca0d153c](https://github.com/sysown/proxysql/commit/7ca0d153cc1c53df120d8048a8d2c814a3aeecc5) | 2026-04-23 | Build/support integration with production slices reviewed in traffic/backend/admin/auth/extensions |
| [5cfeb2ed3](https://github.com/sysown/proxysql/commit/5cfeb2ed39138a07aeec6f252820f191288adb7c) | 2026-04-24 | CI/test/harness/documentation changes; not inferred to change production semantics |
| [4cd48b9db](https://github.com/sysown/proxysql/commit/4cd48b9db6a043ab20113718f8011a8e10c8ab69) | 2026-04-23 | CI/test/harness/documentation changes; not inferred to change production semantics |
| [1c654339c](https://github.com/sysown/proxysql/commit/1c654339c9da9acd54fa8461f99bcbc3bf7d6d74) | 2026-04-23 | CI/test/harness/documentation changes; not inferred to change production semantics |
| [05848ef2e](https://github.com/sysown/proxysql/commit/05848ef2e44ef64a7496de42537a5df40edd9456) | 2026-04-23 | CI/test/harness/documentation changes; not inferred to change production semantics |
| [f7e3d2b26](https://github.com/sysown/proxysql/commit/f7e3d2b26f7ca5e59a09a2bdbbf72ac8604482e9) | 2026-04-23 | Transient build/bundling adjustment reverted or replaced before END |
| [98f9e185c](https://github.com/sysown/proxysql/commit/98f9e185c89fd8f030381ffb05aa3ab2400e7df3) | 2026-04-23 | Transient build/bundling adjustment reverted or replaced before END |
| [a12b62a57](https://github.com/sysown/proxysql/commit/a12b62a575fcb8396332ab3a703a705d7c53e511) | 2026-04-23 | Transient build/bundling adjustment reverted or replaced before END |
| [085c88003](https://github.com/sysown/proxysql/commit/085c8800309874a570576c70bc8c1054ab2dde10) | 2026-04-23 | Transient build/bundling adjustment reverted or replaced before END |
| [0f2b3e64a](https://github.com/sysown/proxysql/commit/0f2b3e64a5f3cf77d1b32d623a0be99218d1d3d7) | 2026-04-24 | Dependency/platform/package changes screened; runtime effects belong to named subsystem streams |
| [e4386a984](https://github.com/sysown/proxysql/commit/e4386a98404a5ed1aa2c1dc4c221a0a72e4ff043) | 2026-04-24 | CI/test/harness/documentation changes; not inferred to change production semantics |
| [0ef544c77](https://github.com/sysown/proxysql/commit/0ef544c7729a6328553d87d4796f9a7f84716119) | 2026-04-24 | CI/test/harness/documentation changes; not inferred to change production semantics |
| [6ef036a00](https://github.com/sysown/proxysql/commit/6ef036a00c6f1dbcf3f27fe7f6e07f3211d7d6f8) | 2026-04-24 | CI/test/harness/documentation changes; not inferred to change production semantics |
| [41c80e30e](https://github.com/sysown/proxysql/commit/41c80e30ebb9f1f5aa818ad2a0a640b99e7a0791) | 2026-04-30 | CI/test/harness/documentation changes; not inferred to change production semantics |
| [849fad944](https://github.com/sysown/proxysql/commit/849fad94401588623cc58e9e1ca560a7bfdce2fc) | 2026-05-01 | Dependency/platform/package changes screened; runtime effects belong to named subsystem streams |
| [b720b43d4](https://github.com/sysown/proxysql/commit/b720b43d4caae786d9294c52c72b46b4f3c0c81b) | 2026-05-02 | Dependency/platform/package changes screened; runtime effects belong to named subsystem streams |
| [683fc7d84](https://github.com/sysown/proxysql/commit/683fc7d841c147f661e1088b0538a01381aab419) | 2026-05-02 | CI/test/harness/documentation changes; not inferred to change production semantics |
| [d564d3cdb](https://github.com/sysown/proxysql/commit/d564d3cdb5cc76bfd295283bd37d485f6850a57f) | 2026-05-03 | CI/test/harness/documentation changes; not inferred to change production semantics |
| [40ee836fc](https://github.com/sysown/proxysql/commit/40ee836fc0cebdc2dfc2f71dd29922dcf5d259be) | 2026-05-03 | Build/support integration with production slices reviewed in traffic/backend/admin/auth/extensions |
| [65c522e63](https://github.com/sysown/proxysql/commit/65c522e635606c74884828a1c28db7becfda15fa) | 2026-05-03 | Dependency/platform/package changes screened; runtime effects belong to named subsystem streams |
| [f3214abce](https://github.com/sysown/proxysql/commit/f3214abce1ae9c74c01742bb24aed72f60cfa592) | 2026-05-03 | CI/test/harness/documentation changes; not inferred to change production semantics |
| [05d0268f7](https://github.com/sysown/proxysql/commit/05d0268f78d76be64e429f8d363c5ce3d999e067) | 2026-05-03 | Dependency/platform/package changes screened; runtime effects belong to named subsystem streams |
| [5e1ee6bc4](https://github.com/sysown/proxysql/commit/5e1ee6bc4102d1d4915d636ede4256d0abbf90d6) | 2026-05-04 | CI/test/harness/documentation changes; not inferred to change production semantics |
| [d16e32c5e](https://github.com/sysown/proxysql/commit/d16e32c5e12d6a5d14ef35462c0353331062b547) | 2026-05-04 | Build/support integration with production slices reviewed in traffic/backend/admin/auth/extensions |
| [6fb2f1ae9](https://github.com/sysown/proxysql/commit/6fb2f1ae994802cd6a4d8136c26a3b6d20afdcbb) | 2026-05-04 | Dependency/platform/package changes screened; runtime effects belong to named subsystem streams |
| [71fd8e134](https://github.com/sysown/proxysql/commit/71fd8e13410e1f308ba30e3b762ad25b0b9965c2) | 2026-05-04 | Dependency/platform/package changes screened; runtime effects belong to named subsystem streams |
| [46e8a9f69](https://github.com/sysown/proxysql/commit/46e8a9f69b431fc63113e15889aec6ad71282202) | 2026-05-04 | Operator/support/lint/release/example tooling; no additional product-policy question found in screen |
| [11eb213f9](https://github.com/sysown/proxysql/commit/11eb213f975a1bedcbb9009d56ecbd50f77ca3fe) | 2026-05-05 | CI/test/harness/documentation changes; not inferred to change production semantics |
| [9cc20a877](https://github.com/sysown/proxysql/commit/9cc20a8775f6c194335a940ed0ca12001166522a) | 2026-05-06 | CI/test/harness/documentation changes; not inferred to change production semantics |
| [0ceb33680](https://github.com/sysown/proxysql/commit/0ceb3368042947f00e7c1d8372d7c88f3a3214a5) | 2026-05-14 | Dependency/platform/package changes screened; runtime effects belong to named subsystem streams |
| [185abefec](https://github.com/sysown/proxysql/commit/185abefec1c0862fd5c14465e84f1ace099a894b) | 2026-05-14 | Dependency/platform/package changes screened; runtime effects belong to named subsystem streams |
| [939962837](https://github.com/sysown/proxysql/commit/939962837a07f641321dd2538635e8a74735c03f) | 2026-05-18 | CI/test/harness/documentation changes; not inferred to change production semantics |
| [9719d4ae0](https://github.com/sysown/proxysql/commit/9719d4ae0591d8de905b9456df08c3e95117d220) | 2026-05-23 | Dependency/platform/package changes screened; runtime effects belong to named subsystem streams |
| [453c7554b](https://github.com/sysown/proxysql/commit/453c7554bff14acdea1b4896e98157a6bcf2d19e) | 2026-05-24 | Dependency/platform/package changes screened; runtime effects belong to named subsystem streams |
| [0c44f394b](https://github.com/sysown/proxysql/commit/0c44f394b37e51de94f601c13bea00475ba193e0) | 2026-05-24 | Dependency/platform/package changes screened; runtime effects belong to named subsystem streams |
| [7bd9339c3](https://github.com/sysown/proxysql/commit/7bd9339c318e67d5d0a036d06ae840285141544f) | 2026-05-25 | Build/support integration with production slices reviewed in traffic/backend/admin/auth/extensions |
| [a1ca6a0ca](https://github.com/sysown/proxysql/commit/a1ca6a0ca39339ea2361fdca816730bf6a23ca77) | 2026-05-26 | Dependency/platform/package changes screened; runtime effects belong to named subsystem streams |
| [b5b4d8bd1](https://github.com/sysown/proxysql/commit/b5b4d8bd13c3ccf2d4b8e532c94a788530995c37) | 2026-05-26 | CI/test/harness/documentation changes; not inferred to change production semantics |
| [cae8c76e1](https://github.com/sysown/proxysql/commit/cae8c76e124a35b12d05e50109c1ac45ccd79b43) | 2026-05-27 | CI/test/harness/documentation changes; not inferred to change production semantics |
| [7ddb3dc01](https://github.com/sysown/proxysql/commit/7ddb3dc015d1440e8a0fb0bbafa2df9aaaa2669d) | 2026-06-05 | Dependency/platform/package changes screened; runtime effects belong to named subsystem streams |
| [8e0060f69](https://github.com/sysown/proxysql/commit/8e0060f6915863a577a804edc14ea7559fc9c7ad) | 2026-06-13 | Build/support integration with production slices reviewed in traffic/backend/admin/auth/extensions |
| [3a9eff2ab](https://github.com/sysown/proxysql/commit/3a9eff2abccef04658871f5a2bfe014b2fe6dd30) | 2026-06-13 | Dependency/platform/package changes screened; runtime effects belong to named subsystem streams |
| [74a33cac6](https://github.com/sysown/proxysql/commit/74a33cac696a15940c1e73308a6981396610581b) | 2026-06-13 | Build/support integration with production slices reviewed in traffic/backend/admin/auth/extensions |
| [2deb0acc3](https://github.com/sysown/proxysql/commit/2deb0acc3e7702a2f42c60fbb80e0a4c77883e74) | 2026-06-16 | Dependency/platform/package changes screened; runtime effects belong to named subsystem streams |
| [e069bfc1e](https://github.com/sysown/proxysql/commit/e069bfc1ec92a3c60a2f2f44289b05ddb71ae64b) | 2026-07-05 | Dependency/platform/package changes screened; runtime effects belong to named subsystem streams |
| [1d500f047](https://github.com/sysown/proxysql/commit/1d500f04739c00d3b01960b54851569ef70011ee) | 2026-07-05 | CI/test/harness/documentation changes; not inferred to change production semantics |
| [2b2d3d109](https://github.com/sysown/proxysql/commit/2b2d3d109ee7dc9e55eda336d8deff12d73520c4) | 2026-07-07 | CI/test/harness/documentation changes; not inferred to change production semantics |
| [49ed2ed78](https://github.com/sysown/proxysql/commit/49ed2ed7831eaffac26be3c380e95a7f88978511) | 2026-07-07 | CI/test/harness/documentation changes; not inferred to change production semantics |
| [ee6cdb935](https://github.com/sysown/proxysql/commit/ee6cdb935899e5795c9703a3bc9d2a5072721ef2) | 2026-07-07 | Build/support integration with production slices reviewed in traffic/backend/admin/auth/extensions |
| [f9b9cf485](https://github.com/sysown/proxysql/commit/f9b9cf485931ce54452b5fd61ce5df1d38e5914c) | 2026-07-07 | CI/test/harness/documentation changes; not inferred to change production semantics |
| [ba546d74f](https://github.com/sysown/proxysql/commit/ba546d74f567ca791a0765afa74481a628783e6c) | 2026-07-08 | Dependency/platform/package changes screened; runtime effects belong to named subsystem streams |
| [2365a46a9](https://github.com/sysown/proxysql/commit/2365a46a92ad8fbdd4c0f48d7e6c03eb000cdbff) | 2026-07-08 | CI/test/harness/documentation changes; not inferred to change production semantics |
| [693013468](https://github.com/sysown/proxysql/commit/693013468a2f9c0076e198aeb986e8a2068c7ea5) | 2026-07-08 | Dependency/platform/package changes screened; runtime effects belong to named subsystem streams |
| [0932b0953](https://github.com/sysown/proxysql/commit/0932b0953135aeda4ac7efb503404e8e64decf25) | 2026-07-08 | Transient build/bundling adjustment reverted or replaced before END |
| [4a6658c0f](https://github.com/sysown/proxysql/commit/4a6658c0fd6107300d54b5ca9552f3ec9c9b0033) | 2026-07-08 | Transient build/bundling adjustment reverted or replaced before END |
| [b0f867847](https://github.com/sysown/proxysql/commit/b0f867847f8a73fa68d8b3593025db2d9734a32d) | 2026-07-08 | Dependency/platform/package changes screened; runtime effects belong to named subsystem streams |
| [1cc46d504](https://github.com/sysown/proxysql/commit/1cc46d50423c874471c0eec948cdfbf52a79d079) | 2026-07-08 | CI/test/harness/documentation changes; not inferred to change production semantics |
| [0a4349a70](https://github.com/sysown/proxysql/commit/0a4349a706dda2459a65b2ad05907bcfed18ed10) | 2026-07-08 | CI/test/harness/documentation changes; not inferred to change production semantics |
| [d5dc69f41](https://github.com/sysown/proxysql/commit/d5dc69f410f654010e656c8465cef88083ec645a) | 2026-07-08 | Dependency/platform/package changes screened; runtime effects belong to named subsystem streams |
| [495553aaa](https://github.com/sysown/proxysql/commit/495553aaa97d726aa6b721d1699b4692baf140a4) | 2026-07-09 | Dependency/platform/package changes screened; runtime effects belong to named subsystem streams |
| [e9dfbeb21](https://github.com/sysown/proxysql/commit/e9dfbeb21dd7225d0cc123b57651b489a05258c0) | 2026-07-11 | Build/support integration with production slices reviewed in traffic/backend/admin/auth/extensions |
| [c2271c1e8](https://github.com/sysown/proxysql/commit/c2271c1e89d05d8681551ec7cfe427caff3dbb63) | 2026-07-11 | Darwin TAP/runtime library link-variable repair |
| [20bbe92a0](https://github.com/sysown/proxysql/commit/20bbe92a0258e78293f3f1359ee901b7aae164bb) | 2026-07-21 | Build/support integration with production slices reviewed in traffic/backend/admin/auth/extensions |
| [c66549e14](https://github.com/sysown/proxysql/commit/c66549e142192932186961f48dca681f0b19cc5d) | 2026-07-27 | Build/support integration with production slices reviewed in traffic/backend/admin/auth/extensions |
| [4390f96f5](https://github.com/sysown/proxysql/commit/4390f96f50367abee9cd5238624a2ac1343bf42e) | 2026-07-27 | CI/test/harness/documentation changes; not inferred to change production semantics |
| [691309e1e](https://github.com/sysown/proxysql/commit/691309e1ec60da6f4422ebdf0b063d5535e29c76) | 2026-07-29 | Build/support integration with production slices reviewed in traffic/backend/admin/auth/extensions |
| [a8c1cef4d](https://github.com/sysown/proxysql/commit/a8c1cef4d44c4beea7f6aa21b8a09a7cb8c75520) | 2026-07-29 | Build/support integration with production slices reviewed in traffic/backend/admin/auth/extensions |
| [8ca2df54f](https://github.com/sysown/proxysql/commit/8ca2df54f6ecb5b15712a27d4e813162cbb0523e) | 2026-07-29 | Dependency/platform/package changes screened; runtime effects belong to named subsystem streams |
| [8bafb8664](https://github.com/sysown/proxysql/commit/8bafb866476be05e4774265112eb68a2a02418e4) | 2026-07-30 | CI/test/harness/documentation changes; not inferred to change production semantics |
| [b3dd57de3](https://github.com/sysown/proxysql/commit/b3dd57de3cf34b4c47168d2e79ee613ce3031ddf) | 2026-07-30 | CI/test/harness/documentation changes; not inferred to change production semantics |
| [f5f1e148e](https://github.com/sysown/proxysql/commit/f5f1e148eab2ffd317babba66d283f0b5a6be7b0) | 2026-07-30 | Dependency/platform/package changes screened; runtime effects belong to named subsystem streams |
| [4362ea995](https://github.com/sysown/proxysql/commit/4362ea99539a9ce7f9c011aafe9a159bd423eabe) | 2026-08-08 | CI/test/harness/documentation changes; not inferred to change production semantics |
| [90d4cc18b](https://github.com/sysown/proxysql/commit/90d4cc18bfe2fc8c8a5c32a7b068332e9db5a09f) | 2026-08-08 | Dependency/platform/package changes screened; runtime effects belong to named subsystem streams |
| [3849dec4a](https://github.com/sysown/proxysql/commit/3849dec4a9d9d1860f18a79633932131c6e5a9d5) | 2026-08-09 | Build/support integration with production slices reviewed in traffic/backend/admin/auth/extensions |
| [bb60ec7ae](https://github.com/sysown/proxysql/commit/bb60ec7aed5ad8f698474b1014363e6b1496d7d6) | 2026-08-09 | Dependency/platform/package changes screened; runtime effects belong to named subsystem streams |
| [e120e435f](https://github.com/sysown/proxysql/commit/e120e435fbfc8ea83b1b45770ff69c50e5cf4876) | 2026-08-09 | CI/test/harness/documentation changes; not inferred to change production semantics |
| [389929fdc](https://github.com/sysown/proxysql/commit/389929fdcf37a352c06a60ff051cff9781076481) | 2026-08-09 | Dependency/platform/package changes screened; runtime effects belong to named subsystem streams |
| [3c793a3dc](https://github.com/sysown/proxysql/commit/3c793a3dce069b062ae26698c65a7cdb86110d44) | 2026-08-09 | CI/test/harness/documentation changes; not inferred to change production semantics |
| [e2293b06f](https://github.com/sysown/proxysql/commit/e2293b06fbd385c0614ec3d85fcec4742708cc64) | 2026-08-09 | CI/test/harness/documentation changes; not inferred to change production semantics |
| [a6f3f1ec6](https://github.com/sysown/proxysql/commit/a6f3f1ec6b413acb641cb5c84c457ddab4e23c2b) | 2026-08-10 | CI/test/harness/documentation changes; not inferred to change production semantics |
| [06f38941e](https://github.com/sysown/proxysql/commit/06f38941e652c96f4d63dd152dfac551438e41d7) | 2026-08-10 | CI/test/harness/documentation changes; not inferred to change production semantics |
| [3b9dc8a69](https://github.com/sysown/proxysql/commit/3b9dc8a69ac7877ca33dd59285c5cf2593eeb38d) | 2026-08-10 | CI/test/harness/documentation changes; not inferred to change production semantics |
| [96ec0a00f](https://github.com/sysown/proxysql/commit/96ec0a00fa97253ff45e58a16fee5f831ad14135) | 2026-08-10 | CI/test/harness/documentation changes; not inferred to change production semantics |
| [53a129d06](https://github.com/sysown/proxysql/commit/53a129d06e68e970df2056c5658b222527cfd042) | 2026-08-10 | CI/test/harness/documentation changes; not inferred to change production semantics |
| [6a6913b7b](https://github.com/sysown/proxysql/commit/6a6913b7b5ad8d7f325a61530c129114bc1cacd7) | 2026-08-10 | Build/support integration with production slices reviewed in traffic/backend/admin/auth/extensions |
| [16b361e46](https://github.com/sysown/proxysql/commit/16b361e46fa17384b714a17a6b8653f5952dbb08) | 2026-08-11 | Build/support integration with production slices reviewed in traffic/backend/admin/auth/extensions |
| [96fa1cf99](https://github.com/sysown/proxysql/commit/96fa1cf9923849a7bfbfb78f432545293802202a) | 2026-08-12 | Dependency/platform/package changes screened; runtime effects belong to named subsystem streams |
| [df292eacc](https://github.com/sysown/proxysql/commit/df292eacc821d56bbed92fcdb68dc98b852e103b) | 2026-08-12 | Build/support integration with production slices reviewed in traffic/backend/admin/auth/extensions |
| [6ebf75fff](https://github.com/sysown/proxysql/commit/6ebf75fff142e843aab701619dc84d2e0e2199e3) | 2026-08-13 | Build/support integration with production slices reviewed in traffic/backend/admin/auth/extensions |
| [efe591090](https://github.com/sysown/proxysql/commit/efe591090254703fb637e4500e17ae14ca184445) | 2026-08-13 | Build/support integration with production slices reviewed in traffic/backend/admin/auth/extensions |
| [cd4bd3ab8](https://github.com/sysown/proxysql/commit/cd4bd3ab86f2c272a3ff62382317dcf829839d90) | 2026-08-13 | CI/test/harness/documentation changes; not inferred to change production semantics |
| [811bedbef](https://github.com/sysown/proxysql/commit/811bedbef0c79a2e1d6ec477380896be537ec871) | 2026-08-13 | Operator-managed role synchronizer defaults, ownership and partial failure; DE03, DE04, DE05, DE06, DE07 |
| [57dc075ec](https://github.com/sysown/proxysql/commit/57dc075ec8df2bb767b5b90548cff80dfe734fa3) | 2026-08-14 | Dependency/platform/package changes screened; runtime effects belong to named subsystem streams |
| [5980f9a24](https://github.com/sysown/proxysql/commit/5980f9a24666e05e27dcc67d25e89a3efc0e5ab2) | 2026-08-14 | CI/test/harness/documentation changes; not inferred to change production semantics |
| [96ad17425](https://github.com/sysown/proxysql/commit/96ad174257fb44bee391bdf713634b2b7bb2d117) | 2026-08-14 | CI/test/harness/documentation changes; not inferred to change production semantics |
| [d18c621a4](https://github.com/sysown/proxysql/commit/d18c621a4151e299c04ff74ea6814bb57a496cae) | 2026-08-15 | CI/test/harness/documentation changes; not inferred to change production semantics |
| [b7f6db118](https://github.com/sysown/proxysql/commit/b7f6db118af6c10284aebf40f6a97ce7df1530df) | 2026-08-15 | CI/test/harness/documentation changes; not inferred to change production semantics |
| [d72f48067](https://github.com/sysown/proxysql/commit/d72f480674a04fa4ac583c1c3fba8f27857a1c50) | 2026-08-15 | Dependency/platform/package changes screened; runtime effects belong to named subsystem streams |
| [84f2d0464](https://github.com/sysown/proxysql/commit/84f2d04647327ab6d061fa807fea4e460429cca7) | 2026-08-15 | CI/test/harness/documentation changes; not inferred to change production semantics |
| [b327de622](https://github.com/sysown/proxysql/commit/b327de62202642f0c32f158e98fd2b1c86c6a386) | 2026-08-16 | CI/test/harness/documentation changes; not inferred to change production semantics |
| [2e4323a7a](https://github.com/sysown/proxysql/commit/2e4323a7a3f5850b29557e31bb21992b5d618945) | 2026-08-16 | CI/test/harness/documentation changes; not inferred to change production semantics |
| [1874f04e2](https://github.com/sysown/proxysql/commit/1874f04e225a604dd85190aa3ac07e8263924334) | 2026-08-16 | CI/test/harness/documentation changes; not inferred to change production semantics |
| [94b3c8260](https://github.com/sysown/proxysql/commit/94b3c82604dab349237f49d9bc7c98019d53a057) | 2026-08-17 | Build/support integration with production slices reviewed in traffic/backend/admin/auth/extensions |
| [a858173ed](https://github.com/sysown/proxysql/commit/a858173eded0ebabe409680b7d66574c46874c0d) | 2026-08-17 | Transient build/bundling adjustment reverted or replaced before END |
| [b4e1d3f54](https://github.com/sysown/proxysql/commit/b4e1d3f5439c6dfc5b1f764649903a443d4ab9ac) | 2026-08-17 | Transient build/bundling adjustment reverted or replaced before END |
| [4468aa213](https://github.com/sysown/proxysql/commit/4468aa21315353102380d3182a3ce8aae06664b6) | 2026-08-17 | Dependency/platform/package changes screened; runtime effects belong to named subsystem streams |
| [99c37c7c1](https://github.com/sysown/proxysql/commit/99c37c7c1b668c46364ecb767ad085838a3cbfef) | 2026-08-18 | Build/support integration with production slices reviewed in traffic/backend/admin/auth/extensions |
| [749c4710c](https://github.com/sysown/proxysql/commit/749c4710c7dbd84140166c1a22c925588286c896) | 2026-08-19 | Build/support integration with production slices reviewed in traffic/backend/admin/auth/extensions |
| [6f2008001](https://github.com/sysown/proxysql/commit/6f2008001acda19c5e266788ee17be2567096b98) | 2026-08-19 | CI/test/harness/documentation changes; not inferred to change production semantics |
| [7c91137a4](https://github.com/sysown/proxysql/commit/7c91137a465454dfc1a62b56f8c188c1ce59c130) | 2026-08-26 | Dependency/platform/package changes screened; runtime effects belong to named subsystem streams |
| [c1bdc6384](https://github.com/sysown/proxysql/commit/c1bdc6384d9279d6ad9912570da9a89cdb0dca3c) | 2026-08-30 | CI/test/harness/documentation changes; not inferred to change production semantics |
| [47bd45ba6](https://github.com/sysown/proxysql/commit/47bd45ba632c2a6073b959b6b1ee21d529044c36) | 2026-08-30 | Dependency/platform/package changes screened; runtime effects belong to named subsystem streams |
| [e4b5a7657](https://github.com/sysown/proxysql/commit/e4b5a765740eb1cdcaeb4e8724d96e2c8f539298) | 2026-08-31 | Vendored dependency ownership/integrity and package follow-ups; #6115 fixed decisions |
| [40ea2de1b](https://github.com/sysown/proxysql/commit/40ea2de1bdf6547951df600185d3b3f1820f1dbe) | 2026-08-31 | Build/support integration with production slices reviewed in traffic/backend/admin/auth/extensions |
| [e7f1ab368](https://github.com/sysown/proxysql/commit/e7f1ab368be3fef61f1ab6fe61a2bb20b0eec5ba) | 2026-08-31 | Dependency/platform/package changes screened; runtime effects belong to named subsystem streams |
| [8dad803bd](https://github.com/sysown/proxysql/commit/8dad803bd840e7e7f8a27cdca20d5b9a51b0a108) | 2026-09-01 | Dependency/platform/package changes screened; runtime effects belong to named subsystem streams |
| [be564e8f7](https://github.com/sysown/proxysql/commit/be564e8f75adffc19e20ac4eca1a2d3b9ab5fec3) | 2026-09-01 | Build/support integration with production slices reviewed in traffic/backend/admin/auth/extensions |
| [c31006d84](https://github.com/sysown/proxysql/commit/c31006d844ec789551fb6cca84317c3dfc254d9d) | 2026-09-02 | Build/support integration with production slices reviewed in traffic/backend/admin/auth/extensions |
| [5940f34ca](https://github.com/sysown/proxysql/commit/5940f34cacca6342fe644b4e5f71e4284bcf0775) | 2026-09-03 | Dependency/platform/package changes screened; runtime effects belong to named subsystem streams |
| [53327da99](https://github.com/sysown/proxysql/commit/53327da99fdf699a1956cb03a400d642f107ff13) | 2026-09-04 | Build/support integration with production slices reviewed in traffic/backend/admin/auth/extensions |
| [75f14db81](https://github.com/sysown/proxysql/commit/75f14db81db505941b4b48c9c56f24b7c50bcece) | 2026-09-04 | Build/support integration with production slices reviewed in traffic/backend/admin/auth/extensions |
| [80941ae5e](https://github.com/sysown/proxysql/commit/80941ae5e2cb29963c8bb14c46a7a441ae4f08d2) | 2026-09-06 | Dependency/platform/package changes screened; runtime effects belong to named subsystem streams |
| [383676233](https://github.com/sysown/proxysql/commit/383676233067cf96962bd6d659223f3a93a13ae0) | 2026-09-06 | Build/support integration with production slices reviewed in traffic/backend/admin/auth/extensions |
| [6cf17a5e7](https://github.com/sysown/proxysql/commit/6cf17a5e76e74ade6d3595f991e44549e3855cf3) | 2026-09-06 | Dependency/platform/package changes screened; runtime effects belong to named subsystem streams |
| [6bf3e56a9](https://github.com/sysown/proxysql/commit/6bf3e56a9d8eeb76252a0be91e9a6fd49bab443e) | 2026-09-06 | GCOV atomic profile update/toolchain validation; engineering/test correctness |
| [7cc70150e](https://github.com/sysown/proxysql/commit/7cc70150e3a1c7d0629bcba217b323ed87582f25) | 2026-09-06 | CI/test/harness/documentation changes; not inferred to change production semantics |
| [f0d998065](https://github.com/sysown/proxysql/commit/f0d99806525e23f28f603c280c88ceb1098f7731) | 2026-09-07 | Vendored dependency ownership/integrity and package follow-ups; #6115 fixed decisions |
| [34a63da97](https://github.com/sysown/proxysql/commit/34a63da97a1d7e9c44ceb2e1d866009cae4afc8d) | 2026-09-07 | CI/test/harness/documentation changes; not inferred to change production semantics |
| [a0a654858](https://github.com/sysown/proxysql/commit/a0a6548586e36237e5f82a1062800de6a464c80f) | 2026-09-07 | Dependency/platform/package changes screened; runtime effects belong to named subsystem streams |
| [ffb12369a](https://github.com/sysown/proxysql/commit/ffb12369ae257834d4f8eedcda0a16513983fa60) | 2026-09-07 | CI/test/harness/documentation changes; not inferred to change production semantics |
| [1155452da](https://github.com/sysown/proxysql/commit/1155452da51eadaf5320ee42d9ec0a1c476a6746) | 2026-09-07 | Build/support integration with production slices reviewed in traffic/backend/admin/auth/extensions |
| [fc7ab9da4](https://github.com/sysown/proxysql/commit/fc7ab9da48cf76ca40343f6ac1844492a37f79f1) | 2026-09-07 | CI/test/harness/documentation changes; not inferred to change production semantics |
| [563e47f1a](https://github.com/sysown/proxysql/commit/563e47f1a819c21e1700136c72b3025ae570ddd0) | 2026-09-08 | Dependency/platform/package changes screened; runtime effects belong to named subsystem streams |
| [08cf04957](https://github.com/sysown/proxysql/commit/08cf04957728229a5511498f712a5ed5945325f1) | 2026-09-15 | Build/support integration with production slices reviewed in traffic/backend/admin/auth/extensions |
| [594ed7cd3](https://github.com/sysown/proxysql/commit/594ed7cd36109dad1db5f8643678e08a2abefa4a) | 2026-09-15 | Build/support integration with production slices reviewed in traffic/backend/admin/auth/extensions |
| [9ed59e93b](https://github.com/sysown/proxysql/commit/9ed59e93bd01e8c10eeb81495a86b9e9fc85c42f) | 2026-09-19 | Vendored dependency ownership/integrity and package follow-ups; #6115 fixed decisions |
| [ec9454d35](https://github.com/sysown/proxysql/commit/ec9454d354e6c568c9bf0bccb88193cf5c876e0d) | 2026-09-26 | Dependency/platform/package changes screened; runtime effects belong to named subsystem streams |
| [0cc7487e4](https://github.com/sysown/proxysql/commit/0cc7487e44c43956321464613fef9959c7298baf) | 2026-09-27 | CI/test/harness/documentation changes; not inferred to change production semantics |
| [bf44ee9e3](https://github.com/sysown/proxysql/commit/bf44ee9e38109f6096722a5f9fcd3e7977bee4fb) | 2026-09-27 | Build/support integration with production slices reviewed in traffic/backend/admin/auth/extensions |
| [4330a3510](https://github.com/sysown/proxysql/commit/4330a35102c9c0c1f771264c7e4a6373be13b305) | 2026-09-28 | Build/support integration with production slices reviewed in traffic/backend/admin/auth/extensions |
| [b4f68d539](https://github.com/sysown/proxysql/commit/b4f68d539a38df9f812664aa4ed55613c911608b) | 2026-09-28 | Build/support integration with production slices reviewed in traffic/backend/admin/auth/extensions |
| [7793268bf](https://github.com/sysown/proxysql/commit/7793268bf09346f75c2a4a96c7c54dea4be293a7) | 2026-09-28 | CI/test/harness/documentation changes; not inferred to change production semantics |
| [b36704101](https://github.com/sysown/proxysql/commit/b367041018cf1c7539dbb41bf16ca2f0e422814a) | 2026-09-29 | Dependency/platform/package changes screened; runtime effects belong to named subsystem streams |
| [8d4ff4db5](https://github.com/sysown/proxysql/commit/8d4ff4db58b777ed33e56d5a76edc7ccb2051eae) | 2026-09-29 | CI/test/harness/documentation changes; not inferred to change production semantics |
| [f9d251bb4](https://github.com/sysown/proxysql/commit/f9d251bb4521377bf742abcee9f15485f7492f35) | 2026-09-30 | CI/test/harness/documentation changes; not inferred to change production semantics |
| [6a4858e69](https://github.com/sysown/proxysql/commit/6a4858e69d7802529e5392ed99b73f17937717c9) | 2026-09-30 | Dependency/platform/package changes screened; runtime effects belong to named subsystem streams |
| [c0bb2b2e0](https://github.com/sysown/proxysql/commit/c0bb2b2e0bf3402f58d5e073394fee7d440f32ea) | 2026-09-30 | Build/support integration with production slices reviewed in traffic/backend/admin/auth/extensions |
| [2e64c0b1e](https://github.com/sysown/proxysql/commit/2e64c0b1e8fc09ac3c6a531b1ad1b170aecb1406) | 2026-09-30 | CI/test/harness/documentation changes; not inferred to change production semantics |
| [e8c1d931a](https://github.com/sysown/proxysql/commit/e8c1d931abaeffaeed7987598a1e4f0827d287fb) | 2026-09-30 | CI/test/harness/documentation changes; not inferred to change production semantics |
| [f23c70b60](https://github.com/sysown/proxysql/commit/f23c70b6069764e7b935a4116b79e7d4ce9159ff) | 2026-09-30 | CI/test/harness/documentation changes; not inferred to change production semantics |
| [bae148763](https://github.com/sysown/proxysql/commit/bae14876302c754b941f2c1dccbdcbba6c112dfe) | 2026-09-30 | CI/test/harness/documentation changes; not inferred to change production semantics |
| [2775bb222](https://github.com/sysown/proxysql/commit/2775bb222ed67e613332fa8bfdff526ae56baa49) | 2026-10-01 | Dependency/platform/package changes screened; runtime effects belong to named subsystem streams |
| [58ada3f87](https://github.com/sysown/proxysql/commit/58ada3f87a50cf6bda0f8c3330b274eee3a40a3f) | 2026-10-01 | CI/test/harness/documentation changes; not inferred to change production semantics |
| [380cb3eac](https://github.com/sysown/proxysql/commit/380cb3eacdb8fd8b485c80c30f7210d625e17aa9) | 2026-10-02 | Build/support integration with production slices reviewed in traffic/backend/admin/auth/extensions |
| [6758c60ce](https://github.com/sysown/proxysql/commit/6758c60ce5b19e463cbd5a9dbf83c1650a678469) | 2026-10-02 | Build/support integration with production slices reviewed in traffic/backend/admin/auth/extensions |
| [04dc9afa0](https://github.com/sysown/proxysql/commit/04dc9afa05757abb94c76dcc21af8550faa436d2) | 2026-10-02 | Build/support integration with production slices reviewed in traffic/backend/admin/auth/extensions |
| [37d627b97](https://github.com/sysown/proxysql/commit/37d627b9743f7d51d6b783b039f994e0b18474f0) | 2026-10-03 | Dependency/platform/package changes screened; runtime effects belong to named subsystem streams |
| [6f438aa1f](https://github.com/sysown/proxysql/commit/6f438aa1f0e9ed38ecdb107d0bc829d27f9a8408) | 2026-10-03 | Build/support integration with production slices reviewed in traffic/backend/admin/auth/extensions |
| [546abf5c8](https://github.com/sysown/proxysql/commit/546abf5c885ff985c3e98852630bac28de9223a3) | 2026-10-03 | Build/support integration with production slices reviewed in traffic/backend/admin/auth/extensions |
| [246210e08](https://github.com/sysown/proxysql/commit/246210e088599cfb0414a96843d0e9d27f535388) | 2026-10-10 | Build/support integration with production slices reviewed in traffic/backend/admin/auth/extensions |
| [74c88dfc3](https://github.com/sysown/proxysql/commit/74c88dfc36f98c2073a280c10599d5cf41acd8fa) | 2026-10-10 | Dependency/platform/package changes screened; runtime effects belong to named subsystem streams |
| [a316e7567](https://github.com/sysown/proxysql/commit/a316e75675a71ec17cded50ac910cf3d46518304) | 2026-10-11 | Build/support integration with production slices reviewed in traffic/backend/admin/auth/extensions |
| [9f58be1d3](https://github.com/sysown/proxysql/commit/9f58be1d3007819e6e8566b5ead98d5327b4fbc4) | 2026-10-11 | Build/support integration with production slices reviewed in traffic/backend/admin/auth/extensions |
| [7601b3937](https://github.com/sysown/proxysql/commit/7601b39375a5b154b0a235c3db24fea7d3ff72f8) | 2026-10-12 | Build/support integration with production slices reviewed in traffic/backend/admin/auth/extensions |
| [58c0e289d](https://github.com/sysown/proxysql/commit/58c0e289d7ec0ad22f3092929579a055d1799d26) | 2026-10-12 | Build/support integration with production slices reviewed in traffic/backend/admin/auth/extensions |
| [970a978ae](https://github.com/sysown/proxysql/commit/970a978ae12eca4e4756bd0decd8bf27f2f53972) | 2026-10-12 | Dependency/platform/package changes screened; runtime effects belong to named subsystem streams |
| [5ace3febc](https://github.com/sysown/proxysql/commit/5ace3febc60b29264fe9a331a05a8e793ebe3237) | 2026-10-12 | Build/support integration with production slices reviewed in traffic/backend/admin/auth/extensions |
| [e100071e2](https://github.com/sysown/proxysql/commit/e100071e2b660c51743d9b52fcd0e7bb515632a0) | 2026-10-12 | Dependency/platform/package changes screened; runtime effects belong to named subsystem streams |
| [2973b8166](https://github.com/sysown/proxysql/commit/2973b81667cdb45d588ad3518a59ed0ede52fbe3) | 2026-10-12 | Build flag/compiler stamp invalidates mismatched objects; correctness repair, not a new runtime choice |
| [a8aca8b75](https://github.com/sysown/proxysql/commit/a8aca8b753e4086ce4d4bf379afcb748bc026574) | 2026-10-12 | CI/test/harness/documentation changes; not inferred to change production semantics |
| [c52887003](https://github.com/sysown/proxysql/commit/c5288700311d324df38b8095953d379861bcf81d) | 2026-10-13 | Build/support integration with production slices reviewed in traffic/backend/admin/auth/extensions |
| [4d7dea573](https://github.com/sysown/proxysql/commit/4d7dea573f7868d46ec5adf00e0bf93dbe34bab2) | 2026-10-14 | Build/support integration with production slices reviewed in traffic/backend/admin/auth/extensions |
| [b0fe50bc3](https://github.com/sysown/proxysql/commit/b0fe50bc3713acd18b270b9330fbcb4a067acc22) | 2026-10-17 | Build/support integration with production slices reviewed in traffic/backend/admin/auth/extensions |
| [ec217c5c6](https://github.com/sysown/proxysql/commit/ec217c5c658f7b30c93304807b37763976a84f20) | 2026-10-17 | Stops tracking a generated build stamp; no feature/tier behavior change |
| [d7ce280a3](https://github.com/sysown/proxysql/commit/d7ce280a3bea04f495d608bbfc8e6f98ce29aaa5) | 2026-10-18 | Cross-platform normal ClickHouse capability; DE02 |
| [9516441f7](https://github.com/sysown/proxysql/commit/9516441f7bd6fdb93f255f1881db19ca9ee56778) | 2026-10-19 | Build/support integration with production slices reviewed in traffic/backend/admin/auth/extensions |
