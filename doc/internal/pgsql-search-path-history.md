# Why PostgreSQL search_path tracking and its configurable default were added

Research date: 2026-10-18. This is a source/history investigation, not an
implementation change or a new invariant. It uses the existing
`docs/invariants-expansion` checkout; current implementation references are
pinned to `a832cbb22be47fffc7a7caf9b82d1f8e76b27171`. No executable reproduction
or integration test was run.

## Answer

There were two different additions. **The 2025 change added tracking so ordinary
`SET search_path` would not lock the session to a hostgroup. The configurable
`pgsql-default_search_path` appeared through the 2026 promotion into the critical
startup group.** The later commit's stated reasons were to give clients that
omit the setting a known default, repair `SET search_path TO DEFAULT`, establish
the value at backend startup, and report it to clients. Those are different
objectives from the original tracking request. Sources: [issue #5148](https://github.com/sysown/proxysql/issues/5148),
[PR #5149](https://github.com/sysown/proxysql/pull/5149),
[promotion commit and rationale](https://github.com/sysown/proxysql/commit/212a628002e7daf1d78938b59425330821a6444c).

## Verified chronology

| Change | Implementation date | First mainline integration | Scope |
| --- | --- | --- | --- |
| [b005c2dd8: Add tracking for PostgreSQL search_path parameter](https://github.com/sysown/proxysql/commit/b005c2dd8cb8f7398e8359415d0308d3744f7b72) | 2025-10-08 | [01862a247, PR #5149](https://github.com/sysown/proxysql/commit/01862a247a9bd0e97ad73a84f6de4f7a78c85505), 2025-10-14 | Adds a dynamic tracked variable and its parser/validator support. |
| [212a62800: track search_path with the reported startup settings](https://github.com/sysown/proxysql/commit/212a628002e7daf1d78938b59425330821a6444c) | 2026-09-18 | [2775bb222, PR #5882](https://github.com/sysown/proxysql/commit/2775bb222ed67e613332fa8bfdff526ae56baa49), 2026-10-01 | Moves it before `PGSQL_NAME_LAST_LOW_WM` and enables its ParameterStatus flag. |

Ancestry checks confirm that `b005c2dd8` is already an ancestor of the twelve-month
review baseline `70228332135431229940279e49b6db186c6e4241`. The original tracking
addition therefore predates that review window; the default-policy promotion is
inside it. Integration was determined from the earliest first-parent commit
containing each implementation commit, rather than from its author date.

## What the original tracking change actually did

The original issue and PR both identify hostgroup locking as the problem:
`search_path` was untracked, so setting it took the ordinary unparsed-SET
fallback. The implementation adds `PGSQL_SEARCH_PATH` above the low-watermark
separator, adds it to `pgsql_other_variables`, and adds a validator plus
`PGTRACKED_VAR_OPT_NO_STRIP_VALUE` so schema-list quoting can survive tracking.
The stated purpose is multiplexable/reproducible session state, not imposing a
global search path on clients that omit it. Sources: [issue #5148](https://github.com/sysown/proxysql/issues/5148),
[original diff](https://github.com/sysown/proxysql/commit/b005c2dd8cb8f7398e8359415d0308d3744f7b72).

The descriptor already contained the conventional value `"$user", public` in
2025. **That field did not create a configurable `pgsql-default_search_path`.**
The generic default-variable initializer, getter, setter, listing and worker
refresh all operated only on indices below `PGSQL_NAME_LAST_LOW_WM`; the new
dynamic variable was outside those loops. The original descriptor-default
readers do not provide a separate dynamic-variable fallback. Historical sources:
[descriptor placement](https://github.com/sysown/proxysql/blob/01862a247a9bd0e97ad73a84f6de4f7a78c85505/include/proxysql_structs.h#L262),
[initialization](https://github.com/sysown/proxysql/blob/01862a247a9bd0e97ad73a84f6de4f7a78c85505/lib/PgSQL_Thread.cpp#L1022),
[getter](https://github.com/sysown/proxysql/blob/01862a247a9bd0e97ad73a84f6de4f7a78c85505/lib/PgSQL_Thread.cpp#L1287),
[setter](https://github.com/sysown/proxysql/blob/01862a247a9bd0e97ad73a84f6de4f7a78c85505/lib/PgSQL_Thread.cpp#L1783),
[generated names](https://github.com/sysown/proxysql/blob/01862a247a9bd0e97ad73a84f6de4f7a78c85505/lib/PgSQL_Thread.cpp#L2212).

## How the 2026 move created the knob and changed the baseline

`212a62800` changes the enum/table position and two session name lists. It adds
no hand-written registration named `default_search_path`: moving the descriptor
into the critical range makes the existing loops generate `default_search_path`,
initialize it from the descriptor, validate/configure it, and refresh it into
workers. The admin namespace supplies the `pgsql-` prefix. Sources:
[promotion diff](https://github.com/sysown/proxysql/commit/212a628002e7daf1d78938b59425330821a6444c),
[generated default names](../../lib/PgSQL_Thread.cpp#L2482),
[getter](../../lib/PgSQL_Thread.cpp#L1436),
[setter](../../lib/PgSQL_Thread.cpp#L2026),
[worker refresh](../../lib/PgSQL_Thread.cpp#L4516),
[admin prefix and registration](../../lib/Admin_FlushVariables.cpp#L369).

| Situation | Dynamic tracking before promotion | Critical tracking after promotion |
| --- | --- | --- |
| Client omits search_path at connection startup | Frontend search_path remains unrecorded. ProxySQL does not add it to the critical backend-startup options, so absent another override the backend's own session default applies. | Frontend initialization fills it from `pgsql-default_search_path`, records that value as the client's startup baseline, and backend creation sends it as `-c search_path=...`. |
| Client explicitly supplies search_path at startup | The tracked value is recorded, including the client's startup snapshot; materialization can apply it as a later SET. | Explicit client input still wins over the configured fallback; it is now among the critical settings sent at backend startup. |
| Client later executes a supported SET search_path | Frontend desired value changes and synchronization applies it when needed. | The same basic desired-state model remains; the variable is always present, including when the client originally omitted it. |
| RESET search_path / SET search_path TO DEFAULT | Uses the frontend startup snapshot if present. If the client omitted it, the accessor returns an empty value/hash rather than the descriptor's conventional default. RESET clears the dynamic override; SET TO DEFAULT has protocol-dependent handling of that missing baseline. | A nonzero frontend startup snapshot exists even for omission. These paths select that recorded baseline, not a freshly read backend role/database default or the latest global knob value. |

Sources for this comparison: [frontend startup parsing/default fill](../../lib/PgSQL_Protocol.cpp#L1443),
[startup snapshot](../../lib/PgSQL_Protocol.cpp#L1536),
[backend startup construction](../../lib/PgSQL_Connection.cpp#L1294),
[startup accessor](../../lib/PgSQL_Connection.cpp#L6120),
[SET TO DEFAULT](../../lib/PgSQL_Session.cpp#L4697),
[RESET](../../lib/PgSQL_Session.cpp#L4948),
and the [pre-promotion accessor and snapshot loops](https://github.com/sysown/proxysql/blob/de27811a8367a26506a459a74b37d6b04762a345/lib/PgSQL_Connection.cpp#L5691).
Tests added alongside the promotion cover missing-startup SET TO DEFAULT,
transaction retention, cross-client isolation, change notifications and RESET;
they document intended assertions, not results executed during this investigation.
See [3ff8aae5e](https://github.com/sysown/proxysql/commit/3ff8aae5e).

The consequence for role/database defaults follows from actual source precedence:
PostgreSQL's `PGC_S_CLIENT` connection-request source outranks database, role and
database-role sources, and also sets the RESET default. Thus ProxySQL's explicit
startup `-c search_path=...` can replace a server-side role/database default.
This is not a discovery of that backend default. PostgreSQL sources:
[GucSource precedence](https://github.com/postgres/postgres/blob/REL_18_STABLE/src/include/utils/guc.h#L78),
[role/database defaults](https://www.postgresql.org/docs/18/sql-alterrole.html),
[RESET semantics](https://www.postgresql.org/docs/18/sql-reset.html).

The literal `"$user", public` is PostgreSQL's conventional default, but it is a
schema search list, not a resolved list of existing schemas. `$user`, privileges,
and schema existence can produce different effective paths; `current_schemas`
distinguishes that result from the text setting. Source:
[PostgreSQL search_path documentation](https://www.postgresql.org/docs/18/runtime-config-client.html#GUC-SEARCH-PATH).

## ParameterStatus and backend-mode qualifications

There are three different observations, which must not be conflated:

1. **What PostgreSQL reports:** PostgreSQL's documentation explicitly says
   `search_path` was not automatically reported before version 18.
   `PQparameterStatus()` returns NULL when the setting is not known. Therefore
   neither native ParameterStatus capture nor the libpq accessor can be assumed
   to reveal search_path on PostgreSQL 17 and earlier. This does not prevent SQL
   inspection through SHOW/current_setting. Source:
   [PostgreSQL 18 connection-status documentation](https://www.postgresql.org/docs/18/libpq-status.html#LIBPQ-PQPARAMETERSTATUS).
2. **What ProxySQL reports:** the critical-range welcome loop now emits the
   frontend's recorded search_path; its new ParameterStatus flag also enables
   local SET/RESET notifications. These shared paths are not gated by backend
   PostgreSQL major version. They report ProxySQL's selected frontend baseline,
   not proof that a backend supplied that value. Sources:
   [welcome_client](../../lib/PgSQL_Protocol.cpp#L1620),
   [descriptor flag](../../include/proxysql_structs.h#L2011),
   [SET notification](../../lib/PgSQL_Session.cpp#L4777),
   [extended notification synthesis](../../lib/PgSQL_Session.cpp#L4828).
3. **What each backend implementation records:** native code retains actual
   ParameterStatus messages in `native_params`; libpq's wrapper delegates to
   `PQparameterStatus`. Neither mechanism is an arbitrary-GUC lookup.
   Startup/reset tracking instead has separate explicit snapshot arrays. Sources:
   [status accessor](../../include/PgSQL_Connection.h#L623),
   [native capture](../../lib/PgSQL_Connection.cpp#L3175),
   [startup snapshot functions](../../lib/PgSQL_Connection.cpp#L6133).

The promotion affects both backend implementations: libpq and native both use
`build_and_record_startup_session_params()`, with different escaping levels.
Before October 1, mainline had the libpq backend. In the promotion's
feature-branch parent, both startup paths already used that same helper and its
critical-range-only loop, so an omitted dynamic search_path was excluded from
both. The promotion changed both paths when they integrated together; there
was no separately shipped native-only default policy. Historical sources:
[shared loop](https://github.com/sysown/proxysql/blob/de27811a8367a26506a459a74b37d6b04762a345/lib/PgSQL_Connection.cpp#L1312),
[libpq caller](https://github.com/sysown/proxysql/blob/de27811a8367a26506a459a74b37d6b04762a345/lib/PgSQL_Connection.cpp#L1426),
[native caller](https://github.com/sysown/proxysql/blob/de27811a8367a26506a459a74b37d6b04762a345/lib/PgSQL_Connection.cpp#L2127).

Stable uses libpq; the native toggle is exposed on `PROXYSQL31` builds. A backend
reset restores the tracked critical startup snapshot, which now includes
search_path, while frontend reset restores its own startup state. The native
actual-reset/startup-copy fixes were completed before PR #5882's first mainline
integration; their earlier feature-branch shortcomings are not separately
shipped history. Sources: [libpq startup](../../lib/PgSQL_Connection.cpp#L1454),
[native startup](../../lib/PgSQL_Connection.cpp#L2281),
[tier selection](../../lib/PgSQL_Thread.cpp#L4399),
[reset bookkeeping](../../lib/PgSQL_Connection.cpp#L5809),
[native reset](https://github.com/sysown/proxysql/commit/b05d67cca116f0853287476a334e3d19275a97b6),
[startup-copy correction](https://github.com/sysown/proxysql/commit/38408be42734ef264b2896e748ca5dc918ca0610).

## Fact, rationale and unresolved policy

The original anti-locking rationale is explicit in issue #5148/PR #5149. The
later known-baseline/SET TO DEFAULT/reporting rationale is explicit in
`212a62800`'s commit message. The code shows how the generic default machinery
made that rationale concrete. It does **not** establish that a configurable
global override was the only possible solution, or that the original issue
approved overriding omitted clients' role/database defaults.

The remaining G1 decision is precise: **when the client omits search_path,
should ProxySQL select its own configured fallback, or preserve the backend's
role/database-specific default?** Safe isolation and truthful synchronization
are required under either policy. This note records no maintainer answer and
does not reopen the agreed pooling/reset/transaction invariants.
