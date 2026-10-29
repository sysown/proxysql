# SPIKE: dbdeployer PostgreSQL deploy command (Task 1)

Status: **CONFIRMED WORKING** — the pinned ProxySQL fork of dbdeployer (v2.2.1) can deploy a
1-primary + 2-replica PostgreSQL 17 streaming-replication sandbox. Task 2a (dbdeployer path) is
viable. This doc records the exact commands, ports, and — critically — several undocumented
gaps/limitations in this fork's PostgreSQL support that Task 2 must work around.

All experiments were run inside a single throwaway `ubuntu:22.04` container
(`docker run -d --name sdd-sp2-spike --network=host ubuntu:22.04 sleep infinity`, removed at the
end via `docker rm -f sdd-sp2-spike`). Nothing was installed on the host.

## 1. dbdeployer version + install method (verbatim, matches the MySQL GR reference Dockerfile)

```bash
curl -fsSL "https://github.com/ProxySQL/dbdeployer/releases/download/v2.2.1/dbdeployer-2.2.1.linux_amd64.tar.gz" \
  | tar -xz -C /usr/local/bin/
chmod +x /usr/local/bin/dbdeployer
```

`dbdeployer --version` → `dbdeployer version 2.2.1`. (No rename/symlink needed — the tarball's
member is already named `dbdeployer`, unlike the brief's assumption of a
`dbdeployer-2.2.1.linux_amd64` binary name.)

`dbdeployer deploy --help` lists a **`postgresql` subcommand** ("deploys a PostgreSQL sandbox")
alongside `single`/`multiple`/`replication`/`proxysql`, and `deploy replication`/`deploy single`
both expose a `--provider string` flag ("Database provider (mysql, postgresql)", default
`mysql`). This is the confirmed PG support surface.

## 2. PostgreSQL is NOT in `dbdeployer downloads list` — use PGDG `.deb`s instead

This is the biggest divergence from the brief's assumed flow. **`dbdeployer downloads list`
(with `--OS=all`, or `--flavor=postgresql|pgsql|postgres`) returns zero PostgreSQL entries** —
the fork's built-in remote tarball index only carries MySQL/Percona/MariaDB tarballs. There is
no `dbdeployer downloads get-unpack <postgres-tarball>` to run.

Instead, `dbdeployer deploy postgresql --help` states the actual prerequisite:

```
Requires PostgreSQL binaries to be extracted first:
    dbdeployer unpack --provider=postgresql postgresql-16_*.deb postgresql-client-16_*.deb
```

i.e. dbdeployer expects **official PGDG `.deb` packages** (not `.tar.gz`), fed to
`dbdeployer unpack --provider=postgresql`, which extracts their file trees into
`$HOME/opt/postgresql/<version>/` (note: separate from `$HOME/opt/mysql`, and NOT affected by
`--sandbox-binary`).

### Exact commands used (PG 17.10, the newest available for jammy/22.04 in PGDG at spike time)

```bash
# Add the PGDG apt repo (ubuntu:22.04 = jammy)
apt-get install -y -qq gnupg lsb-release wget
install -d /usr/share/postgresql-common/pgdg
wget -q -O /usr/share/postgresql-common/pgdg/apt.postgresql.org.asc \
  https://www.postgresql.org/media/keys/ACCC4CF8.asc
echo "deb [signed-by=/usr/share/postgresql-common/pgdg/apt.postgresql.org.asc] \
  https://apt.postgresql.org/pub/repos/apt jammy-pgdg main" \
  > /etc/apt/sources.list.d/pgdg.list
apt-get update -qq

# Fetch the .deb files themselves (do NOT `apt-get install` the PG packages system-wide;
# dbdeployer wants the raw .deb to extract itself)
mkdir -p /root/pgdebs && cd /root/pgdebs
apt-get install -y -qq --download-only --reinstall -o Dir::Cache::archives=/root/pgdebs \
  postgresql-17 postgresql-client-17 postgresql-common postgresql-client-common

# Exact tarball(deb) names used:
#   postgresql-17_17.10-1.pgdg22.04+1_amd64.deb
#   postgresql-client-17_17.10-1.pgdg22.04+1_amd64.deb

# IMPORTANT: the unpack must run as a NON-ROOT user (see §4), and /root is mode 700 —
# pguser cannot traverse into /root/pgdebs at all ("Permission denied"). Copy the debs
# to a pguser-owned location first. Exact commands used in this spike (run as root):
useradd -m -s /bin/bash pguser          # the non-root user from §4 (create it first)
mkdir -p /home/pguser/pgdebs
cp /root/pgdebs/*.deb /home/pguser/pgdebs/
chown -R pguser:pguser /home/pguser/pgdebs
# (Alternative: download straight to a world-readable dir, e.g.
#  -o Dir::Cache::archives=/tmp/pgdebs above, and chown that — either way the .debs
#  must end up readable at a path pguser can reach.)

# Unpack via dbdeployer, as pguser (see §4)
su - pguser -c 'cd /home/pguser/pgdebs && dbdeployer unpack --provider=postgresql \
  postgresql-17_17.10-1.pgdg22.04+1_amd64.deb \
  postgresql-client-17_17.10-1.pgdg22.04+1_amd64.deb'
# => "PostgreSQL 17.10 unpacked to /home/pguser/opt/postgresql/17.10"
```

PG version deployed: **17.10** (PGDG's latest 17.x for jammy at spike time 2026-07-08; 17.8/17.9
were also available — pin whichever exact point release Task 2 wants, all worked identically).

## 3. Runtime shared libraries required (Debian PG binaries are not self-contained)

Unlike the MySQL/Percona/MariaDB tarballs dbdeployer normally consumes (statically-ish bundled,
relocatable), **the PGDG `.deb` payload only contains PostgreSQL's own files** — it does NOT
bundle its shared-library dependencies. Running the unpacked binaries requires these installed
system-wide first (else `initdb`/`postgres` fail with `error while loading shared libraries`):

```bash
apt-get install -y -qq /root/pgdebs/libpq5_*.deb /root/pgdebs/libicu70_*.deb \
  /root/pgdebs/libxml2_*.deb /root/pgdebs/libxslt1.1_*.deb /root/pgdebs/libllvm15_*.deb \
  /root/pgdebs/libedit2_*.deb /root/pgdebs/libbsd0_*.deb /root/pgdebs/libmd0_*.deb \
  /root/pgdebs/tzdata_*.deb
ldconfig
```

**Untested alternative worth trying in Task 2** (simpler, not verified in this spike): instead of
hand-picking these libs, just `apt-get install -y postgresql-17 postgresql-client-17` normally
(full system install, which pulls in all deps AND places files at the standard `/usr/share/postgresql/17`
path — see next point), then *separately* `apt-get download` a second copy of the same `.deb`s to
feed to `dbdeployer unpack`. This would likely avoid the manual lib list above and the symlink
workaround below. Flagging as a recommended experiment for Task 2, not a confirmed fact.

### `pg_config --sharedir` is a hardcoded absolute path, not relocatable

The Debian PG build reports (`pg_config --sharedir --bindir --pkglibdir`):
```
/usr/share/postgresql/17        <- WRONG once relocated by dbdeployer unpack; hardcoded, not relative
$HOME/opt/postgresql/17.10/bin  <- correct, tracks the actual unpack location
$HOME/opt/postgresql/17.10/lib  <- correct
```
`initdb` fails (`could not open directory "/usr/share/postgresql/17/timezonesets"`) because the
binary looks for its share files at the compiled-in absolute path, which doesn't exist once the
tree is copied to `$HOME/opt/postgresql/17.10`. **Workaround used and confirmed working:**

```bash
mkdir -p /usr/share/postgresql
ln -sf "$HOME/opt/postgresql/17.10/share/postgresql/17" /usr/share/postgresql/17
```

(System `/usr/share/zoneinfo` must also exist — i.e. the `tzdata` package must be installed;
it was in the runtime-lib list above.)

## 4. initdb refuses to run as root — must run dbdeployer as a non-root user

`dbdeployer deploy postgresql`/`deploy replication --provider=postgresql` shell out to `initdb`,
which **hard-refuses to run as root** (`initdb: error: cannot be run as root` — no override flag
exists; this is a PostgreSQL security feature, not a dbdeployer bug). This is a real architectural
difference from the MySQL GR reference image, whose entrypoint runs `dbdeployer` as root with no
issue.

**Confirmed working setup:** create a dedicated non-root user, and run every `dbdeployer` command
for PG (`unpack`, `deploy postgresql`, `deploy replication --provider=postgresql`, and any
`sandboxes`/`delete`) via that user (its `$HOME` becomes dbdeployer's default `sandbox-home` /
`sandbox-binary` root for the postgresql provider):

```bash
useradd -m -s /bin/bash pguser
# Copy + chown the downloaded .deb files into pguser's home first — /root is mode 700,
# so pguser cannot read /root/pgdebs (exact commands in §2):
mkdir -p /home/pguser/pgdebs
cp /root/pgdebs/*.deb /home/pguser/pgdebs/
chown -R pguser:pguser /home/pguser/pgdebs
# then, as pguser:
su - pguser -c 'cd /home/pguser/pgdebs && dbdeployer unpack --provider=postgresql postgresql-17_17.10-1.pgdg22.04+1_amd64.deb postgresql-client-17_17.10-1.pgdg22.04+1_amd64.deb'
```

Task 2's entrypoint/Dockerfile should either run the whole container as this user (`USER pguser`
+ appropriate ownership of the build layers), or `su`/`gosu`/`setpriv` into it for the PG-specific
commands only, similar to how official `postgres` images drop privileges.

## 5. The exact WORKING `dbdeployer deploy replication` command

### FINAL RECOMMENDED COMMAND (Task 2: copy this)

Run as `pguser` (see §4). This is the minimal form with the no-op flags removed (see
"silently-ignored flags" below for why `--bind-address`/`--base-port`/`-c` are omitted —
they do nothing for the postgresql provider):

```bash
dbdeployer deploy replication 17.10 \
  --provider=postgresql \
  --topology=master-slave \
  --nodes=3
```

Config injection (`listen_addresses`, `shared_preload_libraries`, `max_connections`,
`pg_hba.conf`) happens **post-deploy** — see the two confirmed workaround blocks below; Task 2's
entrypoint must include both.

On reserved-ports: the spike ran `dbdeployer defaults update reserved-ports '0'` before
deploying, carried over defensively from the MySQL GR recipe (dbdeployer's default reserved list
includes 5432). It was **NOT confirmed necessary for the postgresql provider** — PG ports are
auto-derived to 16710+ regardless of any port flags (see below), nowhere near the reserved list,
and a run without the step was not tested. Keep it or drop it in Task 2; do not treat it as a
proven requirement.

### The command as actually run in the spike (annotated history)

The spike's original invocation included the flags below; it succeeded, but the highlighted flags
were proven no-ops afterwards:

```bash
dbdeployer deploy replication 17.10 \
  --provider=postgresql \
  --topology=master-slave \
  --nodes=3 \
  --bind-address=0.0.0.0 \            # IGNORED for postgresql provider
  --base-port=5432 \                  # IGNORED — ports land at 16710/16711/16712
  -c listen_addresses=0.0.0.0 \       # IGNORED
  -c max_connections=500 \            # IGNORED
  -c shared_preload_libraries=pg_stat_statements   # IGNORED
```

Output:
```
  Primary deployed in $HOME/sandboxes/postgresql_repl_16710/primary (port: 16710)
  Replica 1 deployed in $HOME/sandboxes/postgresql_repl_16710/replica1 (port: 16711)
  Replica 2 deployed in $HOME/sandboxes/postgresql_repl_16710/replica2 (port: 16712)
postgresql replication sandbox (1 primary + 2 replicas) deployed in $HOME/sandboxes/postgresql_repl_16710
```

### IMPORTANT — silently-ignored flags (surprise #1)

**`--base-port`, `--bind-address`, and every `-c` config override above are silently ignored by
the `--provider=postgresql` replication code path in this fork.** The command above "succeeds"
and reports the settings were requested, but:
- Ports are **not** 5432-based; they are auto-derived from the version number
  (`17.10` → primary port **16710**, replicas **16711**/**16712** — pattern is
  `15000 + major*100 + minor`, confirmed by observing the same 16710 base for a plain
  `deploy postgresql 17.10` single-node deploy with no port flags at all).
- `listen_addresses` in the generated `postgresql.conf` stays `127.0.0.1` regardless of
  `--bind-address=0.0.0.0`.
- None of the `-c` key=value pairs appear in `postgresql.conf` at all (verified by `tail`-ing the
  file post-deploy — only dbdeployer's own fixed template lines are present: `port`,
  `listen_addresses`, `unix_socket_directories`, `logging_collector`, `log_directory`,
  `wal_level`, `max_wal_senders`, `hot_standby`).

This is a real fork limitation (verified by testing flag placement both after and before the
`replication` subcommand — no difference), not a usage mistake. **Task 2 cannot rely on `-c` /
`--bind-address` / `--base-port` for the postgresql provider.**

### Confirmed working workaround (surprise #1, mitigation)

Stop all 3 nodes, append overrides directly to each `data/postgresql.conf`, and restart — this
DOES work and was verified end-to-end (config values took effect, replication stayed intact,
extension load succeeded):

```bash
for n in primary replica1 replica2; do
  "$SBASE/$n/stop"
  cat >> "$SBASE/$n/data/postgresql.conf" <<EOF

listen_addresses = '0.0.0.0'
shared_preload_libraries = 'pg_stat_statements'
max_connections = 500
EOF
done
for n in primary replica1 replica2; do "$SBASE/$n/start"; done
```

(`$SBASE` = `$HOME/sandboxes/postgresql_repl_16710`.) Because only `listen_addresses` changes
(not `port`), the replicas' existing `primary_conninfo` (host `127.0.0.1`, port `16710`) stays
valid — replication is unaffected by widening the bind address. Since ports can't be forced to
5432 anyway, **Task 2 should just standardize on the dbdeployer-derived ports for the pinned PG
version** (16710/16711/16712 for 17.10) rather than fighting `--base-port`.

### IMPORTANT — surprise #2: `pg_hba.conf` still blocks non-loopback connections

Even after `listen_addresses = '0.0.0.0'` and a restart, the generated `pg_hba.conf` only has:
```
local   all       all                 trust
host    all       all   127.0.0.1/32  trust
host    all       all   ::1/128       trust
host    replication  all  127.0.0.1/32  trust
```
Verified: connecting from the container's real (non-loopback) IP to port 16710 failed with
`FATAL: no pg_hba.conf entry for host "<ip>", user "postgres", database "postgres", no
encryption` — i.e. **listen_addresses alone is not sufficient for other containers on the Docker
network to reach these nodes; `pg_hba.conf` must also be widened.** Confirmed fix (append + reload,
no restart needed):

```bash
for n in primary replica1 replica2; do
  echo "host all all 0.0.0.0/0 trust"         >> "$SBASE/$n/data/pg_hba.conf"
  echo "host replication all 0.0.0.0/0 trust" >> "$SBASE/$n/data/pg_hba.conf"
done
"$SBASE/primary/use"  -c "SELECT pg_reload_conf();"   # or any node — reload is per-node
"$SBASE/replica1/use" -c "SELECT pg_reload_conf();"
"$SBASE/replica2/use" -c "SELECT pg_reload_conf();"
```
Re-verified with a real (non-loopback) client connection after the reload: succeeded
(`SELECT 1` returned). `trust` auth is obviously permissive — Task 2 may want to scope the CIDR
to the actual Docker bridge subnet and/or switch to `scram-sha-256` with a real password for
anything beyond a fully-isolated test network (see §7 — there's currently no password set at
all).

## 6. Sandbox directory layout & port map (PG 17.10, 1 primary + 2 replicas)

```
$HOME/sandboxes/postgresql_repl_16710/
├── check_recovery          # runs `SELECT pg_is_in_recovery();` against both replica ports
├── check_replication       # runs `SELECT ... FROM pg_stat_replication;` against the primary
├── primary/
│   ├── data/               # PGDATA (postgresql.conf, pg_hba.conf, base/, etc.)
│   ├── postgresql.log
│   ├── start / stop / restart / status / clear / use   # `use` = psql wrapper script
├── replica1/  (same layout)
└── replica2/  (same layout)
```

| Node     | Role    | Port  | `pg_is_in_recovery()` |
|----------|---------|-------|------------------------|
| primary  | primary | 16710 | `f` |
| replica1 | replica | 16711 | `t` |
| replica2 | replica | 16712 | `t` |

**Note:** `dbdeployer sandboxes` (the catalog command) did **not** reliably list this sandbox in
testing — it showed a stale/unrelated entry from an earlier failed attempt while the real,
running `postgresql_repl_16710` tree was absent from its output. **Task 2 should enumerate PG
sandboxes via `ls $HOME/sandboxes/` / the directory tree, not trust `dbdeployer sandboxes` for
the postgresql provider.**

## 7. Superuser, replication user, and adding more users

- Superuser: **`postgres`**, auth method **`trust`** (no password set) for local/loopback
  connections by default. `--db-user`/`--db-password` (global deploy flags, default
  `msandbox`/`msandbox`) are **also ignored** for `--provider=postgresql` — the role is always
  `postgres` with no password, confirmed via `\du` (single role: `postgres`, Superuser/Create
  role/Create DB/Replication/Bypass RLS).
- Replication: dbdeployer does **not** create a dedicated replication role. Each replica's
  `postgresql.auto.conf` sets `primary_conninfo = 'user=postgres passfile=... host=127.0.0.1
  port=16710 ...'` — i.e. replication streams **as the `postgres` superuser itself** via
  streaming replication (`standby.signal` present, `wal_level=replica`, `max_wal_senders=10`,
  `hot_standby=on` baked into the primary's `postgresql.conf` by dbdeployer). No replication
  slots are configured (physical replication via `primary_conninfo`, not slot-based).
- Additional users/passwords: not a dbdeployer feature for PG — just connect as `postgres` via
  the `use` script and run plain SQL, e.g.:
  ```bash
  "$SBASE/primary/use" -c "CREATE ROLE app_user LOGIN PASSWORD 'app_pw';"
  ```

## 8. `pg_stat_statements` availability (confirmed present, verified loadable)

`postgresql-17_17.10-1.pgdg22.04+1_amd64.deb` ships `pg_stat_statements.so` at
`$HOME/opt/postgresql/17.10/lib/pg_stat_statements.so`, plus its control/SQL files under
`share/postgresql/17/extension/pg_stat_statements*`. Confirmed end-to-end:
- `-c shared_preload_libraries=pg_stat_statements` written directly into `postgresql.conf` (see
  §5 workaround) → after restart, `SHOW shared_preload_libraries;` returned `pg_stat_statements`.
- `CREATE EXTENSION pg_stat_statements;` succeeded on the primary; `SELECT 1 FROM
  pg_stat_statements LIMIT 1;` returned a row.

## 9. Full verification transcript (final state)

```
-- primary (port 16710)
SHOW listen_addresses;          -- 0.0.0.0
SHOW max_connections;           -- 500
SHOW shared_preload_libraries;  -- pg_stat_statements
SELECT pg_is_in_recovery();     -- f
CREATE EXTENSION pg_stat_statements;   -- CREATE EXTENSION
SELECT 1 FROM pg_stat_statements LIMIT 1;   -- 1 row

-- check_replication (run on primary, port 16710)
 client_addr |   state   | sent_lsn  | write_lsn | flush_lsn | replay_lsn
-------------+-----------+-----------+-----------+-----------+------------
 127.0.0.1   | streaming | 0/40513C8 | 0/40513C8 | 0/40513C8 | 0/40513C8
 127.0.0.1   | streaming | 0/40513C8 | 0/40513C8 | 0/40513C8 | 0/40513C8

-- check_recovery
=== Replica port 16711 === pg_is_in_recovery = t
=== Replica port 16712 === pg_is_in_recovery = t

-- remote (non-loopback) connectivity, post pg_hba.conf fix
psql -h <container-real-ip> -p 16710 -U postgres -c "SELECT 1 AS remote_ok;"  -- 1
```

## 10. Summary of surprises/limitations for Task 2 to design around

1. No PG tarballs in `dbdeployer downloads list` — must pull PGDG `.deb`s via `apt` and feed them
   to `dbdeployer unpack --provider=postgresql`.
2. Debian PG binaries need their shared-lib dependencies installed system-wide (`libpq5`,
   `libicu70`, `libxml2`, `libxslt1.1`, `libllvm15`, `libedit2`, `libbsd0`, `libmd0`, `tzdata`),
   and a `/usr/share/postgresql/<major>` symlink to the unpacked share dir (hardcoded, non-
   relocatable `sharedir`).
3. `initdb`/`postgres` refuse to run as root — the container must run PG-related dbdeployer
   commands as a non-root user (unlike the MySQL GR image, which runs entirely as root).
4. Because of (3), the downloaded `.deb`s must be readable by that non-root user before
   `dbdeployer unpack` — `/root` is mode 700, so debs fetched under `/root/pgdebs` hit
   "Permission denied". Copy + `chown` them into the user's home (exact commands in §2/§4), or
   download them to a world-readable path in the first place.
5. `--base-port`, `--bind-address`, `-c my-cnf-options`, and `--db-user`/`--db-password` are all
   silently ignored for `--provider=postgresql`; config must be injected by editing
   `postgresql.conf`/`pg_hba.conf` directly and restarting/reloading. Ports are fixed at
   `15000 + major*100 + minor` (16710/16711/16712 for 17.10) — do not fight this, standardize on
   it.
6. `pg_hba.conf` defaults to loopback-only `trust` rules — must append a wider `host ... 0.0.0.0/0`
   (or the actual Docker subnet) entry for cross-container reachability; `pg_reload_conf()` (no
   restart) is sufficient.
7. `dbdeployer sandboxes` does not reliably enumerate PG sandboxes — use the sandbox directory
   tree directly.
8. No dedicated replication role/slots — replicas stream as `postgres` itself with no password
   (`trust`); no password is set for `postgres` by dbdeployer at all.

None of the above break the dbdeployer path — every one has a confirmed, tested workaround above.
**Recommendation: proceed with Task 2a (dbdeployer), incorporating the post-deploy config-patch
step (§5) and the pg_hba widening step (§5) into the Dockerfile/entrypoint.** The native
`postgres:17` fallback (Task 2b) is not needed.
