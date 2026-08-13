# PostgreSQL User Credential Synchronizer Design

## Purpose

Provide an optional sample utility that periodically copies eligible PostgreSQL
role names and password verifiers into ProxySQL's `pgsql_users` table. The
utility gives ProxySQL deployments the useful part of PgBouncer's
`auth_user`/`auth_query` model without putting a remote database lookup in the
client authentication path.

The synchronizer is an external control-plane tool. ProxySQL continues to
authenticate clients exclusively from its in-memory user configuration. An
accepted credential-consistency delay is therefore the configured scheduler
interval plus the duration of one successful synchronization.

This work depends on ProxySQL supporting PostgreSQL SCRAM verifiers and MD5
credential hashes in `pgsql_users`, as proposed by PR #5865 or an equivalent
change. The synchronizer does not implement authentication protocol behavior.

## Goals

- Automatically create ProxySQL users for explicitly selected PostgreSQL login
  roles.
- Copy password verifiers without retrieving or storing plaintext role
  passwords.
- Update credentials and reactivate previously disabled managed users.
- Preserve ProxySQL-specific policy on existing users.
- Make treatment of roles missing from the source snapshot configurable.
- Keep the last successfully loaded runtime configuration when source or
  validation failures occur.
- Provide fast unit tests and an end-to-end PostgreSQL/ProxySQL test.
- Supply secure example configuration, source SQL, and scheduler documentation.

## Non-goals

- A ProxySQL core `auth_query` implementation.
- A login-time credential lookup or cache-miss callback.
- Synchronizing superusers or every role in a PostgreSQL cluster by default.
- Synchronizing ProxySQL routing, limits, TLS, fast-forward, or transaction
  policy from PostgreSQL.
- Terminating already authenticated client sessions after a role is disabled.
- Deleting `pgsql_users` rows. Disabling is reversible and is sufficient for
  the initial sample.
- Coordinating multiple simultaneous synchronization writers.

## Packaging

The sample is placed under `tools/pgsql_user_sync/`:

```text
tools/pgsql_user_sync/
├── README.md
├── create_source_function.sql
├── proxysql_pgsql_user_sync.ini.example
├── proxysql_pgsql_user_sync.py
├── requirements.txt
└── tests/
    └── test_pgsql_user_sync.py
```

The Python implementation uses `psycopg` for PostgreSQL and ProxySQL's
PostgreSQL Admin interface. Database access is isolated behind small adapters
so the reconciliation logic can be tested without live services.

## Source role selection

The example SQL creates:

- a dedicated `NOLOGIN` allow-list role;
- a schema owned by a trusted administrator;
- a fully qualified `SECURITY DEFINER` function; and
- a minimally privileged login role with only `CONNECT`, schema `USAGE`, and
  function `EXECUTE` privileges.

The function has a fixed safe `search_path` and returns exactly two columns:
`username` and `password`. It selects only roles that:

- are direct members of the allow-list role;
- have `rolcanlogin = true`;
- are not superusers;
- have a non-null `rolpassword`; and
- have no expiration or a `rolvaliduntil` later than the current time.

The function checks direct membership through `pg_auth_members`, rather than
`pg_has_role`, so implicit superuser membership cannot bypass the allow-list.
The explicit superuser exclusion prevents accidental import of `postgres`.
Replication users and unrelated service accounts remain excluded unless an
operator explicitly grants direct allow-list membership. A role that stops
satisfying any selection condition is absent from the next snapshot and is
processed according to `missing_role_action`.

## Configuration and command line

The required command form is:

```text
proxysql_pgsql_user_sync.py --config /path/to/pgsql-user-sync.ini [options]
```

The INI file contains three sections:

```ini
[source]
host = postgresql.example
port = 5432
database = postgres
username = proxysql_auth_reader
password = source-secret
connect_timeout = 10
function = proxysql_auth.export_login_roles

[proxysql]
host = 127.0.0.1
port = 6132
username = admin
password = admin-secret
connect_timeout = 10

[sync]
profile = primary-cluster
default_hostgroup = 0
missing_role_action = disable
adopt_existing_users = false
allow_empty_snapshot = false
save_to_disk = true
lock_file = /var/lib/proxysql/proxysql-pgsql-user-sync.lock
```

`profile` is a stable, non-empty identifier used to mark ownership. Profile
names must match `[A-Za-z0-9][A-Za-z0-9_.-]{0,63}`. The configured function
must be a schema-qualified pair of ordinary PostgreSQL identifiers and is
quoted with the driver's identifier-composition API rather than interpolated
into SQL. `default_hostgroup` is a non-negative integer and defaults to `0`,
matching the `pgsql_users` schema. The implementation does not require a
currently populated `pgsql_servers` row for that hostgroup.

The supported non-secret command-line overrides are:

- `--default-hostgroup N`;
- `--missing-role-action disable|keep`;
- `--save-to-disk` and `--no-save-to-disk`;
- `--dry-run`; and
- `--verbose`.

Database passwords are deliberately config-only. They never appear in the
scheduler table, process arguments, or normal logs. The configuration must be a
regular non-symlink file readable by the executing account. Group write/execute
access and all access by other users are rejected; `0600` and root-owned `0640`
with a dedicated ProxySQL group are documented examples. The file is opened and
validated through one descriptor so the checked object cannot be swapped before
parsing. The lock file defaults to ProxySQL's private data directory and also
rejects symlinks. The opened file's metadata is
validated before credentials are used.

## Ownership and row policy

The utility owns only rows bearing this reserved object in the `attributes`
JSON document:

```json
{"proxysql_pgsql_user_sync":{"profile":"primary-cluster"}}
```

Existing attributes outside that reserved key are preserved semantically;
serialization is normalized only when the ownership key must be added or
changed. An existing reserved key with an invalid shape is a conflict rather
than something the script overwrites. Existing `comment` values are not used as
state and are preserved.

For a source role with no ProxySQL row, the utility creates a standard combined
frontend/backend user with:

- `active = 1`;
- `default_hostgroup` from configuration or the CLI override;
- `backend = 1` and `frontend = 1`; and
- all other policy fields at the `pgsql_users` schema defaults.

For an already managed user, the utility changes only `password`, `active`, and
its ownership marker. It preserves `use_ssl`, `default_hostgroup`,
`transaction_persistent`, `fast_forward`, `backend`, `frontend`,
`max_connections`, unrelated attributes, and `comment`.

An existing unmanaged user with the same name is a conflict. By default the
entire run aborts before any write. When `adopt_existing_users = true`, the row
is marked as belonging to the configured profile, its credential is updated,
and all ProxySQL policy fields are preserved. A row already owned by another
profile always causes the run to abort; there is no implicit ownership
transfer.

The script treats the relevant frontend identity as unique. Ambiguous existing
layouts containing multiple rows for the same username are rejected rather
than guessed at.

## Snapshot validation

The complete source result is fetched before connecting changes to ProxySQL.
The snapshot is rejected if:

- it is empty and `allow_empty_snapshot` is false;
- a username is empty, duplicated, contains a NUL byte, or exceeds PostgreSQL's
  63-byte role-name limit when encoded as UTF-8;
- a password value is null or is neither a syntactically valid PostgreSQL SCRAM
  verifier nor an `md5` hash of the expected length; or
- the result shape differs from the documented two-column contract.

The synchronizer validates verifier syntax but never logs verifier contents.
An empty snapshot is not intrinsically invalid, but requiring an explicit
opt-in prevents a source query or permission mistake from disabling every
managed user.

## Reconciliation flow

Each invocation performs these steps:

1. Parse and validate CLI arguments and the protected configuration file.
2. Acquire an exclusive, nonblocking file lock. If another run holds it, report
   a skipped run and exit successfully.
3. Fetch and fully validate the source snapshot.
4. Fetch the relevant `pgsql_users` and `runtime_pgsql_users` rows.
5. Build a deterministic change plan in memory and detect all ownership or row
   conflicts before writing.
6. If `--dry-run` is set, report counts and exit without writing credentials.
7. Apply parameterized Admin statements for planned creates, credential
   updates, reactivations, and optional disables.
8. Run `LOAD PGSQL USERS TO RUNTIME` when Admin rows changed or when the managed
   main/runtime views differ.
9. If configured, run `SAVE PGSQL USERS TO DISK` only after a successful runtime
   load.
10. Emit a summary containing counts, duration, profile, and outcome, then
    release the lock.

ProxySQL's Admin interface acknowledges transaction-control statements without
opening a client-visible SQLite transaction. Therefore the design does not
claim that multiple Admin writes are transactionally atomic. Runtime safety is
the boundary: no `LOAD` is issued until every planned Admin write succeeds. A
mid-write failure can leave `main.pgsql_users` partially updated while
`runtime_pgsql_users` remains the last-known-good configuration. The next run
recomputes the plan from both tables and repairs/reloads it. This limitation is
called out in the README.

`LOAD PGSQL USERS TO RUNTIME` is also required when the source and main table
already match but managed main and runtime rows do not. This makes a load
failure retryable on the next scheduler execution.

## Missing role behavior

`missing_role_action` supports two values:

- `disable` (default): set `active = 0` for managed rows whose names are absent
  from the validated source snapshot;
- `keep`: make no change to managed rows absent from the snapshot.

Only rows owned by the active profile are considered. No mode deletes rows.
When a disabled role becomes eligible again, a later run updates its verifier
and sets `active = 1`.

## Failure handling and observability

- Configuration, source connection, query, and snapshot-validation failures
  occur before writes and exit nonzero.
- Ownership and ambiguous-row conflicts abort before writes and exit nonzero.
- A ProxySQL Admin write failure exits nonzero without loading runtime.
- A runtime-load failure exits nonzero and is retried on the next invocation
  because main/runtime divergence remains visible.
- A disk-save failure exits nonzero but does not roll back the already loaded
  runtime configuration; the summary distinguishes this partial operational
  outcome.
- Lock contention is an expected scheduler condition and exits zero.
- Logs include the profile, elapsed time, and counts for discovered, created,
  updated, reactivated, disabled, unchanged, and conflicted users.
- Logs never include passwords, verifiers, connection strings containing
  passwords, or complete configuration objects.

Normal successful and skipped runs produce one concise summary line. Verbose
mode may report usernames and planned action types, but still never credential
material.

## Scheduler operation

ProxySQL invokes scheduler programs using `execve` with an empty environment and
does not prevent overlapping occurrences. The example therefore uses absolute
paths and relies on the script's file lock:

```sql
INSERT INTO scheduler
    (id, active, interval_ms, filename, arg1, arg2, arg3, comment)
VALUES
    (9100, 1, 10000,
     '/usr/bin/python3',
     '/usr/share/proxysql/tools/pgsql_user_sync/proxysql_pgsql_user_sync.py',
     '--config',
     '/etc/proxysql/pgsql-user-sync.ini',
     'Synchronize PostgreSQL role verifiers');

LOAD SCHEDULER TO RUNTIME;
SAVE SCHEDULER TO DISK;
```

The script does not depend on environment variables. The README documents
installing the Python dependencies in a dedicated virtual environment as an
alternative; in that case `scheduler.filename` is the absolute path to that
environment's Python interpreter.

For a ProxySQL cluster, operators must choose one of these models:

1. Run the synchronizer on one authoritative ProxySQL node and enable
   `pgsql_users` cluster propagation.
2. Run the same deterministic profile on every node and disable cluster
   propagation for `pgsql_users`.

Combining independent writers with cluster propagation is unsupported because
it can cause checksum/epoch churn and competing updates.

## Test strategy

### Unit tests

`tools/pgsql_user_sync/tests/test_pgsql_user_sync.py` uses Python's standard
`unittest` and fake source/Admin adapters. It covers:

- configuration defaults, required fields, permissions, and CLI precedence;
- hostgroup, profile, boolean, enum, and timeout validation;
- SCRAM and MD5 verifier syntax without exposing test values in errors;
- empty, duplicate, malformed, and wrong-shaped source snapshots;
- automatic creation with the built-in and overridden hostgroup;
- credential update and reactivation;
- preservation of every ProxySQL policy field, comment, and unrelated
  attribute;
- managed ownership, unmanaged adoption, cross-profile conflicts, and
  ambiguous existing rows;
- both `disable` and `keep` missing-role behavior;
- empty-snapshot opt-in;
- dry-run behavior;
- source failure and Admin write failure behavior;
- load retry caused by main/runtime divergence;
- conditional disk save;
- lock contention; and
- secret redaction in normal, verbose, and error logs.

The adapters expose narrow methods such as `fetch_snapshot`, `fetch_users`,
`apply_actions`, `load_runtime`, and `save_to_disk`. Planning tests operate on
plain immutable records, keeping most coverage independent of driver versions.

### End-to-end test

A PostgreSQL infrastructure test exercises the installed drivers, source
function, ProxySQL Admin interface, and verifier-capable authentication path:

1. Create the allow-list, reader, source function, and a SCRAM login role.
2. Run the utility and assert automatic creation in both `pgsql_users` and
   `runtime_pgsql_users` with the configured hostgroup and ownership marker.
3. Authenticate through ProxySQL using the source role.
4. Rotate the PostgreSQL password, rerun synchronization, and verify the old
   password fails while the new password succeeds.
5. Remove `LOGIN` or expire the role, rerun with `disable`, and verify the
   managed ProxySQL row becomes inactive.
6. Exercise `keep` and verify the managed row remains active when absent.
7. Verify an unrelated unmanaged ProxySQL user remains byte-for-byte unchanged.
8. Make the source lookup fail and verify runtime users remain unchanged.

The integration test is registered only in a PostgreSQL-backed TAP group and
is gated on verifier-capable ProxySQL behavior. Until the equivalent of PR
PR #5865 is present in the target branch, the test must report a clear dependency
skip rather than masking a synchronizer failure.

## Acceptance criteria

- An allow-listed SCRAM or MD5 PostgreSQL role is automatically provisioned in
  ProxySQL without plaintext password access.
- A configurable default hostgroup is used only for new users.
- Existing ProxySQL policy survives credential changes and adoption.
- Missing managed roles are disabled or kept according to configuration.
- Unmanaged and other-profile rows cannot be silently changed.
- No source-side failure or invalid snapshot changes runtime authentication.
- Runtime loading is retried after main/runtime divergence.
- Secrets and verifiers do not appear in logs or process arguments.
- Unit tests cover reconciliation and error paths; the infrastructure test
  covers creation, authentication, rotation, revocation behavior, isolation,
  and source failure.
