# PostgreSQL user synchronizer sample

This operator-managed sample periodically copies eligible PostgreSQL role
verifiers into ProxySQL's `pgsql_users` table.  It never reads plaintext role
passwords.  ProxySQL continues to authenticate from its runtime user table;
the scheduler interval plus one successful run is the expected propagation
delay.

The sample owns only rows marked in `attributes` with
`{"proxysql_pgsql_user_sync":{"profile":"..."}}`.  It does not synchronize
routing, TLS, connection limits, or other ProxySQL policy.

## Install and protect the configuration

Install the dependencies in a dedicated environment (or into the Python
installation used by Scheduler):

```console
python3 -m venv /opt/proxysql-pgsql-user-sync
/opt/proxysql-pgsql-user-sync/bin/pip install -r requirements.txt
install -m 0755 proxysql_pgsql_user_sync.py /usr/share/proxysql/tools/pgsql_user_sync/
```

Copy `proxysql_pgsql_user_sync.ini.example` to a regular file, replace both
obvious password placeholders, and restrict it before entering real secrets:

```console
install -o proxysql -g proxysql -m 0600 proxysql_pgsql_user_sync.ini.example /etc/proxysql/pgsql-user-sync.ini
```

Set `[proxysql]` to ProxySQL's PostgreSQL Admin interface (normally port
`6132`).  The synchronizer uses PostgreSQL's simple-query protocol there.

The synchronizer rejects group-write/execute and other-user permissions, and
accepts only files owned by root or by the account running it. The primary
example is service-owned `0600` so the ProxySQL service account can read it.
Alternatively, keep the file root-owned and use `chown root:proxysql` with mode
`0640` (a dedicated `proxysql` group); that is also accepted. Database passwords
stay in this file and never appear in Scheduler arguments or normal logs.

## Create the source function and allow-list

As a trusted PostgreSQL administrator, connect to the configured database and
run `create_source_function.sql` with a runtime-only reader password:

```console
psql --set=ON_ERROR_STOP=1 --set=proxysql_auth_reader_password='choose-a-secret' \\
  --file=create_source_function.sql postgres
```

The script is rerunnable: it reapplies the reader password, creates a
`SECURITY DEFINER` function with `SET search_path = pg_catalog`, and explicitly
revokes defaults before granting only database `CONNECT`, schema `USAGE`, and
function `EXECUTE`.

The `proxysql_auth_managed` `NOLOGIN` role is the import allow-list.  Grant and
revoke membership deliberately, for example:

```sql
GRANT proxysql_auth_managed TO app_login;
REVOKE proxysql_auth_managed FROM app_login;
```

The function uses a direct allow-list membership check and additionally
requires a login-capable, non-superuser role with a non-null verifier and no
expired `rolvaliduntil`. Replication roles and service accounts are not
imported unless an operator explicitly places them on the allow-list;
superusers are always excluded.

## Run manually

Always use absolute paths when invoking the script:

```console
/opt/proxysql-pgsql-user-sync/bin/python /usr/share/proxysql/tools/pgsql_user_sync/proxysql_pgsql_user_sync.py \
  --config /etc/proxysql/pgsql-user-sync.ini --dry-run --verbose
```

Remove `--dry-run` to apply the plan.  Useful non-secret overrides are
`--default-hostgroup N`, `--missing-role-action disable|keep`,
`--save-to-disk`/`--no-save-to-disk`, and `--verbose`.  `--dry-run` fetches and
validates both snapshots but performs no writes, runtime load, or disk save.
An exclusive lock makes overlapping scheduler invocations a successful skip.
The default lock is in ProxySQL's private data directory; if you override it,
use a service-owned directory. Symlinked configuration and lock files are
rejected.

## ProxySQL Scheduler

ProxySQL starts scheduler programs with `execve` and an empty environment, so
the filename, script, interpreter, and configuration path must all be
absolute.  The script's lock file handles overlap.  Adapt the ID and paths to
your installation, then run the two load/save statements shown below:

```sql
INSERT INTO scheduler
    (id, active, interval_ms, filename, arg1, arg2, arg3, comment)
VALUES
    (9100, 1, 10000,
     '/opt/proxysql-pgsql-user-sync/bin/python',
     '/usr/share/proxysql/tools/pgsql_user_sync/proxysql_pgsql_user_sync.py',
     '--config',
     '/etc/proxysql/pgsql-user-sync.ini',
     'Synchronize PostgreSQL role verifiers');

LOAD SCHEDULER TO RUNTIME;
SAVE SCHEDULER TO DISK;
```

## Missing roles and existing users

`missing_role_action = disable` (the default) sets `active = 0` for managed
rows absent from the validated source snapshot.  `keep` leaves them alone.
Neither mode deletes rows, and a role that becomes eligible later is updated
and reactivated.

An existing unmanaged username is a conflict and aborts before writes by
default.  Set `adopt_existing_users = true` only after reviewing the row: the
next run marks it for this profile and preserves its other ProxySQL policy.
A row owned by another profile is always a conflict; ownership is never
silently transferred.

## Failure and recovery boundaries

The synchronizer builds and validates the complete source snapshot before
writing.  It uses the Admin interface's autocommit operations, so the main
table and runtime load are **non-transactional**: a mid-run write failure can
leave `main.pgsql_users` partially changed while runtime retains its last
known-good state.  No global `LOAD PGSQL USERS TO RUNTIME` is issued until all
planned writes succeed.  The next run compares both tables and repairs the
main/runtime divergence.

`LOAD PGSQL USERS TO RUNTIME` is global.  To avoid overwriting unrelated
runtime state, a detected unmanaged main/runtime divergence aborts before any
write or load.  A runtime-load failure is retried on the next run.  A disk
save occurs only after a successful load; if it fails, the already-loaded
runtime remains active and the outcome is reported as partial.  Set
`save_to_disk = false` or use `--no-save-to-disk` when disk persistence is
managed separately.

Successful and skipped runs emit one concise summary containing profile,
duration, and discovered/created/updated/reactivated/disabled/unchanged/
conflicted counts.  Errors are nonzero except lock contention, which is an
expected successful skip.  Logs never contain passwords, verifiers, password-
bearing connection strings, or complete configuration objects.  Verbose mode
may name users and action types, but still never credential material.

## Cluster operation

Choose exactly one of these mutually exclusive models:

1. Run the synchronizer on one authoritative ProxySQL node and enable
   `pgsql_users` cluster propagation.
2. Run the same deterministic profile on every node and disable cluster
   propagation for `pgsql_users`.

Do not combine independent writers with cluster propagation: competing loads
can cause checksum/epoch churn and race one another.
