# Managed API engine checks

`aws-managed-mysql-g1` and `aws-managed-pgsql-g1` exercise a paired core, AWS
plugin and web plugin deployment prepared by the web repository's managed
acceptance runner. They use the normal repository infrastructure scripts and
real MySQL 8.4 / PostgreSQL 17 backends.

Prepare each runtime with explicit local test credentials and verified TLS.
Write its fixture to
`$WORKSPACE/ci_infra_logs/$INFRA_ID/aws-managed/MYSQL.json` or
`POSTGRESQL.json`. Keep generated credential fixtures private and remove them
when the owned runtime is torn down. They are test artifacts, never source files.
The runner must bind an address reachable from the test container, and the
certificate must match the API and database hostnames/IP addresses used there.

Fixture fields:

- `api_url`: complete HTTPS native configuration resource URL.
- `region`, `ca_path`, `access_key_id`, `secret_access_key`: explicit signing and
  certificate inputs. No ambient AWS credential provider is used.
- `envelope`: complete schema-v1 replacement, including write-only `secrets`.
  The test supplies current `expected_revision` and a fresh idempotency key.
- `proxy`: `host`, numeric `port`, `user`, `password`, `database`, `ca_path`.
- `check`: a SQL `query` returning one row/column and string `expected` proving
  the configured per-hostgroup `init_connect` took effect.

The envelope should change a frontend credential from bootstrap and configure
matching existing backend credentials, routing, TLS and `init_connect`. Both
engines require an actual verified TLS connection and SQL execution. The test
never issues Admin `LOAD` or `SAVE`. Missing fixtures, signing failures, failed
API activation or unavailable databases fail; none are treated as skips.

Run the selected group through `test/infra/control/run-tests-isolated.bash`
after the repository `ensure-infras.bash` initialization and owned runtime setup.
The paired web acceptance suite additionally owns interruption/restart,
pending/applied recovery and SDK/CLI/Terraform checks; these short engine tests
do not replace those gates.
