# AWS RDS Blue/Green Deployment Simulator

**Document status:** DESIGN APPROVED; IMPLEMENTATION NOT STARTED

**Applies to:** `TEST_RDS_BGD`, the SQLite3-server simulation surface, BGD TAP
helpers, the local Docker runner, and the matching GitHub Actions job

**Related monitor contract:** [RDS_BGD_Monitor.md](RDS_BGD_Monitor.md)

## Purpose

This document defines the simulator used to test ProxySQL's AWS RDS Blue/Green
Deployment monitor. It combines the behavioral contract, SQLite3-server
changes, TAP helper API, network fixture, local runner, CI job, and supported
coverage into one implementation specification.

## Architecture

The TAP test is the scenario controller. It configures ProxySQL with AWS-style
hostnames, writes simulated backend state to ProxySQL's SQLite3 server, changes
that state to drive the BGD FSM, and verifies ProxySQL through runtime,
statistics, and simulator probe-log tables. Topology state is keyed by backend
IP, while read-only state is keyed by the configured hostname.

No `test/deps/cluster_simulator` process or backend database container is
required. A common TAP helper owns reusable SQLite3-server operations, while a
BGD helper translates explicit test intent into topology state and probe-log
queries. Neither helper advances the FSM or owns scenario timing.

## `TEST_RDS_BGD` Boundary

Simulator tables, BGD response interception, listener changes, and supporting
members are compiled only under `TEST_RDS_BGD`. A production build contains no
BGD simulator surface and preserves the existing production monitor queries,
connection behavior, and DNS behavior.

The flag reuses shared TEST-mode SQLite3-server infrastructure, including the
existing `READONLY_STATUS` mechanism, without changing the behavior of
`TEST_AURORA`, `TEST_GALERA`, `TEST_GROUPREP`, `TEST_READONLY`, or
`TEST_REPLICATIONLAG` builds.

## Network Model

The BGD TAP group injects a shared `/etc/hosts` map containing AWS-style blue
and green names. Every hostname resolves to a distinct loopback IP and uses
port 3306, preserving the address shape used by AWS while a single wildcard
SQLite3-server listener handles all simulated endpoints.

Tests add servers to ProxySQL by hostname. They configure topology state using
the corresponding IP and read-only state using the configured hostname and
port. Distinct destination IPs retain the blue/green split when ProxySQL
resolves a hostname or directly probes the resolved green IP.

The map reserves multiple clusters and two green endpoint sets for cluster 1.
Tests configure only the endpoints they need: separate clusters support
simultaneous switchovers, and the alternate cluster-1 green set supports a
second switchover after the previous FSM resets on empty or absent topology.

## Backend Identity and Topology Ownership

ProxySQL sends the production BGD queries unchanged. The SQLite3 server calls
`getsockname()` on the accepted connection and uses the resulting
`backend_ip, backend_port` as the simulator key; no hostname, address, port, or
comment is appended to the query.

Topology belongs only to backend keys explicitly updated by the TAP test. A
normal scenario publishes metadata to the blue and green writer IPs; readers
have no topology table unless a test intentionally configures one. The helper
does not copy state between deployment members implicitly.

Under `TEST_RDS_BGD`, use `sockaddr_storage` for IPv4 and IPv6-safe local
address extraction. Failure to resolve the accepted local address is a
simulator error and must not fall back to an arbitrary backend row.

## SQLite3-Server Storage

Create the following tables in `SQLite3_Server::init()` and store them in the
existing persistent `GloVars.sqlite3serverdb` database:

```sql
CREATE TABLE RDS_BGD_CONTROL (
    backend_ip TEXT NOT NULL,
    backend_port INTEGER NOT NULL,
    topology_present INTEGER NOT NULL DEFAULT 0 CHECK (topology_present IN (0,1)),
    error_code INTEGER NOT NULL DEFAULT 0,
    error_msg TEXT NOT NULL DEFAULT '',
    PRIMARY KEY (backend_ip, backend_port)
);

CREATE TABLE RDS_BGD_TOPOLOGY (
    backend_ip TEXT NOT NULL,
    backend_port INTEGER NOT NULL,
    row_order INTEGER NOT NULL,
    id TEXT NOT NULL,
    endpoint TEXT NOT NULL,
    topology_port INTEGER NOT NULL,
    role TEXT NOT NULL,
    status TEXT NOT NULL,
    PRIMARY KEY (backend_ip, backend_port, row_order)
);

CREATE TABLE RDS_BGD_PROBE_LOG (
    sequence_id INTEGER PRIMARY KEY AUTOINCREMENT,
    backend_ip TEXT NOT NULL,
    backend_port INTEGER NOT NULL,
    probe_kind TEXT NOT NULL CHECK (probe_kind IN ('table_check','metadata')),
    encrypted INTEGER NOT NULL CHECK (encrypted IN (0,1))
);
```

Each SQLite3-server session already opens this database in WAL/FULLMUTEX mode.
TAP writes and monitor reads therefore share persistent state without an
attached in-memory schema or a control connection that keeps data alive.

## Query Dispatch

Run the existing SQL normalization first: collapse whitespace, remove trailing
spaces or semicolons, and compare case-insensitively. Intercept only a complete
match for one of the production BGD constants:

```sql
SELECT 1 FROM information_schema.TABLES
 WHERE TABLE_SCHEMA='mysql' AND TABLE_NAME='rds_topology'

SELECT * FROM mysql.rds_topology
```

For either match, resolve the accepted backend key, load its control row,
select the response described below, append a probe-log row, and send the
result. An address-extraction failure returns a simulator error without
selecting state or logging an invalid backend identity.

Simulated read-only checks follow the handling described below. All remaining
statements continue through normal SQLite3-server handling. TAP control and
inspection statements against the simulator tables are not rewritten or
recorded as BGD monitor probes.

## Control-State Meaning

The TAP helper updates the control and topology tables in one transaction, so
a monitor query observes either the previous state or the complete new state.
The supported states are:

| `RDS_BGD_CONTROL` state | Topology rows | Meaning |
|---|---|---|
| No backend row | None | Backend is unconfigured; topology is absent. |
| `topology_present=1`, `error_code=0` | One or more | Return the configured topology. |
| `topology_present=1`, `error_code=0` | Empty | Table exists but contains no topology. |
| `topology_present=1`, `error_code!=0` | Unchanged | Table exists, but its metadata query fails. |
| `topology_present=0`, `error_code=1146` | Empty | Table has been dropped. |

Topology update and delete operations clear `error_code` and `error_msg`.
Configured errors other than 1146 mark the table present and retain its rows;
error 1146 marks it absent. Dropping topology also removes its rows. Other flag
combinations are invalid helper state.

## Topology Responses

The table check consults only `topology_present`. Metadata handling applies a
configured error before reading topology rows:

| Query | Selected backend state | MySQL response |
|---|---|---|
| Table check | No control row or `topology_present=0` | Successful result with zero rows. |
| Table check | `topology_present=1` | One column named `1`, containing one row with value `1`. |
| Metadata | No control row | Error 1146: `Table 'mysql.rds_topology' doesn't exist`. |
| Metadata | `error_code!=0` | Stored `error_code` and `error_msg`. |
| Metadata | `error_code=0`, `topology_present=0` | Error 1146 as a defensive fallback. |
| Metadata | `error_code=0`, `topology_present=1` | Ordered backend rows; an empty set remains successful. |

A successful metadata result exposes `id, endpoint, port, role, status`.
`topology_port` supplies the `port` result, and `row_order` determines row
order. Rows belonging to another backend key must never enter the result.

## Error Packets and Probe Log

The existing `send_MySQL_ERR()` always returns error 1045. Add an overload that
accepts an error code and message; error 1146 uses SQLSTATE `42S02`, while other
configured simulator errors may use `HY000` unless a test requires a specific
mapping.

Every handled topology-table check or metadata query appends one row to
`RDS_BGD_PROBE_LOG`, including empty and error responses. `sequence_id`
preserves order, `probe_kind` identifies the query, `backend_ip, backend_port`
identify the destination, and `encrypted` records the accepted stream's TLS
state.

The TAP test is the only probe-log consumer; ProxySQL never reads it. A test
captures a sequence watermark before changing state and then reads later rows
to verify the selected destination and TLS mode. A probe-log insertion failure
is a simulator failure and must not be silently reported as a normal backend
response.

## Read-Only Simulation

`TEST_RDS_BGD` builds the shared `READONLY_STATUS(hostname, port, read_only)`
table and the read-only cache, without calling `enable_readonly_testing()`.
The TAP test owns ProxySQL hostgroup and server configuration and writes each
read-only value using the AWS hostname configured in `mysql_servers`.

Read-only monitor tasks send the simulation query
`SELECT @@global.read_only read_only <hostname>:<port>`. The SQLite3 server
uses the suffix to read the cached value populated from `READONLY_STATUS` and
returns one `read_only` column. Table writes refresh the cache, and a missing
entry returns the safe default `read_only=1`.

BGD topology tasks send the production topology queries unchanged. Read-only
handling does not consult `RDS_BGD_CONTROL` or write `RDS_BGD_PROBE_LOG`.

## TAP Helper API

The API follows existing TAP conventions: write methods return `EXIT_SUCCESS`
or `EXIT_FAILURE`, and read methods return the existing `rc_t<T>` type. The
signatures below are the initial API and may grow with reviewed test cases.

### Common Endpoint

```cpp
struct Simulator_Endpoint {
	std::string host;
	int port;
};
```

Identifies one simulated backend. For BGD topology and probe-log operations,
`host` is the backend IP. For `read_only_update()`, `host` is the AWS hostname
configured in ProxySQL.

### `Cluster_Simulator`

```cpp
int connect(
	const char* host,
	int port,
	const char* username,
	const char* password,
	bool use_ssl = false);

int read_only_update(const Simulator_Endpoint& backend, bool read_only);
```

`connect()` opens the SQLite3-server control connection with the MySQL client
API; the helper closes it when destroyed. `read_only_update()` changes the
`READONLY_STATUS` row identified by configured hostname and port.

### Topology and Host Types

```cpp
struct RDS_BGD_Topology_Row {
	std::string id;
	std::string endpoint;
	int port;
	std::string role;
	std::string status;
};

struct RDS_BGD_Host {
	std::string hostname;
	std::string ip;
	int port;

	Simulator_Endpoint endpoint() const;
};
```

`RDS_BGD_Topology_Row` represents one `mysql.rds_topology` row using
C++11-compatible field types. `RDS_BGD_Host` keeps the ProxySQL-facing
hostname and simulator-facing IP together.

### Shared Cluster Fixture

```cpp
class RDS_BGD_Cluster {
public:
	const RDS_BGD_Host& blue_writer() const;
	const RDS_BGD_Host& green_writer() const;
	const std::vector<RDS_BGD_Host>& blue_readers() const;
	const std::vector<RDS_BGD_Host>& green_readers() const;
	std::vector<Simulator_Endpoint> get_writers() const;
	std::vector<RDS_BGD_Topology_Row> get_topology(
		const std::string& status) const;
};

const RDS_BGD_Cluster& rds_bgd_test_cluster();
```

The fixture encapsulates the shared `/etc/hosts` mapping. `get_writers()`
returns the selected blue and green writer IPs; `get_topology(status)` returns
the standard two-row SOURCE/TARGET topology using the writer hostnames and the
provided status.

### BGD Topology Operations

```cpp
int topology_update(
	const std::vector<Simulator_Endpoint>& backends,
	const std::vector<RDS_BGD_Topology_Row>& rows);

int topology_delete(const std::vector<Simulator_Endpoint>& backends);

int topology_drop(const std::vector<Simulator_Endpoint>& backends);

int topology_error(
	const std::vector<Simulator_Endpoint>& backends,
	unsigned int error_code,
	const std::string& error_msg);
```

`topology_update()` marks the table present, clears any configured error, and
replaces rows on only the supplied backends. `topology_delete()` clears rows
and errors while leaving the table present.

`topology_drop()` clears rows, marks the table absent, and records error 1146
with `Table 'mysql.rds_topology' doesn't exist`. `topology_error()` requires a
nonzero code; 1146 marks topology absent, while any other code marks it present
and leaves existing rows unchanged.

### Probe-Log Operations

```cpp
enum class RDS_BGD_Probe_Kind {
	table_check,
	metadata,
};

struct RDS_BGD_Probe_Log {
	uint64_t sequence_id;
	Simulator_Endpoint backend;
	RDS_BGD_Probe_Kind probe_kind;
	bool encrypted;
};

rc_t<uint64_t> probe_log_last_sequence();

rc_t<std::vector<RDS_BGD_Probe_Log>> probe_log_since(uint64_t sequence_id);

rc_t<RDS_BGD_Probe_Log> wait_for_probe_log(
	uint64_t sequence_id,
	const Simulator_Endpoint& backend,
	RDS_BGD_Probe_Kind probe_kind,
	uint32_t timeout_ms,
	int encrypted = -1);
```

The watermark method returns zero for an empty log. `probe_log_since()` returns
rows after a watermark. `wait_for_probe_log()` waits for one matching row;
`encrypted` is `-1` for either mode, `0` for plaintext, and `1` for TLS.

## Typical TAP Test

```cpp
int main() {
	plan(3);

	CommandLine cl {};
	if (cl.getEnv()) BAIL_OUT("failed to load TAP environment");

	MYSQL* admin = init_mysql_conn(
		cl.admin_host, cl.admin_port, cl.admin_username, cl.admin_password);
	if (!admin) BAIL_OUT("failed to connect to ProxySQL Admin");

	const RDS_BGD_Cluster& cluster = rds_bgd_test_cluster();
	if (configure_proxysql_for_bgd(admin, cluster) != EXIT_SUCCESS)
		BAIL_OUT("failed to configure ProxySQL");

	std::pair<std::string, int> sqlite_server;
	if (extract_sqlite3_host_port(admin, sqlite_server) != EXIT_SUCCESS)
		BAIL_OUT("failed to find SQLite3-server address");

	RDS_BGD_Simulator simulator;
	if (simulator.connect(
		sqlite_server.first.c_str(), sqlite_server.second,
		cl.username, cl.password) != EXIT_SUCCESS)
		BAIL_OUT("failed to connect to SQLite3 server");
	if (simulator.read_only_update(
			{ cluster.blue_writer().hostname, cluster.blue_writer().port }, false) != EXIT_SUCCESS ||
		simulator.read_only_update(
			{ cluster.green_writer().hostname, cluster.green_writer().port }, false) != EXIT_SUCCESS)
		BAIL_OUT("failed to configure writer read_only state");

	const rc_t<uint64_t> mark = simulator.probe_log_last_sequence();
	if (mark.first != EXIT_SUCCESS)
		BAIL_OUT("failed to read probe-log watermark");

	const int update_rc = simulator.topology_update(
		cluster.get_writers(), cluster.get_topology("AVAILABLE"));
	ok(update_rc == EXIT_SUCCESS, "publish topology to both writer IPs");
	if (update_rc != EXIT_SUCCESS)
		BAIL_OUT("failed to publish topology");

	ok(wait_for_cond(admin,
		"SELECT status='AVAILABLE' FROM runtime_mysql_aws_rds_bgd_hostgroups "
		"WHERE writer_hostgroup=10", 5) == EXIT_SUCCESS,
		"ProxySQL enters AVAILABLE");

	const rc_t<RDS_BGD_Probe_Log> green_log = simulator.wait_for_probe_log(
		mark.second,
		cluster.green_writer().endpoint(),
		RDS_BGD_Probe_Kind::metadata,
		5000);
	ok(green_log.first == EXIT_SUCCESS,
		"ProxySQL probes the green writer IP directly");

	mysql_close(admin);
	return exit_status();
}
```

ProxySQL configuration remains test-local. The simulator changes backend
responses and reads probe evidence; assertions against ProxySQL use Admin SQL.

## Build Integration

Add `build_lib_test_rds_bgd`, `build_src_test_rds_bgd`, and the top-level
`test_rds_bgd` target. The lib and src targets compile with
`-DDEBUG -DTEST_RDS_BGD`; none depends on `build_cluster_simulator`.

`test_rds_bgd` depends on `build_src_test_rds_bgd` and then invokes `make
debug` in `test/tap`:

```text
build_deps_debug -> build_lib_test_rds_bgd -> build_src_test_rds_bgd
                 -> TAP debug build
```

Use `test_rds_bgd` as the single entry point. Do not invoke
`build_tap_test_debug` afterward because its `build_src_debug` dependency
selects the normal debug daemon. Add `-DTEST_RDS_BGD` to `testall` as well.

## Local CI Group

Add `test/tap/groups/cluster_sim_rds_bgd/` and execute it as
`cluster_sim_rds_bgd-g1`.

| File | BGD-specific content |
|---|---|
| `env.sh` | Set `CLUSTER_SIM_HOST_FILE` and `SKIP_CLUSTER_START=1`. |
| `add-hosts` | Define the fixed hostname/IP map below. |
| `pre-proxysql.bash` | Keep the existing short startup wait before Admin writes. |
| `pre-proxysql.sql` | Add the simulator user and move the SQLite3 server to port 3306. |

The group has no `infras.lst`, `CLUSTER_SIM_BINARY_PATH`, or
`CLUSTER_SIM_TESTS_ROOT`. The TAP binary controls the simulator directly.

```bash
export CLUSTER_SIM_HOST_FILE="${WORKSPACE}/test/tap/groups/cluster_sim_rds_bgd/add-hosts"
export SKIP_CLUSTER_START=1
```

### Fixed Host Map

All BGD TAP tests use this map. Green endpoints retain the blue endpoint's
first label and append `-green-<suffix>` before the common domain.

```text
# Cluster 1: blue endpoints
db-1.c1yqcg0ie39o.eu-north-1.rds.amazonaws.com                         127.10.0.11
db-1-reader-1.c1yqcg0ie39o.eu-north-1.rds.amazonaws.com                127.10.0.12
db-1-reader-2.c1yqcg0ie39o.eu-north-1.rds.amazonaws.com                127.10.0.13

# Cluster 1: green deployment A
db-1-green-iqu47r.c1yqcg0ie39o.eu-north-1.rds.amazonaws.com            127.10.0.14
db-1-reader-1-green-dlzky7.c1yqcg0ie39o.eu-north-1.rds.amazonaws.com   127.10.0.15
db-1-reader-2-green-3fpjuu.c1yqcg0ie39o.eu-north-1.rds.amazonaws.com   127.10.0.16

# Cluster 1: green deployment B, for repeated switchovers
db-1-green-s7m2kx.c1yqcg0ie39o.eu-north-1.rds.amazonaws.com            127.10.0.17
db-1-reader-1-green-v4n8qp.c1yqcg0ie39o.eu-north-1.rds.amazonaws.com   127.10.0.18
db-1-reader-2-green-w6h3rz.c1yqcg0ie39o.eu-north-1.rds.amazonaws.com   127.10.0.19

# Cluster 2: reserved for multi-cluster tests
db-2.c1yqcg0ie39o.eu-north-1.rds.amazonaws.com                         127.10.0.20
db-2-reader-1.c1yqcg0ie39o.eu-north-1.rds.amazonaws.com                127.10.0.21
db-2-reader-2.c1yqcg0ie39o.eu-north-1.rds.amazonaws.com                127.10.0.22
db-2-green-iqu47r.c1yqcg0ie39o.eu-north-1.rds.amazonaws.com            127.10.0.23
db-2-reader-1-green-dlzky7.c1yqcg0ie39o.eu-north-1.rds.amazonaws.com   127.10.0.24
db-2-reader-2-green-3fpjuu.c1yqcg0ie39o.eu-north-1.rds.amazonaws.com   127.10.0.25

# Cluster 3: reserved for multi-cluster tests
db-3.c1yqcg0ie39o.eu-north-1.rds.amazonaws.com                         127.10.0.26
db-3-reader-1.c1yqcg0ie39o.eu-north-1.rds.amazonaws.com                127.10.0.27
db-3-reader-2.c1yqcg0ie39o.eu-north-1.rds.amazonaws.com                127.10.0.28
db-3-green-iqu47r.c1yqcg0ie39o.eu-north-1.rds.amazonaws.com            127.10.0.29
db-3-reader-1-green-dlzky7.c1yqcg0ie39o.eu-north-1.rds.amazonaws.com   127.10.0.30
db-3-reader-2-green-3fpjuu.c1yqcg0ie39o.eu-north-1.rds.amazonaws.com   127.10.0.31
```

Every endpoint uses port 3306. Cluster 1 with green deployment A is sufficient
for normal FSM cases. A repeated-switchover test completes deployment A, waits
for empty or absent topology to reset the FSM, replaces A's green hostgroup
rows with deployment B, and publishes the next topology. Clusters 2 and 3 are
available for simultaneous switchovers.

### SQLite3-Server Hook

`pre-proxysql.sql` provisions the simulator credentials and changes the
SQLite3-server listener from the CI default to port 3306:

```sql
INSERT OR REPLACE INTO mysql_users
    (username, password, default_hostgroup, active)
    VALUES ('testuser', 'testuser', 0, 1);
LOAD MYSQL USERS TO RUNTIME;
SAVE MYSQL USERS TO DISK;

SET sqliteserver-mysql_ifaces='0.0.0.0:3306';
LOAD SQLITESERVER VARIABLES TO RUNTIME;
SAVE SQLITESERVER VARIABLES TO DISK;
```

The hook does not populate `mysql_servers` or
`mysql_aws_rds_bgd_hostgroups`; each test owns its ProxySQL configuration and
simulator transitions. From the TAP container, the control connection uses
`proxysql:3306` on the existing isolated Docker network.

### Group Registration and Local Run

Register each BGD TAP binary in `test/tap/groups/groups.json`:

```json
"test_rds_bgd-t": [ "cluster_sim_rds_bgd-g1" ]
```

Add the group and its `make test_rds_bgd` requirement to the simulator table in
`test/infra/README.md`. Clean when switching compile flavors because Make does
not track changed preprocessor flags:

```bash
make clean
make -j"$(nproc)" test_rds_bgd

export INFRA_ID="rds-bgd-$(date +%s)"
export TAP_GROUP="cluster_sim_rds_bgd-g1"

./test/infra/control/ensure-infras.bash
./test/infra/control/run-tests-isolated.bash
./test/infra/control/destroy-infras.bash
```

The existing runner injects the host aliases, starts ProxySQL with
`--sqlite3-server`, executes the registered TAP binaries in the test container,
and collects logs. No BGD branch is required in `ensure-infras.bash`,
`start-proxysql-isolated.bash`, or `run-tests-isolated.bash`.

## GitHub Actions

Add `.github/workflows/CI-rds-bgd-simulator.yml`. It runs on
`workflow_dispatch` and after a successful `CI-trigger`, follows the repository's
existing concurrency/cancellation pattern, and checks out the exact triggering
SHA.

The regular Ubuntu TAP cache contains a daemon built without `TEST_RDS_BGD` and
must not be used as the BGD executable. The workflow therefore has a BGD build
job and a dependent execution job.

The build job checks out the triggering SHA, installs or reuses the normal
Ubuntu TAP build dependencies, and runs:

```bash
make -j"$(nproc)" test_rds_bgd
```

After verifying `src/proxysql` and `test/tap/tests/test_rds_bgd-t`, it saves the
build output as two BGD-specific cache entries, following the existing CI
separation between daemon and test artifacts:

```text
${SHA}_ubuntu22-tap-rds-bgd_src   -> src/
${SHA}_ubuntu22-tap-rds-bgd_test  -> test/
```

The cache keys are exact and include the BGD build flavor. Do not configure
`restore-keys`: falling back to the normal Ubuntu TAP cache could execute a
daemon compiled without `TEST_RDS_BGD`. The workflow must grant the cache-save
permission required by its `workflow_run` context.

The execution job depends on the build job, checks out the same SHA, and
restores both entries with `fail-on-cache-miss: true`. It verifies the restored
executables before building the runner image and starting the test group. One
producer can therefore supply the same flagged artifacts to additional BGD
execution jobs without rebuilding ProxySQL.

| Execution-job step | Required behavior |
|---|---|
| Checkout | Check out the triggering SHA, not the default branch tip. |
| Restore `src` | Restore the exact BGD `_src` key into `src/`; fail on a miss. |
| Restore `test` | Restore the exact BGD `_test` key into `test/`; fail on a miss. |
| Verify artifacts | Confirm `src/proxysql` and `test/tap/tests/test_rds_bgd-t` are executable. |
| Build runner image | Build `test/infra/docker-base` as `proxysql-ci-base:latest`. |
| Start | Export the shared variables below and run `ensure-infras.bash`. |
| Test | Run `run-tests-isolated.bash`; this execution, not compilation alone, is the required check. |
| Cleanup | With `if: always()`, stop ProxySQL and run `destroy-infras.bash`; cleanup failures must not hide the test result. |
| Logs | On failure, upload `ci_infra_logs/` with the workflow name, SHA, and run number in the artifact name. |

The start, test, and cleanup steps use the same values:

```bash
export WORKSPACE="${GITHUB_WORKSPACE}"
export INFRA_ID="rds-bgd-${GITHUB_RUN_ID}"
export TAP_GROUP="cluster_sim_rds_bgd-g1"
source test/infra/common/env.sh
```

The job starts no backend infrastructure and never invokes
`test/deps/cluster_simulator`. Its pass condition is: the flagged build
succeeds, the BGD TAP group executes, every TAP test exits successfully, and
the standard runner reports no infrastructure or test failure.

## Supported Test Coverage

### Simulator Acceptance

The simulator implementation needs one end-to-end smoke test, not a separate
unit-test suite for every helper method. `test_rds_bgd-t` proves that the
`TEST_RDS_BGD` daemon accepts TAP-controlled topology, ProxySQL observes an
`AVAILABLE` deployment, the green-IP probe is logged, and the automatic CI job
executes the group without `test/deps/cluster_simulator`.

The configuration and lifecycle tests below exercise the remaining helper and
SQLite3-server paths through BGD behavior. Before changing simulator state,
each test captures a probe watermark; failures report the configured backend
state, last ProxySQL runtime state, and later probe rows.

### Configuration and Discovery

Configuration tests keep topology at `AVAILABLE` until the expected runtime row
and worker generation are stable. A relevant case then continues through a
switchover, proving that the configuration adopted during setup is the one used
by the FSM.

| Case | Configuration sequence | Expected observations |
|---|---|---|
| Available topology before blue writer | Publish `AVAILABLE`, enable automatic discovery, then add the blue writer and its replication-hostgroup mapping. | The read-only discovery path creates one runtime BGD row with derived blue hostgroups, NULL green hostgroups, and `auto_generated=1`; its worker begins probing. |
| Blue deployment before BGD exists | Add the blue writer and readers while topology is absent, then publish `AVAILABLE`. | No BGD row is created before discovery; topology appearance creates the auto-generated runtime row and starts its worker. |
| Blue readers added after discovery | Start from an auto-generated row with only the blue writer, then add one or more blue readers and load servers to runtime. | The host checksum changes, the worker generation is replaced, probing resumes, and later reader actions use the new reader set. |
| Explicit BGD row before servers | Disable automatic discovery, load an explicit BGD hostgroup row, then add the blue writer, blue readers, green writer, and green readers. | The row remains `auto_generated=0`; no worker runs without an eligible blue server, and each relevant server change is incorporated by the replacement worker. |
| Servers before explicit BGD row | Add blue and green servers first with automatic discovery disabled, then load the explicit BGD hostgroup row. | No BGD worker runs before the row exists; loading it starts a worker that uses the existing server membership. |
| Blue first, green later | Configure blue servers, publish `AVAILABLE`, then add explicit green writer and reader rows before starting switchover. | Green membership changes replace the worker and rebuild its mapping; existing rows are not duplicated and the explicit green writer supplies its configured TLS mode. |
| Existing explicit green TLS | Configure the blue writer with `use_ssl=0` and the exact green TARGET row at the supported port with `use_ssl=1`, then publish `AVAILABLE`. | The direct metadata probe targets the resolved green writer IP with `encrypted=1`. |
| Discovered green TLS defaults | Configure the blue writer with `use_ssl=0`, leave the configured green writer hostgroup empty, and set its `servers_defaults.use_ssl=1`, then publish `AVAILABLE`. | Discovery adds the exact TARGET row with runtime `use_ssl=1`, and the subsequent green-IP metadata probe has `encrypted=1`. |
| Green timing variants | With explicit green hostgroups, add green nodes before `AVAILABLE`, after discovery, or after the worker starts but before switchover. | Each ordering converges on the same runtime membership and blue/green mapping before the FSM advances. |
| Automatic to explicit configuration | Allow discovery to create an automatic row, then load a user row with explicit green hostgroups. | The runtime row becomes user-defined with `auto_generated=0`, explicit green hostgroups replace NULLs, and a replacement worker uses the new configuration. |
| Configuration mutation | Change `active`, hostgroup IDs, `writer_is_also_reader`, check interval/timeout, server status, or `use_ssl`; also cover row disablement and removal. | Relevant checksum changes stop the old worker, run phase-appropriate cleanup, and start or suppress a worker from the new active configuration. |
| Persistence and validation | Save automatic and explicit runtime state, and attempt invalid persistent rows. | Auto-generated rows are not persisted; explicit rows are retained; missing or mixed green hostgroups and other schema-invalid configurations are rejected. |

Configuration assertions use `runtime_mysql_aws_rds_bgd_hostgroups`,
`runtime_mysql_servers`, probe-log destinations, and subsequent hostgroup
effects. They do not depend only on worker log messages.

### Switchover, Rollback, and Cleanup

| Case | Simulator/configuration transition | Expected observations |
|---|---|---|
| Normal lifecycle | Advance AVAILABLE → INITIATED → IN_PROGRESS → POST_PROCESSING → COMPLETED, then make topology empty or absent. | Runtime status follows every phase; writer/reader placement, server status, DNS effects, and connection-pool changes occur at their defined boundaries; final cleanup returns status to `NONE`. |
| Cancellation rollback | Move from INITIATED or IN_PROGRESS back to `AVAILABLE`. | Accumulated effects are rolled back, the blue writer and reader policy are restored, probe pinning is rebuilt for AVAILABLE, and the deployment remains monitorable. |
| Pre-completion topology loss | Delete or drop topology before writer completion. | Empty and absent observations remain distinguishable, but both select rollback rather than successful finalization. |
| Configuration change during switchover | Add/remove servers, disable/remove the BGD row, or change relevant configuration while a non-NONE phase is active. | The old worker performs one-shot phase-appropriate rollback before its replacement uses the new configuration; stale mappings do not drive later actions. |
| Rollback postconditions | Trigger rollback after writer demotion, reader shunning, or DNS pinning has occurred. | Blue writer service and configured reader membership are restored, BGD-shunned readers are unshunned, pins and direct-probe state are cleared or rebuilt, runtime status resets, green rows remain, and green connections are not drained. |
| Successful cleanup | Complete writer switchover, enter reader switchover, then drain topology. | Eligible green connections are drained while green rows and statuses remain; readers are reconciled and the worker returns to `NONE`. |
| Late entry | Start a fresh worker with INITIATED, IN_PROGRESS, POST_PROCESSING, or COMPLETED already published. | The worker reconstructs only the state supported by that observation and applies the defined phase actions without requiring earlier samples. |
| Direct-probe policy | Vary blue/green IP and blue versus explicit-green `use_ssl` while every endpoint uses port 3306. | Probe-log rows identify the correct green writer destination at port 3306 and the correct automatic or explicit TLS source. |
| Reader and offline handling | Use matched, unmatched, and `OFFLINE_SOFT`/`OFFLINE_HARD` blue and green readers. | Only eligible pairs are mapped or drained; unmatched readers follow BGD shun policy and offline nodes are excluded. |
| Metadata failures | Return an empty result, error 1146, or another configured query error from selected writers. | Absence, empty metadata, and generic query failure remain distinct and never masquerade as a successful switchover. |
| Repeated switchover | Complete cluster-1 deployment A, reset on empty/absent topology, replace its green rows with deployment B, and run again. | The second lifecycle uses deployment B without stale mapping, probe, or simulator state from deployment A. |
| Concurrent switchovers | Publish independent topology for clusters 1, 2, or 3 and advance them independently. | Multiple workers make isolated progress; configuration or topology changes in one cluster do not alter another. |

The simulator does not claim to validate application traffic, AWS control-plane
timing, mutable DNS propagation, packet loss, or exact post-switchover address
movement. Those require separate integration infrastructure when a test's
assertion depends on them.

## Code Boundaries

| Area | Required change |
|---|---|
| `Makefile` | Add the BGD build targets and include `TEST_RDS_BGD` in `testall`. |
| `include/SQLite3_Server.h` | Add BGD table definitions/helpers and the coded-error overload under the flag. |
| `src/SQLite3_Server.cpp` | Add listener setup, endpoint extraction, table creation, BGD/read-only interception, and probe logging. |
| `test/tap` helpers | Add the common simulator and BGD-specific API defined above. |
| `test/tap/groups/cluster_sim_rds_bgd` | Add the fixed host map and SQLite3-server group configuration. |
| `test/tap/groups/groups.json` | Register BGD TAP binaries in `cluster_sim_rds_bgd-g1`. |
| `test/infra/README.md` | Document the group and its required `test_rds_bgd` build target. |
| `.github/workflows/CI-rds-bgd-simulator.yml` | Build the flagged flavor and execute the BGD simulator group automatically. |
| BGD production monitor | Reuse existing query constants; add no simulator query decoration or test initializer. |

Existing simulator builds retain their behavior. The scenario, not the helper,
owns topology publication, FSM timing, ProxySQL configuration, and expected
outcomes.
