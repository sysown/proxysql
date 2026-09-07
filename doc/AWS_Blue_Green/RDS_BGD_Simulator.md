# AWS RDS Blue/Green Deployment Simulator

**Document status:** IMPLEMENTED

**Applies to:** `TEST_RDS_BGD`, the SQLite3-server simulation surface, BGD TAP
helpers, local and GitHub runners, and supported simulator coverage

**Related monitor contract:** [RDS_BGD_Monitor.md](RDS_BGD_Monitor.md)

## Purpose

This document defines the simulator used to test ProxySQL's AWS RDS Blue/Green
Deployment monitor. It combines the behavioral contract, SQLite3-server
changes, TAP helper API, network fixture, local runner, and supported coverage
into one implementation specification.

## Architecture

The TAP test is the scenario controller. It configures ProxySQL with AWS-style
hostnames, writes simulated backend state to ProxySQL's SQLite3 server, changes
that state to drive the BGD FSM, and verifies ProxySQL through runtime,
statistics, and simulator probe-log tables. Topology state is keyed by backend
IP and port, while read-only state is keyed by the configured hostname and port.

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
CREATE TABLE AWS_BGD_CONTROL (
    backend_ip TEXT NOT NULL,
    backend_port INTEGER NOT NULL,
    topology_present INTEGER NOT NULL DEFAULT 0 CHECK (topology_present IN (0,1)),
    error_code INTEGER NOT NULL DEFAULT 0,
    error_msg TEXT NOT NULL DEFAULT '',
    PRIMARY KEY (backend_ip, backend_port)
);

CREATE TABLE AWS_BGD_TOPOLOGY (
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

CREATE TABLE AWS_BGD_PROBE_LOG (
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

For either match, resolve the accepted backend key, append a probe-log row,
load its control row, and select the response described below. An
address-extraction failure returns a simulator error without selecting state or
logging an invalid backend identity.

Simulated read-only checks follow the handling described below. All remaining
statements continue through normal SQLite3-server handling. TAP control and
inspection statements against the simulator tables are not rewritten or
recorded as BGD monitor probes.

## Control-State Meaning

The TAP helper publishes control and topology changes atomically. Monitor probes
read committed simulator state without holding a cross-query snapshot. The
supported states are:

| `AWS_BGD_CONTROL` state | Topology rows | Meaning |
|---|---|---|
| No backend row | None | Backend is unconfigured; topology is absent. |
| `topology_present=1`, `error_code=0` | One or more | Return the configured topology. |
| `topology_present=1`, `error_code=0` | Empty | Table exists but contains no topology. |
| `topology_present=1`, `error_code!=0` | Unchanged | Table exists, but its metadata query fails. |
| `topology_present=0`, `error_code=1146` | Empty | Table has been dropped. |

Topology update and delete operations clear `error_code` and `error_msg`.
Configured errors other than 1146 treat the table as present and retain its rows;
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
`AWS_BGD_PROBE_LOG`, including empty and error responses. `sequence_id`
preserves order, `probe_kind` identifies the query, `backend_ip, backend_port`
identify the destination, and `encrypted` records the accepted stream's TLS
state.

The TAP test is the only probe-log consumer; ProxySQL never reads it. A test
reads the last sequence before changing state and then reads later rows
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
handling does not consult `AWS_BGD_CONTROL` or write `AWS_BGD_PROBE_LOG`.

## TAP Helper API

The API follows existing TAP conventions: write methods return `EXIT_SUCCESS`
or `EXIT_FAILURE`, and read methods return the existing `rc_t<T>` type. The
interfaces below form the simulator design surface used by BGD scenarios.

### Common Endpoint

```cpp
struct Endpoint {
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
	char* host,
	int port,
	char* username,
	char* password,
	bool use_ssl = false);

int read_only_update(Endpoint backend, bool read_only);
```

`connect()` opens the SQLite3-server control connection with the MySQL client
API; the helper closes it when destroyed. `read_only_update()` changes the
`READONLY_STATUS` row identified by configured hostname and port.

### Topology and Host Types

```cpp
struct BGD_Topology_Row {
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

	Endpoint endpoint();
	Endpoint host_endpoint();
};
```

`BGD_Topology_Row` represents one `mysql.rds_topology` row using
C++11-compatible field types. `RDS_BGD_Host` keeps the ProxySQL-facing
hostname and simulator-facing IP together.

### Cluster Fixture

```cpp
class RDS_BGD_Cluster {
public:
	RDS_BGD_Host blue_writer;
	RDS_BGD_Host green_writer;
	std::vector<RDS_BGD_Host> blue_readers;
	std::vector<RDS_BGD_Host> green_readers;

	std::vector<Endpoint> get_writers();
	std::vector<Endpoint> get_blue_endpoints();
	std::vector<Endpoint> get_green_endpoints();
	std::vector<Endpoint> get_endpoints();
	std::vector<BGD_Topology_Row> get_topology(std::string status);
};
```

Each TAP test owns and initializes the cluster fixtures it uses. A fixture
keeps the selected `/etc/hosts` mapping together. `get_writers()` returns the
blue and green writer IP endpoints. `get_blue_endpoints()` and
`get_green_endpoints()` include the writer and readers for one deployment,
while `get_endpoints()` returns the complete cluster. `get_topology(status)`
returns the standard two-row SOURCE/TARGET writer topology using the configured
hostnames and status. Tests add reader rows explicitly when the scenario needs
reader mapping.

### BGD Topology Operations

```cpp
int topology_update(
	std::vector<Endpoint> backends,
	std::vector<BGD_Topology_Row> rows);

int topology_delete(std::vector<Endpoint> backends);

int topology_drop(std::vector<Endpoint> backends);

int topology_error(
	std::vector<Endpoint> backends,
	int error_code,
	std::string error_msg);

int cleanup();
```

`topology_update()` marks the table present, clears any configured error, and
replaces rows on only the supplied backends. `topology_delete()` clears rows
and errors while leaving the table present.

`topology_drop()` clears rows, marks the table absent, and records error 1146
with `Table 'mysql.rds_topology' doesn't exist`. `topology_error()` requires a
nonzero code; 1146 marks topology absent, while any other code marks it present
and leaves existing rows unchanged.

`cleanup()` removes read-only state, topology rows, control rows, and probe-log
rows. Tests call it together with their ProxySQL Admin cleanup so scenarios do
not inherit simulator state from an earlier binary.

### Probe-Log Operations

```cpp
enum class BGD_Probe_Kind {
	table_check,
	metadata,
};

struct BGD_Probe_Log {
	uint64_t sequence_id;
	Endpoint backend;
	BGD_Probe_Kind probe_kind;
	bool encrypted;
};

rc_t<uint64_t> probe_log_last_sequence();

rc_t<std::vector<BGD_Probe_Log>> probe_log_since(uint64_t sequence_id);

rc_t<BGD_Probe_Log> wait_for_probe_log(
	uint64_t sequence_id,
	Endpoint backend,
	BGD_Probe_Kind probe_kind,
	uint32_t timeout_ms,
	int encrypted = -1);
```

`probe_log_last_sequence()` returns zero for an empty log. `probe_log_since()`
returns rows after the supplied sequence. `wait_for_probe_log()` waits for one matching row;
`encrypted` is `-1` for either mode, `0` for plaintext, and `1` for TLS.

## Typical TAP Test

```cpp
int main() {
	plan(3);

	CommandLine cl {};
	MYSQL* admin = nullptr;
	BGD_Simulator simulator {};

	if (setup(cl, admin, simulator) != EXIT_SUCCESS)
		return exit_status();

	TestState state {};

	if (publish_available_topology(simulator, state) != EXIT_SUCCESS)
		goto exit_cleanup;

	if (configure_bgd_available(admin, state) != EXIT_SUCCESS)
		goto exit_cleanup;

	if (test_plaintext_green_writer_probe(simulator, state) != EXIT_SUCCESS)
		goto exit_cleanup;

exit_cleanup:
	if (cleanup(admin, simulator) != EXIT_SUCCESS)
		return EXIT_FAILURE;
	return exit_status();
}
```

Each test defines small setup, scenario, and cleanup functions around this
control flow. ProxySQL configuration remains test-local. The simulator changes
backend responses and reads probe evidence; assertions against ProxySQL use
Admin SQL. Cleanup removes both Admin and simulator state before returning.

## Build Integration

The build provides `build_lib_test_rds_bgd`, `build_src_test_rds_bgd`, and the
top-level `test_rds_bgd` target. The lib and src targets compile with
`-DDEBUG -DTEST_RDS_BGD`; none depends on `build_cluster_simulator`.

`test_rds_bgd` depends on `build_src_test_rds_bgd` and then invokes `make
debug` in `test/tap`:

```text
build_deps_debug -> build_lib_test_rds_bgd -> build_src_test_rds_bgd
                 -> TAP debug build
```

`test_rds_bgd` is the focused local entry point. Do not invoke
`build_tap_test_debug` afterward because its `build_src_debug` dependency
selects the normal debug daemon. `testall` includes `-DTEST_RDS_BGD` and is
used by the shared cluster-simulator CI build.

## Local CI Group

The `test/tap/groups/cluster_sim_rds_bgd/` group executes as
`cluster_sim_rds_bgd-g1`.

| File | BGD-specific content |
|---|---|
| `env.sh` | Set the fixed host map, wait for the SQLite3-server port, and skip backend cluster startup. |
| `add-hosts` | Define the fixed hostname/IP map below. |
| `pre-proxysql.bash` | Keep the existing short startup wait before Admin writes. |
| `pre-proxysql.sql` | Add the simulator user and move the SQLite3 server to port 3306. |

The group has no `infras.lst`, `CLUSTER_SIM_BINARY_PATH`, or
`CLUSTER_SIM_TESTS_ROOT`. The TAP binary controls the simulator directly.

```bash
export CLUSTER_SIM_HOST_FILE="${WORKSPACE}/test/tap/groups/cluster_sim_rds_bgd/add-hosts"
export PROXYSQL_READY_PORTS_EXTRA="3306"
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

The BGD TAP binaries are registered in `test/tap/groups/groups.json` under
`cluster_sim_rds_bgd-g1`. The registry is the source of truth for both local
execution and GitHub CI. The simulator table in `test/infra/README.md` records
the group and its `make test_rds_bgd` requirement.

Clean when switching compile flavors because Make does not track changed
preprocessor flags:

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

## GitHub CI

`.github/workflows/CI-cluster-simulator.yml` builds and executes every registered
`cluster_sim_*` group. It discovers groups and their TAP binaries from
`test/tap/groups/groups.json`, so registration in `cluster_sim_rds_bgd-g1`
places the complete BGD suite in the workflow matrix without BGD-specific YAML.
The workflow runs for pull requests and `workflow_dispatch`.

The build job uses `test/infra/control/cluster-simulator-ci.bash` to build
`testall`, the cluster-simulator binary, the TAP library, and every registered
simulation binary. `testall` is intentional: one ProxySQL executable contains
all simulation flags, including `TEST_RDS_BGD`, and is shared by the matrix
jobs. The verified runtime is staged in an exact-SHA cache.

Each matrix job restores and verifies that runtime for its selected group,
builds the common runner image, and executes `ensure-infras.bash` followed by
`run-tests-isolated.bash`. Cleanup always stops ProxySQL and destroys the
isolated runner; failure logs are archived by group and SHA.

The shared runtime includes `test/deps/cluster_simulator` for groups that need
it. The BGD group sets `SKIP_CLUSTER_START=1`, starts no backend infrastructure,
and drives ProxySQL's SQLite3-server simulator directly.

## Supported Test Coverage

The suite is behavior-driven rather than a unit test for every helper method.
Tests publish backend observations through the simulator and verify the BGD
monitor through Admin runtime tables, server placement, connection-pool state,
backend routing, read-only logs, and the simulator probe log.

### Configuration and Discovery

| Behavior | Coverage |
|---|---|
| Automatic discovery ordering | Topology before blue configuration and blue configuration before topology both converge on one runtime-only automatic BGD row. |
| Explicit startup ordering | A worker starts only after both an explicit BGD row and an eligible blue server exist, regardless of which is loaded first. |
| Green membership ordering | Configured green membership may arrive before `AVAILABLE`, after discovery, or after the worker starts. |
| Configuration ownership | Automatic rows remain runtime-only; explicit rows persist; invalid partial green-hostgroup configuration is rejected; automatic discovery does not overwrite administrator-owned rows. |
| Probe destination and TLS | Automatic and explicit configurations select the mapped writer tuple, apply the correct TLS source, and probe table check, blue metadata, and green metadata in order. |
| Active configuration refresh | Server TLS, membership, status, interval, timeout, hostgroups, and mapped-writer changes are incorporated while preserving the applicable BGD phase and probe policy. |
| Disablement and removal | Disabling or deleting an active BGD row performs phase-appropriate rollback and suppresses or removes the runtime worker. |

### Switchover, Rollback, and Cleanup

| Behavior | Coverage |
|---|---|---|
| Acceptance | An explicitly configured worker consumes TAP-controlled `AVAILABLE` topology and probes the green writer directly. |
| Writer switchover | `AVAILABLE`, `SWITCHOVER_INITIATED`, `SWITCHOVER_IN_PROGRESS`, and `SWITCHOVER_IN_POST_PROCESSING` drive the defined status, placement, suppression, pool-drain, and routing effects. Repeated post-processing does not redrain a post-cutover pool. |
| Reader switchover and cleanup | Target-only `SWITCHOVER_COMPLETED` enters reader switchover; terminal empty or absent topology restores reader policy, drains eligible green pools, retains configured green rows, and returns to `NONE`. |
| Cancellation rollback | Returning from initiated or in-progress topology to `AVAILABLE` restores blue routing and monitoring without removing explicit green rows or draining green pools. |
| Topology loss and errors | Empty topology, absent topology, metadata error 1146, and generic metadata errors retain their distinct effects before and after writer completion. |
| Late entry | Fresh workers starting at initiated, in-progress, post-processing, or completed observations apply only the state supported by the first observation. |
| Reader and pool policy | Matched and unmatched readers, writer fallback, and `ONLINE`, `SHUNNED`, `OFFLINE_SOFT`, and `OFFLINE_HARD` green pools follow their routing and cleanup policies. |
| Repeated and concurrent deployments | A second deployment reuses hostgroups without stale membership or probes, while three simultaneous workers retain independent topology, phase, placement, and TLS state. |

The simulator does not claim to validate application traffic, AWS control-plane
timing, mutable DNS propagation, packet loss, or exact post-switchover address
movement. Those require separate integration infrastructure when a test's
assertion depends on them.

## Code Boundaries

| Area | Boundary |
|---|---|
| `Makefile` | Provides the BGD build targets and includes `TEST_RDS_BGD` in `testall`. |
| `include/SQLite3_Server.h` | Declares the TEST-mode table ownership and shared read-only simulator members. |
| `src/SQLite3_Server.cpp` | Handles endpoint extraction, table creation, BGD/read-only interception, and probe logging. |
| `test/tap` helpers | Provide the common simulator and BGD-specific API defined above. |
| `test/tap/groups/cluster_sim_rds_bgd` | Defines the fixed host map and SQLite3-server group configuration. |
| `test/tap/groups/groups.json` | Registers BGD TAP binaries in `cluster_sim_rds_bgd-g1`. |
| `test/infra/README.md` | Documents the group and its required `test_rds_bgd` build target. |
| `.github/workflows/CI-cluster-simulator.yml` | Builds the combined simulation flavor and executes each registered simulator group in its own matrix job. |
| `test/infra/control/cluster-simulator-ci.bash` | Discovers groups and binaries, builds and verifies the shared runtime, and stages the exact-SHA cache payload. |
| BGD production monitor | Reuses existing query constants without simulator query decoration or a test initializer. |

Existing simulator builds retain their behavior. The scenario, not the helper,
owns topology publication, FSM timing, ProxySQL configuration, and expected
outcomes.
