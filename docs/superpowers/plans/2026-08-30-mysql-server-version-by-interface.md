# Per-Interface MySQL Server Version Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a `PROXYSQL31`-gated `mysql-server_version_by_interface` JSON catalog that overrides the frontend MySQL version for exact `mysql-interfaces` listener tokens while retaining `mysql-server_version` as the fallback.

**Architecture:** A focused parser/resolver validates JSON into an immutable interface-to-version map. `MySQL_Threads_Handler` stages and atomically publishes that map through the existing variable commit generation, workers acquire the current snapshot, and the accept path copies the resolved version into frontend data-stream state before generating the handshake. All later internally generated version-dependent responses read the connection-pinned value.

**Tech Stack:** C++17, nlohmann JSON, ProxySQL MySQL thread-variable generation, MySQL protocol handshake, MariaDB Connector/C, TAP, GNU Make, ProxySQL Cluster variable synchronization.

---

## Global Constraints

- Treat [the approved design](../specs/2026-08-30-mysql-server-version-by-interface-design.md) as authoritative.
- Compile the new variable, parsed catalog, worker snapshot, and frontend pinned state only under `PROXYSQL31`. `PROXYSQL40=1` inherits the feature through the existing Makefile hierarchy.
- Keep `mysql-server_version` unchanged as the scalar fallback. Do not make either variable polymorphic and do not add precedence beyond exact-map-hit then scalar-fallback.
- Treat `mysql-server_version_by_interface` as a loose catalog. Never reject, delete, warn about, or normalize an entry merely because it does not match the current `mysql-interfaces` value.
- Match the exact original listener token, case-sensitively. Do not reconstruct it from address and port, resolve hostnames, expand wildcards, or fall back to port-only matching.
- Pin the resolved value before the initial handshake. Runtime reloads affect new frontend connections only.
- Use the pinned value for the initial handshake, internal `SELECT @@version` / `SELECT VERSION()` responses, and the `SELECT $$` capability probe. Preserve all existing `mysql-select_version_forwarding` routing modes.
- Do not change `mysql-interfaces` mutability or grammar, backend routing, `mysql_servers`, `mysql_servers_ssl_params`, SQLite table definitions, or historical schema signatures.
- Publish only fully validated, immutable catalogs. Do not share independently freed raw pointers between the handler, workers, listener manager, or frontend sessions.
- Let the new variable follow ordinary MySQL-variable persistence, checksum, and cluster synchronization. Do not add it to `CLUSTER_SYNC_INTERFACES_MYSQL`.
- Preserve the unrelated untracked `test/tap/tests/test_cluster_leader_election_config/` and `test/tap/tests/test_cluster_tsdb_aggregation_config/` directories.
- Run tests red before production changes, green after the smallest change, and commit at each task boundary.

## File Map

- Create `include/MySQL_Server_Version_By_Interface.h`: immutable catalog types plus parser and resolver declarations.
- Create `lib/MySQL_Server_Version_By_Interface.cpp`: JSON parsing, duplicate/NUL validation, and exact lookup.
- Modify `lib/Makefile`: include the parser/resolver object only in `PROXYSQL31` builds.
- Create `test/tap/tests/unit/mysql_server_version_by_interface_unit-t.cpp`: focused parser, loose-correlation, scale, and resolver tests.
- Modify `test/tap/tests/unit/Makefile`: build the focused unit only when `PROXYSQL31=1`.
- Modify `test/tap/groups/groups.json`: register new unit and integration coverage at minimum ProxySQL version 3.1.
- Modify `include/MySQL_Thread.h`: handler-owned accepted snapshot and worker-owned snapshot declarations.
- Modify `lib/MySQL_Thread.cpp`: variable registration, staging, atomic commit/rollback, worker refresh, exact listener identity, and accept-time resolution.
- Modify `test/tap/tests/unit/mysql_variables_unit-t.cpp`: tier registration, default, rejection rollback, getter, and Admin persistence coverage.
- Modify `include/MySQL_Data_Stream.h`: connection-pinned frontend version and effective-version accessor.
- Modify `lib/mysql_data_stream.cpp`: effective-version accessor implementation.
- Modify `lib/MySQL_Protocol.cpp`: use the pinned value in the initial handshake.
- Modify `lib/MySQL_Session.cpp`: use the pinned value in internal version queries and the dollar-quote probe.
- Create `test/tap/tests/mysql-server_version_by_interface-t.cpp`: self-launched multi-listener end-to-end coverage without backend dependencies.
- Modify `test/tap/tests/test_cluster_sync-t.cpp`: prove ordinary catalog sync independently from `mysql-interfaces`.

### Task 1: Create an isolated implementation worktree

**Files:**

- Preserve in the current worktree: `docs/superpowers/specs/2026-08-30-mysql-server-version-by-interface-design.md`
- Preserve in the current worktree: `docs/superpowers/plans/2026-08-30-mysql-server-version-by-interface.md`

- [ ] **Step 1: Resolve the reviewed plan commit and create the worktree**

```bash
git fetch origin v3.0
server_version_plan_commit=$(git log -1 --format=%H -- \
  docs/superpowers/plans/2026-08-30-mysql-server-version-by-interface.md)
git worktree add \
  /data/rene/proxysql7/proxysql-server-version-by-interface \
  -b feature/mysql-server-version-by-interface \
  "$server_version_plan_commit"
```

Expected: the new worktree contains the approved spec and this plan without moving or deleting either unrelated untracked test directory in the original worktree.

- [ ] **Step 2: Bring the implementation branch onto the latest v3.0 base**

```bash
git -C /data/rene/proxysql7/proxysql-server-version-by-interface rebase origin/v3.0
git -C /data/rene/proxysql7/proxysql-server-version-by-interface status --short --branch
```

Expected: the feature branch is based on the fetched `origin/v3.0` and the new worktree is clean.

### Task 2: Build and test the JSON catalog as an isolated unit

**Files:**

- Create: `include/MySQL_Server_Version_By_Interface.h`
- Create: `lib/MySQL_Server_Version_By_Interface.cpp`
- Create: `test/tap/tests/unit/mysql_server_version_by_interface_unit-t.cpp`
- Modify: `lib/Makefile:129-131`
- Modify: `test/tap/tests/unit/Makefile:457-459`
- Modify: `test/tap/groups/groups.json`

**Public interface:**

```cpp
#ifndef MYSQL_SERVER_VERSION_BY_INTERFACE_H
#define MYSQL_SERVER_VERSION_BY_INTERFACE_H

#include <memory>
#include <string>
#include <unordered_map>

using MySQLServerVersionByInterfaceMap =
	std::unordered_map<std::string, std::string>;

struct MySQLServerVersionByInterfaceParseResult {
	std::shared_ptr<const MySQLServerVersionByInterfaceMap> catalog;
	std::string error;

	bool accepted() const noexcept { return catalog != nullptr && error.empty(); }
};

MySQLServerVersionByInterfaceParseResult
parse_mysql_server_version_by_interface(const std::string& raw_json);

std::string resolve_mysql_server_version_for_interface(
	const MySQLServerVersionByInterfaceMap& catalog,
	const std::string& interface_id,
	const std::string& scalar_fallback
);

#endif
```

- [ ] **Step 1: Register a failing focused unit test**

Add `mysql_server_version_by_interface_unit-t` to `UNIT_TESTS` inside the existing `ifeq ($(PROXYSQL31),1)` block and register:

```json
"mysql_server_version_by_interface_unit-t" : [ "unit-tests-g1", "@proxysql_min_version:3.1" ]
```

Create the test with assertions covering:

```cpp
const auto empty = parse_mysql_server_version_by_interface("{}");
ok(empty.accepted() && empty.catalog->empty(), "accepts an empty catalog");

const auto loose = parse_mysql_server_version_by_interface(
	R"({"0.0.0.0:6033":"8.0.30","127.0.0.1:9999":"5.7.44","/tmp/future.sock":"8.4.0"})"
);
ok(loose.accepted() && loose.catalog->size() == 3,
	"retains mappings without consulting active listeners");

ok(resolve_mysql_server_version_for_interface(
	*loose.catalog, "0.0.0.0:6033", "8.0.11") == "8.0.30",
	"exact listener hit overrides the scalar");
ok(resolve_mysql_server_version_for_interface(
	*loose.catalog, "0.0.0.0:6034", "8.0.11") == "8.0.11",
	"unmatched listener uses the scalar");
ok(resolve_mysql_server_version_for_interface(
	*loose.catalog, "0.0.0.0:6033 ", "8.0.11") == "8.0.11",
	"lookup does not normalize listener text");
```

Also generate 1,000 distinct `127.0.0.1:<port>` pairs and assert all are retained. Add table-driven rejection cases for malformed JSON, array/scalar/null roots, empty keys, empty values, numeric/boolean/object values, duplicate keys, `\u0000` in a key, and `\u0000` in a value. Add exact IPv6 and Unix-socket resolution cases.

- [ ] **Step 2: Run the focused build and verify RED**

```bash
make -C test/tap/tests/unit mysql_server_version_by_interface_unit-t PROXYSQL31=1
```

Expected: compilation fails because `MySQL_Server_Version_By_Interface.h` and its functions do not exist.

- [ ] **Step 3: Implement strict parsing and exact resolution**

Implement parsing in `lib/MySQL_Server_Version_By_Interface.cpp` with `nlohmann::json`. Use a parser callback to record every key and set a duplicate flag when insertion into an `unordered_set<string>` fails. After parsing:

```cpp
if (!document.is_object()) {
	return { nullptr, "root must be a JSON object" };
}
if (duplicate_key) {
	return { nullptr, "duplicate interface key" };
}

MySQLServerVersionByInterfaceMap entries;
for (const auto& item : document.items()) {
	const std::string& interface_id = item.key();
	if (interface_id.empty() || interface_id.find('\0') != std::string::npos) {
		return { nullptr, "interface keys must be non-empty strings without NUL" };
	}
	if (!item.value().is_string()) {
		return { nullptr, "server versions must be strings" };
	}
	const std::string server_version = item.value().get<std::string>();
	if (server_version.empty() || server_version.find('\0') != std::string::npos) {
		return { nullptr, "server versions must be non-empty strings without NUL" };
	}
	entries.emplace(interface_id, server_version);
}
return {
	std::make_shared<const MySQLServerVersionByInterfaceMap>(std::move(entries)),
	{}
};
```

Catch `json::exception` and return its message in `error`. Implement resolution as one `find()` followed by a copied mapped value or copied fallback. Do not validate listener syntax or consult `mysql-interfaces`.

Add `MySQL_Server_Version_By_Interface.oo` to `_OBJ_CXX` in the existing `PROXYSQL31` block in `lib/Makefile`.

- [ ] **Step 4: Run the focused unit and verify GREEN**

```bash
make -C lib PROXYSQL31=1
make -C test/tap/tests/unit mysql_server_version_by_interface_unit-t PROXYSQL31=1
./test/tap/tests/unit/mysql_server_version_by_interface_unit-t
git diff --check -- \
  include/MySQL_Server_Version_By_Interface.h \
  lib/MySQL_Server_Version_By_Interface.cpp \
  lib/Makefile \
  test/tap/tests/unit/mysql_server_version_by_interface_unit-t.cpp \
  test/tap/tests/unit/Makefile \
  test/tap/groups/groups.json
```

Expected: every parser/resolver TAP assertion passes and the diff check produces no output.

- [ ] **Step 5: Commit the isolated catalog**

```bash
git add \
  include/MySQL_Server_Version_By_Interface.h \
  lib/MySQL_Server_Version_By_Interface.cpp \
  lib/Makefile \
  test/tap/tests/unit/mysql_server_version_by_interface_unit-t.cpp \
  test/tap/tests/unit/Makefile \
  test/tap/groups/groups.json
git commit -m "feat: add interface server version catalog"
```

### Task 3: Register the variable and make LOAD atomic

**Files:**

- Modify: `include/MySQL_Thread.h:430-575,820-860`
- Modify: `lib/MySQL_Thread.cpp:360-510,1460-1475,1681-1770,1930-1970,2115-2145,2440-2480,3503-3525`
- Modify: `test/tap/tests/unit/mysql_variables_unit-t.cpp`

**Handler state:**

```cpp
#ifdef PROXYSQL31
	char *server_version_by_interface;
#endif
```

```cpp
#ifdef PROXYSQL31
	std::string accepted_server_version_by_interface_ { "{}" };
	std::shared_ptr<const MySQLServerVersionByInterfaceMap>
		server_version_by_interface_snapshot_ {
			std::make_shared<const MySQLServerVersionByInterfaceMap>()
		};
#endif
```

Expose this accessor; callers must already hold the handler read or write lock used by `refresh_variables()`:

```cpp
#ifdef PROXYSQL31
std::shared_ptr<const MySQLServerVersionByInterfaceMap>
server_version_by_interface_snapshot() const {
	return server_version_by_interface_snapshot_;
}
#endif
```

- [ ] **Step 1: Add failing handler and Admin-variable tests**

Extend `mysql_variables_unit-t.cpp` with `PROXYSQL31` assertions that:

- the list contains `server_version_by_interface` and its getter defaults to `{}`;
- staging and committing a valid loose catalog publishes a two-entry immutable snapshot;
- replacing it publishes a new snapshot while a retained `shared_ptr` still exposes the old map;
- clearing it with `{}` publishes an empty snapshot;
- committing malformed JSON reports exactly `server_version_by_interface` as rejected and restores both the previous getter string and snapshot;
- loading malformed JSON through `ProxySQL_Admin::load_mysql_variables_to_runtime()` increments `Rejected`, decrements `Updated`, and rewrites `global_variables` plus `runtime_global_variables` to the accepted JSON;
- valid JSON round-trips byte-for-byte through the getter, including whitespace and key order.

In the non-`PROXYSQL31` branch, assert that the variable list does not contain `server_version_by_interface` and `has_variable()` returns false.
Update both compile-time TAP plan counts to include the exact number of new
assertions; do not use `plan(NO_PLAN)`.

- [ ] **Step 2: Run both tier variants and verify RED**

```bash
make clean
make -j4 debug
make -C test/tap/tests/unit mysql_variables_unit-t
./test/tap/tests/unit/mysql_variables_unit-t

make clean
make -j4 debug PROXYSQL31=1
make -C test/tap/tests/unit mysql_variables_unit-t PROXYSQL31=1
./test/tap/tests/unit/mysql_variables_unit-t
```

Expected: the stable assertions pass only after they are added to the TAP plan; the 3.1 build fails because the variable is not registered and no snapshot is published.

- [ ] **Step 3: Add gated registration, storage, getters, setter, and cleanup**

Under `#ifdef PROXYSQL31`:

- add `server_version_by_interface` next to `server_version` in `mysql_thread_variables_names`;
- initialize `variables.server_version_by_interface = strdup("{}")`;
- return a duplicate of it from both string getter paths;
- stage every non-null input in `set_variable()` by replacing the owned C string and returning true;
- free the owned C string in `MySQL_Threads_Handler::~MySQL_Threads_Handler()`.

Do not add a stable-tier name or dummy variable. An empty string may reach the commit validator and be rejected like other malformed JSON.

- [ ] **Step 4: Publish or roll back the catalog inside `commit()`**

After the existing RSA grouped validation, parse the staged string and append rather than overwrite any earlier rejected-variable names:

```cpp
const auto parsed = parse_mysql_server_version_by_interface(
	variables.server_version_by_interface != nullptr
		? variables.server_version_by_interface : ""
);
if (parsed.accepted()) {
	accepted_server_version_by_interface_ = variables.server_version_by_interface;
	server_version_by_interface_snapshot_ = parsed.catalog;
} else {
	proxy_error(
		"Rejected mysql-server_version_by_interface: %s\n",
		parsed.error.c_str()
	);
	free(variables.server_version_by_interface);
	variables.server_version_by_interface =
		strdup(accepted_server_version_by_interface_.c_str());
	commit_result.rejected_variables.push_back("server_version_by_interface");
}
```

Keep the existing global variable-generation increment after validation. This lets all workers refresh consistently even when another variable in the same LOAD was accepted. The existing Admin flush code will use `rejected_variables` to restore the database rows; do not special-case the new variable in `Admin_FlushVariables.cpp`.

- [ ] **Step 5: Run handler, parser, and Admin rollback tests**

```bash
make -C lib PROXYSQL31=1
make -C test/tap/tests/unit \
  mysql_variables_unit-t \
  mysql_server_version_by_interface_unit-t \
  PROXYSQL31=1
./test/tap/tests/unit/mysql_variables_unit-t
./test/tap/tests/unit/mysql_server_version_by_interface_unit-t
```

Expected: all 3.1 variable, immutable-snapshot, invalid-load rollback, and parser assertions pass.

- [ ] **Step 6: Rebuild stable and prove the variable is absent**

```bash
make clean
make -j4 debug
make -C test/tap/tests/unit mysql_variables_unit-t
./test/tap/tests/unit/mysql_variables_unit-t
```

Expected: the stable unit passes with no registered `server_version_by_interface` variable and unchanged scalar behavior.

- [ ] **Step 7: Commit atomic variable publication**

```bash
git add include/MySQL_Thread.h lib/MySQL_Thread.cpp \
  test/tap/tests/unit/mysql_variables_unit-t.cpp
git commit -m "feat: register interface server version variable"
```

### Task 4: Resolve and pin the version on the accepting listener

**Files:**

- Modify: `include/MySQL_Thread.h:180-260`
- Modify: `lib/MySQL_Thread.cpp:230-315,4965-5120,5210-5230,5350-5390`
- Modify: `include/MySQL_Data_Stream.h:100-190`
- Modify: `lib/mysql_data_stream.cpp`
- Modify: `lib/MySQL_Protocol.cpp:1260-1330`
- Create: `test/tap/tests/mysql-server_version_by_interface-t.cpp`
- Modify: `test/tap/groups/groups.json`

**Connection contract:**

```cpp
#ifdef PROXYSQL31
// MySQL_Data_Stream
std::string frontend_server_version;
const char* get_frontend_server_version() const;
#endif
```

- [ ] **Step 1: Add a failing self-launched multi-listener TAP test**

Create `mysql-server_version_by_interface-t.cpp` following the process lifecycle in `test_load_restapi_from_config_startup-t.cpp`: use a private runtime directory, write a config, launch `WORKSPACE/src/proxysql` with `wexecvp()` in a thread, wait for the Admin listener, issue `PROXYSQL SHUTDOWN SLOW`, join the launcher, print captured logs on failure, and remove the private directory.

Use these listeners:

```cpp
static constexpr int ADMIN_PORT = 26084;
static constexpr int SHARED_PORT = 36084;
static constexpr int FALLBACK_PORT = 36085;
static constexpr int IPV6_PORT = 36086;
```

Configure:

```text
mysql-interfaces:
  127.0.0.1:36084
  127.0.0.2:36084
  127.0.0.1:36085
  <runtime-dir>/proxysql.sock
  [::1]:36086 when an AF_INET6 bind probe succeeds

mysql-server_version: 8.0.11
mysql-server_version_by_interface:
  127.0.0.1:36084 -> 8.0.30-interface-a
  127.0.0.2:36084 -> 5.7.44-interface-b
  <runtime-dir>/proxysql.sock -> 8.4.1-interface-socket
  [::1]:36086 -> 8.1.0-interface-v6 when enabled
  192.0.2.10:49999 -> 9.9.9-unused
```

Add one frontend user in the config and set `select_version_forwarding=0`; no backend servers are required. Connect separately through every active listener and assert `mysql_get_server_info()` returns the mapped version for both same-port IPv4 addresses, the Unix socket, and optional IPv6, while the unmapped fallback port returns `8.0.11`.

Register:

```json
"mysql-server_version_by_interface-t" : [ "legacy-g1", "@proxysql_min_version:3.1" ]
```

- [ ] **Step 2: Run the integration test and verify RED**

```bash
make clean
make -j4 debug PROXYSQL31=1
make -C test/tap/tests mysql-server_version_by_interface-t
WORKSPACE=$(pwd) INFRA_ID=dev-$USER TAP_GROUP=legacy-g1 \
  TEST_PY_TAP_INCL=mysql-server_version_by_interface-t \
  test/infra/control/run-tests-isolated.bash
```

Expected: the secondary ProxySQL starts and accepts the catalog variable, but mapped listeners still report the scalar because accept-time resolution is not implemented.

- [ ] **Step 3: Preserve the exact listener token**

At the start of `MySQL_Listeners_Manager::add()`, copy the unmodified input:

```cpp
const std::string original_iface { iface };
```

Continue using the existing mutable parsing variables for address, port, IPv6, and Unix-socket setup, but pass `original_iface.c_str()` as the first argument to every `iface_info` constructor. This targeted correction ensures `iface_info::iface` contains `[::1]:36086` rather than the pointer left after the IPv6 parser splits the token. Keep duplicate detection and listener deletion keyed by that exact original value.

- [ ] **Step 4: Add handler-to-worker snapshot refresh**

Include the catalog header under `PROXYSQL31` and add this member to `MySQL_Thread`:

```cpp
std::shared_ptr<const MySQLServerVersionByInterfaceMap>
	server_version_by_interface_snapshot_;
```

Initialize it to an empty immutable map in `MySQL_Thread::MySQL_Thread()`. In `refresh_variables()`, while the existing `GloMTH` read lock is held, acquire the accepted handler snapshot:

```cpp
#ifdef PROXYSQL31
server_version_by_interface_snapshot_ =
	GloMTH->server_version_by_interface_snapshot();
#endif
```

The worker keeps the `shared_ptr`, so a later commit can replace the handler snapshot without invalidating readers.

- [ ] **Step 5: Pin the resolved value before handshake generation**

Implement `MySQL_Data_Stream::get_frontend_server_version()` entirely under
`PROXYSQL31`:

```cpp
#ifdef PROXYSQL31
const char* MySQL_Data_Stream::get_frontend_server_version() const {
	if (!frontend_server_version.empty()) {
		return frontend_server_version.c_str();
	}
	return mysql_thread___server_version;
}
#endif
```

In `listener_handle_new_connection()`, after resolving `iface_info` and before calling `generate_pkt_initial_handshake()`:

```cpp
#ifdef PROXYSQL31
const std::string interface_id = ifi != nullptr && ifi->iface != nullptr
	? ifi->iface : "";
const MySQLServerVersionByInterfaceMap empty_catalog;
const auto& catalog = server_version_by_interface_snapshot_ != nullptr
	? *server_version_by_interface_snapshot_ : empty_catalog;
sess->client_myds->frontend_server_version =
	resolve_mysql_server_version_for_interface(
		catalog,
		interface_id,
		mysql_thread___server_version != nullptr
			? mysql_thread___server_version : ""
	);
#endif
```

In `generate_pkt_initial_handshake()`, retain the stable scalar initializer and
override it only in the feature tier:

```cpp
const char* server_version = mysql_thread___server_version;
#ifdef PROXYSQL31
server_version = (*myds)->get_frontend_server_version();
#endif
```

Use that local for both packet-length calculation and the payload copy. Do not
read the thread-global scalar again in that function.

- [ ] **Step 6: Run the live listener matrix and existing handshake regressions**

```bash
make -C lib PROXYSQL31=1
make -C src PROXYSQL31=1
make -C test/tap/tests mysql-server_version_by_interface-t
WORKSPACE=$(pwd) INFRA_ID=dev-$USER TAP_GROUP=legacy-g1 \
  TEST_PY_TAP_INCL=mysql-server_version_by_interface-t \
  test/infra/control/run-tests-isolated.bash
```

Expected: every mapped listener reports its exact version, the same numeric port can return two versions on different addresses, the Unix socket and optional IPv6 token match, and the unmapped listener uses the scalar.

- [ ] **Step 7: Commit listener resolution and handshake pinning**

```bash
git add \
  include/MySQL_Thread.h \
  lib/MySQL_Thread.cpp \
  include/MySQL_Data_Stream.h \
  lib/mysql_data_stream.cpp \
  lib/MySQL_Protocol.cpp \
  test/tap/tests/mysql-server_version_by_interface-t.cpp \
  test/tap/groups/groups.json
git commit -m "feat: advertise versions by MySQL listener"
```

### Task 5: Keep internal frontend behavior consistent for the session lifetime

**Files:**

- Modify: `lib/MySQL_Session.cpp:1260-1280,8460-8510`
- Modify: `test/tap/tests/mysql-server_version_by_interface-t.cpp`

- [ ] **Step 1: Extend the integration test with failing consistency assertions**

For every mapped and fallback connection, query both `SELECT @@version` and `SELECT VERSION()` and compare the single-row result to `mysql_get_server_info()`.

For a mapped pre-8.1 listener and a mapped 8.1-or-newer listener, issue `SELECT $$` and assert the existing version-dependent error contract:

```cpp
ok(mysql_errno(connection) == ER_BAD_FIELD_ERROR,
	"pre-8.1 pinned listener uses the old dollar-quote response");
ok(mysql_errno(connection) == ER_PARSE_ERROR,
	"8.1+ pinned listener uses the new dollar-quote response");
```

Hold an `8.0.30-interface-a` connection open, replace the catalog at runtime so `127.0.0.1:36084` maps to `9.0.1-reloaded`, and open a second connection. Assert:

- the old connection's internal version queries remain `8.0.30-interface-a`;
- the new connection's handshake and internal version queries use `9.0.1-reloaded`;
- clearing the catalog with `{}` makes a third new connection use scalar `8.0.11`;
- neither reload changes the versions pinned to the first two connections.

- [ ] **Step 2: Run the focused integration and verify RED**

```bash
make -C test/tap/tests mysql-server_version_by_interface-t
WORKSPACE=$(pwd) INFRA_ID=dev-$USER TAP_GROUP=legacy-g1 \
  TEST_PY_TAP_INCL=mysql-server_version_by_interface-t \
  test/infra/control/run-tests-isolated.bash
```

Expected: handshake assertions pass, but one or more old-session `SELECT VERSION()` or `SELECT $$` assertions follow the refreshed thread-global scalar instead of the pinned value.

- [ ] **Step 3: Replace only frontend-internal scalar reads**

In `MySQL_Session::handler_special_queries()`, retain the stable scalar and
override it only in a `PROXYSQL31` build:

```cpp
const char* frontend_server_version = mysql_thread___server_version;
#ifdef PROXYSQL31
frontend_server_version = client_myds->get_frontend_server_version();
#endif
```

Use it instead of `mysql_thread___server_version` in exactly these places:

- the argument to `get_dollar_quote_error()` for the MySQL frontend `SELECT $$` probe;
- `SELECT_VERSION_NEVER` responses;
- the fallback for `SELECT_VERSION_SMART_FALLBACK_INTERNAL`.

Do not change the Admin and SQLite-server dollar-quote handlers; they are not connections accepted through `mysql-interfaces`. Do not change backend-derived values in smart mode, `SELECT_VERSION_ALWAYS`, or `SELECT_VERSION_SMART_FALLBACK_PROXY`.

- [ ] **Step 4: Run focused and existing version-mode regressions**

```bash
make -C lib PROXYSQL31=1
make -C src PROXYSQL31=1
make -C test/tap/tests \
  mysql-server_version_by_interface-t \
  mysql-select_version_without_backend-t \
  reg_test_4300-dollar_quote_check-t
WORKSPACE=$(pwd) INFRA_ID=dev-$USER TAP_GROUP=legacy-g1 \
  TEST_PY_TAP_INCL="mysql-server_version_by_interface-t mysql-select_version_without_backend-t" \
  test/infra/control/run-tests-isolated.bash
WORKSPACE=$(pwd) INFRA_ID=dev-$USER TAP_GROUP=legacy-g2 \
  TEST_PY_TAP_INCL=reg_test_4300-dollar_quote_check-t \
  test/infra/control/run-tests-isolated.bash
```

Expected: the interface test proves new/old connection pinning and internal consistency; the two existing scalar/version-forwarding regressions remain green.

- [ ] **Step 5: Commit session-consistent version behavior**

```bash
git add lib/MySQL_Session.cpp \
  test/tap/tests/mysql-server_version_by_interface-t.cpp
git commit -m "fix: pin frontend version for internal responses"
```

### Task 6: Prove persistence and ordinary cluster synchronization

**Files:**

- Modify: `test/tap/tests/mysql-server_version_by_interface-t.cpp`
- Modify: `test/tap/tests/test_cluster_sync-t.cpp:2423-2625`

- [ ] **Step 1: Add disk round-trip coverage to the self-launched test**

Through the secondary Admin connection:

1. Set a catalog containing active and inactive mappings.
2. `LOAD MYSQL VARIABLES TO RUNTIME`.
3. `SAVE MYSQL VARIABLES TO DISK`.
4. Replace the in-memory catalog with `{}` and load it to runtime.
5. `LOAD MYSQL VARIABLES FROM DISK`, then load to runtime again.
6. Assert the exact saved JSON string is restored in both `global_variables` and `runtime_global_variables` and a new connection uses its mapped value.

This proves ordinary persistence without adding a custom table or serialization path. The config-file startup portion of the same test proves initial loading before the Admin disk round trip.

- [ ] **Step 2: Add the catalog to the existing cluster variable matrix when available**

Before building `update_mysql_variables_queries`, query the master for:

```sql
SELECT COUNT(*) FROM global_variables
WHERE variable_name='mysql-server_version_by_interface'
```

When the count is one, append this literal pair to `update_mysql_variables_values`:

```cpp
std::make_tuple(
	"mysql-server_version_by_interface",
	"{\"0.0.0.0:6033\":\"8.0.30-cluster\",\"192.0.2.10:49999\":\"9.9.9-unused\"}"
)
```

The cluster fixture already runs with `cluster_sync_interfaces=false`. Keep `mysql-interfaces` absent from the matrix and assert the new catalog reaches the replica unchanged. The runtime presence check keeps the same source test valid on stable builds where the gated variable is intentionally absent.

Before triggering synchronization, read and retain the replica's
`mysql-interfaces` value. After the catalog arrives, query it again and add a TAP
assertion that it is byte-for-byte unchanged. This directly proves that the
catalog follows normal MySQL-variable sync while listener configuration remains
local.

- [ ] **Step 3: Run persistence and cluster coverage**

```bash
make -C test/tap/tests \
  mysql-server_version_by_interface-t \
  test_cluster_sync-t
WORKSPACE=$(pwd) INFRA_ID=dev-$USER TAP_GROUP=legacy-g1 \
  TEST_PY_TAP_INCL=mysql-server_version_by_interface-t \
  test/infra/control/run-tests-isolated.bash
WORKSPACE=$(pwd) INFRA_ID=dev-$USER TAP_GROUP=legacy-g5 \
  TEST_PY_TAP_INCL=test_cluster_sync-t \
  test/infra/control/run-tests-isolated.bash
```

Expected: the saved catalog round-trips exactly, and the replica receives `mysql-server_version_by_interface` while retaining its local `mysql-interfaces` value.

- [ ] **Step 4: Commit persistence and cluster proof**

```bash
git add \
  test/tap/tests/mysql-server_version_by_interface-t.cpp \
  test/tap/tests/test_cluster_sync-t.cpp
git commit -m "test: cover interface version persistence and sync"
```

### Task 7: Verify both feature tiers and review scope

**Files:**

- Review all files changed since the approved design commit.

- [ ] **Step 1: Run a clean stable build and stable unit regressions**

```bash
make clean
make -j4 debug
make -C test/tap/tests/unit mysql_variables_unit-t
./test/tap/tests/unit/mysql_variables_unit-t
make -C test/tap/tests \
  mysql-select_version_without_backend-t \
  reg_test_4300-dollar_quote_check-t
```

Expected: v3.0 compiles without the new variable or catalog object and the existing scalar tests build successfully.

- [ ] **Step 2: Run a clean PROXYSQL31 build and focused unit suite**

```bash
make clean
make -j4 debug PROXYSQL31=1
make -C test/tap/tests/unit \
  mysql_variables_unit-t \
  mysql_server_version_by_interface_unit-t \
  PROXYSQL31=1
./test/tap/tests/unit/mysql_variables_unit-t
./test/tap/tests/unit/mysql_server_version_by_interface_unit-t
```

Expected: the v3.1 build and every focused unit assertion pass.

- [ ] **Step 3: Run the complete focused integration matrix**

```bash
make -C test/tap/tests \
  mysql-server_version_by_interface-t \
  mysql-select_version_without_backend-t \
  reg_test_4300-dollar_quote_check-t \
  test_cluster_sync-t
WORKSPACE=$(pwd) INFRA_ID=dev-$USER TAP_GROUP=legacy-g1 \
  TEST_PY_TAP_INCL="mysql-server_version_by_interface-t mysql-select_version_without_backend-t" \
  test/infra/control/run-tests-isolated.bash
WORKSPACE=$(pwd) INFRA_ID=dev-$USER TAP_GROUP=legacy-g2 \
  TEST_PY_TAP_INCL=reg_test_4300-dollar_quote_check-t \
  test/infra/control/run-tests-isolated.bash
WORKSPACE=$(pwd) INFRA_ID=dev-$USER TAP_GROUP=legacy-g5 \
  TEST_PY_TAP_INCL=test_cluster_sync-t \
  test/infra/control/run-tests-isolated.bash
```

Expected: all selected tests pass with no TAP plan mismatch, leaked secondary ProxySQL process, or retained private runtime directory.

- [ ] **Step 4: Compile-smoke the inherited PROXYSQL40 tier**

```bash
make clean
make -j4 debug PROXYSQL40=1
make -C test/tap/tests/unit \
  mysql_variables_unit-t \
  mysql_server_version_by_interface_unit-t \
  PROXYSQL40=1 PROXYSQL31=1
./test/tap/tests/unit/mysql_variables_unit-t
./test/tap/tests/unit/mysql_server_version_by_interface_unit-t
```

Expected: the v4 build inherits the variable through `PROXYSQL31` and both
focused units pass without a second feature gate.

- [ ] **Step 5: Inspect the final diff against the approved scope**

```bash
git diff --check origin/v3.0...HEAD
git diff --stat origin/v3.0...HEAD
git diff --name-status origin/v3.0...HEAD
git grep -n "server_version_by_interface" -- \
  ':!docs/superpowers/specs/*' \
  ':!docs/superpowers/plans/*'
git diff origin/v3.0...HEAD -- \
  include lib test/tap/tests test/tap/groups/groups.json
```

Confirm explicitly:

- no server or SSL table schema changed;
- no backend row, hostgroup, routing, or monitor code changed;
- the variable and supporting state are absent without `PROXYSQL31`;
- unmatched mappings remain accepted and silent;
- exact listener identity is used;
- handler, worker, and connection ownership use `std::shared_ptr`, `std::string`, or existing owned C strings without shallow pointer copies;
- all new tests are registered with the 3.1 minimum-version marker.

- [ ] **Step 6: Commit any verification-only correction, otherwise leave history unchanged**

If verification required a focused correction, stage only its files and commit it with a message describing that correction. If no correction was needed, do not create an empty commit.

### Task 8: Open the replacement PR, then close PR #4784

**Files:**

- No additional source changes.

- [ ] **Step 1: Push the verified feature branch**

```bash
git push -u origin feature/mysql-server-version-by-interface
```

Expected: the remote branch contains the approved spec, implementation plan, implementation commits, and verified tests.

- [ ] **Step 2: Open the replacement PR**

```bash
gh pr create \
  --base v3.0 \
  --head feature/mysql-server-version-by-interface \
  --title "Add per-interface MySQL server versions" \
  --body-file docs/superpowers/specs/2026-08-30-mysql-server-version-by-interface-design.md
```

Edit the generated description if necessary so its summary leads with the user-visible configuration example, states the `PROXYSQL31` gate, explains scalar fallback and loose correlation, and reports the exact stable/v3.1 test commands and results.

- [ ] **Step 3: Close #4784 only after the replacement URL exists**

```bash
replacement_pr_url=$(gh pr view feature/mysql-server-version-by-interface --json url --jq .url)
gh pr close 4784 --comment \
  "Closing in favor of ${replacement_pr_url}. The replacement models server version as a frontend listener property, keeps mysql-server_version as the fallback, supports a loosely correlated mysql-server_version_by_interface catalog, is gated by PROXYSQL31, and avoids mysql_servers schema changes."
```

Expected: PR #4784 is closed with a link to the open replacement, so the rationale and continuation are discoverable.
