# Frontend X.509 Authentication Policy Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a `PROXYSQL31`-gated, additive `mysql_users.attributes.require_x509` frontend policy, preserve SPIFFE's stronger identity semantics across `COM_CHANGE_USER`, and enforce both policies consistently before pass-through cache lookup or backend probing.

**Architecture:** Under `PROXYSQL31`, capture certificate presence and OpenSSL's verification result once, when the frontend TLS handshake completes, retain that immutable connection evidence on `MySQL_Data_Stream`, and route initial login, `COM_CHANGE_USER`, and row-backed pass-through through one certificate-policy evaluator in `MySQL_Protocol.cpp`. A default v3.0 build does not define the new state or inspect `require_x509`; it retains the existing SPIFFE path. Keep password verification additive for `require_x509`, keep SPIFFE identity-exclusive, reject SPIFFE and pass-through targets during `COM_CHANGE_USER`, and never attempt TLS renegotiation.

**Tech Stack:** C++17, OpenSSL, nlohmann/json, RE2, MySQL/MariaDB client libraries, ProxySQL TAP tests, GNU Make.

**Design addendum:** `docs/superpowers/specs/2026-08-10-frontend-x509-proxysql31-gating-design.md`

## Global Constraints

- The entire `require_x509` feature is available only when `PROXYSQL31` is defined; `PROXYSQL40=1` inherits it through the existing build hierarchy.
- A stable v3.0.x build has no knowledge of `require_x509`: it does not define the new generic certificate-evidence fields and does not look up, parse, validate, log, or enforce the key.
- A stable v3.0.x build preserves the pre-feature SPIFFE initial-authentication and `COM_CHANGE_USER` behavior.
- Null-checking `GENERAL_NAMES*` and exception-safe/type-safe handling of the existing `spiffe_id` attribute are unconditional cross-tier hardening, not gated feature behavior.
- Register the feature TAP test with `@proxysql_min_version:3.1`; separately prove with a focused compatibility test that v3.0 does not recognize the key.
- Always run `make clean` before switching between default, `PROXYSQL31=1`, DEBUG, and release builds because the Makefiles do not reliably invalidate objects when feature flags change.
- The new user attribute is exactly `"require_x509": true|false`; it does not add a column or change the `mysql_users` schema.
- `require_x509=true` means both the existing password/auth-plugin check and a trusted frontend client certificate must succeed.
- A trusted certificate means all three conditions are true on the current physical frontend connection: TLS is active, a peer certificate was presented, and `SSL_get_verify_result()` returned `X509_V_OK`.
- A client certificate with no URI SAN is valid for `require_x509`. SPIFFE extraction remains a separate concern.
- Do not change `callback_ssl_verify_peer()` to reject invalid or absent client certificates during the TLS handshake. Users without `require_x509` must remain backward compatible, so the authentication layer applies the per-user decision.
- Do not renegotiate TLS in `COM_CHANGE_USER`. TLS 1.3 removed renegotiation, and ProxySQL's context uses `SSL_VERIFY_CLIENT_ONCE`; the only available evidence is the certificate presented during the original connection handshake.
- Reject `COM_CHANGE_USER` when the current session authenticated via SPIFFE, and reject any target account containing `spiffe_id`. This closes both directions: a SPIFFE identity cannot escape to a password identity, and a password identity cannot switch into SPIFFE without a fresh TLS/authentication handshake.
- Allow `COM_CHANGE_USER` into a `require_x509=true` target only when the original connection already carries a trusted client certificate. Otherwise return the existing generic authentication failure and require the client to reconnect with a certificate.
- Preserve the current Phase 1 behavior that a pass-through-eligible target is rejected by `COM_CHANGE_USER`, even when a valid client certificate is present.
- For row-backed pass-through, enforce `require_x509` before username-pattern checks, cache lookup, metrics mutation, `AuthMoreData{0x04}`, or backend probe creation. This guarantees identical cold-cache and warm-cache behavior.
- An empty-password row containing `spiffe_id` is not a pass-through signal. It follows the existing SPIFFE/passwordless row path and must neither read nor populate the pass-through cache.
- Unknown-user pass-through has no `mysql_users.attributes` value, so this change cannot apply `require_x509` to it. It remains protected by `mysql-passthrough_auth_require_tls`; a global unknown-user client-certificate gate is a separate feature.
- The frontend client's certificate is never forwarded to a backend. Backend TLS client identity continues to come from ProxySQL's `mysql_servers_ssl_params` configuration.
- All authentication-layer policy denials sent to a client remain generic MySQL error 1045. Preserve the existing earlier TLS-handshake failure for an untrusted certificate that itself carries a SPIFFE URI SAN; detailed reasons may be logged internally but must not reveal account existence or policy configuration over the wire.
- Preserve user-supplied worktree changes and do not broaden this work into PostgreSQL frontend authentication.

---

## Task 1: Add certificate-policy TAP fixtures and failing initial-login coverage

**Files:**

- Create: `test/tap/tests/test_frontend_x509_auth-t.cpp`
- Modify: `test/tap/groups/groups.json`
- Reference: `test/tap/tests/test_auth_methods-t.cpp:530`
- Reference: `test/tap/tests/reg_test_4556-ssl_error_queue-t.cpp:95`
- Reference: `src/proxy_tls.cpp:224`

**Interfaces:**

```cpp
struct client_tls_material {
	std::string key;
	std::string cert;
	std::string ca;
};

static unsigned int try_frontend_connect(
	const CommandLine& cl,
	const char* username,
	const char* password,
	bool use_tls,
	const client_tls_material* client_identity = nullptr
);
```

- [ ] **Step 1: Build a self-contained certificate fixture in the TAP test.**

  Read `REGULAR_INFRA_DATADIR` and require these standard test-infrastructure files:

  ```text
  ${REGULAR_INFRA_DATADIR}/proxysql-ca.pem
  ${REGULAR_INFRA_DATADIR}/proxysql-key.pem
  ${REGULAR_INFRA_DATADIR}/proxysql-cert.pem
  ```

  Create a temporary directory with `mkdtemp()`. Add helpers that invoke the `openssl` executable and quote every path. Generate:

  1. A trusted client key/certificate with `CN=tap-require-x509` and deliberately no SAN, signed by `proxysql-ca.pem` using `proxysql-key.pem`.
  2. An untrusted self-signed client key/certificate with `CN=tap-untrusted`.

  Use unique explicit serials, for example `5928001` and `5928002`, and a one-day validity. The trusted command sequence is:

  ```sh
  openssl req -new -newkey rsa:2048 -nodes \
    -subj /CN=tap-require-x509 \
    -keyout CLIENT_KEY -out CLIENT_CSR
  openssl x509 -req -days 1 -set_serial 5928001 \
    -in CLIENT_CSR -CA proxysql-ca.pem -CAkey proxysql-key.pem \
    -out CLIENT_CERT
  openssl verify -CAfile proxysql-ca.pem CLIENT_CERT
  ```

  The standard ProxySQL-generated test certificates use the same private key for the CA and server certificate (`ssl_mkit()` in `src/proxy_tls.cpp`). If the active environment uses custom certificates and the CA private key is unavailable or does not match, emit a clear TAP diagnostic and skip only the certificate-positive cases; do not silently treat generation failure as an authentication result.

- [ ] **Step 2: Add a connection helper that distinguishes TLS-without-certificate from TLS-with-certificate.**

  Use the MariaDB client API in the same style as existing TAP tests:

  ```cpp
  unsigned long flags = 0;
  if (use_tls) {
	if (client_identity) {
		mysql_ssl_set(mysql,
			client_identity->key.c_str(),
			client_identity->cert.c_str(),
			client_identity->ca.c_str(), nullptr, nullptr);
	} else {
		mysql_ssl_set(mysql, nullptr, nullptr, nullptr, nullptr, nullptr);
	}
	flags |= CLIENT_SSL;
  }
  MYSQL* connected = mysql_real_connect(
	mysql, cl.host, username, password, nullptr, cl.port, nullptr, flags);
  const unsigned int result = connected ? 0 : mysql_errno(mysql);
  ```

  Do not enable hostname verification: this test is proving the certificate ProxySQL receives from the client, not the client's validation of ProxySQL's hostname.

- [ ] **Step 3: Provision dedicated frontend users and add the failing assertions.**

  Insert users with distinct names and passwords, then `LOAD MYSQL USERS TO RUNTIME`:

  ```sql
  INSERT INTO mysql_users(username,password,default_hostgroup,active,attributes)
  VALUES
    ('tap_x509_none','tap-x509-password',0,1,''),
    ('tap_x509_required','tap-x509-password',0,1,'{"require_x509":true}'),
    ('tap_x509_false','tap-x509-password',0,1,'{"require_x509":false}'),
    ('tap_x509_bad_type','tap-x509-password',0,1,'{"require_x509":"true"}');
  LOAD MYSQL USERS TO RUNTIME;
  ```

  Assert the following matrix. Every rejection must be `ER_ACCESS_DENIED_ERROR`/1045, never a disconnect, parse exception, or TLS-library error:

  | User policy | Transport/client cert | Expected |
  |---|---|---|
  | no attribute | plaintext | success |
  | no attribute | TLS, no client cert | success |
  | `false` | TLS, no client cert | success |
  | `true` | plaintext | 1045 |
  | `true` | TLS, no client cert | 1045 |
  | `true` | TLS, untrusted client cert | 1045 |
  | `true` | TLS, trusted cert without SAN | success |
  | `true` | TLS, trusted cert, wrong password | 1045 |
  | string `"true"` | TLS, trusted cert | 1045 (fail closed, no crash) |

  At setup, snapshot `mysql-passthrough_auth_enabled`, force it to `false`, and load variables so the empty-password SPIFFE cases added later cannot inherit pass-through state from another TAP test. Delete the dedicated frontend rows before inserting and again during cleanup. Use an RAII cleanup object for the exact directory returned by `mkdtemp()`; never remove a path assembled from an unchecked environment value.

- [ ] **Step 4: Register the test in integration groups.**

  Add `test_frontend_x509_auth-t` beside the authentication tests in `test/tap/groups/groups.json`, using the same broad server groups as `reg_test_3504-change_user-t`:

  ```json
  "test_frontend_x509_auth-t" : [ "legacy-g6", "mysql84-g6", "mysql90-g1", "mysql95-g1", "@proxysql_min_version:3.1" ],
  ```

  No `Makefile` source-list edit is needed: `test/tap/tests/Makefile:220` discovers every `*-t.cpp` through `wildcard`.

- [ ] **Step 5: Build and run the new test to prove the feature is absent.**

  ```sh
  make clean
  PROXYSQL31=1 make -j4 debug
  make -C test/tap/tests test_frontend_x509_auth-t
  # Run test_frontend_x509_auth-t against the PROXYSQL31 isolated runtime.
  ```

  Expected before implementation in a v3.1 build: baseline cases pass, while at least plaintext/no-cert/untrusted `require_x509=true` cases incorrectly authenticate. Record the failing TAP assertion numbers in the commit message body. A default v3.0 runtime is not valid RED evidence because that tier intentionally does not recognize the key.

- [ ] **Step 6: Commit only the failing test and group registration.**

  ```sh
  git add test/tap/tests/test_frontend_x509_auth-t.cpp test/tap/groups/groups.json
  git commit -m "test: cover frontend require_x509 policy"
  ```

---

## Task 2: Capture client-certificate evidence and implement one policy evaluator

**Files:**

- Modify: `include/MySQL_Data_Stream.h:133`
- Modify: `lib/mysql_data_stream.cpp:220`
- Modify: `lib/mysql_data_stream.cpp:349`
- Modify: `lib/MySQL_Protocol.cpp:3402`
- Modify: `lib/MySQL_Protocol.cpp:92`
- Modify: `include/MySQL_Protocol.h:256`
- Create: `test/tap/tests/test_frontend_x509_tier_gate-t.cpp`
- Modify: `test/tap/groups/groups.json`
- Test: `test/tap/tests/test_frontend_x509_auth-t.cpp`

**Interfaces:**

Add immutable-for-the-connection evidence beside `x509_subject_alt_name`:

```cpp
char *x509_subject_alt_name;
#ifdef PROXYSQL31
bool client_cert_present;
long client_cert_verify_result;
bool frontend_authenticated_via_spiffe;
#endif
SSL *ssl;
```

Define the policy types at file scope in `lib/MySQL_Protocol.cpp`, entirely inside `#ifdef PROXYSQL31`:

```cpp
enum class frontend_auth_context : uint8_t {
	INITIAL_HANDSHAKE,
	COM_CHANGE_USER,
	PASSTHROUGH
};

struct frontend_certificate_policy_result {
	bool allowed { true };
	bool has_spiffe_id { false };
};

static frontend_certificate_policy_result evaluate_frontend_certificate_policy(
	MySQL_Data_Stream* myds,
	const char* attributes,
	const unsigned char* user,
	frontend_auth_context context,
	int calling_line,
	const char* calling_func
);
```

The tier-gate TAP test owns these file-local helpers:

```cpp
static int get_proxy_version(MYSQL* admin, int& major, int& minor) {
	if (mysql_query(admin,
		"SELECT variable_value FROM global_variables "
		"WHERE variable_name='admin-version'")) {
		return EXIT_FAILURE;
	}
	MYSQL_RES* result = mysql_store_result(admin);
	if (!result) {
		return EXIT_FAILURE;
	}
	MYSQL_ROW row = mysql_fetch_row(result);
	const int parsed = row && row[0]
		? std::sscanf(row[0], "%d.%d", &major, &minor) : 0;
	mysql_free_result(result);
	return parsed == 2 ? EXIT_SUCCESS : EXIT_FAILURE;
}

static unsigned int try_plaintext_frontend_connect(
	const CommandLine& cl,
	const char* username,
	const char* password
);
```

- [ ] **Step 1: Add and establish a cross-tier compatibility regression.**

  Create `test_frontend_x509_tier_gate-t.cpp`. Connect to the admin interface and read the running build from:

  ```sql
  SELECT variable_value
    FROM global_variables
   WHERE variable_name='admin-version'
  ```

  Parse the leading `major.minor` numbers. Provision one frontend user with a normal password and `attributes='{"require_x509":true}'`, then attempt a plaintext connection with the correct password:

  ```cpp
  const bool has_feature = major > 3 || (major == 3 && minor >= 1);
  const unsigned int expected = has_feature ? ER_ACCESS_DENIED_ERROR : 0;
  const unsigned int actual = try_frontend_connect(
	cl, "tap_x509_tier_gate", "tap-x509-tier-password", false);
  ok(actual == expected,
	"require_x509 is %s on ProxySQL %d.%d: expected errno=%u, got errno=%u",
	has_feature ? "enforced" : "unrecognized", major, minor, expected, actual);
  ```

  The test must plan an admin-version parse assertion, the tier-dependent authentication assertion, and cleanup assertions. It deletes only its dedicated row and restores no global variables. Register it without a minimum-version tag:

  ```json
  "test_frontend_x509_tier_gate-t" : [ "legacy-g6", "mysql84-g6", "mysql90-g1", "mysql95-g1" ],
  ```

  Update `test_frontend_x509_auth-t` registration to append `"@proxysql_min_version:3.1"`.

  Run it first against a clean default v3.0 DEBUG build. On the pristine Task 1 base it establishes the compatibility baseline with `actual=0`; if an in-progress evaluator is already compiled into the stable tier it fails and exposes the missing gate. After Task 2 it must pass in both tiers, with opposite expected authentication results selected from `admin-version`.

- [ ] **Step 2: Initialize the new data-stream fields only for Innovative-tier builds.**

  Keep `x509_subject_alt_name` and `ssl` unconditional. Wrap only the new state in the class definition and constructor:

  ```cpp
  x509_subject_alt_name = nullptr;
  #ifdef PROXYSQL31
  client_cert_present = false;
  client_cert_verify_result = X509_V_OK;
  frontend_authenticated_via_spiffe = false;
  #endif
  ssl = nullptr;
  ```

  `client_cert_present` is required because OpenSSL's verification result alone does not distinguish “no certificate” from a successfully verified certificate. Do not clear these fields in `MySQL_Session::reset()`; they belong to the physical connection and must survive `COM_RESET_CONNECTION` and `COM_CHANGE_USER`.

- [ ] **Step 3: Record generic verification state only under `PROXYSQL31`, while hardening SAN handling in every tier.**

  Restructure the successful branch of `MySQL_Data_Stream::do_ssl_handshake()` as follows:

  ```cpp
  if (n == 1) {
    X509* cert = SSL_get_peer_certificate(ssl);
  #ifdef PROXYSQL31
    client_cert_present = (cert != nullptr);
    client_cert_verify_result = cert ? SSL_get_verify_result(ssl) : X509_V_OK;
  #endif

    if (cert) {
      GENERAL_NAMES* alt_names = static_cast<GENERAL_NAMES*>(
        X509_get_ext_d2i(cert, NID_subject_alt_name, nullptr, nullptr));
      if (alt_names) {
        // Preserve the existing first spiffe:// URI extraction loop.
        sk_GENERAL_NAME_pop_free(alt_names, GENERAL_NAME_free);
      }
      X509_free(cert);
    }

    if (x509_subject_alt_name && SSL_get_verify_result(ssl) != X509_V_OK) {
      // Preserve the existing SPIFFE handshake-failure behavior.
      return SSLSTATUS_FAIL;
    }
  }
  ```

  Guard `alt_names` before calling `sk_GENERAL_NAME_num()`. The trusted no-SAN certificate in Task 1 is specifically intended to exercise this null case and prevent a regression crash.

- [ ] **Step 4: Implement strict, exception-safe attribute parsing behind the tier gate.**

  Compile the shared evaluator only under `#ifdef PROXYSQL31`. It must:

  1. Treat null/empty attributes as allowed.
  2. Catch all `nlohmann::json::exception` values and fail closed.
  3. Require `require_x509` to be a JSON boolean. Any other type logs a configuration error and denies authentication.
  4. Set `has_spiffe_id=true` whenever the key exists, even if its value is malformed, so malformed SPIFFE rows cannot accidentally become pass-through rows.
  5. Require `spiffe_id` to be a string and fail closed otherwise.
  6. Reuse the current exact `spiffe://...` comparison and `!regex` full-match semantics with quiet RE2 options.

  In every tier, make the `#ifdef DEBUG` `debug_spiffe_id()` helper follow the same `is_string()` and exception-safety rules. Otherwise a malformed `spiffe_id` can still terminate a debug build inside `PPHR_5passwordTrue()` before the common evaluator runs.

  Core `require_x509` check:

  ```cpp
  const auto require_x509 = attrs.find("require_x509");
  if (require_x509 != attrs.end()) {
	if (!require_x509->is_boolean()) {
		result.allowed = false;
		// log invalid type; do not call get<bool>()
		return result;
	}
	if (require_x509->get<bool>()) {
		result.allowed = myds
			&& myds->encrypted
			&& myds->ssl
			&& myds->client_cert_present
			&& myds->client_cert_verify_result == X509_V_OK;
		if (!result.allowed) {
			// Include presence/verify text in internal log only.
			return result;
		}
	}
  }
  ```

  Evaluate `require_x509` and `spiffe_id` conjunctively when both are present. Do not let a successful SPIFFE match overwrite a previous `require_x509` denial.

- [ ] **Step 5: Make initial authentication select the tier-appropriate path.**

  Use the common evaluator only in `PROXYSQL31` builds. Preserve the existing SPIFFE-only block verbatim in the stable `#else` path:

  ```cpp
  #ifdef PROXYSQL31
  const char* attributes = (*myds)->sess->user_attributes;
  const auto policy = evaluate_frontend_certificate_policy(
    *myds, attributes, user,
    frontend_auth_context::INITIAL_HANDSHAKE,
    calling_line, calling_func);
  if (!policy.allowed) {
    return false;
  }
  (*myds)->frontend_authenticated_via_spiffe = policy.has_spiffe_id;
  #else
  // Existing v3.0 SPIFFE-only attribute handling. Never inspect require_x509.
  #endif
  ```

  Retain the existing `default-transaction_isolation` application after policy success. Parse the JSON once in the function or pass a parsed object through a private helper; do not reintroduce uncaught `get<std::string>()` exceptions.

  Task 3 will retain `user_attributes_has_spiffe()` only inside the stable `#ifndef PROXYSQL31` path, because that path must preserve the existing late SPIFFE target check. Innovative-tier code must use the common evaluator instead.

- [ ] **Step 6: Prove both tier behaviors and run focused TLS regressions.**

  ```sh
  make clean
  make -j4 debug
  make -C test/tap/tests test_frontend_x509_tier_gate-t
  INFRA_ID=x509-tier-stable TAP_GROUP=mysql84-g6 \
    test/infra/control/start-proxysql-isolated.bash
  INFRA_ID=x509-tier-stable TAP_GROUP=mysql84-g6 \
    test/infra/control/ensure-infras.bash
  WORKSPACE=$(pwd) INFRA_ID=x509-tier-stable TAP_GROUP=mysql84-g6 \
    TEST_PY_TAP_INCL='^test_frontend_x509_tier_gate-t$' \
    test/infra/control/run-tests-isolated.bash

  make clean
  PROXYSQL31=1 make -j4 debug
  make -C test/tap/tests test_frontend_x509_auth-t reg_test_4556-ssl_error_queue-t test_auth_methods-t
  INFRA_ID=x509-tier-31 TAP_GROUP=mysql84-g6 \
    test/infra/control/start-proxysql-isolated.bash
  INFRA_ID=x509-tier-31 TAP_GROUP=mysql84-g6 \
    test/infra/control/ensure-infras.bash
  WORKSPACE=$(pwd) INFRA_ID=x509-tier-31 TAP_GROUP=mysql84-g6 \
    TEST_PY_TAP_INCL='^(test_frontend_x509_auth-t|test_frontend_x509_tier_gate-t)$' \
    test/infra/control/run-tests-isolated.bash
  INFRA_ID=x509-tier-31 TAP_GROUP=mysql84-g2 \
    test/infra/control/ensure-infras.bash
  WORKSPACE=$(pwd) INFRA_ID=x509-tier-31 TAP_GROUP=mysql84-g2 \
    TEST_PY_TAP_INCL='^reg_test_4556-ssl_error_queue-t$' \
    test/infra/control/run-tests-isolated.bash
  INFRA_ID=x509-tier-31 TAP_GROUP=mysql84-g7 \
    test/infra/control/ensure-infras.bash
  WORKSPACE=$(pwd) INFRA_ID=x509-tier-31 TAP_GROUP=mysql84-g7 \
    TEST_PY_TAP_INCL='^test_auth_methods-t$' \
    test/infra/control/run-tests-isolated.bash
  ```

  Expected: the v3.0 compatibility probe authenticates because the key is unrecognized. In the `PROXYSQL31` build, all Task 1 scenarios pass, ordinary TLS connections without a client certificate remain accepted, and the SSL error queue regression remains green.

- [ ] **Step 7: Commit the tier gate, handshake evidence, and common evaluator.**

  ```sh
  git add include/MySQL_Data_Stream.h include/MySQL_Protocol.h \
    lib/mysql_data_stream.cpp lib/MySQL_Protocol.cpp \
    test/tap/tests/test_frontend_x509_tier_gate-t.cpp \
    test/tap/groups/groups.json
  git commit -m "feat: enforce per-user frontend X.509 policy"
  ```

---

## Task 3: Define and test `COM_CHANGE_USER` behavior

**Files:**

- Modify: `test/tap/tests/test_frontend_x509_auth-t.cpp`
- Modify: `lib/MySQL_Protocol.cpp:1398`
- Modify: `lib/MySQL_Protocol.cpp:1671`
- Modify: `include/MySQL_Protocol.h:257`
- Reference: `lib/MySQL_Session.cpp:8311`
- Regression: `test/tap/tests/reg_test_3504-change_user-t.cpp`

**Interfaces:**

```cpp
static unsigned int try_change_user(
	MYSQL* connection,
	const char* target_user,
	const char* target_password
) {
	return mysql_change_user(connection, target_user, target_password, nullptr) == 0
		? 0 : mysql_errno(connection);
}
```

- [ ] **Step 1: Add failing `COM_CHANGE_USER` scenarios to the X.509 TAP test.**

  Provision these additional users:

  ```sql
  ('tap_x509_source','source-password',0,1,''),
  ('tap_x509_target','target-password',0,1,'{"require_x509":true}'),
  ('tap_spiffe_source','',0,1,'{"spiffe_id":"spiffe://tap/source"}'),
  ('tap_spiffe_target','',0,1,'{"spiffe_id":"spiffe://tap/target"}')
  ```

  Generate two trusted SPIFFE client certificates using a temporary OpenSSL extension file:

  ```text
  subjectAltName=URI:spiffe://tap/source
  subjectAltName=URI:spiffe://tap/target
  ```

  Add `-extfile EXTFILE` to `openssl x509 -req`. Assert:

  | Existing connection | Target | Expected |
  |---|---|---|
  | plaintext password source | `require_x509` target | 1045 |
  | TLS password source, no cert | `require_x509` target | 1045 |
  | TLS password source, untrusted cert | `require_x509` target | 1045 |
  | TLS password source, trusted cert | `require_x509` target | success |
  | TLS password source, trusted cert, wrong target password | `require_x509` target | 1045 |
  | TLS password source, trusted cert | ordinary target | success (control) |
  | SPIFFE-authenticated source | ordinary password target | 1045 |
  | password-authenticated source | SPIFFE target, matching target cert | 1045 |

  For each rejected change, assert `mysql_errno()==1045`. The server currently treats failed `COM_CHANGE_USER` as terminal, so use a fresh connection per row rather than querying the old session afterward.

- [ ] **Step 2: Prove no certificate renegotiation is attempted.**

  The “TLS password source, no cert → `require_x509` target” scenario is the regression test: it must fail without an SSL protocol error or a second certificate request. Add a diagnostic comment explaining that a reconnect using the trusted certificate succeeds, while `COM_CHANGE_USER` on the original connection cannot acquire one.

  Do not add calls to `SSL_renegotiate()`, `SSL_verify_client_post_handshake()`, or client-library reconnect internals.

- [ ] **Step 3: Reject a SPIFFE-authenticated source before target lookup side effects.**

  Under `#ifdef PROXYSQL31`, at the start of `process_pkt_COM_CHANGE_USER()`, after safe packet parsing but before account state is copied, add:

  ```cpp
  if ((*myds)->frontend_authenticated_via_spiffe) {
	proxy_error(
		"Client %s:%d cannot run COM_CHANGE_USER after SPIFFE authentication\n",
		(*myds)->addr.addr, (*myds)->addr.port);
	free(pass);
	return false;
  }
  ```

  Use the function's existing cleanup conventions rather than duplicating cleanup if a local cleanup helper is introduced. The marker is on `MySQL_Data_Stream`, so the preceding `MySQL_Session::reset()` does not erase it.

- [ ] **Step 4: Evaluate the target account before session mutation or Auth Switch.**

  Under `#ifdef PROXYSQL31`, immediately after `GloMyAuth->lookup()` and `get_password(account_details, PRIMARY)`, but before assigning `default_hostgroup`, `transaction_persistent`, or `user_attributes`, evaluate:

  ```cpp
  const auto target_policy = evaluate_frontend_certificate_policy(
	*myds,
	account_details.attributes,
	user,
	frontend_auth_context::COM_CHANGE_USER,
	__LINE__, __func__);

  if (!target_policy.allowed || target_policy.has_spiffe_id) {
	// common generic-denial cleanup; no Auth Switch Request
	return false;
  }
  ```

  In `COM_CHANGE_USER` context, the evaluator should mark any `spiffe_id` target denied without attempting identity matching. This makes direct-password and password-omitted/Auth-Switch forms follow the same rule.

  Keep the existing pass-through-target check directly after this policy gate. Its eligibility must use `!target_policy.has_spiffe_id`, matching Task 4's initial-login logic.

- [ ] **Step 5: Keep the stable SPIFFE block and replace it only in Innovative-tier code.**

  In `PROXYSQL31` builds, delete the `user_attributes_has_spiffe()` call around current `lib/MySQL_Protocol.cpp:1671`; the new source marker and early target evaluator replace it. In stable builds, retain that pre-feature block and compile the helper declaration/definition inside `#ifndef PROXYSQL31`. Stable behavior must not gain the new source-identity rule or inspect `require_x509`.

  In `PROXYSQL31` builds, after successful change to a non-SPIFFE account, explicitly keep:

  ```cpp
  (*myds)->frontend_authenticated_via_spiffe = false;
  ```

  This is currently implied because all SPIFFE transitions are denied, but the assignment documents and preserves the state invariant.

- [ ] **Step 6: Run focused and existing change-user tests.**

  ```sh
  make clean
  PROXYSQL31=1 make -j4 debug
  make -C test/tap/tests test_frontend_x509_auth-t reg_test_3504-change_user-t \
    reg_test_3504-change_user_libmariadb_helper \
    reg_test_3504-change_user_libmysql_helper
  cd test/tap/tests && ./test_frontend_x509_auth-t
  cd test/tap/tests && ./reg_test_3504-change_user-t
  ```

  Expected: the new matrix passes and ordinary password-to-password `COM_CHANGE_USER` remains unchanged across SSL/non-SSL and supported plugins.

- [ ] **Step 7: Commit the `COM_CHANGE_USER` policy.**

  ```sh
  git add include/MySQL_Protocol.h lib/MySQL_Protocol.cpp \
    test/tap/tests/test_frontend_x509_auth-t.cpp
  git commit -m "fix: preserve certificate identity across change user"
  ```

---

## Task 4: Enforce X.509 before pass-through cache/probe paths

**Files:**

- Create: `test/tap/tests/test_frontend_x509_passthrough-t.cpp`
- Modify: `test/tap/groups/groups.json`
- Modify: `lib/MySQL_Protocol.cpp:2736`
- Reference: `lib/MySQL_Protocol.cpp:2577`
- Reference: `lib/MySQL_Session.cpp:1885`
- Regression: `test/tap/tests/test_passthrough_auth_e2e-t.cpp`
- Regression: `test/tap/tests/test_passthrough_auth_security-t.cpp`

**Interfaces:**

Reuse Task 1's certificate-generation and connect patterns. If copying the helpers would create more than roughly 100 duplicated lines, extract test-only helpers into:

```text
test/tap/tests/frontend_x509_test_utils.h
```

Keep the helper header-only so the wildcard Makefile rules need no additional link object.

- [ ] **Step 1: Write a pass-through test that differentiates policy from backend behavior.**

  Create a MySQL 8+ backend user using `caching_sha2_password`, and an empty-password ProxySQL row carrying the X.509 policy:

  ```sql
  CREATE USER 'tap_x509_pt'@'%'
    IDENTIFIED WITH 'caching_sha2_password' BY 'x509-pass-through-password';
  GRANT SELECT ON *.* TO 'tap_x509_pt'@'%';

  INSERT INTO mysql_users(username,password,default_hostgroup,active,attributes)
  VALUES
    ('tap_x509_pt','',30,1,'{"require_x509":true}'),
    ('tap_x509_pt_target','ordinary-target-password',30,1,'');
  LOAD MYSQL USERS TO RUNTIME;
  ```

  Enable only row-backed pass-through, raise test failure-rate caps, and flush the cache:

  ```sql
  SET mysql-passthrough_auth_enabled='true';
  SET mysql-passthrough_auth_empty_password='true';
  SET mysql-passthrough_auth_unknown_users='false';
  SET mysql-passthrough_auth_require_tls='true';
  SET mysql-passthrough_auth_max_failures_per_user='10000';
  SET mysql-passthrough_auth_max_failures_per_ip='10000';
  SET mysql-default_authentication_plugin='caching_sha2_password';
  LOAD MYSQL VARIABLES TO RUNTIME;
  PROXYSQL FLUSH PASSTHROUGH_AUTH_CACHE;
  ```

- [ ] **Step 2: Add failing cold-cache ordering assertions.**

  Snapshot `cache_hits`, `probes_attempted`, and the per-user cache row count before each attempt. Assert:

  1. TLS without a client certificate returns 1045.
  2. `probes_attempted` is unchanged.
  3. No cache entry was created.
  4. TLS with an untrusted client certificate has the same outcome.
  5. TLS with the trusted no-SAN certificate but the wrong backend password returns 1045, increments `probes_attempted`, and leaves the cache empty.
  6. TLS with the trusted no-SAN certificate and the correct backend password succeeds, increments `probes_attempted` again, and creates one cache entry.

  Use queries modeled on `test_passthrough_auth_metrics-t.cpp`:

  ```sql
  SELECT metric_value
    FROM stats_mysql_passthrough_auth_metrics
   WHERE metric_name='probes_attempted';

  SELECT COUNT(*)
    FROM stats_mysql_passthrough_auth_cache
   WHERE username='tap_x509_pt';
  ```

- [ ] **Step 3: Add failing warm-cache ordering assertions.**

  With the cache now populated:

  1. TLS without a client certificate returns 1045 and `cache_hits` is unchanged.
  2. TLS with the trusted client certificate succeeds and increments `cache_hits` by one.

  This specifically detects the tempting but incorrect implementation that checks attributes only in `verify_user_attributes()`: cold probe completion sends OK directly from `MySQL_Session::handler_again___status_AUTHENTICATING_BACKEND_FOR_CLIENT()` and never reaches that epilogue.

- [ ] **Step 4: Add SPIFFE/pass-through precedence coverage.**

  Provision an empty-password row with only:

  ```json
  {"spiffe_id":"spiffe://tap/pass-through-exclusion"}
  ```

  Connect with a trusted certificate bearing that URI SAN and an empty frontend password. Assert:

  1. Authentication succeeds through the normal SPIFFE path.
  2. `probes_attempted` is unchanged.
  3. No pass-through cache entry exists for the SPIFFE user.

  A mismatching/no-certificate attempt must return 1045, still without a probe. This protects SPIFFE's identity semantics from the new empty-password pass-through interpretation.

- [ ] **Step 5: Preserve `COM_CHANGE_USER` rejection for pass-through targets.**

  Open an ordinary password-authenticated TLS connection with the trusted client certificate, then call `mysql_change_user()` targeting `tap_x509_pt` with the correct backend password. Assert 1045 and unchanged `probes_attempted`. A certificate satisfies `require_x509`; it does not make the unsupported pass-through state machine legal in `COM_CHANGE_USER`.

  As a directional control, open a successfully pass-through-authenticated `tap_x509_pt` connection with the trusted certificate and change to the ordinary password-backed `tap_x509_pt_target`. Assert success. Pass-through is not a connection-bound identity scheme: only a pass-through *target* is unsupported, and `MySQL_Session::reset()` deliberately clears `passthrough_credential` before authenticating the new target.

- [ ] **Step 6: Register the pass-through test in MySQL 8+ groups and run it failing.**

  Add:

  ```json
  "test_frontend_x509_passthrough-t" : [ "mysql84-g4", "mysql90-g4", "mysql95-g4", "@proxysql_min_version:3.1" ],
  ```

  Then run:

  ```sh
  make -C test/tap/tests test_frontend_x509_passthrough-t
  cd test/tap/tests && ./test_frontend_x509_passthrough-t
  ```

  Expected before implementation: no-cert attempts reach pass-through/cache behavior, and the SPIFFE empty row may be misclassified as pass-through.

- [ ] **Step 7: Compute policy before pass-through eligibility and side effects.**

  At the top of the pass-through block in `PPHR_verify_password()`, keep the stable code unchanged. Under `#ifdef PROXYSQL31`, retain the raw row state separately from effective eligibility:

  ```cpp
  const bool raw_empty_pw_case =
	mysql_thread___passthrough_auth_empty_password
	&& vars1.password != nullptr
	&& vars1.password[0] == '\0';

  frontend_certificate_policy_result row_policy {};
  if (raw_empty_pw_case) {
	row_policy = evaluate_frontend_certificate_policy(
		*myds,
		account_details.attributes,
		vars1.user,
		frontend_auth_context::PASSTHROUGH,
		__LINE__, __func__);
  }

  const bool empty_pw_case = raw_empty_pw_case && !row_policy.has_spiffe_id;
  ```

  Then enforce:

  ```cpp
  if (mysql_thread___passthrough_auth_enabled
	&& empty_pw_case
	&& !row_policy.allowed) {
	return false;
  }
  ```

  This gate must appear before:

  - the non-`caching_sha2_password` hard rejection,
  - username allowlist evaluation,
  - unknown-user default synthesis,
  - `GloMyPTAuthCache->lookup()` and counter increments,
  - `PPHR_5passwordTrue()`, and
  - `PPHR_passthrough_init()`.

  The `#else` branch must contain the existing empty-password pass-through classification and must not reference the evaluator, `require_x509`, or the new data-stream fields. Pass-through itself remains unarmable on v3.0 through its existing `MySQL_Threads_Handler::commit()` tier gate.

  When `raw_empty_pw_case && row_policy.has_spiffe_id`, skip all pass-through-only rejection/dispatch code and continue through the legacy empty-password branch. The common `verify_user_attributes()` epilogue then performs the SPIFFE identity match. Do not accept the backend password for this case: the configured frontend empty password remains the expected password input before SPIFFE validation.

- [ ] **Step 8: Keep unknown-user semantics explicit.**

  Do not run the evaluator with fabricated empty attributes for `unknown_user_case`, and do not add a global variable in this change. Add an in-source comment:

  ```cpp
  // Unknown-user pass-through has no mysql_users row and therefore no
  // per-user require_x509 attribute. Its transport gate remains
  // mysql-passthrough_auth_require_tls.
  ```

- [ ] **Step 9: Run pass-through and change-user regressions.**

  ```sh
  make clean
  PROXYSQL31=1 make -j4 debug
  make -C test/tap/tests \
    test_frontend_x509_passthrough-t \
    test_passthrough_auth_e2e-t \
    test_passthrough_auth_security-t \
    test_passthrough_auth_unknown_user-t \
    reg_test_3504-change_user-t

  cd test/tap/tests && ./test_frontend_x509_passthrough-t
  cd test/tap/tests && ./test_passthrough_auth_e2e-t
  cd test/tap/tests && ./test_passthrough_auth_security-t
  cd test/tap/tests && ./test_passthrough_auth_unknown_user-t
  cd test/tap/tests && ./reg_test_3504-change_user-t
  ```

  Expected: all pass, including cold/warm X.509 differentials, no-probe SPIFFE assertions, existing TLS gate behavior, unknown-user behavior, and pass-through `COM_CHANGE_USER` rejection.

  In the test cleanup path, drop backend user `tap_x509_pt`, delete every ProxySQL frontend row created by the fixture (`tap_x509_pt`, `tap_x509_pt_target`, and the SPIFFE exclusion user), flush the pass-through cache, restore every snapshotted `mysql-passthrough_auth_*` and default-authentication-plugin value, and load users/variables back to runtime. Cleanup must run after failed assertions as well as successful ones so later tests in `mysql84-g4` do not inherit this fixture.

- [ ] **Step 10: Commit pass-through integration separately.**

  ```sh
  git add lib/MySQL_Protocol.cpp \
    test/tap/tests/test_frontend_x509_passthrough-t.cpp \
    test/tap/tests/test_frontend_x509_auth-t.cpp \
    test/tap/tests/frontend_x509_test_utils.h \
    test/tap/groups/groups.json
  git commit -m "fix: apply X.509 policy before pass-through auth"
  ```

  Omit `frontend_x509_test_utils.h` from `git add` if no shared helper was extracted.

---

## Task 5: Validate configuration types and document operator-visible semantics

**Files:**

- Modify: `lib/MySQL_Authentication.cpp:188`
- Create: `doc/frontend_x509_authentication.md`
- Modify: `doc/internal/passthrough_authentication.md:30`
- Modify: `doc/internal/passthrough_authentication.md:172`
- Modify: `doc/internal/passthrough_authentication.md:246`
- Test: `test/tap/tests/test_frontend_x509_auth-t.cpp`

- [ ] **Step 1: Add load-time diagnostics without turning malformed values into allow.**

  Under `#ifdef PROXYSQL31`, in the existing JSON validation block in `MySQL_Authentication::add()`, inspect `require_x509`:

  ```cpp
  const auto require_x509 = valid.find("require_x509");
  if (require_x509 != valid.end() && !require_x509->is_boolean()) {
	proxy_error(
		"Invalid require_x509 attribute for user %s: expected JSON boolean; "
		"authentication will be denied until corrected\n",
		username);
  }
  ```

  Preserve the original attribute in runtime so the evaluator can fail closed. Do not erase the key, coerce strings/numbers, or replace all attributes with an empty string; each of those would turn a configuration error into an unintended allow. The stable path must not call `find("require_x509")` or emit a diagnostic for that key.

- [ ] **Step 2: Extend the invalid-type TAP assertion.**

  Verify both:

  1. `LOAD MYSQL USERS TO RUNTIME` completes without crashing ProxySQL.
  2. Login for the malformed account returns 1045 even with a trusted certificate.

  If the test already tails `proxysql.log`, also assert one diagnostic containing the username and `expected JSON boolean`. Do not make the test depend on an exact full log sentence.

- [ ] **Step 3: Write the frontend X.509 operator guide.**

  `doc/frontend_x509_authentication.md` must include:

  - Availability: the feature requires a v3.1.x Innovative-tier or v4.x build; v3.0.x does not recognize the key.

  - Configuration example:

    ```sql
    UPDATE mysql_users
       SET attributes='{"require_x509":true}'
     WHERE username='application_user';
    LOAD MYSQL USERS TO RUNTIME;
    SAVE MYSQL USERS TO DISK;
    ```

  - Trust source: the frontend certificate is validated against ProxySQL's frontend `proxysql-ca.pem` loaded by the TLS context.
  - Additive semantics: valid password plus valid client certificate.
  - Difference from `use_ssl`: `use_ssl` requires encryption; `require_x509` additionally requires a verified peer certificate.
  - Difference from `spiffe_id`: SPIFFE binds the username to a URI identity and remains the authoritative certificate-identity check after the configured frontend password step; `require_x509` only proves membership in the trusted PKI and is additive to password authentication.
  - `COM_CHANGE_USER`: no renegotiation; it reuses the original connection certificate, rejects when absent/invalid, and always rejects SPIFFE source/target identities.
  - Pass-through: row-backed `require_x509` is checked before cache/probe; passwords still come from backend verification; SPIFFE rows are excluded; unknown users have no per-user attribute. `COM_CHANGE_USER` into a pass-through target is rejected, while changing from a pass-through-authenticated source into an ordinary password-backed target remains supported.
  - Backend separation: ProxySQL never forwards the frontend certificate; backend certificates/keys are configured independently.
  - Failure behavior: authentication-policy failures return 1045 and detailed certificate reasons remain in ProxySQL logs. An untrusted certificate carrying a SPIFFE URI SAN retains the existing earlier TLS-handshake failure behavior.

- [ ] **Step 4: Update the pass-through design document.**

  Add a “Frontend certificate policy” subsection near eligibility and amend §5.4 and §7.1 with this ordering:

  ```text
  row lookup
    -> require_x509 / SPIFFE classification
    -> username allowlist
    -> pass-through TLS gate
    -> cache lookup
    -> cleartext request
    -> backend probe
  ```

  State explicitly that cold-probe completion sends the frontend OK from `MySQL_Session`, which is why the X.509 decision is made before dispatch rather than relying only on the normal handshake epilogue.

- [ ] **Step 5: Run the config test and documentation checks.**

  ```sh
  make clean
  PROXYSQL31=1 make -j4 debug
  make -C test/tap/tests test_frontend_x509_auth-t
  cd test/tap/tests && ./test_frontend_x509_auth-t
  rg -n "require_x509|COM_CHANGE_USER|SPIFFE|pass-through|unknown" \
    doc/frontend_x509_authentication.md \
    doc/internal/passthrough_authentication.md
  ```

- [ ] **Step 6: Commit validation and documentation.**

  ```sh
  git add lib/MySQL_Authentication.cpp \
    doc/frontend_x509_authentication.md \
    doc/internal/passthrough_authentication.md \
    test/tap/tests/test_frontend_x509_auth-t.cpp
  git commit -m "docs: define frontend X.509 authentication semantics"
  ```

---

## Task 6: Full verification, invariants audit, and cleanup

**Files:**

- Review: `include/MySQL_Data_Stream.h`
- Review: `include/MySQL_Protocol.h`
- Review: `lib/mysql_data_stream.cpp`
- Review: `lib/MySQL_Protocol.cpp`
- Review: `lib/MySQL_Authentication.cpp`
- Review: `lib/MySQL_Session.cpp`
- Review: `test/tap/tests/test_frontend_x509_auth-t.cpp`
- Review: `test/tap/tests/test_frontend_x509_tier_gate-t.cpp`
- Review: `test/tap/tests/test_frontend_x509_passthrough-t.cpp`
- Review: `test/tap/groups/groups.json`
- Review: `doc/frontend_x509_authentication.md`
- Review: `doc/internal/passthrough_authentication.md`

- [ ] **Step 1: Audit every authentication completion path.**

  Use `rg` to confirm the intended coverage:

  ```sh
  rg -n "generate_pkt_OK|PPHR_passthrough_init|PPHR_verify_password|verify_user_attributes|process_pkt_COM_CHANGE_USER" \
    lib/MySQL_Protocol.cpp lib/MySQL_Session.cpp
  ```

  Manually verify these invariants:

  - Normal initial auth reaches `verify_user_attributes()` after password success.
  - Warm-cache pass-through cannot touch the cache before the row X.509 gate.
  - Cold-cache pass-through cannot send AuthMoreData or probe before the row X.509 gate.
  - Cold-probe success's direct OK is safe because the immutable certificate evidence was already checked.
  - Additional-password retry runs the same policy and cannot bypass it.
  - `COM_CHANGE_USER` evaluates source SPIFFE state and target attributes before Auth Switch and target session-attribute mutation.
  - Unknown-user pass-through remains unchanged and is never mistaken for an attribute-bearing row.
  - Every new evaluator call and state access is inside a `PROXYSQL31` path; the stable path never inspects `require_x509`.
  - The stable `COM_CHANGE_USER` path retains its pre-feature `user_attributes_has_spiffe()` behavior.

- [ ] **Step 2: Audit certificate ownership and reset behavior.**

  Confirm:

  - Under `PROXYSQL31`, `client_cert_present`, `client_cert_verify_result`, and `frontend_authenticated_via_spiffe` are initialized exactly once per `MySQL_Data_Stream`.
  - Without `PROXYSQL31`, those three fields are not present in the class definition and no stable object file references them.
  - No OpenSSL/X509 pointer is retained; only scalar status and the existing duplicated URI string survive the handshake.
  - `GENERAL_NAMES` is freed only when non-null and `X509` is freed on every certificate branch.
  - `MySQL_Session::reset()` does not clear physical TLS evidence.
  - The destructor needs no new cleanup for scalar fields.

- [ ] **Step 3: Search for stale helpers, unsafe parsing, and accidental renegotiation.**

  ```sh
  rg -n "user_attributes_has_spiffe|SSL_renegotiate|SSL_verify_client_post_handshake" \
    include lib src
  rg -n 'require_x509.*get<|spiffe_id.*get<' lib/MySQL_Protocol.cpp
  rg -n -C 4 'PROXYSQL31|require_x509|client_cert_present|frontend_authenticated_via_spiffe' \
    include/MySQL_Data_Stream.h include/MySQL_Protocol.h \
    lib/mysql_data_stream.cpp lib/MySQL_Protocol.cpp lib/MySQL_Authentication.cpp
  ```

  Expected: no renegotiation call exists. `user_attributes_has_spiffe()` exists only in the stable `#ifndef PROXYSQL31` branch. Any remaining JSON `get<>` is guarded by an `is_boolean()`/`is_string()` check and an exception boundary.

- [ ] **Step 4: Clean-build and test the stable v3.0 tier.**

  ```sh
  make clean
  make -j4 debug
  ./src/proxysql --version
  make -C test/tap/tests \
    test_frontend_x509_tier_gate-t \
    test_auth_methods-t \
    reg_test_3504-change_user-t \
    reg_test_4556-ssl_error_queue-t

  INFRA_ID=x509-final-stable TAP_GROUP=mysql84-g6 \
    test/infra/control/start-proxysql-isolated.bash
  INFRA_ID=x509-final-stable TAP_GROUP=mysql84-g6 \
    test/infra/control/ensure-infras.bash
  WORKSPACE=$(pwd) INFRA_ID=x509-final-stable TAP_GROUP=mysql84-g6 \
    TEST_PY_TAP_INCL='^(test_frontend_x509_tier_gate-t|reg_test_3504-change_user-t)$' \
    test/infra/control/run-tests-isolated.bash
  INFRA_ID=x509-final-stable TAP_GROUP=mysql84-g2 \
    test/infra/control/ensure-infras.bash
  WORKSPACE=$(pwd) INFRA_ID=x509-final-stable TAP_GROUP=mysql84-g2 \
    TEST_PY_TAP_INCL='^reg_test_4556-ssl_error_queue-t$' \
    test/infra/control/run-tests-isolated.bash
  INFRA_ID=x509-final-stable TAP_GROUP=mysql84-g7 \
    test/infra/control/ensure-infras.bash
  WORKSPACE=$(pwd) INFRA_ID=x509-final-stable TAP_GROUP=mysql84-g7 \
    TEST_PY_TAP_INCL='^test_auth_methods-t$' \
    test/infra/control/run-tests-isolated.bash
  ```

  Expected version prefix: `3.0`. Run the compatibility, ordinary-authentication, change-user, and TLS regression binaries against the stable isolated runtime. The tier-gate test must show that a correct-password plaintext login succeeds even though the row carries `{"require_x509":true}`. The feature test is excluded from stable groups by `@proxysql_min_version:3.1`.

- [ ] **Step 5: Clean-build the Innovative tier and run the complete focused TAP matrix.**

  ```sh
  make clean
  PROXYSQL31=1 make -j4 debug
  ./src/proxysql --version
  make -C test/tap/tests \
    test_frontend_x509_auth-t \
    test_frontend_x509_tier_gate-t \
    test_frontend_x509_passthrough-t \
    test_auth_methods-t \
    reg_test_3504-change_user-t \
    reg_test_4556-ssl_error_queue-t \
    test_passthrough_auth_e2e-t \
    test_passthrough_auth_security-t \
    test_passthrough_auth_unknown_user-t

  INFRA_ID=x509-final-31 TAP_GROUP=mysql84-g6 \
    test/infra/control/start-proxysql-isolated.bash
  INFRA_ID=x509-final-31 TAP_GROUP=mysql84-g6 \
    test/infra/control/ensure-infras.bash
  WORKSPACE=$(pwd) INFRA_ID=x509-final-31 TAP_GROUP=mysql84-g6 \
    TEST_PY_TAP_INCL='^(test_frontend_x509_auth-t|test_frontend_x509_tier_gate-t|reg_test_3504-change_user-t)$' \
    test/infra/control/run-tests-isolated.bash
  INFRA_ID=x509-final-31 TAP_GROUP=mysql84-g4 \
    test/infra/control/ensure-infras.bash
  WORKSPACE=$(pwd) INFRA_ID=x509-final-31 TAP_GROUP=mysql84-g4 \
    TEST_PY_TAP_INCL='^(test_frontend_x509_passthrough-t|test_passthrough_auth_e2e-t|test_passthrough_auth_security-t|test_passthrough_auth_unknown_user-t)$' \
    test/infra/control/run-tests-isolated.bash
  INFRA_ID=x509-final-31 TAP_GROUP=mysql84-g2 \
    test/infra/control/ensure-infras.bash
  WORKSPACE=$(pwd) INFRA_ID=x509-final-31 TAP_GROUP=mysql84-g2 \
    TEST_PY_TAP_INCL='^reg_test_4556-ssl_error_queue-t$' \
    test/infra/control/run-tests-isolated.bash
  INFRA_ID=x509-final-31 TAP_GROUP=mysql84-g7 \
    test/infra/control/ensure-infras.bash
  WORKSPACE=$(pwd) INFRA_ID=x509-final-31 TAP_GROUP=mysql84-g7 \
    TEST_PY_TAP_INCL='^test_auth_methods-t$' \
    test/infra/control/run-tests-isolated.bash
  ```

  Expected version prefix: `3.1`. Every TAP plan completes with zero failed assertions. The tier-gate test must now return 1045 for the same plaintext account. Record any environment-based certificate skips explicitly; CI's standard auto-generated CA must execute, not skip, the trusted-certificate and SPIFFE cases.

  Confirm the v4 inheritance mechanically without creating a second X.509 gate:

  ```sh
  make PROXYSQL40=1 \
    --eval='print-proxysql31: ; @printf "%s\n" "$(PROXYSQL31)"' \
    print-proxysql31
  ```

  Expected output: `1`.

- [ ] **Step 6: Run static diff hygiene checks.**

  ```sh
  git diff --check
  git status --short
  git diff --stat
  git diff -- include/MySQL_Data_Stream.h include/MySQL_Protocol.h \
    lib/mysql_data_stream.cpp lib/MySQL_Protocol.cpp \
    lib/MySQL_Authentication.cpp lib/MySQL_Session.cpp
  ```

  Review specifically for accidental password/certificate logging, non-generic client errors, unrelated formatting churn, and modifications to the TLS callback that would make certificates globally mandatory.

- [ ] **Step 7: Commit any verification-only corrections.**

  If verification required a scoped fix, rerun its failing test first, then the focused matrix, and commit only that correction:

  ```sh
  git add include/MySQL_Data_Stream.h include/MySQL_Protocol.h \
    lib/mysql_data_stream.cpp lib/MySQL_Protocol.cpp \
    lib/MySQL_Authentication.cpp lib/MySQL_Session.cpp \
    test/tap/tests/test_frontend_x509_auth-t.cpp \
    test/tap/tests/test_frontend_x509_tier_gate-t.cpp \
    test/tap/tests/test_frontend_x509_passthrough-t.cpp \
    test/tap/groups/groups.json \
    doc/frontend_x509_authentication.md \
    doc/internal/passthrough_authentication.md
  git commit -m "test: tighten frontend X.509 regressions"
  ```

  If no correction was needed, do not create an empty commit.

---

## Acceptance Matrix

Except for the explicit stable-tier rows, every `require_x509` result and every new SPIFFE/`COM_CHANGE_USER` restriction below applies only when `PROXYSQL31` is defined.

| Flow | Account policy | Connection evidence | Result |
|---|---|---|---|
| Stable v3.0 initial login | row contains `require_x509` | any | Key is unrecognized; existing password/SPIFFE behavior |
| Stable v3.0 `COM_CHANGE_USER` | row contains `require_x509` | any | Existing pre-feature behavior; key is not inspected |
| Initial login | none / `require_x509=false` | plaintext or TLS without cert | Existing password behavior |
| Initial login | `require_x509=true` | plaintext | 1045 |
| Initial login | `require_x509=true` | TLS, no cert | 1045 |
| Initial login | `require_x509=true` | TLS, untrusted cert | 1045 |
| Initial login | `require_x509=true` | TLS, trusted cert, no SAN | Password result decides |
| Initial login | `spiffe_id` | matching trusted URI SAN | Existing SPIFFE success |
| Initial login | `spiffe_id` | missing/mismatching trusted cert | 1045 |
| TLS handshake | client cert carries SPIFFE URI SAN | untrusted cert | Existing TLS-handshake failure |
| `COM_CHANGE_USER` | ordinary → `require_x509=true` | original trusted cert | Target password result decides |
| `COM_CHANGE_USER` | ordinary → `require_x509=true` | no original trusted cert | 1045; reconnect required |
| `COM_CHANGE_USER` | SPIFFE source → any target | any | 1045 |
| `COM_CHANGE_USER` | any source → SPIFFE target | any | 1045 |
| `COM_CHANGE_USER` | any source → pass-through target | any | 1045 |
| Pass-through cold cache | row has `require_x509=true` | no trusted cert | 1045; no cache/probe activity |
| Pass-through cold cache | row has `require_x509=true` | trusted cert | Backend probe decides |
| Pass-through warm cache | row has `require_x509=true` | no trusted cert | 1045; no cache hit |
| Pass-through warm cache | row has `require_x509=true` | trusted cert | Cached password verification decides |
| Pass-through classification | row has `spiffe_id` and empty password | matching SPIFFE cert | SPIFFE path; no cache/probe |
| `COM_CHANGE_USER` | pass-through source → ordinary target | target credentials/policy pass | Success |
| Unknown-user pass-through | no row/attributes | TLS according to global gate | Existing behavior unchanged |
