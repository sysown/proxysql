# Client-Pinned caching_sha2_password RSA Authentication Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Allow non-TLS Oracle MySQL clients using `--server-public-key-path` to complete `caching_sha2_password` RSA full authentication without changing Stable 3.0 behavior.

**Architecture:** Capture the existing immutable RSA key snapshot when ProxySQL emits the `0x04` full-authentication challenge. Route both the stage-6 requested-key ciphertext and the stage-5 direct ciphertext through one guarded `MySQL_Protocol` decryption helper, then reuse the existing stage-5 password and pass-through verification paths.

**Tech Stack:** C++17, OpenSSL EVP RSA-OAEP, ProxySQL MySQL frontend protocol, TAP, Oracle MySQL CLI, GNU Make, isolated Docker TAP harness.

## Global Constraints

- Every new product declaration, field access, branch, and diagnostic is compiled only under `PROXYSQL31`.
- ProxySQL 3.0 Stable must not expose or execute the direct-ciphertext path.
- ProxySQL 3.1 must support both `--get-server-public-key` and `--server-public-key-path`.
- ProxySQL 4.0 must support both paths because `PROXYSQL40=1` implies `PROXYSQL31=1`.
- Non-TLS cleartext `caching_sha2_password` responses remain forbidden.
- Retain one immutable RSA snapshot from the `0x04` challenge through ciphertext decryption.
- Recovered cleartext and ciphertext must never be logged or exposed through internal-session output.
- Use the existing RSA key manager, key formats, variables, OAEP implementation, and error mapping; do not add configuration surface.
- Modify only the approved protocol header/source, existing #5988 TAP, RSA documentation, and design/plan documents.
- Use `make clean` before every tier switch and pass the same tier flag to every make in that build sequence.
- Use `run-tests-isolated.bash`; do not create, start, restart, or reconfigure Docker containers manually.
- Incorporate upstream changes with rebase, never merge.

---

### Task 1: Add the direct-ciphertext regression and prove RED

**Files:**
- Modify: `test/tap/tests/reg_test_5988-caching_sha2_rsa-t.cpp`

**Interfaces:**
- Consumes: the existing generated key pair beneath `REGULAR_INFRA_DATADIR` and `run_mysql_cli()` fixture.
- Produces: `enum class ServerPublicKeyMode` and a 13-assertion E2E matrix covering the pinned-key CLI path.

- [ ] **Step 1: Establish the unchanged Innovative baseline**

Run a clean 3.1 DEBUG build and the unmodified #5988 test:

```bash
make clean
PROXYSQL31=1 make -j4 debug
PROXYSQL31=1 make -C test/tap/tests reg_test_5988-caching_sha2_rsa-t
WORKSPACE=$(pwd) INFRA_ID=caching-sha2-pinned-baseline TAP_GROUP=no-infra-g1 \
  test/infra/control/ensure-infras.bash
WORKSPACE=$(pwd) INFRA_ID=caching-sha2-pinned-baseline TAP_GROUP=no-infra-g1 \
  TEST_PY_TAP_INCL='^reg_test_5988-caching_sha2_rsa-t$' \
  test/infra/control/run-tests-isolated.bash
```

Expected: ProxySQL reports a 3.1 DEBUG version and the existing TAP completes
`1..11` with 11 `ok` assertions and RC 0.

- [ ] **Step 2: Replace the Boolean CLI switch with an explicit key mode**

Add the enum immediately before `run_mysql_cli()`:

```cpp
enum class ServerPublicKeyMode {
	NONE,
	REQUEST,
	PATH
};
```

Change the helper signature to accept both the mode and a pinned-key path:

```cpp
static int run_mysql_cli(
	const CommandLine& cl,
	const string& username,
	const string& password,
	ServerPublicKeyMode public_key_mode,
	const string& public_key_path,
	const string& query,
	string& output
)
```

Build the arguments without shell interpolation:

```cpp
const string server_public_key_path_arg =
	"--server-public-key-path=" + public_key_path;
if (public_key_mode == ServerPublicKeyMode::REQUEST) {
	args.push_back("--get-server-public-key");
} else if (public_key_mode == ServerPublicKeyMode::PATH) {
	args.push_back(server_public_key_path_arg.c_str());
}
```

Update every existing call to pass `ServerPublicKeyMode::NONE` or
`ServerPublicKeyMode::REQUEST` and an empty path.

- [ ] **Step 3: Extend capability checks and TAP accounting**

Change the plan to `plan(13)`. Require both CLI options:

```cpp
if (help_rc != 0 ||
	mysql_help.find("get-server-public-key") == string::npos ||
	mysql_help.find("server-public-key-path") == string::npos ||
	mysql_help.find("ssl-mode") == string::npos) {
	skip(13, "Oracle MySQL CLI with RSA public-key options and --ssl-mode is unavailable");
	return exit_status();
}
```

Adjust early skip counts to preserve the plan:

- missing `REGULAR_INFRA_DATADIR`:
  `skip(13, "REGULAR_INFRA_DATADIR is required to clean generated RSA key artifacts")`;
- failed Admin connection after assertion 1:
  `skip(12, "Cannot continue without an Admin connection")`;
- failed setup after assertion 2:
  `skip(10, "Cannot run authentication assertions after setup failure")`.

- [ ] **Step 4: Add pinned-key success and wrong-password assertions**

After the fixture re-enables and loads the generated RSA pair, construct the
shared absolute public-key path:

```cpp
const string pinned_public_key_path = test_key_directory + test_public_key;
```

Add these assertions before the existing internal-session redaction check:

```cpp
output.clear();
const int pinned_key_rc = enabled_ok ? run_mysql_cli(
	cl, username, password, ServerPublicKeyMode::PATH,
	pinned_public_key_path, "SELECT 5988", output
) : -1;
ok(enabled_ok && pinned_key_rc == 0,
	"Non-TLS caching_sha2_password authentication succeeds with --server-public-key-path");

output.clear();
const int pinned_wrong_password_rc = enabled_ok ? run_mysql_cli(
	cl, username, wrong_password, ServerPublicKeyMode::PATH,
	pinned_public_key_path, "SELECT 5988", output
) : 0;
ok(enabled_ok && pinned_wrong_password_rc != 0 &&
	output.find("ERROR 1045") != string::npos,
	"Pinned RSA full authentication rejects an incorrect password with 1045");
```

- [ ] **Step 5: Run TAP static analysis and compile the changed test**

```bash
make lint-tests FILES=test/tap/tests/reg_test_5988-caching_sha2_rsa-t.cpp
PROXYSQL31=1 make -C test/tap/tests reg_test_5988-caching_sha2_rsa-t
```

Expected: TAP lint prints `OK (1 files)` and the test binary links.

- [ ] **Step 6: Run the changed test and verify the intended RED**

Reuse the baseline runtime because production has not changed:

```bash
WORKSPACE=$(pwd) INFRA_ID=caching-sha2-pinned-baseline TAP_GROUP=no-infra-g1 \
  TEST_PY_TAP_INCL='^reg_test_5988-caching_sha2_rsa-t$' \
  test/infra/control/run-tests-isolated.bash
```

Expected: setup and the existing RSA exchange pass, while
`Non-TLS caching_sha2_password authentication succeeds with --server-public-key-path`
is `not ok` because the direct ciphertext is rejected in stage 5. The test
returns non-zero for the missing production behavior, not for a fixture,
compiler, or CLI-option error.

- [ ] **Step 7: Commit the RED regression**

```bash
git add test/tap/tests/reg_test_5988-caching_sha2_rsa-t.cpp
git diff --cached --check
git commit -m "test: cover client-pinned caching SHA-2 RSA auth"
```

---

### Task 2: Capture the challenge snapshot and share RSA decryption

**Files:**
- Modify: `include/MySQL_Protocol.h`
- Modify: `lib/MySQL_Protocol.cpp`

**Interfaces:**
- Consumes: `MySQL_Caching_Sha2_RSA::acquire()`, `decrypt_password()`, `MyProt_tmp_auth_vars`, and the existing `caching_sha2_rsa_snapshot_` field.
- Produces: guarded `capture_caching_sha2_rsa_snapshot()` and `PPHR_decrypt_caching_sha2_rsa_response()` member helpers.

- [ ] **Step 1: Declare guarded internal helpers**

Inside the existing `#ifdef PROXYSQL31` block near
`generate_auth_more_data()`, add private declarations and restore public access
after them:

```cpp
private:
	/** @brief Retain the active RSA snapshot for a non-TLS full-auth exchange. */
	void capture_caching_sha2_rsa_snapshot();
	/**
	 * @brief Decrypt one exact-size RSA response and prepare stage-5 verification.
	 * @return The existing PPHR status: 2 on decrypted input, 1 on rejection.
	 */
	int PPHR_decrypt_caching_sha2_rsa_response(
		unsigned char* pkt,
		unsigned int len,
		bool& ret,
		MyProt_tmp_auth_vars& vars1
	);
public:
```

Keep the declarations inside `#ifdef PROXYSQL31`; Stable must not contain them.

- [ ] **Step 2: Extract the existing stage-6 decryption body**

Move the current stage-6 validation/decryption/allocation logic from
`PPHR_1()` into `PPHR_decrypt_caching_sha2_rsa_response()`. Preserve these
properties exactly:

```cpp
const auto key_snapshot = caching_sha2_rsa_snapshot_;
caching_sha2_rsa_snapshot_.reset();
const size_t ciphertext_length =
	len >= sizeof(mysql_hdr) ? len - sizeof(mysql_hdr) : 0;
```

The helper must:

1. set `auth_in_progress=0`, `ret=false`, and the current username;
2. reject a null snapshot or a length unequal to `ciphertext_size()`;
3. call the existing `decrypt_password()` with the retained snapshot and
   connection scramble;
4. use `ScopedStringCleanser` for temporary cleartext;
5. allocate/copy one NUL-terminated sensitive password buffer;
6. fill `pass_len`, `pass`, `pass_is_sensitive`, `db`, `charset`, and
   `capabilities`;
7. restore `auth_plugin_id` from `switching_auth_type` and stage 5; and
8. return 2 on success or 1 on rejection.

The stage-6 branch at the top of `PPHR_1()` becomes:

```cpp
#ifdef PROXYSQL31
	if ((*myds)->switching_auth_stage == 6) {
		return PPHR_decrypt_caching_sha2_rsa_response(pkt, len, ret, vars1);
	}
#endif
```

- [ ] **Step 3: Capture the snapshot at both active challenge producers**

Implement the capture helper without logging key material:

```cpp
void MySQL_Protocol::capture_caching_sha2_rsa_snapshot() {
	caching_sha2_rsa_snapshot_.reset();
	if (!(*myds)->encrypted && GloMTH != nullptr &&
		GloMTH->caching_sha2_rsa() != nullptr) {
		caching_sha2_rsa_snapshot_ = GloMTH->caching_sha2_rsa()->acquire();
	}
}
```

Call the helper under `#ifdef PROXYSQL31` immediately before
`generate_one_byte_pkt(0x04)` in both `PPHR_sha2full()` and
`PPHR_passthrough_init()`. If packet generation fails, reset the retained
snapshot before returning; only a successfully queued challenge may publish
stage 4/auth-in-progress state:

```cpp
#ifdef PROXYSQL31
	capture_caching_sha2_rsa_snapshot();
#endif
	if (!generate_one_byte_pkt(perform_full_authentication)) {
#ifdef PROXYSQL31
		caching_sha2_rsa_snapshot_.reset();
#endif
		return;
	}
```

- [ ] **Step 4: Reuse the retained snapshot for the `0x02` request path**

Remove the request-time `acquire()` assignment from the existing `0x02`
branch. Keep the existing null check, public-key packet allocation, stage-6
transition, error mapping, and diagnostics. The public key must come from the
snapshot retained at the preceding `0x04` challenge.

- [ ] **Step 5: Dispatch direct stage-5 ciphertext only in Innovative tiers**

Keep the outer non-TLS caching-SHA2 stage-5 condition so Stable sees the same
guard. Split its body by tier:

```cpp
if (auth_plugin_id == AUTH_MYSQL_CACHING_SHA2_PASSWORD &&
	(*myds)->switching_auth_stage == 5 && !(*myds)->encrypted) {
#ifdef PROXYSQL31
	if (caching_sha2_rsa_snapshot_ == nullptr) {
		frontend_auth_error_ = MySQLFrontendAuthError::CACHING_SHA2_RSA_UNAVAILABLE;
	}
	return PPHR_decrypt_caching_sha2_rsa_response(pkt, len, ret, vars1);
#else
	ret = false;
	vars1.user = (unsigned char *)(*myds)->myconn->userinfo->username;
	proxy_debug(PROXY_DEBUG_MYSQL_AUTH, 5,
		"Session=%p , DS=%p , user='%s' . Rejected cleartext caching_sha2_password response without TLS\n",
		(*myds)->sess, (*myds), vars1.user);
	return 1;
#endif
}
```

The exact-size check inside the helper is the discriminator between valid RSA
ciphertext and every malformed or cleartext response. The one-byte `0x02`
branch remains earlier in `PPHR_1()` and therefore never reaches this dispatch.

- [ ] **Step 6: Compile the Innovative product and focused TAP**

```bash
PROXYSQL31=1 make -j4 debug
PROXYSQL31=1 make -C test/tap/tests reg_test_5988-caching_sha2_rsa-t
```

Expected: both commands exit 0 with `-DDEBUG -DPROXYSQL31` in changed-source
compiler commands.

- [ ] **Step 7: Restart only the isolated ProxySQL and verify GREEN**

```bash
WORKSPACE=$(pwd) INFRA_ID=caching-sha2-pinned-baseline TAP_GROUP=no-infra-g1 \
  test/infra/control/start-proxysql-isolated.bash
WORKSPACE=$(pwd) INFRA_ID=caching-sha2-pinned-baseline TAP_GROUP=no-infra-g1 \
  TEST_PY_TAP_INCL='^reg_test_5988-caching_sha2_rsa-t$' \
  test/infra/control/run-tests-isolated.bash
```

Expected: TAP `1..13`, all 13 assertions `ok`, RC 0. Both CLI forms execute;
the pinned wrong-password case reports `ERROR 1045`.

- [ ] **Step 8: Build and run focused unit regressions**

```bash
PROXYSQL31=1 make -C test/tap/tests/unit caching_sha2_rsa_unit-t protocol_unit-t
WORKSPACE=$(pwd) INFRA_ID=caching-sha2-pinned-unit TAP_GROUP=unit-tests-g1 \
  test/infra/control/ensure-infras.bash
WORKSPACE=$(pwd) INFRA_ID=caching-sha2-pinned-unit TAP_GROUP=unit-tests-g1 \
  TEST_PY_TAP_INCL='^(caching_sha2_rsa_unit|protocol_unit)-t$' \
  test/infra/control/run-tests-isolated.bash
```

Expected: both unit TAPs pass without skipped or `not ok` assertions.

- [ ] **Step 9: Commit the minimal product implementation**

```bash
git add include/MySQL_Protocol.h lib/MySQL_Protocol.cpp
git diff --cached --check
git commit -m "feat(auth): support client-pinned caching SHA-2 RSA auth"
```

---

### Task 3: Document both client modes and verify all tiers

**Files:**
- Modify: `doc/caching_sha2_password_rsa.md`

**Interfaces:**
- Consumes: the final protocol behavior and existing RSA operator documentation.
- Produces: explicit CLI examples and key-rotation guidance for requested and pinned keys.

- [ ] **Step 1: Document the requested-key and pinned-key CLI forms**

Retain the current `--get-server-public-key` example and add:

```bash
mysql --default-auth=caching_sha2_password \
  --ssl-mode=DISABLED \
  --server-public-key-path=/secure/config/proxysql-caching-sha2-public-key.pem \
  --host=127.0.0.1 --port=6033 --user=app --password
```

State that requested-key clients receive the active key during each exchange,
whereas pinned-key clients skip `0x02` and immediately send ciphertext. Explain
that operators must securely distribute a matching public key and coordinate
client updates with ProxySQL key rotation. Preserve the TLS recommendation and
clarify that RSA protects only the password exchange, not session integrity.

- [ ] **Step 2: Commit the documentation**

```bash
git add doc/caching_sha2_password_rsa.md
git diff --cached --check
git commit -m "docs: describe client-pinned caching SHA-2 RSA auth"
```

- [ ] **Step 3: Run focused source and TAP lint**

Generate a 3.1 compile database from clean objects, then inspect normalized
diagnostics for the changed product files:

```bash
make clean
PROXYSQL31=1 ./scripts/lint/generate-compile-commands.sh \
  "make PROXYSQL31=1 build_src -j4"
./scripts/lint/run-local.sh lib/MySQL_Protocol.cpp
! rg -n '(^|/)(MySQL_Protocol\.cpp|MySQL_Protocol\.h)' \
  lint/clang-tidy.txt lint/cppcheck.txt
make lint-tests FILES=test/tap/tests/reg_test_5988-caching_sha2_rsa-t.cpp
python3 test/tap/groups/lint_groups_json.py
python3 test/tap/groups/lint_group_coverage.py
git diff --check
```

Expected: no changed-file source diagnostics, TAP lint `OK (1 files)`, both
group linters exit 0, and no whitespace errors.

- [ ] **Step 4: Run the final Innovative 3.1 matrix from a clean build**

```bash
make clean
PROXYSQL31=1 make -j4 debug
PROXYSQL31=1 make -j4 build_tap_test_debug
```

Confirm `src/proxysql --version` reports 3.1 and run these isolated selections:

```bash
WORKSPACE=$(pwd) INFRA_ID=caching-sha2-pinned-final-31-rsa TAP_GROUP=no-infra-g1 \
  test/infra/control/ensure-infras.bash
WORKSPACE=$(pwd) INFRA_ID=caching-sha2-pinned-final-31-rsa TAP_GROUP=no-infra-g1 \
  TEST_PY_TAP_INCL='^reg_test_5988-caching_sha2_rsa-t$' \
  test/infra/control/run-tests-isolated.bash

WORKSPACE=$(pwd) INFRA_ID=caching-sha2-pinned-final-31-g4 TAP_GROUP=mysql84-g4 \
  test/infra/control/ensure-infras.bash
WORKSPACE=$(pwd) INFRA_ID=caching-sha2-pinned-final-31-g4 TAP_GROUP=mysql84-g4 \
  TEST_PY_TAP_INCL='^(test_frontend_x509_passthrough|test_passthrough_auth_e2e|test_passthrough_auth_security|test_passthrough_auth_unknown_user)-t$' \
  test/infra/control/run-tests-isolated.bash

WORKSPACE=$(pwd) INFRA_ID=caching-sha2-pinned-final-31-g6 TAP_GROUP=mysql84-g6 \
  test/infra/control/ensure-infras.bash
WORKSPACE=$(pwd) INFRA_ID=caching-sha2-pinned-final-31-g6 TAP_GROUP=mysql84-g6 \
  TEST_PY_TAP_INCL='^(reg_test_3504-change_user|test_frontend_x509_auth)-t$' \
  test/infra/control/run-tests-isolated.bash

WORKSPACE=$(pwd) INFRA_ID=caching-sha2-pinned-final-31-g7 TAP_GROUP=mysql84-g7 \
  test/infra/control/ensure-infras.bash
WORKSPACE=$(pwd) INFRA_ID=caching-sha2-pinned-final-31-g7 TAP_GROUP=mysql84-g7 \
  TEST_PY_TAP_INCL='^test_auth_methods-t$' \
  test/infra/control/run-tests-isolated.bash
```

Expected: #5988 is 13/13; all selected pass-through, X.509, change-user, and
authentication TAPs return RC 0 with no in-test skips or `not ok` lines.

- [ ] **Step 5: Prove Stable 3.0 exclusion and regressions**

```bash
make clean
make -j4 debug
make -j4 build_tap_test_debug
src/proxysql --version
```

Expected: version 3.0, compiler commands omit `-DPROXYSQL31`, and the build
succeeds. Scan the changed production objects:

```bash
! strings lib/obj/MySQL_Protocol.oo | rg \
  'capture_caching_sha2_rsa_snapshot|PPHR_decrypt_caching_sha2_rsa_response|server-public-key-path'
```

Run Stable regressions:

```bash
WORKSPACE=$(pwd) INFRA_ID=caching-sha2-pinned-final-stable-g6 TAP_GROUP=mysql84-g6 \
  test/infra/control/ensure-infras.bash
WORKSPACE=$(pwd) INFRA_ID=caching-sha2-pinned-final-stable-g6 TAP_GROUP=mysql84-g6 \
  TEST_PY_TAP_INCL='^(reg_test_3504-change_user|test_frontend_x509_tier_gate)-t$' \
  test/infra/control/run-tests-isolated.bash

WORKSPACE=$(pwd) INFRA_ID=caching-sha2-pinned-final-stable-g7 TAP_GROUP=mysql84-g7 \
  test/infra/control/ensure-infras.bash
WORKSPACE=$(pwd) INFRA_ID=caching-sha2-pinned-final-stable-g7 TAP_GROUP=mysql84-g7 \
  TEST_PY_TAP_INCL='^test_auth_methods-t$' \
  test/infra/control/run-tests-isolated.bash
```

Expected: Stable change-user, tier-gate, and authentication TAPs all return RC
0; the tier gate confirms 3.0 behavior, and #5988 remains excluded by its
minimum-version registration.

- [ ] **Step 6: Prove 4.0 inheritance with a clean build and runtime**

```bash
make clean
PROXYSQL40=1 make -j4 debug
PROXYSQL40=1 make -C test/tap/tests reg_test_5988-caching_sha2_rsa-t
src/proxysql --version
```

Expected: version 4.0 and compiler commands include both `-DPROXYSQL40` and
`-DPROXYSQL31`.

```bash
WORKSPACE=$(pwd) INFRA_ID=caching-sha2-pinned-final-40 TAP_GROUP=no-infra-g1 \
  test/infra/control/ensure-infras.bash
WORKSPACE=$(pwd) INFRA_ID=caching-sha2-pinned-final-40 TAP_GROUP=no-infra-g1 \
  TEST_PY_TAP_INCL='^reg_test_5988-caching_sha2_rsa-t$' \
  test/infra/control/run-tests-isolated.bash
```

Expected: #5988 is 13/13 under the 4.0 binary, including both RSA client modes.

- [ ] **Step 7: Perform final hygiene and tear down only task runtimes**

Call the supported stop script for every task runtime; do not touch unrelated
containers:

```bash
WORKSPACE=$(pwd) INFRA_ID=caching-sha2-pinned-baseline TAP_GROUP=no-infra-g1 \
  test/infra/control/stop-proxysql-isolated.bash
WORKSPACE=$(pwd) INFRA_ID=caching-sha2-pinned-final-31-rsa TAP_GROUP=no-infra-g1 \
  test/infra/control/stop-proxysql-isolated.bash
WORKSPACE=$(pwd) INFRA_ID=caching-sha2-pinned-final-31-g4 TAP_GROUP=mysql84-g4 \
  test/infra/control/stop-proxysql-isolated.bash
WORKSPACE=$(pwd) INFRA_ID=caching-sha2-pinned-final-31-g6 TAP_GROUP=mysql84-g6 \
  test/infra/control/stop-proxysql-isolated.bash
WORKSPACE=$(pwd) INFRA_ID=caching-sha2-pinned-final-31-g7 TAP_GROUP=mysql84-g7 \
  test/infra/control/stop-proxysql-isolated.bash
WORKSPACE=$(pwd) INFRA_ID=caching-sha2-pinned-final-stable-g6 TAP_GROUP=mysql84-g6 \
  test/infra/control/stop-proxysql-isolated.bash
WORKSPACE=$(pwd) INFRA_ID=caching-sha2-pinned-final-stable-g7 TAP_GROUP=mysql84-g7 \
  test/infra/control/stop-proxysql-isolated.bash
WORKSPACE=$(pwd) INFRA_ID=caching-sha2-pinned-final-40 TAP_GROUP=no-infra-g1 \
  test/infra/control/stop-proxysql-isolated.bash
```

Then verify repository state:

```bash
git diff --check
git diff HEAD~3 --check
git status --short
git log --oneline --decorate origin/v3.0..HEAD
git diff --stat origin/v3.0...HEAD
```

Expected: no tracked or untracked build/report artifacts, no whitespace errors,
no merge commits, and only the approved source, test, documentation, design,
and plan files differ from `origin/v3.0`.
