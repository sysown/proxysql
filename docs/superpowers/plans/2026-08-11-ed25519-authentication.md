# MariaDB ed25519 Authentication Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

> **Historical artifact.** This plan reflects plan-time expectations; review-driven
> fix rounds amended the implementation afterwards (e.g. the unit test grew from 19
> to a larger assertion count, the e2e test from 10, and the nonce moved to a
> dedicated `ed25519_nonce` member). The shipped code and tests are authoritative;
> embedded expected outputs here are not updated retroactively.

**Goal:** Support MariaDB's ed25519 authentication (`client_ed25519`) for frontend client connections (v3.1+ tier) and backend connections (all tiers, via the connector), per the approved spec `docs/superpowers/specs/2026-08-11-ed25519-authentication-design.md`.

**Architecture:** The vendored MariaDB Connector/C's `client_ed25519` plugin is flipped from DYNAMIC to STATIC, which (a) gives backend connections ed25519 transparently and (b) puts the ref10 crypto symbols (`crypto_sign_keypair`, `crypto_sign_open`) into `libmariadbclient.a` where a thin new wrapper (`lib/MySQL_Ed25519.cpp`) calls them. Frontend auth always runs through an Auth Switch carrying a fresh 32-byte nonce; the client answers with a 64-byte signature verified against a stored `$ED$<base64>` public key or a key derived from a stored cleartext password.

**Tech Stack:** C++17, ref10 Ed25519 (from `deps/`, via `libmariadbclient.a`), OpenSSL (`RAND_bytes`, `EVP_DecodeBlock`), TAP tests, Docker test infra (`mariadb10-galera`).

## Global Constraints

- **Tier**: all frontend code behind `#ifdef PROXYSQLED25519`; `PROXYSQL31=1` implies `PROXYSQLED25519=1` (Makefile cascade, same pattern as `PROXYSQLFFTO`).
- **Every build command in this plan uses the tier flag**: `PROXYSQL31=1 make debug -j$(nproc)`. If the tree was last built without it, run `make clean` first (stale-object tier mismatch, see CLAUDE.md).
- **The binary under TAP test must be a DEBUG build** (`PROXYSQL31=1 make debug`).
- Stored credential formats: cleartext (full function) and `$ED$` + 43-char base64 (frontend-verification-only). Prefix match is case-insensitive; total length exactly 47.
- Wire constants: nonce 32 bytes, signature 64 bytes, public key 32 bytes, plugin name `client_ed25519`.
- All auth failures surface as the standard access-denied (1045) — no client-visible distinction between wrong password / bad signature / malformed stored key.
- No new admin variables.
- Never run `./src/proxysql` directly; use the documented isolated test harness.
- Known-answer vectors (generated from the deps ref10 sources; `"secret"` matches the MariaDB KB documented example, which independently validates compatibility):
  - `"secret"` → `ZIgUREUg5PVgQ6LskhXmO+eZLS0nC8be6HPjYWR4YJY`
  - `"ed25519_pass_1"` → `5TBW79xTAMbhi8QKQtLLVS0V0b2w9mlKnRG6c+2NxTQ`
  - `""` → `4LH+dBF+G5W2CKTyId8xR3SyDqZoQjUNUVNxx8aWbG4`
  - signature of nonce `0x00..0x1f` under `"ed25519_pass_1"`:
    `004a2ab8c18a320bdde27a5fff54ae43f66b4c21373ba3c1852ce0eb9255d073f7b6125fb6ee1a236633da90d0e38b3b58c3295b4ab9eb418402cbfa6f879701`

---

### Task 1: Connector STATIC patch + tier flag plumbing

**Files:**
- Modify: `deps/mariadb-client-library/plugin_auth_CMakeLists.txt.patch`
- Modify: `Makefile` (~lines 63-72, 106-107, 416-430)
- Modify: `lib/Makefile` (~lines 67-74, 86)
- Modify: `src/Makefile` (~lines 86-90, 104)

**Interfaces:**
- Consumes: nothing.
- Produces: `libmariadbclient.a` exports `crypto_sign_keypair(unsigned char *pk, unsigned char *pw, unsigned long long pwlen)`, `crypto_sign_open(unsigned char *sm, unsigned long long smlen, const unsigned char *pk)`, `ma_crypto_sign(...)` — Task 2's wrapper links against them. Make variable `PROXYSQLED25519` and compiler define `-DPROXYSQLED25519` active in `lib/` and `src/` whenever `PROXYSQL31=1`.

- [ ] **Step 1: Add the client_ed25519 hunk to the connector patch**

The pristine `plugins/auth/CMakeLists.txt` (from `mariadb-connector-c-3.3.8-src.tar.gz`) has the `client_ed25519` `REGISTER_PLUGIN` block at lines 55-64 with `DEFAULT DYNAMIC` at line 58. Insert this hunk as the **first** hunk of `deps/mariadb-client-library/plugin_auth_CMakeLists.txt.patch` (hunks must stay in ascending line order; the existing hunks are at 77, 88, 137). Insert after the `+++ plugins/auth/CMakeLists.txt` header line:

```diff
@@ -55,7 +55,7 @@
   REGISTER_PLUGIN(TARGET client_ed25519
                 TYPE MARIADB_CLIENT_PLUGIN_AUTH
                 CONFIGURATIONS DYNAMIC STATIC OFF
-                DEFAULT DYNAMIC
+                DEFAULT STATIC
                 SOURCES ${CC_SOURCE_DIR}/plugins/auth/ed25519.c 
                         ${REF10_SOURCES}
                         ${CRYPT_SOURCE}
```

IMPORTANT: the `SOURCES ...ed25519.c ` context line ends with a **trailing space** — copy it exactly (verify against the pristine file, next step).

- [ ] **Step 2: Validate the patch applies cleanly against the pristine file**

```bash
cd deps/mariadb-client-library
tar -zxf mariadb-connector-c-3.3.8-src.tar.gz -O mariadb-connector-c-3.3.8-src/plugins/auth/CMakeLists.txt > /tmp/cml_pristine.txt
cp /tmp/cml_pristine.txt /tmp/cml_test.txt
patch /tmp/cml_test.txt < plugin_auth_CMakeLists.txt.patch
grep -A4 "TARGET client_ed25519" /tmp/cml_test.txt | grep "DEFAULT STATIC"
```
Expected: `patch` reports 4 hunks applied cleanly, and the grep prints `                DEFAULT STATIC`. If a hunk fails, fix whitespace in the new hunk (do not use `--fuzz`).

- [ ] **Step 3: Top-level Makefile — cascade and export**

In `Makefile`, inside the existing `ifeq ($(PROXYSQL31),1)` cascade block (~line 71, where `PROXYSQLFFTO := 1` is set), add:

```make
    PROXYSQLED25519 := 1
```

Next to `export PROXYSQLFFTO` (~line 107), add:

```make
export PROXYSQLED25519
```

Then update the recursive lib/src build lines: `grep -n 'cd lib &&\|cd src &&' Makefile` (4 lines, ~416, 420, 424, 430) and append `PROXYSQLED25519=$(PROXYSQLED25519)` next to the existing `PROXYSQLTSDB=$(PROXYSQLTSDB)` on each. Do NOT touch the `cd deps` or `cd plugins/*` lines (deps are tier-independent; the connector patch applies unconditionally, which is the accepted spec behavior: backend ed25519 works in all tiers).

Also update the tier documentation comment at ~line 63 to read: `PROXYSQL40=1 implies PROXYSQL31=1 implies PROXYSQLFFTO=1 + PROXYSQLTSDB=1 + PROXYSQLED25519=1`.

- [ ] **Step 4: lib/Makefile and src/Makefile — translate to -D**

In `lib/Makefile` after the `PSQLTSDB` block (~line 70-74):

```make
PSQLED25519 :=
ifeq ($(PROXYSQLED25519),1)
	PSQLED25519 := -DPROXYSQLED25519
endif
```

and append `$(PSQLED25519)` to the `MYCXXFLAGS :=` line (~line 86, after `$(PSQLTSDB)`).

In `src/Makefile`, same block after `PSQLFFTO` (~line 90), and append `$(PSQLED25519)` to the `MYCXXFLAGS +=` line (~line 104).

- [ ] **Step 5: Rebuild the connector and verify the symbols**

```bash
rm deps/mariadb-client-library/mariadb_client/libmariadb/libmariadbclient.a
PROXYSQL31=1 make build_deps_debug
nm deps/mariadb-client-library/mariadb_client/libmariadb/libmariadbclient.a | grep -E " T (crypto_sign_keypair|crypto_sign_open|ma_crypto_sign)$"
```
Expected: the recipe re-extracts the tarball, applies all patches (including the new hunk), rebuilds, and `nm` prints all three `T` symbols. If `nm` prints nothing, the STATIC flip did not take — inspect `deps/mariadb-client-library/mariadb_client/plugins/auth/CMakeLists.txt` for `client_ed25519 ... DEFAULT STATIC`.

- [ ] **Step 6: Full debug build still links**

```bash
PROXYSQL31=1 make debug -j$(nproc)
```
Expected: clean build (no source changes yet — this proves the flag plumbing and the fatter `libmariadbclient.a` don't break the link).

- [ ] **Step 7: Commit**

```bash
git add deps/mariadb-client-library/plugin_auth_CMakeLists.txt.patch Makefile lib/Makefile src/Makefile
git commit -m "build: statically link client_ed25519 connector plugin, add PROXYSQLED25519 tier flag

The connector's client_ed25519 plugin (with the full ref10 Ed25519
implementation) is flipped from DYNAMIC to STATIC in the existing
plugin_auth CMakeLists patch. This transparently enables ed25519
authentication for backend connections (server-driven auth switch,
no ProxySQL code involved) and exports crypto_sign_keypair /
crypto_sign_open from libmariadbclient.a for the upcoming frontend
verification wrapper.

PROXYSQLED25519 is a new feature macro implied by PROXYSQL31,
following the PROXYSQLFFTO cascade pattern. deps are intentionally
NOT tier-gated (single connector build serves all tiers, per spec)."
```

---

### Task 2: MySQL_Ed25519 wrapper + unit test (TDD)

**Files:**
- Create: `include/MySQL_Ed25519.h`
- Create: `lib/MySQL_Ed25519.cpp`
- Create: `test/tap/tests/unit/ed25519_unit-t.cpp`
- Modify: `lib/Makefile` (`_OBJ_CXX` conditional, ~line 124-138)
- Modify: `test/tap/tests/unit/Makefile` (tier probe ~line 277-292, `UNIT_TESTS` registration ~line 434-436, `OPT` line)
- Modify: `test/tap/groups/groups.json`

**Interfaces:**
- Consumes: `crypto_sign_keypair`, `crypto_sign_open` from `libmariadbclient.a` (Task 1).
- Produces (used by Tasks 3-4):
  - `void proxysql_ed25519_derive_public_key(const char *password, size_t password_len, unsigned char *out_pubkey)` — 32-byte key from arbitrary-length cleartext.
  - `bool proxysql_ed25519_verify_signature(const unsigned char *signature, const unsigned char *nonce, const unsigned char *pubkey)` — 64B sig over 32B nonce.
  - `bool proxysql_ed25519_is_pubkey_format(const char *password)` — `$ED$` + 43 base64, length 47, prefix case-insensitive; NULL-safe.
  - `bool proxysql_ed25519_decode_pubkey(const char *stored, unsigned char *out_pubkey)` — false on malformed input.
  - Macros: `ED25519_NONCE_LEN` (32), `ED25519_SIG_LEN` (64), `ED25519_PUBKEY_LEN` (32), `ED25519_PUBKEY_B64_LEN` (43), `ED25519_STORED_PREFIX` (`"$ED$"`), `ED25519_STORED_PREFIX_LEN` (4), `ED25519_STORED_LEN` (47).

- [ ] **Step 1: Write the failing unit test**

Create `test/tap/tests/unit/ed25519_unit-t.cpp`:

```cpp
/**
 * @file ed25519_unit-t.cpp
 * @brief Known-answer and edge-case tests for the MariaDB-variant Ed25519
 *   helpers in lib/MySQL_Ed25519.cpp.
 *
 * The "secret" vector matches the documented example in the MariaDB KB
 * (CREATE USER ... IDENTIFIED VIA ed25519 USING 'ZIgUREUg5...'), which
 * independently validates that the ref10 sources vendored in deps/ implement
 * the same scheme as the auth_ed25519 server plugin.
 */
#include "tap.h"

#include "MySQL_Ed25519.h"

#include <cstring>
#include <cstdio>
#include <string>

#include <openssl/evp.h>

struct derivation_kat { const char* password; const char* pubkey_b64; };

static const derivation_kat KATS[] = {
	{ "secret",         "ZIgUREUg5PVgQ6LskhXmO+eZLS0nC8be6HPjYWR4YJY" },
	{ "ed25519_pass_1", "5TBW79xTAMbhi8QKQtLLVS0V0b2w9mlKnRG6c+2NxTQ" },
	{ "",               "4LH+dBF+G5W2CKTyId8xR3SyDqZoQjUNUVNxx8aWbG4" },
};

// 64-byte signature of nonce 0x00..0x1f under password "ed25519_pass_1",
// generated with the connector's own ma_crypto_sign() (the scheme is
// deterministic, so this vector is stable).
static const char SIG_HEX[] =
	"004a2ab8c18a320bdde27a5fff54ae43f66b4c21373ba3c1852ce0eb9255d073"
	"f7b6125fb6ee1a236633da90d0e38b3b58c3295b4ab9eb418402cbfa6f879701";

static void unhex(const char* hex, unsigned char* out, size_t outlen) {
	for (size_t i = 0; i < outlen; i++) {
		unsigned int b = 0;
		sscanf(hex + 2 * i, "%2x", &b);
		out[i] = static_cast<unsigned char>(b);
	}
}

static std::string b64_no_pad(const unsigned char* in, size_t len) {
	unsigned char out[64] = { 0 };
	EVP_EncodeBlock(out, in, len);
	std::string s(reinterpret_cast<char*>(out));
	while (!s.empty() && s.back() == '=') s.pop_back();
	return s;
}

int main() {
	plan(
		3 /* derivation KATs */ +
		3 /* decode round-trips */ +
		7 /* is_pubkey_format edge cases */ +
		2 /* decode_pubkey malformed */ +
		1 /* signature KAT */ +
		3 /* tampered signature / nonce / key */
	);

	// 1. derivation known-answer tests
	for (const derivation_kat& kat : KATS) {
		unsigned char pk[ED25519_PUBKEY_LEN];
		proxysql_ed25519_derive_public_key(kat.password, strlen(kat.password), pk);
		std::string encoded = b64_no_pad(pk, sizeof(pk));
		ok(encoded == kat.pubkey_b64,
			"derive_public_key('%s') = '%s' (expected '%s')",
			kat.password, encoded.c_str(), kat.pubkey_b64);
	}

	// 2. decode_pubkey round-trips against derivation
	for (const derivation_kat& kat : KATS) {
		unsigned char derived[ED25519_PUBKEY_LEN];
		unsigned char decoded[ED25519_PUBKEY_LEN];
		proxysql_ed25519_derive_public_key(kat.password, strlen(kat.password), derived);
		std::string stored = std::string(ED25519_STORED_PREFIX) + kat.pubkey_b64;
		bool rc = proxysql_ed25519_decode_pubkey(stored.c_str(), decoded);
		ok(rc && memcmp(derived, decoded, ED25519_PUBKEY_LEN) == 0,
			"decode_pubkey('%s') matches derived key", stored.c_str());
	}

	// 3. is_pubkey_format edge cases
	{
		std::string valid = std::string(ED25519_STORED_PREFIX) + KATS[1].pubkey_b64;
		ok(proxysql_ed25519_is_pubkey_format(valid.c_str()) == true, "valid $ED$ string accepted");
		std::string lower = std::string("$ed$") + KATS[1].pubkey_b64;
		ok(proxysql_ed25519_is_pubkey_format(lower.c_str()) == true, "prefix match is case-insensitive");
		ok(proxysql_ed25519_is_pubkey_format(KATS[1].pubkey_b64) == false, "bare 43-char base64 rejected (prefix mandatory)");
		ok(proxysql_ed25519_is_pubkey_format("$ED$tooshort") == false, "wrong length rejected");
		std::string toolong = valid + "X";
		ok(proxysql_ed25519_is_pubkey_format(toolong.c_str()) == false, "48-char string rejected");
		ok(proxysql_ed25519_is_pubkey_format(NULL) == false, "NULL rejected");
		ok(proxysql_ed25519_is_pubkey_format("*THISLOOKSLIKEASHA1HASHXXXXXXXXXXXXXXXXX") == false, "SHA1-format password rejected");
	}

	// 4. decode_pubkey malformed input
	{
		unsigned char pk[ED25519_PUBKEY_LEN];
		// 43 chars but contains characters outside the base64 alphabet
		std::string bad = std::string(ED25519_STORED_PREFIX) + "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!";
		ok(proxysql_ed25519_decode_pubkey(bad.c_str(), pk) == false, "invalid base64 chars rejected");
		ok(proxysql_ed25519_decode_pubkey("not-ed25519-at-all", pk) == false, "non-$ED$ string rejected");
	}

	// 5. signature known-answer test
	unsigned char sig[ED25519_SIG_LEN];
	unsigned char nonce[ED25519_NONCE_LEN];
	unsigned char pk[ED25519_PUBKEY_LEN];
	unhex(SIG_HEX, sig, sizeof(sig));
	for (int i = 0; i < ED25519_NONCE_LEN; i++) nonce[i] = static_cast<unsigned char>(i);
	proxysql_ed25519_derive_public_key("ed25519_pass_1", strlen("ed25519_pass_1"), pk);
	ok(proxysql_ed25519_verify_signature(sig, nonce, pk) == true, "known-answer signature verifies");

	// 6. negative cases
	{
		unsigned char tampered_sig[ED25519_SIG_LEN];
		memcpy(tampered_sig, sig, sizeof(sig));
		tampered_sig[10] ^= 0xff;
		ok(proxysql_ed25519_verify_signature(tampered_sig, nonce, pk) == false, "tampered signature rejected");

		unsigned char wrong_nonce[ED25519_NONCE_LEN];
		memcpy(wrong_nonce, nonce, sizeof(nonce));
		wrong_nonce[0] ^= 0x01;
		ok(proxysql_ed25519_verify_signature(sig, wrong_nonce, pk) == false, "wrong nonce rejected");

		unsigned char wrong_pk[ED25519_PUBKEY_LEN];
		proxysql_ed25519_derive_public_key("some_other_password", strlen("some_other_password"), wrong_pk);
		ok(proxysql_ed25519_verify_signature(sig, nonce, wrong_pk) == false, "wrong public key rejected");
	}

	return exit_status();
}
```

- [ ] **Step 2: Register the unit test in the unit Makefile and groups.json**

In `test/tap/tests/unit/Makefile`:

1. After the `PSQLTSDB` nm-probe block (~line 277-281), add an nm probe (the mangled C++ symbol contains the plain name, so `grep -c` matches):

```make
PSQLED25519 :=
ifneq ($(shell nm $(LIBPROXYSQLAR) 2>/dev/null | grep -c proxysql_ed25519_verify_signature),0)
	PROXYSQLED25519 := 1
	PSQLED25519 := -DPROXYSQLED25519
endif
```

2. Append `$(PSQLED25519)` to the `OPT :=` line (the one already containing `$(PSQL31) $(PSQLFFTO) $(PSQLTSDB)`).

3. Next to the existing `ifeq ($(PROXYSQL31),1) / UNIT_TESTS += caching_sha2_rsa_unit-t / endif` block (~line 434), add:

```make
ifeq ($(PROXYSQLED25519),1)
UNIT_TESTS += ed25519_unit-t
endif
```

In `test/tap/groups/groups.json`, add (keep alphabetical ordering with the surrounding keys):

```json
  "ed25519_unit-t" : [ "unit-tests-g1","@proxysql_min_version:3.1" ],
```

- [ ] **Step 3: Verify the test fails to build (header does not exist yet)**

```bash
cd test/tap/tests/unit && make ed25519_unit-t
```
Expected: FAIL with `MySQL_Ed25519.h: No such file or directory`.

- [ ] **Step 4: Write the header**

Create `include/MySQL_Ed25519.h`:

```cpp
#ifndef __CLASS_MYSQL_ED25519_H
#define __CLASS_MYSQL_ED25519_H
#ifdef PROXYSQLED25519

#include <cstddef>

/**
 * MariaDB-variant Ed25519 helpers for frontend client authentication
 * (the client_ed25519 / auth_ed25519 scheme).
 *
 * MariaDB derives the keypair from SHA512(password) where the password has
 * arbitrary length (standard Ed25519 hashes a fixed 32-byte seed), so the
 * derivation MUST use the ref10 implementation vendored in
 * deps/mariadb-client-library (statically linked into libmariadbclient.a via
 * the client_ed25519 plugin). Signature verification is standard Ed25519.
 *
 * Stored-credential format in mysql_users.password:
 *   "$ED$" + 43-char unpadded base64 of the 32-byte public key
 * (prefix case-insensitive, total length exactly 47). This mirrors MariaDB's
 * mysql.user.authentication_string with an explicit marker so it cannot be
 * confused with a cleartext password.
 */

#define ED25519_NONCE_LEN 32
#define ED25519_SIG_LEN 64
#define ED25519_PUBKEY_LEN 32
#define ED25519_PUBKEY_B64_LEN 43
#define ED25519_STORED_PREFIX "$ED$"
#define ED25519_STORED_PREFIX_LEN 4
#define ED25519_STORED_LEN (ED25519_STORED_PREFIX_LEN + ED25519_PUBKEY_B64_LEN)

/** @brief Derive the 32-byte public key from a cleartext password (MariaDB variant). */
void proxysql_ed25519_derive_public_key(const char* password, size_t password_len, unsigned char* out_pubkey);

/** @brief Verify a 64-byte signature over a 32-byte nonce against a 32-byte public key. */
bool proxysql_ed25519_verify_signature(const unsigned char* signature, const unsigned char* nonce, const unsigned char* pubkey);

/** @brief True when 'password' is a stored ed25519 public key ("$ED$" + 43 base64 chars). NULL-safe. */
bool proxysql_ed25519_is_pubkey_format(const char* password);

/** @brief Decode a "$ED$..." stored credential into a 32-byte public key. False on malformed input. */
bool proxysql_ed25519_decode_pubkey(const char* stored, unsigned char* out_pubkey);

#endif // PROXYSQLED25519
#endif // __CLASS_MYSQL_ED25519_H
```

- [ ] **Step 5: Write the implementation**

Create `lib/MySQL_Ed25519.cpp`:

```cpp
#ifdef PROXYSQLED25519

#include "MySQL_Ed25519.h"

#include <cstring>
#include <strings.h>

#include <openssl/evp.h>

// ref10 entry points compiled into libmariadbclient.a by the STATIC
// client_ed25519 plugin registration (deps/mariadb-client-library).
extern "C" {
int crypto_sign_keypair(unsigned char* pk, unsigned char* pw, unsigned long long pwlen);
int crypto_sign_open(unsigned char* sm, unsigned long long smlen, const unsigned char* pk);
}

void proxysql_ed25519_derive_public_key(const char* password, size_t password_len, unsigned char* out_pubkey) {
	// ref10 takes a non-const pw but never modifies it
	crypto_sign_keypair(out_pubkey, reinterpret_cast<unsigned char*>(const_cast<char*>(password)), password_len);
}

bool proxysql_ed25519_verify_signature(const unsigned char* signature, const unsigned char* nonce, const unsigned char* pubkey) {
	// crypto_sign_open() expects a mutable "signed message" R||S||M and
	// clobbers it during verification, so build a local copy.
	unsigned char sm[ED25519_SIG_LEN + ED25519_NONCE_LEN];
	memcpy(sm, signature, ED25519_SIG_LEN);
	memcpy(sm + ED25519_SIG_LEN, nonce, ED25519_NONCE_LEN);
	return crypto_sign_open(sm, sizeof(sm), pubkey) == 0;
}

bool proxysql_ed25519_is_pubkey_format(const char* password) {
	if (password == NULL) return false;
	if (strncasecmp(password, ED25519_STORED_PREFIX, ED25519_STORED_PREFIX_LEN) != 0) return false;
	return strlen(password) == ED25519_STORED_LEN;
}

bool proxysql_ed25519_decode_pubkey(const char* stored, unsigned char* out_pubkey) {
	if (proxysql_ed25519_is_pubkey_format(stored) == false) return false;
	// 43 base64 chars + '=' forms one complete 44-char group. EVP_DecodeBlock
	// emits 33 bytes for it; the 33rd is padding garbage and is discarded.
	unsigned char in[ED25519_PUBKEY_B64_LEN + 1];
	memcpy(in, stored + ED25519_STORED_PREFIX_LEN, ED25519_PUBKEY_B64_LEN);
	in[ED25519_PUBKEY_B64_LEN] = '=';
	unsigned char out[33];
	if (EVP_DecodeBlock(out, in, sizeof(in)) != 33) return false;
	memcpy(out_pubkey, out, ED25519_PUBKEY_LEN);
	return true;
}

#endif // PROXYSQLED25519
```

- [ ] **Step 6: Register the object in lib/Makefile**

In `lib/Makefile`, next to the existing FFTO conditional (~line 134-136), add:

```make
# ed25519 frontend authentication (MariaDB client_ed25519)
ifeq ($(PROXYSQLED25519),1)
_OBJ_CXX += MySQL_Ed25519.oo
endif
```

- [ ] **Step 7: Rebuild libproxysql and run the unit test**

```bash
PROXYSQL31=1 make debug -j$(nproc)
cd test/tap/tests/unit && make ed25519_unit-t && ./ed25519_unit-t
```
Expected: builds, prints `1..19` and all `ok` lines, exit status 0. In particular the three derivation KATs must pass — if they fail, the wrapper is NOT calling the connector's ref10 (check `nm` from Task 1 Step 5).

- [ ] **Step 8: Commit**

```bash
git add include/MySQL_Ed25519.h lib/MySQL_Ed25519.cpp lib/Makefile \
  test/tap/tests/unit/ed25519_unit-t.cpp test/tap/tests/unit/Makefile test/tap/groups/groups.json
git commit -m "feat: add MariaDB-variant Ed25519 helpers with known-answer unit tests

proxysql_ed25519_{derive_public_key,verify_signature,is_pubkey_format,
decode_pubkey} wrap the ref10 symbols statically linked into
libmariadbclient.a. Key derivation must use ref10 because MariaDB
hashes an arbitrary-length password (SHA512) where standard Ed25519
hashes a fixed 32-byte seed; verification is standard Ed25519.

The 'secret' derivation vector reproduces the documented MariaDB KB
example, independently confirming scheme compatibility."
```

---

### Task 3: Frontend protocol — initial handshake auth switch and verification

**Files:**
- Modify: `include/MySQL_Protocol.h` (enum ~line 36-41; PPHR method declarations next to `PPHR_sha2full`)
- Modify: `lib/MySQL_Protocol.cpp` (plugins[] ~91; `generate_pkt_auth_switch_request` ~1131-1219; `PPHR_1` ~2090; `PPHR_3` ~2315-2341; switch matrix ~3563-3619; new `PPHR_ed25519_switch`/`PPHR_ed25519_verify` near `PPHR_sha2full` ~2916; `PPHR_verify_password` insertions ~3429 and ~3445)
- Modify: `lib/mysql_data_stream.cpp` (auth-plugin JSON dump ~1936-1946)

**Interfaces:**
- Consumes: all `proxysql_ed25519_*` functions and `ED25519_*` macros from Task 2.
- Produces: enum value `AUTH_MYSQL_ED25519` (= 3) in `enum proxysql_auth_plugins`; plugin name string `"client_ed25519"` as `plugins[AUTH_MYSQL_ED25519]`; methods `void MySQL_Protocol::PPHR_ed25519_switch(bool& ret, MyProt_tmp_auth_vars& vars1)` and `void MySQL_Protocol::PPHR_ed25519_verify(bool& ret, MyProt_tmp_auth_vars& vars1)` (Task 4 reuses the same verification flow via the shared state machine).

**Flow being implemented** (mirrors how MariaDB itself works — ed25519 is never advertised in the greeting; it always runs through an Auth Switch):

```text
client HandshakeResponse (any plugin)
  → PPHR_verify_password stage 0: stored "$ED$" OR client asked client_ed25519
  → PPHR_ed25519_switch(): 32-byte RAND_bytes nonce into scramble_buff,
    AuthSwitchRequest "client_ed25519" + nonce, stage=1, auth_in_progress=1
  → client sends 64-byte signature → PPHR_1 (stage 1→2, no NUL-strip)
  → PPHR_verify_password dispatch → PPHR_ed25519_verify()
```

Known v1 limitation (document, do not fix): if ProxySQL already committed a *native* auth switch before the account lookup (client offered `caching_sha2_password` against a native greeting — `PPHR_4auth0` path), a stored-`$ED$` user cannot be verified because the protocol allows only one switch. Standard clients (libmariadb answering the greeting plugin, or explicitly requesting `client_ed25519`) do not hit this.

- [ ] **Step 1: enum + method declarations in include/MySQL_Protocol.h**

Extend the enum at line 36-41:

```cpp
enum proxysql_auth_plugins {
	AUTH_UNKNOWN_PLUGIN = -1,
	AUTH_MYSQL_NATIVE_PASSWORD = 0,
	AUTH_MYSQL_CLEAR_PASSWORD,
	AUTH_MYSQL_CACHING_SHA2_PASSWORD,
#ifdef PROXYSQLED25519
	AUTH_MYSQL_ED25519, // MariaDB client_ed25519 (value 3)
#endif
};
```

Find the `PPHR_sha2full` declaration in the `MySQL_Protocol` class (`grep -n PPHR_sha2full include/MySQL_Protocol.h`) and add next to it:

```cpp
#ifdef PROXYSQLED25519
	void PPHR_ed25519_switch(bool& ret, MyProt_tmp_auth_vars& vars1);
	void PPHR_ed25519_verify(bool& ret, MyProt_tmp_auth_vars& vars1);
#endif
```

- [ ] **Step 2: plugins[] and includes in lib/MySQL_Protocol.cpp**

Replace the array at line 91-95 (drop the explicit `[3]` size):

```cpp
static const char *plugins[] = {
	"mysql_native_password",
	"mysql_clear_password",
	"caching_sha2_password",
#ifdef PROXYSQLED25519
	"client_ed25519",
#endif
};
```

Near the other includes at the top of the file add:

```cpp
#ifdef PROXYSQLED25519
#include "MySQL_Ed25519.h"
#include <openssl/rand.h>
#endif
```

- [ ] **Step 3: generate_pkt_auth_switch_request — ed25519 case**

In the first `switch((*myds)->switching_auth_type)` (length computation, ~line 1148-1171) add before `default:`:

```cpp
#ifdef PROXYSQLED25519
		case AUTH_MYSQL_ED25519:
			myhdr.pkt_length=1 // fe
				+ (strlen(plugins[AUTH_MYSQL_ED25519])+1)
				+ ED25519_NONCE_LEN; // 32-byte nonce; NO trailing 0x00 (client requires exactly 32 bytes of plugin data)
			break;
#endif
```

In the second `switch` (packet body, ~line 1181-1204) add before `default:`:

```cpp
#ifdef PROXYSQLED25519
		case AUTH_MYSQL_ED25519:
			memcpy(_ptr+l,plugins[AUTH_MYSQL_ED25519],strlen(plugins[AUTH_MYSQL_ED25519]));
			l+=strlen(plugins[AUTH_MYSQL_ED25519]);
			_ptr[l]=0x00; l++;
			memcpy(_ptr+l, (*myds)->myconn->scramble_buff, ED25519_NONCE_LEN); l+=ED25519_NONCE_LEN;
			break;
#endif
```

Guard the unconditional trailing NUL at ~line 1205 — for ed25519, `l` already equals the packet size, so the write would land one byte past the buffer:

```cpp
#ifdef PROXYSQLED25519
	if ((*myds)->switching_auth_type != AUTH_MYSQL_ED25519) // ed25519 packet ends exactly after the nonce
#endif
	_ptr[l]=0x00; //l+=1; //0x00
```

- [ ] **Step 4: PPHR_1 — accept the raw 64-byte signature**

At ~line 2090, the native branch takes the payload verbatim while every other plugin requires NUL termination. A 64-byte signature is raw binary (it may legitimately contain `0x00` anywhere), so it must take the native-style branch:

```cpp
	if (auth_plugin_id == AUTH_MYSQL_NATIVE_PASSWORD
#ifdef PROXYSQLED25519
		|| auth_plugin_id == AUTH_MYSQL_ED25519 // raw 64-byte signature, not NUL-terminated
#endif
	) {
		vars1.pass_len = payload_length;
	} else {
```

- [ ] **Step 5: PPHR_3 — recognize the plugin name**

In the name-mapping chain at ~line 2323-2338, add a branch before the closing brace of the chain:

```cpp
#ifdef PROXYSQLED25519
		} else if (strncmp((char *)vars1.auth_plugin,plugins[AUTH_MYSQL_ED25519],strlen(plugins[AUTH_MYSQL_ED25519]))==0) {
			// client explicitly requested client_ed25519; the Auth Switch with a
			// 32-byte nonce is driven later by PPHR_verify_password at stage 0
			auth_plugin_id = AUTH_MYSQL_ED25519;
#endif
		}
```

- [ ] **Step 6: switch matrix — let ed25519 requests through**

In `process_pkt_handshake_response`, the `sent_auth_plugin_id == AUTH_MYSQL_NATIVE_PASSWORD` switch (~line 3564-3590) has `default: assert(0)`. Add before `default:`:

```cpp
#ifdef PROXYSQLED25519
			case AUTH_MYSQL_ED25519:
				// nothing to do here; PPHR_verify_password() decides the ed25519
				// Auth Switch at stage 0 (after the account lookup)
				break;
#endif
```

The `sent_auth_plugin_id == AUTH_MYSQL_CACHING_SHA2_PASSWORD` switch (~line 3592-3616) already has `default: break;`, so `AUTH_MYSQL_ED25519` falls through safely — add the same explicit case there anyway, directly above `default:`, for symmetry and greppability.

- [ ] **Step 7: implement PPHR_ed25519_switch and PPHR_ed25519_verify**

Place both right after `PPHR_sha2full` (~line 2916) in `lib/MySQL_Protocol.cpp`:

```cpp
#ifdef PROXYSQLED25519
/**
 * @brief Initiate the client_ed25519 Auth Switch (stage 0 -> 1).
 * @details Generates a fresh 32-byte nonce into 'scramble_buff' (40 bytes, so
 *   it fits) and sends an AuthSwitchRequest naming client_ed25519. The client
 *   answers with a 64-byte signature that PPHR_1 collects (stage 1 -> 2) and
 *   PPHR_ed25519_verify() checks. Mirrors the state handling of PPHR_4auth0.
 */
void MySQL_Protocol::PPHR_ed25519_switch(bool& ret, MyProt_tmp_auth_vars& vars1) {
	ret = false;
	if (RAND_bytes(reinterpret_cast<unsigned char *>((*myds)->myconn->scramble_buff), ED25519_NONCE_LEN) != 1) {
		proxy_error("RAND_bytes() failed generating the ed25519 nonce for user '%s'\n", vars1.user);
		return;
	}
	(*myds)->switching_auth_type = AUTH_MYSQL_ED25519;
	(*myds)->switching_auth_stage = 1;
	(*myds)->auth_in_progress = 1;
	generate_pkt_auth_switch_request(true, NULL, NULL);
	(*myds)->myconn->userinfo->set((char *)vars1.user, NULL, vars1.db, NULL);
	proxy_debug(PROXY_DEBUG_MYSQL_AUTH, 5, "Session=%p , DS=%p , user='%s' . Sent client_ed25519 Auth Switch\n",
		(*myds)->sess, (*myds), vars1.user);
}

/**
 * @brief Verify the 64-byte client_ed25519 signature over the nonce sent by
 *   PPHR_ed25519_switch() (or by the COM_CHANGE_USER switch path).
 * @details The public key comes from a stored "$ED$" credential, or is derived
 *   from a stored cleartext password (MariaDB variant, ref10). Every failure
 *   mode -- wrong length, malformed stored key, bad signature -- yields the
 *   same generic auth failure; nothing distinguishable leaks to the client.
 */
void MySQL_Protocol::PPHR_ed25519_verify(bool& ret, MyProt_tmp_auth_vars& vars1) {
	ret = false;
	if (vars1.pass_len != ED25519_SIG_LEN) {
		proxy_debug(PROXY_DEBUG_MYSQL_AUTH, 5, "Session=%p , DS=%p , user='%s' . Malformed ed25519 signature length %u\n",
			(*myds)->sess, (*myds), vars1.user, vars1.pass_len);
		return;
	}
	unsigned char pubkey[ED25519_PUBKEY_LEN];
	if (proxysql_ed25519_is_pubkey_format(vars1.password)) {
		if (proxysql_ed25519_decode_pubkey(vars1.password, pubkey) == false) {
			proxy_error("mysql_users entry for '%s' has a malformed $ED$ ed25519 credential; denying access\n", vars1.user);
			return;
		}
	} else {
		proxysql_ed25519_derive_public_key(vars1.password, strlen(vars1.password), pubkey);
	}
	if (proxysql_ed25519_verify_signature(vars1.pass, reinterpret_cast<unsigned char *>((*myds)->myconn->scramble_buff), pubkey)) {
		ret = true;
	}
	OPENSSL_cleanse(pubkey, sizeof(pubkey));
	proxy_debug(PROXY_DEBUG_MYSQL_AUTH, 5, "Session=%p , DS=%p , user='%s' . ed25519 signature verification %s\n",
		(*myds)->sess, (*myds), vars1.user, ret ? "succeeded" : "failed");
}
#endif // PROXYSQLED25519
```

- [ ] **Step 8: PPHR_verify_password — stage-0 gate and verification dispatch**

Insertion A — the stage-0 gate. Locate the call to `PPHR_5passwordTrue(ret, vars1, reply, account_details);` (~line 3427) and insert **immediately after it**, BEFORE the `if (vars1.pass_len==0 && strlen(vars1.password)==0)` block:

```cpp
#ifdef PROXYSQLED25519
		// ed25519 gate (stage 0): a client that requested client_ed25519 sends an
		// empty auth response in the HandshakeResponse -- it cannot sign before
		// receiving the 32-byte nonce -- so this decision MUST precede the
		// empty-response checks below. A stored "$ED$" credential forces the
		// ed25519 exchange regardless of the plugin the client offered.
		// 'switching_auth_sent' guards re-entry: after the switch, the signature
		// arrives with stage 0 on the COM_CHANGE_USER path and stage 2 here.
		if ((*myds)->switching_auth_stage == 0 &&
			(*myds)->switching_auth_sent != AUTH_MYSQL_ED25519 &&
			(*myds)->sess->session_type != PROXYSQL_SESSION_CLICKHOUSE) {
			const bool stored_is_ed = proxysql_ed25519_is_pubkey_format(vars1.password);
			// a '*SHA1' or '$A$' hash cannot derive an ed25519 key
			const bool cred_usable = stored_is_ed ||
				(vars1.password[0] != '*' &&
				!(strlen(vars1.password) == 70 && strncasecmp(vars1.password,"$A$0",4)==0));
			if (stored_is_ed || (auth_plugin_id == AUTH_MYSQL_ED25519 && cred_usable)) {
				PPHR_ed25519_switch(ret, vars1);
				return ret;
			}
			if (auth_plugin_id == AUTH_MYSQL_ED25519) {
				// client insists on ed25519 but the stored hash cannot derive a key
				return ret; // ret == false
			}
		}
#endif
```

Insertion B — the verification dispatch. At ~line 3445, the credential-format chain starts with the `$A$` caching_sha2 check. Put the ed25519 dispatch FIRST in that chain:

```cpp
#ifdef PROXYSQLED25519
				if (auth_plugin_id == AUTH_MYSQL_ED25519 || proxysql_ed25519_is_pubkey_format(vars1.password)) {
					// signature collected by PPHR_1 after the Auth Switch; a stored
					// "$ED$" key with a non-ed25519 response fails the length check
					// inside PPHR_ed25519_verify (generic denial)
					PPHR_ed25519_verify(ret, vars1);
				} else
#endif
				if (
					auth_plugin_id == AUTH_MYSQL_CACHING_SHA2_PASSWORD
					&&
					strlen(vars1.password) == 70
					...
```

(Only add the new branch and the `else`; the existing chain is unchanged.)

- [ ] **Step 9: data-stream JSON dump**

In `lib/mysql_data_stream.cpp` (~line 1936-1946), in the `switch (myprot.auth_plugin_id)` add before `default:`:

```cpp
#ifdef PROXYSQLED25519
		case AUTH_MYSQL_ED25519:
			jc1["prot"]["auth_plugin"] = "client_ed25519";
			break;
#endif
```

- [ ] **Step 10: Build both tiers**

```bash
PROXYSQL31=1 make debug -j$(nproc)
```
Expected: clean build. Then confirm the stable tier still compiles (all new code is `#ifdef`-gated):

```bash
make clean && make -j$(nproc) && make clean && PROXYSQL31=1 make debug -j$(nproc)
```
Expected: both builds succeed (the final rebuild restores the debug 3.1 binary for later tasks).

- [ ] **Step 11: Re-run the unit tests**

```bash
cd test/tap/tests/unit && make ed25519_unit-t && ./ed25519_unit-t
```
Expected: still all `ok`.

- [ ] **Step 12: Commit**

```bash
git add include/MySQL_Protocol.h lib/MySQL_Protocol.cpp lib/mysql_data_stream.cpp
git commit -m "feat: frontend client_ed25519 authentication via Auth Switch

Adds AUTH_MYSQL_ED25519 to the frontend plugin registry and implements
the MariaDB flow: ed25519 is never advertised in the greeting (its
challenge is 32 bytes, the greeting scramble is 20); instead
PPHR_verify_password decides at stage 0 -- when the stored credential
is \$ED\$ or the client requested client_ed25519 -- and sends an
AuthSwitchRequest with a fresh RAND_bytes nonce (PPHR_ed25519_switch).
The 64-byte signature returns through PPHR_1 (native-style raw
payload, no NUL terminator) and PPHR_ed25519_verify checks it against
the stored public key or one derived from the stored cleartext
password. All failures collapse into the generic access-denied path.

Known v1 limitation: a client that triggers the early native switch
(PPHR_4auth0, e.g. caching_sha2 offer against a native greeting)
cannot be re-switched to ed25519 for \$ED\$ users -- the protocol
allows a single switch. Standard libmariadb clients are unaffected."
```

---

### Task 4: COM_CHANGE_USER support + credential validation warning

**Files:**
- Modify: `lib/MySQL_Protocol.cpp` (`verify_user_pass` ~1524-1560; `process_pkt_COM_CHANGE_USER` ~1823-1848)
- Modify: `lib/MySQL_Authentication.cpp` (`MySQL_Authentication::add` at line 164)

**Interfaces:**
- Consumes: `PPHR_ed25519_verify` flow via the shared state machine (the change-user switch response re-enters `process_pkt_handshake_response` → `PPHR_1` → `PPHR_verify_password`; `switching_auth_sent == AUTH_MYSQL_ED25519` set by `generate_pkt_auth_switch_request` prevents the stage-0 gate from re-firing); `proxysql_ed25519_is_pubkey_format`, `proxysql_ed25519_decode_pubkey`, `ED25519_*` macros.
- Produces: COM_CHANGE_USER to an ed25519 user works via Auth Switch; malformed `$ED$` rows warn at load time.

- [ ] **Step 1: verify_user_pass — recognize the plugin name, reject inline data**

In the name-mapping chain at ~line 1524-1531 add:

```cpp
#ifdef PROXYSQLED25519
	} else if (strncmp((char *)auth_plugin,plugins[AUTH_MYSQL_ED25519],strlen(plugins[AUTH_MYSQL_ED25519]))==0) {
		auth_plugin_id = AUTH_MYSQL_ED25519;
#endif
	}
```

In the cleartext branch (`password[0]!='*'`, ~line 1533-1560) add before the final `else`:

```cpp
#ifdef PROXYSQLED25519
		} else if (auth_plugin_id == AUTH_MYSQL_ED25519) {
			// Inline ed25519 auth data in COM_CHANGE_USER is not part of the
			// MariaDB flow: the client cannot sign before receiving a fresh
			// nonce. The nonce-based exchange is driven by
			// process_pkt_COM_CHANGE_USER via Auth Switch; reject inline data.
			ret = false;
#endif
```

(The hashed branch, `password[0]=='*'`, needs no change: its `else` leg already fails closed for non-native plugins in MYSQL sessions.)

- [ ] **Step 2: process_pkt_COM_CHANGE_USER — ed25519 Auth Switch**

At ~line 1823, the credential dispatch currently reads `if (password==NULL) { ret=false; } else { if (pass_len==0 && strlen(password)==0) ...`. Insert an ed25519 branch as the FIRST check inside the `else`:

```cpp
	if (password==NULL) {
		ret=false;
	} else {
#ifdef PROXYSQLED25519
		// A stored "$ED$" credential (or an explicit client_ed25519 request)
		// can only be verified through a fresh-nonce Auth Switch: any inline
		// auth data was computed against the original scramble and is
		// meaningless for ed25519. Mirrors the native pass_len==0 switch below
		// (issue #3504); the response re-enters process_pkt_handshake_response
		// where PPHR_1 picks up switching_auth_type and PPHR_verify_password
		// verifies the signature (switching_auth_sent guards its stage-0 gate).
		const bool ed25519_switch_needed =
			session_type != PROXYSQL_SESSION_CLICKHOUSE &&
			(proxysql_ed25519_is_pubkey_format(password) ||
			(client_auth_plugin && strcmp(client_auth_plugin, plugins[AUTH_MYSQL_ED25519]) == 0));
		if (ed25519_switch_needed) {
			if (RAND_bytes(reinterpret_cast<unsigned char *>((*myds)->myconn->scramble_buff), ED25519_NONCE_LEN) != 1) {
				proxy_error("RAND_bytes() failed generating the ed25519 nonce for user '%s'\n", user);
				ret = false;
			} else {
				(*myds)->switching_auth_type = AUTH_MYSQL_ED25519;
				(*myds)->sess->change_user_auth_switch = true;
				generate_pkt_auth_switch_request(true, NULL, NULL);
				(*myds)->myconn->userinfo->set((char *)user, NULL, db, NULL);
				ret = false;
			}
		} else
#endif
		if (pass_len==0 && strlen(password)==0) {
```

(The rest of the chain — the empty-password accept, the native `pass_len==0` switch, and the `verify_user_pass` call — is unchanged and stays attached to the final `else`.)

- [ ] **Step 3: backend connect warning for $ED$-only credentials**

Per spec §4, an `$ED$`-stored user cannot authenticate to backends (the
connector would send the literal `$ED$…` string as the password). Emit an
explicit warning where the backend connection is initiated so admins are not
left with generic access-denied noise. In `lib/mysql_connection.cpp`, inside
`MySQL_Connection::connect_start` (~line 998), immediately before the
`mysql_real_connect_start` invocation, add:

```cpp
#ifdef PROXYSQLED25519
	if (userinfo->password && proxysql_ed25519_is_pubkey_format(userinfo->password)) {
		proxy_warning(
			"User '%s' has an ed25519 public-key-only ($ED$) credential;"
			" backend authentication requires the cleartext password and will fail\n",
			userinfo->username);
	}
#endif
```

and near the top of `lib/mysql_connection.cpp` add:

```cpp
#ifdef PROXYSQLED25519
#include "MySQL_Ed25519.h"
#endif
```

- [ ] **Step 4: load-time validation warning in MySQL_Authentication::add**

At the top of `MySQL_Authentication::add` (line 164, before the hashing), add:

```cpp
#ifdef PROXYSQLED25519
	if (password && strncasecmp(password, ED25519_STORED_PREFIX, ED25519_STORED_PREFIX_LEN) == 0) {
		unsigned char tmp_pk[ED25519_PUBKEY_LEN];
		if (proxysql_ed25519_decode_pubkey(password, tmp_pk) == false) {
			proxy_warning(
				"mysql_users entry for '%s' has a malformed $ED$ ed25519 credential"
				" (expected \"$ED$\" followed by exactly 43 base64 characters);"
				" every authentication attempt for this user will fail\n", username);
		}
	}
#endif
```

and add near the top of `lib/MySQL_Authentication.cpp`:

```cpp
#ifdef PROXYSQLED25519
#include "MySQL_Ed25519.h"
#endif
```

- [ ] **Step 5: Build and run unit tests**

```bash
PROXYSQL31=1 make debug -j$(nproc)
cd test/tap/tests/unit && make ed25519_unit-t && ./ed25519_unit-t
```
Expected: clean build, unit tests all `ok`.

- [ ] **Step 6: Commit**

```bash
git add lib/MySQL_Protocol.cpp lib/MySQL_Authentication.cpp lib/mysql_connection.cpp
git commit -m "feat: COM_CHANGE_USER support for ed25519 users, \$ED\$ load-time validation

COM_CHANGE_USER targeting a stored-\$ED\$ user (or naming
client_ed25519) now performs the fresh-nonce Auth Switch instead of
failing on unverifiable inline auth data; the signature response rides
the existing change_user_auth_switch rails (#3504) back through
process_pkt_handshake_response. Unlike caching_sha2 (#4618), no
sub-protocol is needed, so change-user works fully.

MySQL_Authentication::add() warns once at load time when a \$ED\$
credential is malformed, and connect_start() warns when a backend
connection is attempted with a public-key-only \$ED\$ credential,
instead of leaving admins to puzzle over generic access-denied
errors."
```

---

### Task 5: End-to-end TAP test on MariaDB infra

**Files:**
- Create: `test/tap/tests/test_ed25519_auth-t.cpp`
- Modify: `test/tap/groups/groups.json`

**Interfaces:**
- Consumes: the complete frontend + backend feature; TAP helpers `CommandLine` (`command_line.h`), `mysql_query_t`/`MYSQL_QUERY` (`utils.h`), the `mariadb10-galera` infra. The TAP client binary links the patched vendored connector, so it can itself answer a `client_ed25519` Auth Switch — no external client needed.
- Produces: `test_ed25519_auth-t` registered in `mariadb10-galera-g4`, gated `@proxysql_min_version:3.1`.

Backend/user fixture (all through ProxySQL as `cl.username`, which routes to the Galera writer):
- password `ed25519_pass_1` ↔ pubkey `5TBW79xTAMbhi8QKQtLLVS0V0b2w9mlKnRG6c+2NxTQ` (Global Constraints vectors).

- [ ] **Step 1: Write the test**

Create `test/tap/tests/test_ed25519_auth-t.cpp`:

```cpp
/**
 * @file test_ed25519_auth-t.cpp
 * @brief End-to-end MariaDB ed25519 authentication (frontend + backend).
 * @details Requires a MariaDB backend (mariadb10-galera infra): installs the
 *   auth_ed25519 server plugin, creates ed25519 backend users, and exercises:
 *     1. cleartext-stored user: frontend ed25519 auth AND backend ed25519 auth
 *        (query reaches the backend);
 *     2. $ED$-stored user: frontend auth succeeds, backend query fails
 *        (public key cannot drive backend auth -- documented limitation);
 *     3. wrong password -> 1045;
 *     4. COM_CHANGE_USER into an ed25519 user via Auth Switch;
 *     5. additional-password (attributes JSON) retry.
 */
#include <cstdlib>
#include <cstring>
#include <string>

#include "mysql.h"

#include "tap.h"
#include "command_line.h"
#include "utils.h"

const char* ED_PASS = "ed25519_pass_1";
const char* ED_PUBKEY = "5TBW79xTAMbhi8QKQtLLVS0V0b2w9mlKnRG6c+2NxTQ";

int main(int argc, char** argv) {
	CommandLine cl;
	if (cl.getEnv()) {
		diag("Failed to get the required environmental variables.");
		return EXIT_FAILURE;
	}

	plan(10);

	// ---- fixture: backend plugin + users, via ProxySQL default routing ----
	MYSQL* wr = mysql_init(NULL);
	if (!mysql_real_connect(wr, cl.host, cl.username, cl.password, NULL, cl.port, NULL, 0)) {
		diag("Failed to connect to ProxySQL: %s", mysql_error(wr));
		return EXIT_FAILURE;
	}
	// tolerate "already installed"
	if (mysql_query(wr, "INSTALL SONAME 'auth_ed25519'")) {
		diag("INSTALL SONAME: %s (tolerated if already installed)", mysql_error(wr));
	}
	{
		MYSQL_RES* res = NULL;
		MYSQL_QUERY(wr, "SELECT COUNT(*) FROM information_schema.plugins WHERE plugin_name='ed25519'");
		res = mysql_store_result(wr);
		MYSQL_ROW row = mysql_fetch_row(res);
		bool plugin_ok = row && strcmp(row[0], "1") == 0;
		mysql_free_result(res);
		if (!plugin_ok) {
			diag("auth_ed25519 server plugin unavailable on this backend");
			return EXIT_FAILURE;
		}
	}
	MYSQL_QUERY(wr, "CREATE DATABASE IF NOT EXISTS test");
	std::string create_user =
		std::string("CREATE USER IF NOT EXISTS 'ed_user'@'%' IDENTIFIED VIA ed25519 USING '") + ED_PUBKEY + "'";
	MYSQL_QUERY(wr, create_user.c_str());
	std::string create_user_pk =
		std::string("CREATE USER IF NOT EXISTS 'ed_user_pk'@'%' IDENTIFIED VIA ed25519 USING '") + ED_PUBKEY + "'";
	MYSQL_QUERY(wr, create_user_pk.c_str());
	MYSQL_QUERY(wr, "GRANT ALL ON test.* TO 'ed_user'@'%'");
	MYSQL_QUERY(wr, "GRANT ALL ON test.* TO 'ed_user_pk'@'%'");

	// ---- proxysql users ----
	MYSQL* admin = mysql_init(NULL);
	if (!mysql_real_connect(admin, cl.admin_host, cl.admin_username, cl.admin_password, NULL, cl.admin_port, NULL, 0)) {
		diag("Failed to connect to ProxySQL admin: %s", mysql_error(admin));
		return EXIT_FAILURE;
	}
	int def_hg = 0;
	{
		MYSQL_QUERY(admin, "SELECT MIN(hostgroup_id) FROM runtime_mysql_servers WHERE status='ONLINE'");
		MYSQL_RES* res = mysql_store_result(admin);
		MYSQL_ROW row = mysql_fetch_row(res);
		if (row && row[0]) { def_hg = atoi(row[0]); }
		mysql_free_result(res);
	}
	std::string q1 =
		"INSERT OR REPLACE INTO mysql_users (username,password,active,default_hostgroup,default_schema) VALUES"
		" ('ed_user','" + std::string(ED_PASS) + "',1," + std::to_string(def_hg) + ",'test')";
	MYSQL_QUERY(admin, q1.c_str());
	std::string q2 =
		"INSERT OR REPLACE INTO mysql_users (username,password,active,default_hostgroup,default_schema) VALUES"
		" ('ed_user_pk','$ED$" + std::string(ED_PUBKEY) + "',1," + std::to_string(def_hg) + ",'test')";
	MYSQL_QUERY(admin, q2.c_str());
	MYSQL_QUERY(admin, "LOAD MYSQL USERS TO RUNTIME");

	// ---- 1-2: cleartext-stored user, full frontend+backend path ----
	{
		MYSQL* c = mysql_init(NULL);
		bool conn_ok = mysql_real_connect(c, cl.host, "ed_user", ED_PASS, "test", cl.port, NULL, 0) != NULL;
		ok(conn_ok, "cleartext-stored user connects via ed25519 auth switch (err: %s)", conn_ok ? "-" : mysql_error(c));
		if (conn_ok) {
			int rc = mysql_query(c, "SELECT CURRENT_USER()");
			ok(rc == 0, "query reaches the ed25519 backend user (err: %s)", rc ? mysql_error(c) : "-");
			if (rc == 0) { mysql_free_result(mysql_store_result(c)); }
		} else {
			ok(false, "query skipped: connection failed");
		}
		mysql_close(c);
	}

	// ---- 3: wrong password -> 1045 ----
	{
		MYSQL* c = mysql_init(NULL);
		bool conn_ok = mysql_real_connect(c, cl.host, "ed_user", "wrong_password", "test", cl.port, NULL, 0) != NULL;
		ok(conn_ok == false && mysql_errno(c) == 1045,
			"wrong password denied with 1045 (got errno %u)", mysql_errno(c));
		mysql_close(c);
	}

	// ---- 4-5: $ED$-stored user: frontend OK, backend query fails ----
	{
		MYSQL* c = mysql_init(NULL);
		bool conn_ok = mysql_real_connect(c, cl.host, "ed_user_pk", ED_PASS, "test", cl.port, NULL, 0) != NULL;
		ok(conn_ok, "$ED$-stored user passes frontend verification (err: %s)", conn_ok ? "-" : mysql_error(c));
		if (conn_ok) {
			int rc = mysql_query(c, "SELECT 1");
			if (rc == 0) { mysql_free_result(mysql_store_result(c)); }
			ok(rc != 0, "backend query fails for public-key-only credential (documented limitation)");
		} else {
			ok(false, "backend check skipped: connection failed");
		}
		mysql_close(c);
	}

	// ---- 6: bad frontend password for $ED$ user ----
	{
		MYSQL* c = mysql_init(NULL);
		bool conn_ok = mysql_real_connect(c, cl.host, "ed_user_pk", "wrong_password", "test", cl.port, NULL, 0) != NULL;
		ok(conn_ok == false && mysql_errno(c) == 1045,
			"$ED$ user, wrong password denied with 1045 (got errno %u)", mysql_errno(c));
		mysql_close(c);
	}

	// ---- 7-8: COM_CHANGE_USER into the ed25519 user ----
	{
		MYSQL* c = mysql_init(NULL);
		bool conn_ok = mysql_real_connect(c, cl.host, cl.username, cl.password, "test", cl.port, NULL, 0) != NULL;
		if (!conn_ok) {
			ok(false, "base connection for change_user failed: %s", mysql_error(c));
			ok(false, "change_user skipped");
		} else {
			int rc = mysql_change_user(c, "ed_user", ED_PASS, "test");
			ok(rc == 0, "COM_CHANGE_USER into ed25519 user succeeds (err: %s)", rc ? mysql_error(c) : "-");
			rc = mysql_query(c, "SELECT 1");
			if (rc == 0) { mysql_free_result(mysql_store_result(c)); }
			ok(rc == 0, "query works after change_user (err: %s)", rc ? mysql_error(c) : "-");
		}
		mysql_close(c);
	}

	// ---- 9-10: additional-password retry (attributes JSON, hex-encoded) ----
	{
		// primary password wrong on purpose; additional_password holds the real one
		char hexpass[64] = { 0 };
		for (size_t i = 0; i < strlen(ED_PASS); i++) {
			sprintf(hexpass + 2 * i, "%02x", (unsigned char)ED_PASS[i]);
		}
		std::string q =
			"UPDATE mysql_users SET password='not_the_real_password',"
			" attributes='{\"additional_password\":\"" + std::string(hexpass) + "\"}'"
			" WHERE username='ed_user'";
		MYSQL_QUERY(admin, q.c_str());
		MYSQL_QUERY(admin, "LOAD MYSQL USERS TO RUNTIME");

		MYSQL* c = mysql_init(NULL);
		bool conn_ok = mysql_real_connect(c, cl.host, "ed_user", ED_PASS, "test", cl.port, NULL, 0) != NULL;
		ok(conn_ok, "additional-password retry verifies ed25519 signature (err: %s)", conn_ok ? "-" : mysql_error(c));
		if (conn_ok) {
			int rc = mysql_query(c, "SELECT 1");
			if (rc == 0) { mysql_free_result(mysql_store_result(c)); }
			ok(rc == 0, "query works on additional password (err: %s)", rc ? mysql_error(c) : "-");
		} else {
			ok(false, "query skipped: connection failed");
		}
		mysql_close(c);
	}

	// ---- cleanup ----
	MYSQL_QUERY(admin, "DELETE FROM mysql_users WHERE username IN ('ed_user','ed_user_pk')");
	MYSQL_QUERY(admin, "LOAD MYSQL USERS TO RUNTIME");
	mysql_query(wr, "DROP USER IF EXISTS 'ed_user'@'%'");
	mysql_query(wr, "DROP USER IF EXISTS 'ed_user_pk'@'%'");
	mysql_close(admin);
	mysql_close(wr);

	return exit_status();
}
```

NOTE for the implementer: check `command_line.h` for the exact member names (`cl.host`, `cl.port`, `cl.username`, `cl.password`, `cl.admin_host`, `cl.admin_port`, `cl.admin_username`, `cl.admin_password`) and the `MYSQL_QUERY` macro in `utils.h`; mirror whatever `test_auth_methods-t.cpp` uses if any name differs. If `INSERT OR REPLACE INTO mysql_users` conflicts with the runner's fixed config, switch to `DELETE FROM mysql_users WHERE username=...` + `INSERT`.

- [ ] **Step 2: Register the test in groups.json**

```json
  "test_ed25519_auth-t" : [ "mariadb10-galera-g4","@proxysql_min_version:3.1" ],
```

(Only the `mariadb10-galera` infra provides a MariaDB backend; `INSTALL SONAME 'auth_ed25519'` fails on MySQL backends, so do NOT add other groups.)

- [ ] **Step 3: Build the TAP tests**

```bash
PROXYSQL31=1 make build_tap_test_debug
```
Expected: `test_ed25519_auth-t` compiles and links.

- [ ] **Step 4: Run the test in the isolated harness**

```bash
WORKSPACE=$(pwd) INFRA_ID=dev-$USER TAP_GROUP=mariadb10-galera-g4 test/infra/control/ensure-infras.bash
WORKSPACE=$(pwd) INFRA_ID=dev-$USER TAP_GROUP=mariadb10-galera-g4 \
  TEST_PY_TAP_INCL="test_ed25519_auth-t" \
  test/infra/control/run-tests-isolated.bash
```
Expected: `1..11`, all `ok`. On any failure, read the test output AND the proxysql container log; identify the specific failing step before changing anything (per CLAUDE.md failure-reporting rules). Also verify the `$ED$` backend-failure warning appears in the proxysql log during step 5's run (`grep -i "ed25519" <proxysql log>`).

- [ ] **Step 5: Run the full unit-test group to catch regressions**

```bash
WORKSPACE=$(pwd) INFRA_ID=dev-$USER TAP_GROUP=unit-tests-g1 test/infra/control/run-tests-isolated.bash
```
Expected: all tests pass, including `ed25519_unit-t` and pre-existing auth tests.

- [ ] **Step 6: Commit**

```bash
git add test/tap/tests/test_ed25519_auth-t.cpp test/tap/groups/groups.json
git commit -m "test: end-to-end MariaDB ed25519 authentication TAP test

Runs on the mariadb10-galera infra (@proxysql_min_version:3.1):
installs auth_ed25519 on the backend and covers the full matrix --
cleartext-stored user through to backend query execution, \$ED\$
public-key-only user (frontend OK, backend fails as documented),
wrong-password 1045 for both formats, COM_CHANGE_USER via Auth
Switch, and additional-password retry. The TAP client itself answers
the client_ed25519 Auth Switch because the vendored connector now
links the plugin statically."
```

---

### Task 6: Documentation + spec-coverage check

**Files:**
- Create: `doc/ed25519_authentication.md`

**Interfaces:**
- Consumes: everything above.
- Produces: user-facing documentation; final verified branch.

- [ ] **Step 1: Write the documentation**

Create `doc/ed25519_authentication.md`:

```markdown
# MariaDB ed25519 Authentication

ProxySQL supports MariaDB's ed25519 authentication scheme
(`client_ed25519` client plugin / `auth_ed25519` server plugin) on both
sides of the proxy.

## Availability

| Side | Tier | Mechanism |
|------|------|-----------|
| Backend (ProxySQL → MariaDB) | all tiers | The bundled MariaDB Connector/C links `client_ed25519` statically and answers the server's auth switch transparently. |
| Frontend (client → ProxySQL) | v3.1+ (`PROXYSQL31`) | ProxySQL verifies `client_ed25519` signatures itself. |

Oracle MySQL has no ed25519 plugin; this is a MariaDB-ecosystem feature.

## Credential formats in `mysql_users.password`

| Format | Example | Frontend auth | Backend auth |
|--------|---------|---------------|--------------|
| cleartext | `my_password` | yes (key derived on the fly) | yes (connector signs with it) |
| `$ED$` + 43-char base64 public key | `$ED$ZIgUREUg5PVgQ6LskhXmO+eZLS0nC8be6HPjYWR4YJY` | yes (signature verified against the key) | **no** — the password is unknown |

The `$ED$` payload is exactly the value MariaDB stores in
`mysql.user.authentication_string` for an ed25519 user — to migrate,
prefix it with `$ED$`. The prefix is case-insensitive and mandatory: a
bare 43-character string is treated as a cleartext password.

A malformed `$ED$` value (wrong length or invalid base64) logs a warning
at `LOAD MYSQL USERS TO RUNTIME` time and every authentication attempt
for that user fails with the standard access-denied error.

## Protocol behavior

ed25519 is never advertised in the initial handshake (its challenge is
32 bytes; the greeting scramble is 20). ProxySQL sends an
`AuthSwitchRequest` naming `client_ed25519` with a fresh 32-byte nonce
whenever:

- the stored credential is `$ED$…` (whatever plugin the client offered), or
- the client explicitly requested `client_ed25519` and the stored
  credential is cleartext or `$ED$`.

The client answers with a 64-byte signature. This mirrors MariaDB's own
behavior, so any client able to authenticate against MariaDB ed25519
works unchanged. `COM_CHANGE_USER` into an ed25519 user is supported via
the same auth-switch mechanism.

TLS is not required: the exchange never transmits a secret.

## Limitations

- `$ED$` (public-key-only) users cannot open backend connections: the
  signature scheme is not replayable and the cleartext is unknown.
  ProxySQL logs an explicit warning when such a user's backend
  connection fails. Store the cleartext password for full functionality.
- Pass-through authentication (`mysql-passthrough_auth_*`) cannot learn
  credentials from an ed25519 exchange, by construction.
- If a client triggers an early switch to `mysql_native_password`
  (e.g. it offered `caching_sha2_password` against a native greeting),
  a stored-`$ED$` user cannot be verified on that connection — the
  MySQL protocol allows a single auth switch. Standard MariaDB clients
  do not hit this.
- MariaDB PARSEC (11.6+) is not supported.
```

- [ ] **Step 2: Spec-coverage check**

Re-read `docs/superpowers/specs/2026-08-11-ed25519-authentication-design.md` section by section and confirm each maps to a completed task: §1 build/gating → Task 1; §2 storage → Task 2 + Task 3 Step 8; §3 protocol → Task 3 (+ change-user in Task 4); §4 backend → Task 1 (+ `$ED$` connect warning in Task 4 Step 3, exercised by Task 5's log grep); §5 admin/observability → Tasks 3 (JSON dump) and 4 (load warning); §6 errors → Tasks 3-4; §7 tests/docs → Tasks 2, 5, 6. Any gap found here becomes a new task before proceeding.

- [ ] **Step 3: Final full verification**

```bash
PROXYSQL31=1 make debug -j$(nproc)
cd test/tap/tests/unit && make ed25519_unit-t && ./ed25519_unit-t && cd -
PROXYSQL31=1 make build_tap_test_debug
WORKSPACE=$(pwd) INFRA_ID=dev-$USER TAP_GROUP=mariadb10-galera-g4 \
  TEST_PY_TAP_INCL="test_ed25519_auth-t" \
  test/infra/control/run-tests-isolated.bash
```
Expected: everything green.

- [ ] **Step 4: Commit**

```bash
git add doc/ed25519_authentication.md
git commit -m "docs: MariaDB ed25519 authentication guide

Formats, MariaDB migration path, protocol behavior, tier
availability, and the documented limitations (\$ED\$ backend
connections, passthrough incompatibility, single-auth-switch edge,
PARSEC out of scope)."
```
