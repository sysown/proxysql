# cppcheck Static Analysis Fixes Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Fix cppcheck warnings/errors in ProxySQL codebase, excluding third-party dependencies (deps/json, deps/openssl, etc.)

**Architecture:** Focus on highest-value issues: uninitialized member variables (potential bugs), memory leaks, and performance improvements. Skip style-only issues like `noExplicitConstructor` and `cstyleCast` as they are numerous and low-risk.

**Tech Stack:** C++17, cppcheck 2.13

---

## Exclusion Rules

All issues in these paths are excluded (third-party or low-value):
- `deps/*`
- `*/json.hpp` (nlohmann json)
- `noExplicitConstructor` - too many, low risk
- `cstyleCast` - too many, low risk
- `noConstructor` - style only
- `duplInheritedMember` - architectural, low risk

---

## Task 1: Fix memleakOnRealloc in gen_utils.h

**Files:**
- Modify: `include/gen_utils.h:144-149`

- [ ] **Step 1: Read the current code**

```cpp
// Around line 144-149 in include/gen_utils.h
void *pdata = nullptr;
...
pdata=(void **)new_pdata;
...
pdata=(void **)realloc(pdata,new_size*sizeof(void *));
```

- [ ] **Step 2: Fix the memory leak**

The issue is that `realloc` can fail and return null, but the original pointer is lost. Fix by:
```cpp
void *new_pdata = realloc(pdata, new_size * sizeof(void *));
if (new_pdata) {
    pdata = (void **)new_pdata;
} else {
    // Handle error - pdata remains valid
}
```

- [ ] **Step 3: Verify with cppcheck**

```bash
cppcheck -I include --std=c++17 --enable=warning --suppress=missingIncludeSystem --max-configs=1 lib/MySQL_Authentication.cpp 2>&1 | grep memleakOnRealloc
```
Expected: No output (issue fixed)

- [ ] **Step 4: Commit**

```bash
git add include/gen_utils.h
git commit -m "fix: resolve memleakOnRealloc in PtrArray::allocate"
```

---

## Task 2: Fix useInitializationList in Servers_SslParams.h

**Files:**
- Modify: `include/Servers_SslParams.h:28-46`

- [ ] **Step 1: Read the current constructor**

```cpp
// Lines 28-46 in include/Servers_SslParams.h
Servers_SslParams(char *_h, uint16_t _p, char *_u, char *ca, char *cert, char *key, char *crl, char *crlpath, char *cipher, char *tls, char *c) {
  hostname = _h;
  username = _u;
  ssl_ca = ca;
  // ... more assignments
}
```

- [ ] **Step 2: Convert to initialization list**

```cpp
Servers_SslParams(char *_h, uint16_t _p, char *_u, char *ca, char *cert, char *key, char *crl, char *crlpath, char *cipher, char *tls, char *c)
  : hostname(_h), username(_u), ssl_ca(ca), ssl_cert(cert), ssl_key(key),
    ssl_crl(crl), ssl_crlpath(crlpath), ssl_cipher(cipher), tls_version(tls), comment(c), MapKey("")
{
}
```

- [ ] **Step 3: Verify with cppcheck**

```bash
cppcheck -I include --std=c++17 --enable=warning --suppress=missingIncludeSystem --max-configs=1 lib/MySQL_Authentication.cpp 2>&1 | grep "Servers_SslParams"
```
Expected: No useInitializationList warnings for Servers_SslParams

- [ ] **Step 4: Commit**

```bash
git add include/Servers_SslParams.h
git commit -m "perf: use initialization list in Servers_SslParams constructor"
```

---

## Task 3: Fix noCopyConstructor and noOperatorEq in ProxySQL_Poll.h

**Files:**
- Modify: `include/ProxySQL_Poll.h:13`

- [ ] **Step 1: Read the current class**

```cpp
// Line 13 in include/ProxySQL_Poll.h
class iface_info {
  char *iface;
public:
  iface_info(const char *_i) { iface=strdup(_i); }
  ~iface_info() { free(iface); }
};
```

- [ ] **Step 2: Delete the class or add proper copy semantics**

Since this class owns memory, either delete copy operations or implement them properly:

```cpp
class iface_info {
  char *iface;
public:
  iface_info(const char *_i) { iface=strdup(_i); }
  ~iface_info() { free(iface); }
  iface_info(const iface_info&) = delete;
  iface_info& operator=(const iface_info&) = delete;
};
```

- [ ] **Step 3: Verify with cppcheck**

```bash
cppcheck -I include --std=c++17 --enable=warning --suppress=missingIncludeSystem --max-configs=1 lib/MySQL_Authentication.cpp 2>&1 | grep "ProxySQL_Poll"
```
Expected: No noCopyConstructor/noOperatorEq warnings for ProxySQL_Poll

- [ ] **Step 4: Commit**

```bash
git add include/ProxySQL_Poll.h
git commit -m "fix: delete copy operations in iface_info class"
```

---

## Task 4: Fix uninitMemberVar in Query_Processor_Output

**Files:**
- Modify: `include/query_processor.h:187`

- [ ] **Step 1: Read the current constructor**

```cpp
// Line 187 in include/query_processor.h
Query_Processor_Output() {
    // cppcheck warns about many uninitialized members
}
```

- [ ] **Step 2: Add member initialization**

```cpp
Query_Processor_Output()
  : ptr(nullptr), size(0), destination_hostgroup(-1), mirror_hostgroup(-1),
    mirror_flagOUT(false), next_query_flagIN(false), cache_ttl(0),
    cache_empty_result(false), cache_timeout(0), reconnect(true),
    timeout(0), retries(3), delay(0), error_msg(nullptr), OK_msg(nullptr),
    sticky_conn(false), multiplex(true), max_lag_ms(0), log(false),
    firewall_whitelist_mode(false), attributes(nullptr), comment(nullptr),
    create_new_conn(false), new_query(false)
{
}
```

- [ ] **Step 3: Verify with cppcheck**

```bash
cppcheck -I include --std=c++17 --enable=warning --suppress=missingIncludeSystem --max-configs=1 lib/MySQL_Session.cpp 2>&1 | grep "Query_Processor_Output"
```
Expected: No uninitMemberVar warnings for Query_Processor_Output

- [ ] **Step 4: Commit**

```bash
git add include/query_processor.h
git commit -m "fix: initialize all members in Query_Processor_Output constructor"
```

---

## Task 5: Fix uninitMemberVar in MySQL_Protocol

**Files:**
- Modify: `include/MySQL_Protocol.h:145`

- [ ] **Step 1: Read the current constructor**

```cpp
// Line 145 in include/MySQL_Protocol.h
MySQL_Protocol() {
    // cppcheck warns: userinfo, sess, myds, current_PreStmt
}
```

- [ ] **Step 2: Add member initialization**

```cpp
MySQL_Protocol()
  : userinfo(nullptr), sess(nullptr), myds(nullptr), current_PreStmt(nullptr)
{
}
```

- [ ] **Step 3: Verify with cppcheck**

```bash
cppcheck -I include --std=c++17 --enable=warning --suppress=missingIncludeSystem --max-configs=1 lib/MySQL_Protocol.cpp 2>&1 | grep "MySQL_Protocol"
```
Expected: No uninitMemberVar warnings for MySQL_Protocol

- [ ] **Step 4: Commit**

```bash
git add include/MySQL_Protocol.h
git commit -m "fix: initialize all members in MySQL_Protocol constructor"
```

---

## Task 6: Fix uninitMemberVar in Query_Info (lib)

**Files:**
- Modify: `lib/MySQL_Session.cpp:366`

- [ ] **Step 1: Find and read the constructor**

```cpp
// Around line 366 in lib/MySQL_Session.cpp
Query_Info::Query_Info() {
    // cppcheck warns: sess, mysql_stmt, stmt_meta, stmt_global_id
}
```

- [ ] **Step 2: Add member initialization**

```cpp
Query_Info::Query_Info()
  : sess(nullptr), mysql_stmt(nullptr), stmt_meta(nullptr), stmt_global_id(0)
{
}
```

- [ ] **Step 3: Verify with cppcheck**

```bash
cppcheck -I include --std=c++17 --enable=warning --suppress=missingIncludeSystem --max-configs=1 lib/MySQL_Session.cpp 2>&1 | grep "Query_Info"
```
Expected: No uninitMemberVar warnings for Query_Info

- [ ] **Step 4: Commit**

```bash
git add lib/MySQL_Session.cpp
git commit -m "fix: initialize all members in Query_Info constructor"
```

---

## Task 7: Fix uninitMemberVar in MySQL_Query_Processor_Output

**Files:**
- Modify: `include/MySQL_Query_Processor.h:15`

- [ ] **Step 1: Read the current constructor**

```cpp
// Line 15 in include/MySQL_Query_Processor.h
MySQL_Query_Processor_Output() = default;
```

- [ ] **Step 2: Fix to initialize all members**

```cpp
MySQL_Query_Processor_Output() = default;
// Note: inherits from Query_Processor_Output, ensure parent is initialized
// If parent constructor initializes all members, this should be fine
```

Actually, since this uses `= default` and inherits from `Query_Processor_Output`, the fix is already covered by Task 4. Verify:

- [ ] **Step 3: Verify with cppcheck**

```bash
cppcheck -I include --std=c++17 --enable=warning --suppress=missingIncludeSystem --max-configs=1 lib/MySQL_Session.cpp 2>&1 | grep "MySQL_Query_Processor_Output"
```
Expected: No uninitMemberVar warnings

- [ ] **Step 4: Commit (if changes needed)**

```bash
git add include/MySQL_Query_Processor.h
git commit -m "fix: ensure MySQL_Query_Processor_Output initializes inherited members"
```

---

## Summary

After completing all tasks, run final verification:

```bash
cppcheck -I include \
  -I deps/jemalloc/jemalloc/include \
  -I deps/mariadb-client-library/mariadb_client/include \
  -I deps/sqlite3/sqlite3 \
  -I deps/openssl/include \
  -I deps/prometheus-cpp/prometheus-cpp/core/include \
  -I deps/prometheus-cpp/prometheus-cpp/pull/include \
  -I deps/libconfig/libconfig/lib \
  -I deps/libmicrohttpd/libmicrohttpd/src/include \
  -I deps/curl/curl/include \
  -I deps/libev/libev \
  --std=c++17 --enable=warning --suppress=missingIncludeSystem --suppress=toomanyconfigs --max-configs=1 \
  lib/*.cpp 2>&1 | grep -v "deps/" | grep -E "(error|warning):" | wc -l
```

Expected: Significant reduction in warnings (from ~100+ to <20)