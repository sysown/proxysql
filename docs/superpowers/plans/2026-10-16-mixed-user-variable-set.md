# Mixed user-variable SET implementation plan

**Goal:** Track the two initialization statements in sysown/proxysql#6479 without binding a backend for the client's lifetime.

**Design:** Extend the existing pending user-variable SET analysis with ordered, validated session assignments. Initially accept only `max_execution_time` (unsigned decimal integer, 0..4294967295) and `wait_timeout` (unsigned decimal integer, 1..1728000 seconds), with implicit session scope, SESSION, LOCAL, or corresponding @@ qualifiers. Every other system target and every context-changing target falls back atomically. Retain original SQL and commit frontend/backend state only after a warning-free backend OK. Treat OK with warnings conservatively as backend-authoritative fallback. Apply wait_timeout to the frontend only after OK and reset its backend before pool reuse; never reset an attached active transaction.

ParserSQL 1.1.1 already exposes the required typed AST; no dependency change is planned unless regression tests reveal a grammar/information-loss defect.

- [x] Add failing analyzer and integration coverage for successful mixed assignments, scope/order/repeats, failures, pool isolation and replay.
- [x] Extend typed analysis and stage both kinds without mutating session state.
- [x] Commit after clean backend OK; clear pending state on existing failure/reset paths; reset ignored backend timeout before pooling.
- [x] Run parser/state unit tests, build the server and run the integration suite against isolated MySQL/ProxySQL instances.
- [x] Update user-variable tracking documentation and review the final diff.

**Review focus:** inherited GLOBAL scope must never become session tracking; warnings cannot certify an exact backend value; resource-limit fallback cannot partially commit; ignored backend timeouts must not leak; active transactions must not be reset by cleanup.


## Validation and review

- Native server/core build completed with C++17 and the committed ParserSQL 1.1.1 archive; existing compiled dependencies were reused from a local cache.
- Parser adapter: 271 checks; user-variable connection/state: 74 checks; digest fallback: 92 checks; MySQL 8.0.46 integration: 64 checks.
- Live warning regression: a separate MySQL instance started with `--maximum-max-execution-time=100` clamps a mixed assignment requesting 1000. Before the review fix, the hostgroup stayed -1. After the fix, it is locked to the authoritative hostgroup, cross-hostgroup routing is rejected, and the backend retains its actual user-variable value and `max_execution_time=100`.
- Independent code review found the missing post-OK hostgroup lock on warning fallback; fixed and verified with the live regression.
- Repeated timeout targets initially incremented the command counter twice. A failing integration check now passes with last-value semantics and one counter increment per command.
- Additional run with global multiplexing disabled passes all new mixed-SET checks but fails the existing exact-backend-ID assertion after COM_CHANGE_USER. The original integration test from HEAD reproduces the same failure without any mixed-SET traffic; that separate assertion is unchanged.
- TAP clang-tidy cannot complete with its generated include paths (`jemalloc.h` missing), and reports existing style diagnostics. The native compiler build and runtime tests above pass.
