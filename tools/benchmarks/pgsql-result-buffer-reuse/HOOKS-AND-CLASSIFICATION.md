# Disabled timing hooks and remaining command-classification work

These notes refer to the current deferred-I/O/phased source. The accompanying source copies are for inspection; the result-buffer experiment does not change these functions.

## Disabled timing hook

Definition: [lib/PgSQL_Thread.cpp:84](source/PgSQL_Thread.cpp#L84).

```cpp
static void pgsql_loop_timing_point(unsigned phase, int poll_rc = 0) {
    static const char *path = getenv("PX_PGSQL_LOOP_TIMING");
    if (!path) return;
    const int saved_errno = errno;
    // Two clock reads, phase accounting and periodic output follow.
}
```

`getenv()` is evaluated once, when the function-local static is initialized. With the environment variable absent, the clock reads and reporting are skipped, but the function calls, generated entry/return work, and static/gate checks remain. The earlier profiles measured about 1.65–1.76% of worker userspace cycles in this function itself. This is experimental diagnostic overhead, not an upstream behavior claim.

The 16 call sites in `lib/PgSQL_Thread.cpp` are:

| Line | Boundary |
|---:|---|
| 3435 | Begin next outer iteration |
| 3546 | Before periodic waiter rearm |
| 3564 | Before poll |
| 3568 | Immediately after poll |
| 3645 | Before poll-error check |
| 3663 | Begin runnable-flag reset |
| 3676 | Begin after-poll processing |
| 3721 | Begin waiter-rearm cleanup |
| 3773 | Begin session-processing setup |
| 3780 | Begin local-pool publication |
| 3785 | Outer-iteration tail |
| 4616 | Begin availability and waiter retries |
| 4639 | Begin early frontend dispatch |
| 4670 | Begin backend-owning session scan |
| 4814 | Begin remaining backendless session scan |
| 4838 | Begin session accounting / return |

A possible subsequent change is an inline enable gate at each call site, with enabled-only timestamp/accounting code in an out-of-line function. It must preserve errno and the existing initialization/enable semantics. It is not included in the buffer benchmarks.

## Command classification

The actual legacy classifier starts at [lib/PgSQL_Query_Processor.cpp:798](source/PgSQL_Query_Processor.cpp#L798). Its SELECT case is at line 1231, and cancellation/termination refinement is at line 659.

After the previous snprintf-to-memcpy fix, its observed path still accounts for about 4.64% of worker userspace cycles in the DWARF capture. The path still:

1. Scans the full input length in `tokenizer()`.
2. Copies short input into the tokenizer buffer, or duplicates longer input on the heap.
3. Scans for delimiters and overwrites them with NUL bytes.
4. Calls case-insensitive string comparisons to classify the resulting tokens.
5. For SELECT, reads the next token and checks intercepted cancellation/termination calls.

The next general improvement is a non-owning token cursor: return a pointer and length into the original immutable text. Compare token length with the compile-time keyword length before a bounded case-insensitive comparison. For instance, a six-byte SELECT token cannot be the nine-byte SAVEPOINT token, so that case needs no character comparison. Leading parentheses can be handled by advancing the view, without calling strlen to find whether another byte exists.

This eliminates the initial whole-input copy and long-input allocation, and lets the classifier scan only as many tokens as it needs. It is not a SELECT 1 cache or special case.

There is also a smaller independent target: `pgsql_stmt_first_keyword_is()` in `lib/pgsql_tokenizer.cpp:3519` calls `strlen(keyword)` in an out-of-line function. The SELECT target helper calls it with literal names `pg_cancel_backend` and `pg_terminate_backend`; those lengths are known at compile time. A literal-length overload/helper could avoid that length scan while preserving the existing case and identifier-boundary rules.

Behavior to preserve includes the legacy `" ;"` delimiter set, empty tokens, leading parentheses, multi-token DDL categories, ROLLBACK variants, NULL input, and cancellation/termination classification. A bounded token view cannot be passed blindly to a helper expecting a NUL-terminated token. That helper needs a length-aware equivalent or an explicit safe fallback.

Request command classification and completion-time connection-pinning checks are separate jobs. Recognizing SELECT does not establish that a query has no session effects, so it is not sufficient to skip completion-state tracking.

No classifier rewrite or hook optimization is included in the buffer commits. Their performance effects should be measured separately.
