# AWS RDS BGD TAP Style Rules

These rules apply to every new or refactored AWS RDS BGD TAP file.

## Test Scope And Documentation

- Use one TAP executable per independently reportable behavior.
- Keep each TAP executable focused on the behavior named by the file. Do not
  add connection-pool, TLS, server-status, or other property mutations unless
  that behavior requires them.
- Move independently useful coverage into a dedicated TAP executable instead
  of carrying it through an unrelated scenario.
- File and test headers must name the exact BGD configuration change, topology
  state, and expected ProxySQL result.
- Use names from the BGD implementation and Admin tables. Avoid generic wording
  such as "surface", "departure", or "input replacement".
- Document multi-step tests with setup, mutation, and verification bullets.
- Test public configuration and observable routing, runtime, connection-pool,
  and probe behavior. Do not test or document non-public internal server states.

## Local Test Harness

- Every BGD TAP file defines local `setup()` and `cleanup()` functions.
- `setup()` initializes only the test harness: load the TAP environment,
  connect to ProxySQL Admin, and connect to the SQLite simulator.
- `setup()` must not configure BGD topology, Admin rows, simulated writer
  state, or other scenario prerequisites.
- `setup()` must not contain TAP assertions.
- `setup()` releases any partially created connection before returning a
  failure. `main()` then returns `exit_status()` without calling `cleanup()`.
- `cleanup()` clears the ProxySQL Admin/runtime and simulator state created by
  the test, then closes test connections.
- `cleanup()` is called only after `setup()` succeeds and may assume its
  connections are valid.
- `cleanup()` attempts every cleanup operation, closes test connections, and
  returns `EXIT_FAILURE` if any Admin or simulator cleanup operation fails.
- A cleanup failure must fail the TAP executable so the developer and CI can
  see that the test did not leave a clean state.
- Store the Admin and simulator cleanup results separately. Log each failure
  with an `Error:` diagnostic, continue with the remaining cleanup operations,
  and return one combined result.
- Close the Admin connection immediately after its cleanup operation. Do not
  skip connection closure because cleanup failed.
- Do not wait for probe quiescence during cleanup.
- After harness setup succeeds, failures must flow to a single
  `exit_cleanup:` label in `main()`. That label always calls the local
  `cleanup()` function.
- Declare the TAP plan before calling `setup()`. After `exit_cleanup:`, return
  `EXIT_FAILURE` when cleanup fails; otherwise return `exit_status()`. A setup
  failure is then reported as missing planned assertions instead of bypassing
  TAP result handling.
- At `exit_cleanup:`, check `cleanup()` directly without a temporary result.
  Return `EXIT_FAILURE` immediately when cleanup fails.
- Do not use `BAIL_OUT()` after test resources have been created or test state
  has been changed. Log the failure, set the process result, and continue to
  `exit_cleanup:`.
- Do not register global pointers or `atexit` handlers for test cleanup.
- A test assumes clean ProxySQL and simulator state at entry. Do not clear
  state at the start of `setup()` or the test function.
- Scenario topology, ProxySQL configuration, mutations, waits, and TAP
  assertions belong in the named test function.
- Keep `main()` limited to `plan()`, `setup()`, the named test, the
  `exit_cleanup:` path, and the TAP exit status.

## C++ Layout

- Do not wrap TAP test files in an anonymous namespace. Each TAP file builds as
  its own executable, so file-local namespace isolation is unnecessary.
- When phases share local state, name the struct `TestState`. Do not include
  the test or file name in the local state type.
- Call the named test phases directly from `main()`. Do not add a wrapper test
  function whose only job is to call the phases.
- The comment before each phase call in `main()` must make the phase
  understandable without opening the function. State the concrete simulator
  or ProxySQL configuration, the BGD status or server placement being
  produced, and the observable result being verified.
- Do not write call-site comments that merely restate the function name or use
  vague verbs such as "establish", "prepare", "handle", or "process".
- Keep call-site phase comments concise, but use exact BGD statuses,
  hostgroups, tables, or server roles where they matter.
- Name simulator state helpers after the exact variable and value being set,
  such as `set_writer_read_only_0()`. Avoid interpreted names such as
  `set_writers_writable()`.
- Organize phase comments by the system being acted on, using labels such as
  `Simulator:`, `ProxySQL:`, `Client:`, and `Verify:`. Include only the
  applicable systems, and state the concrete action or expected result for
  each one.
- Always use braces for `if` statements, including one-line bodies:

  ```cpp
  if (condition) {
      action();
  }
  ```

- Keep complete function declarations, definitions, and calls on one line
  whenever they remain readable. Use 120 characters as a guideline, not a
  hard limit; prefer a small overrun to splitting a simple call across lines.
  Wrap only when the complete statement is materially too long.
- Do not add `const` qualifiers to function parameters in these TAP files.
  Prefer shorter, simpler signatures over strict const-correctness in
  test-local helpers.
- Build SQL strings, expected-result text, and list arguments in named local
  variables before calling a helper. Do not mix string concatenation,
  temporary lists, and the function call in one statement.
- Format query helpers in four visible blocks separated by blank lines:
  construct the query, construct related arguments, call the helper, and
  return the stored result.
- When a helper call must wrap, group related arguments across as few lines as
  possible and place the closing `);` on its own line.
- Keep return statements simple. Store a function result in a local variable
  and return that variable instead of returning a large function call or a
  heavily combined expression.
- Do not create duplicate query helpers that differ only by one expected
  value. Pass that expected value as an argument to one clearly named helper.
- Do not place multiple function calls inside one `ok()` condition. Evaluate
  each call into a clearly named local variable first, then combine those
  boolean variables in the assertion.
- When a helper performs multiple function calls, execute them one at a time.
  Return `EXIT_FAILURE` immediately after the specific call that fails, then
  return `EXIT_SUCCESS` after all calls succeed. Do not combine calls with
  `&&` and a ternary return.
- Apply the same sequential pattern inside test phases. Separate each
  call-and-failure-check block with a blank line; do not conditionally invoke
  later operations through ternary expressions.
- Before returning `EXIT_FAILURE` from setup, helper, phase, or `main()`, emit
  a diagnostic beginning with `Error:` that names the failed operation.
  Cleanup may log its individual failures before returning one combined
  result.
- Shared condition and probe wait helpers must only return their result. They
  must not dump timeout diagnostics; the calling phase logs the relevant
  `Error:` message.
- Use `bgd_expect_no_table_check()` and `bgd_expect_no_metadata_probe()` for
  negative probe checks instead of duplicating timeout logic in TAP files.
  Pass the bounded timeout explicitly; these helpers return success only when
  the unwanted probe wait returns `ETIMEDOUT`.
- Pass wait helpers only the values required to perform the wait. Do not pass
  scenario names, phase names, expected text, probe sequences, or hostgroup
  lists solely for generic diagnostics.
- Do not add `ok(false, ...)` to a failure-return path. Emit the `Error:`
  diagnostic and return `EXIT_FAILURE`; the incomplete TAP plan will fail the
  executable.
- Assertion messages and phase names must identify concrete BGD statuses,
  hostgroups, tables, or server movements. Avoid undefined relational wording
  such as "original definition", "current state", or "changed setup".
- In assertion messages, describe a runtime BGD status as
  `BGD status for wHG <id>` instead of the longer
  `runtime BGD row for writer hostgroup <id>`.
- Separate environment loading, Admin connection, and simulator connection
  into distinct blocks with blank lines.
- Separate setup, test execution, and cleanup calls in `main()` with blank
  lines.
- Use `RDS_BGD_Cluster::get_endpoints()`, `get_blue_endpoints()`, and
  `get_green_endpoints()` instead of rebuilding endpoint lists with reader
  loops in individual tests.
- Keep positive condition and probe waits at three seconds or less. Use bounded
  waits instead of fixed sleeps.
