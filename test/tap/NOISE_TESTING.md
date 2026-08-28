# ProxySQL TAP Test Noise Injection Framework

The Noise Injection framework (Approach 2) is designed to increase the complexity and realism of functional TAP tests by introducing concurrent background activity. This helps identify race conditions, deadlocks, and stability issues that might not surface in single-threaded functional tests.

## Overview

When enabled, a TAP test can spawn one or more background "noise" tools. These tools run independently of the test logic, generating load against various ProxySQL interfaces (MySQL, PostgreSQL, Admin, Stats).

- **Global Toggle:** Controlled by an environment variable.
- **Automatic Cleanup:** All spawned tools are automatically killed when the test finishes via `exit_status()`.
- **Fatal Failure Detection:** If a noise tool fails critically (e.g., permanent connection loss), the main TAP test will report a failure.
- **Isolation:** Noise tools run in their own process groups (external) or threads (internal). External tool `stdout` is redirected to `/dev/null`, while `stderr` is preserved for debugging.

## Configuration

### Environment Variable
The framework is globally controlled by the `TAP_USE_NOISE` environment variable.

| Value | Effect |
| :--- | :--- |
| `1` or `true` | Enables noise injection. |
| `0` or `false` (default) | Disables noise injection. `spawn_noise()` becomes a no-op. |

### Path Resolution
Noise tools are typically located in `test/tap/noise/`. When calling `spawn_noise`, you can provide the relative path to these scripts or absolute paths to system binaries.

## Standard Noise Tools (External)

Initial noise scripts are provided in `test/tap/noise/`:

1.  **`noise_stats_poller.py`**: Periodically queries `stats_mysql_query_digest` and `stats_mysql_connection_pool`.
2.  **`noise_admin_pinger.sh`**: Executes `SELECT 1` against the Admin interface.
3.  **`noise_pgsql_poller.sh`**: Generates simple PostgreSQL traffic using `psql`.

## Built-in Noise Routines (Internal)

Internal routines run as threads within the TAP test process. This is **highly recommended for debugging with GDB**, as stopping the test process will also pause the noise.

### Standard Internal Noise Functions:
- `internal_noise_admin_pinger`: Executes `SELECT 1` against Admin (default 200ms).
- `internal_noise_stats_poller`: Polls various `stats_*` tables (default 200ms).
- `internal_noise_prometheus_poller`: Fetches Prometheus metrics via both MySQL and PostgreSQL protocol (default 1000ms).
- `internal_noise_random_stats_poller`: Shuffles and queries a set of MySQL and PostgreSQL stats tables (default 500ms).
- `internal_noise_mysql_traffic`: Generates unprivileged query load on the main MySQL port (default 100ms).
- `internal_noise_pgsql_traffic`: Generates unprivileged query load on the main PostgreSQL port (default 100ms).
- `internal_noise_pgsql_traffic_v2`: High-concurrency PostgreSQL load generator with automatic table setup, row population (10k rows), and multi-threaded workers (default 20 connections, 200ms delay).
- `internal_noise_mysql_traffic_v2`: High-concurrency MySQL load generator with automatic table setup, row population (10k rows), and multi-threaded workers (default 20 connections, 200ms delay).
- `internal_noise_rest_prometheus_poller`: Periodically scrapes metrics via the REST API (default 1000ms). Supports `enable_rest_api` auto-configuration.

## Usage in C++ TAP Tests

Include `utils.h` and `noise_utils.h`.

```cpp
#include "tap.h"
#include "command_line.h"
#include "utils.h"
#include "noise_utils.h"

int main(int argc, char** argv) {
    CommandLine cl;
    if (cl.getEnv()) return exit_status();

    // --- Configuration ---
    NoiseOptions opt;
    opt["interval_ms"] = "100";
    opt["max_retries"] = "10";

    // --- Spawning ---
    // External (separate process)
    spawn_noise(cl, "../noise/noise_stats_poller.py", {"--interval", "0.1"});

    // Internal (same process, GDB-friendly)
    spawn_internal_noise(cl, internal_noise_admin_pinger, opt);

    // --- TAP Plan ---
    // You MUST increase the plan count by the number of spawned noise tools
    // only if noise is enabled.
    int expected_functional_tests = 10;
    if (cl.use_noise) {
        plan(expected_functional_tests + 2); // 10 tests + 2 noise tools
    } else {
        plan(expected_functional_tests);
    }

    // ... your test logic here ...
    ok(perform_op(), "Functional test 1");
    // ...

    return exit_status(); // Automatically cleans up noise and verifies their success
}
```

## Internal Safety Mechanisms

1.  **Process Group Isolation**: `spawn_noise` calls `setpgid(0, 0)` in the child. This ensures that signals like `SIGINT` (Ctrl+C) sent to the test runner are not automatically forwarded to the noise tools.
2.  **Fatal Failure Propagation**: If an internal noise routine fails critically (e.g., exceeds `max_retries` during connection), it calls `register_noise_failure(routine_name)` which appends the error to the global `noise_failures` vector.
3.  **Lifecycle Management**:
    *   `exit_status()` calls `stop_noise_tools()`.
    *   If `noise_failures` is not empty, `exit_status()` reports the failed routines and returns `EXIT_FAILURE` even if all functional tests passed.
4.  **Graceful Termination**: The framework sends `SIGTERM` first, waits 100ms for the process to reap, and follows up with `SIGKILL` if the process is still alive.

## Testing the Framework

A dedicated verification test is provided:
```bash
# From test/tap/tests
TAP_USE_NOISE=1 ./test_noise_injection-t
```
