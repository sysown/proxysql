# ProxySQL TAP Test Noise Injection Framework

The Noise Injection framework (Approach 2) is designed to increase the complexity and realism of functional TAP tests by introducing concurrent background activity. This helps identify race conditions, deadlocks, and stability issues that might not surface in single-threaded functional tests.

## Overview

When enabled, a TAP test can spawn one or more background "noise" tools. These tools run independently of the test logic, generating load against various ProxySQL interfaces (MySQL, PostgreSQL, Admin, Stats).

- **Global Toggle:** Controlled by an environment variable.
- **Automatic Cleanup:** All spawned tools are automatically killed when the test finishes via `exit_status()`.
- **Isolation:** Noise tools run in their own process groups with I/O redirected to `/dev/null` to avoid polluting TAP output.

## Configuration

### Environment Variable
The framework is globally controlled by the `TAP_USE_NOISE` environment variable.

| Value | Effect |
| :--- | :--- |
| `1` or `true` | Enables noise injection. |
| `0` or `false` (default) | Disables noise injection. `spawn_noise()` becomes a no-op. |

### Path Resolution
Noise tools are typically located in `test/tap/noise/`. When calling `spawn_noise`, you can provide the relative path to these scripts or absolute paths to system binaries.

## Standard Noise Tools

Initial noise scripts are provided in `test/tap/noise/`:

1.  **`noise_stats_poller.py`**:
    *   **Action**: Periodically queries `stats_mysql_query_digest` and `stats_mysql_connection_pool`.
    *   **Arguments**: `--host`, `--port`, `--user`, `--password`, `--interval`.
2.  **`noise_admin_pinger.sh`**:
    *   **Action**: Executes `SELECT 1` against the Admin interface.
    *   **Arguments**: `[host] [port] [user] [pass] [interval]`.
3.  **`noise_pgsql_poller.sh`**:
    *   **Action**: Generates simple PostgreSQL traffic using `psql`.
    *   **Arguments**: `[host] [port] [user] [pass] [interval]`.

## Usage in C++ TAP Tests

Include `utils.h` and `noise_utils.h`.

### External Tools
Use `spawn_noise` to run scripts or binaries in a separate process.
```cpp
spawn_noise(cl, "../noise/noise_stats_poller.py", {"--interval", "0.1"});
```

### Internal Threads
Use `spawn_internal_noise` to run built-in C++ functions in background threads within the same process. This is **highly recommended for debugging with GDB**, as stopping the test process will also pause the noise.

```cpp
#include "noise_utils.h"

// ... inside main ...
spawn_internal_noise(cl, internal_noise_admin_pinger);
```

#### Standard Internal Noise Functions:
- `internal_noise_admin_pinger`: Executes `SELECT 1` against Admin every 500ms.
- `internal_noise_stats_poller`: Polls various `stats_*` tables every 200ms.
- `internal_noise_prometheus_poller`: Fetches Prometheus metrics via both MySQL and PostgreSQL protocol every 1000ms.
- `internal_noise_random_stats_poller`: Shuffles and queries a set of MySQL and PostgreSQL stats tables (e.g., `stats_mysql_query_digest`, `stats_pgsql_processlist`) every 500ms.

## Internal Safety Mechanisms

1.  **Process Group Isolation**: `spawn_noise` calls `setpgid(0, 0)` in the child. This ensures that signals like `SIGINT` (Ctrl+C) sent to the test runner are not automatically forwarded to the noise tools, allowing the `utils` library to manage their shutdown sequence explicitly.
2.  **Double-Hook Cleanup**:
    *   **Primary**: `exit_status()` calls `stop_noise_tools()`.
    *   **Fallback**: An `atexit()` handler is registered during the first `spawn_noise` call to catch unexpected (but clean) exits.
3.  **Graceful Termination**: The framework sends `SIGTERM` first, waits 100ms for the process to reap, and follows up with `SIGKILL` if the process is still alive.

## Testing the Framework

A dedicated verification test is provided:
```bash
# From test/tap/tests
TAP_USE_NOISE=1 ./test_noise_injection-t
```
This test spawns a bash sub-process, verifies it is alive via its PID, and then verifies it is successfully killed by the cleanup logic.
