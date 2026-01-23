# Scheduler

:::info
**Note**: Changes made to the configuration on this page must be explicitly loaded to the runtime to take effect. Please refer to the **[Admin Commands](../the_admin_schemas/admin_commands)** documentation for details on the `LOAD` and `SAVE` commands.
:::

## Overview

ProxySQL includes a built-in **Scheduler** designed to execute external scripts at regular intervals. This powerful feature allows administrators to extend ProxySQL's functionality by automating tasks such as:
- Custom health checks for non-standard backends.
- Dynamic reconfiguration based on external events.
- Advanced monitoring and alerting.
- Interaction with external service discovery tools (Consul, ZooKeeper).

The scheduler runs in its own dedicated thread and can manage multiple concurrent tasks.

---

## Configuration

The scheduler is configured via the `scheduler` table in the **Admin** interface.

### Table Schema: `scheduler`

| Column | Type | Description |
| :--- | :--- | :--- |
| `id` | INTEGER | Unique identifier for the task. |
| `active` | BOOLEAN | Set to `1` to enable the task, `0` to disable. |
| `interval_ms` | INTEGER | The execution interval in milliseconds. (Minimum: 100ms). |
| `filename` | VARCHAR | The full path to the executable script or binary. |
| `arg1`..`arg5` | VARCHAR | Optional arguments passed to the script. |
| `comment` | VARCHAR | Free-form text for documentation purposes. |

### Example: Adding a Task

```sql
INSERT INTO scheduler (id, active, interval_ms, filename, arg1) 
VALUES (10, 1, 5000, '/usr/local/bin/check_backend.sh', 'hostgroup_1');
```

---

## Technical Details

### Execution Model
The scheduler uses a **non-blocking asynchronous model**:
1.  **Forking**: For every task execution, ProxySQL performs a `fork()`.
2.  **Execution**: The child process executes the script using `execve()` with an empty environment for security.
3.  **Cleanup**: ProxySQL spawns a lightweight, detached thread to perform a non-blocking `waitpid()`, ensuring no zombie processes are left on the system.

### Precision
The scheduler uses `monotonic_time()` to calculate the next execution run, ensuring that system clock jumps (e.g., via NTP) do not cause unexpected task bursts or delays.

---

## Activation & Persistence

Like most ProxySQL modules, changes to the `scheduler` table are not active until loaded.

- **To Activate**: `LOAD SCHEDULER TO RUNTIME`
- **To Persist**: `SAVE SCHEDULER TO DISK`

*See the **[Admin Commands](../the_admin_schemas/admin_commands)** documentation for more details.*

---

## Security Considerations

- **Permissions**: The ProxySQL process must have execute permissions on the `filename` specified.
- **Environment**: Scripts are executed with an empty environment. Any required variables (like `PATH` or database credentials) should be explicitly set within the script or passed as arguments.
- **Isolation**: Scripts run as the same user as the ProxySQL process. Ensure the script itself is secure and follows best practices.

---
**Apply your changes**: Remember to use the appropriate `LOAD` and `SAVE` commands to activate and persist your configuration. See the complete **[Admin Commands](../the_admin_schemas/admin_commands)** reference.
