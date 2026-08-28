# ProxySQL: Understanding "Closing killed client connection" Warnings

## Introduction

ProxySQL logs the message `"Closing killed client connection <IP>:<PORT>"` as a final cleanup step when a client session that has already been marked for termination is removed from a worker thread. This warning appears **only after** the session has been marked as killed (`killed=true`), and it does **not** indicate the **reason** for the kill.

To diagnose why connections are being killed, you must look for earlier log entries that explain **why** the session was marked as killed in the first place.

## Two‑Phase Kill Process

ProxySQL handles client connection termination in two distinct phases:

1. **Kill Decision Phase**: A condition triggers the session to be marked as killed (`killed=true`).
   - **With warning**: Most timeout‑based mechanisms log a `"Killing client connection … because …"` warning at this point.
   - **Without warning**: Explicit kill commands (admin interface, client KILL statements) set `killed=true` silently.

2. **Cleanup Phase**: The worker thread detects `killed=true` and performs final cleanup, logging:
   `"Closing killed client connection <IP>:<PORT>"`

**Key Insight**: If you see **only** the `"Closing killed client connection …"` warning without a preceding `"Killing client connection because …"` message, the kill was triggered by an explicit command, **not** by a timeout.

---

## Kill Triggers That Log a Warning

These mechanisms log a `"Killing client connection … because …"` warning **before** setting `killed=true`.
If any of these are the cause, you will see **both** the reason warning **and** the final cleanup warning.

### 1. **Idle Timeout** (`wait_timeout`)
- **Trigger**: Client connection inactive (no queries) longer than `wait_timeout`.
- **Warning**:
  `"Killing client connection <IP>:<PORT> because inactive for <ms>ms"`
- **Configuration**:
  - `mysql‑wait_timeout` (global)
  - Client‑specific `wait_timeout` (if set via `SET wait_timeout=…`)

### 2. **Transaction Idle Timeout** (`max_transaction_idle_time`)
- **Trigger**: A transaction has been started but remains idle (no statements executed) longer than `max_transaction_idle_time`.
- **Warning**:
  `"Killing client connection <IP>:<PORT> because of (possible) transaction idle for <ms>ms"`
- **Configuration**: `mysql‑max_transaction_idle_time`

### 3. **Transaction Running Timeout** (`max_transaction_time`)
- **Trigger**: A transaction has been actively running (executing statements) longer than `max_transaction_time`.
- **Warning**:
  `"Killing client connection <IP>:<PORT> because of (possible) transaction running for <ms>ms"`
- **Configuration**: `mysql‑max_transaction_time`

### 4. **Fast‑Forward Mode with Offline Backends**
- **Trigger**: Session is in `session_fast_forward` mode and all backends are OFFLINE.
- **Warning**:
  `"Killing client connection <IP>:<PORT> due to 'session_fast_forward' and offline backends"`
- **Configuration**: `mysql‑session_fast_forward`

---

## Kill Triggers That Do **Not** Log a Warning

These triggers set `killed=true` **without** logging a `"Killing client connection because …"` warning.
You will see **only** the final `"Closing killed client connection …"` message.

### 1. **Admin‑Initiated Kill**
- **Trigger**: `KILL CONNECTION` command executed via the ProxySQL Admin interface.
- **Path**: `MySQL_Threads_Handler::kill_session()` → sets `killed=true` directly.
- **No warning logged** at kill decision time.

### 2. **Kill‑Queue Request**
- **Trigger**: `kill_connection_or_query()` called by:
  - MySQL client `KILL CONNECTION` or `KILL QUERY` statements
  - Admin‑interface kill commands (same as above)
- **Path**:
  `kill_connection_or_query()` → places request in per‑thread queue → `Scan_Sessions_to_Kill()` processes queue → sets `killed=true`.
- **No warning logged** when `killed=true` is set.

---

## Log Analysis and Troubleshooting Guide

### Scenario 1: You see **both** warnings
```
[WARNING] Killing client connection 192.168.123.45:56789 because inactive for 3600000ms
[WARNING] Closing killed client connection 192.168.123.45:56789
```
**Diagnosis**: A timeout mechanism killed the connection.
**Action**: Adjust the relevant timeout variable (`wait_timeout`, `max_transaction_idle_time`, etc.) or investigate why the client stayed idle so long.

### Scenario 2: You see **only** the cleanup warning
```
[WARNING] Closing killed client connection 192.168.123.45:56789
```
**Diagnosis**: The connection was killed by an explicit command (admin or client KILL).
**Action**:
1. Check if any component (application, connection pool, admin script) is issuing `KILL CONNECTION` commands.
2. Review ProxySQL admin logs for `KILL` commands.
3. Check application logs for connection‑pool cleanup activities.

### Scenario 3: Many cleanup warnings appear unexpectedly
**Possible Causes**:
1. **Connection‑pool cleanup**: Pools that aggressively close idle connections may issue `KILL` commands.
2. **Admin automation**: Scripts or monitoring tools that kill “stuck” connections.
3. **Client applications**: Applications that manually kill their own connections.

**Investigation Steps**:
1. **Enable audit logging**:
   ```sql
   SET mysql-auditlog_filename='/var/log/proxysql_audit.log';
   LOAD MYSQL VARIABLES TO RUNTIME;
   ```
   Audit logs capture `KILL` commands with source IP and username.

2. **Check `stats_mysql_commands_counters`**:
   ```sql
   SELECT * FROM stats_mysql_commands_counters WHERE Command='Kill';
   ```
   Shows how many `KILL` commands have been executed.

3. **Monitor active kills**:
   ```sql
   SELECT * FROM stats_mysql_processlist WHERE info LIKE 'KILL%';
   ```
   Shows currently executing `KILL` commands.

4. **Review client‑side logs**: Look for connection‑pool or application‑layer kill patterns.

---

## Configuration Parameters Reference

| Variable | Default | Description |
|----------|---------|-------------|
| `mysql‑wait_timeout` | 28800000 ms (8 hours) | Maximum idle time before connection is killed. |
| `mysql‑max_transaction_idle_time` | 0 (disabled) | Maximum idle time for an open transaction. |
| `mysql‑max_transaction_time` | 0 (disabled) | Maximum total time a transaction can run. |
| `mysql‑session_fast_forward` | false | Enable fast‑forward mode (kills connections if backends go OFFLINE). |
| `mysql‑throttle_max_transaction_time` | 0 (disabled) | Alternative to `max_transaction_time`; throttles instead of kills. |

**Note**: Timeouts are expressed in **milliseconds**. A value of `0` disables the timeout.

---

## Best Practices for Monitoring and Handling

### 1. **Differentiate Between Expected and Unexpected Kills**
- **Expected**: Connection‑pool cleanup, scheduled maintenance, application‑controlled termination.
- **Unexpected**: Unknown source of `KILL` commands, timeouts that are too aggressive for your workload.

### 2. **Set Appropriate Timeouts**
- **Production**: Align `wait_timeout` with your application’s connection‑pool `idleTimeout`.
- **Transactions**: Enable `max_transaction_idle_time` and `max_transaction_time` to prevent runaway transactions.
- **Testing**: Start with conservative values and adjust based on observed behavior.

### 3. **Use Audit Logging for Forensic Analysis**
```sql
-- Enable audit logging
SET mysql-auditlog_filename='/var/log/proxysql_audit.log';
SET mysql-auditlog_filesize=1000000;
SET mysql-auditlog=true;
LOAD MYSQL VARIABLES TO RUNTIME;
SAVE MYSQL VARIABLES TO DISK;
```
Audit logs record every `KILL` command with timestamp, client IP, and username.

### 4. **Monitor Kill Statistics**
```sql
-- Track kill sources
SELECT
    SUM(CASE WHEN Command='Kill' THEN Total_Time_us ELSE 0 END) AS kill_time_us,
    SUM(CASE WHEN Command='Kill' THEN cnt ELSE 0 END) AS kill_count
FROM stats_mysql_commands_counters;

-- Check for recent kills in the processlist
SELECT * FROM stats_mysql_processlist
WHERE info LIKE 'KILL%'
ORDER BY time_ms DESC
LIMIT 10;
```

### 5. **Responding to Unexpected Kill Storms**
1. **Identify the source** via audit logs and `stats_mysql_commands_counters`.
2. **If client applications**: Coordinate with developers to adjust connection‑pool settings.
3. **If admin scripts**: Review automation logic and add appropriate guards.
4. **If unknown**: Temporarily enable verbose logging (`mysql‑query_processor_log`) to capture more context.

---

## Common Questions and Answers

### Q: Why don’t I see a “Killing client connection because …” warning?
**A**: The kill was triggered by an explicit `KILL` command (admin or client), not by a timeout. Explicit kills do not log a reason at the moment `killed=true` is set.

### Q: Can I disable the “Closing killed client connection” warnings?
**A**: Yes, by lowering the log‑verbosity level. However, doing so removes visibility into connection termination. Instead, investigate and address the root cause of the kills.

### Q: Are PostgreSQL connections handled differently?
**A**: The same two‑phase pattern applies to PostgreSQL, with analogous timeout variables (`pgsql‑wait_timeout`, etc.) and kill mechanisms. The warning messages are similar but may appear in `PgSQL_Thread` instead of `MySQL_Thread`.

### Q: How can I distinguish between a client `KILL` and an admin `KILL`?
**A**: Audit logs show the source IP and username. Client `KILL` commands originate from application IPs; admin `KILL` commands come from the admin‑interface IP (usually `127.0.0.1` or your admin network).

### Q: What should I do if kills are causing application errors?
**A**:
1. Verify timeout values match your application’s expected behavior.
2. Ensure connection pools are configured to `KILL` connections gracefully (e.g., with `COM_QUIT` instead of `KILL CONNECTION`).
3. Consider increasing timeouts temporarily while diagnosing.

---

## Summary

The `"Closing killed client connection …"` warning is a **cleanup message**, not a **root‑cause indicator**. Diagnosing why connections are killed requires examining earlier logs for `"Killing client connection because …"` warnings or identifying explicit `KILL` commands via audit logs and statistics.

- **Timeout kills** → preceded by a reason warning.
- **Explicit kills** → no preceding reason warning.

Use the troubleshooting steps and monitoring practices outlined above to identify the source of kills and adjust your configuration or application behavior accordingly.