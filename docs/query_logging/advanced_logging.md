# Advanced Event and Query Logging

**Version Introduced**: ProxySQL 2.7.2

## Overview

The Advanced Event and Query Logging feature provides a powerful mechanism to capture, store, and analyze
events in ProxySQL. It is designed for all ProxySQL users but is especially beneficial for high-performance
setups. The feature is invaluable for **troubleshooting**, **auditing**, **performance analysis**, and
**real-time traffic insights**, enabling statistical and pattern analysis, such as failure patterns and
Service Level Objectives (SLO) monitoring.

## High-Level Architecture and Data Flow

1. **Circular Buffer**:

   - A configurable, fixed-size circular buffer temporarily stores recent events.
   - Events are overwritten when the buffer becomes full unless transferred elsewhere.

2. **Storage Options**:

   - **In-Memory SQLite Table**: Provides fast, real-time access for analysis.
   - **On-Disk SQLite Table**: Offers persistent storage for long-term retention.

3. **Event Transfer**:

   - Events are transferred asynchronously to the SQLite tables using commands or at defined intervals.
   - Supported transfer commands:
     - `DUMP EVENTSLOG FROM BUFFER TO MEMORY`
     - `DUMP EVENTSLOG FROM BUFFER TO DISK`
     - `DUMP EVENTSLOG FROM BUFFER TO BOTH`

4. **Performance Optimization**:

   - A dedicated thread manages event logging to prevent performance impact on real-time traffic.
   - Writes are batched to minimize disk I/O.

5. **Dynamic Configuration**:
   - Configuration variables can be adjusted at runtime, ensuring flexibility and adaptability to different
     workloads.

---

## Configuration

The following configuration variables control the behavior of the logging system:

| Variable                                  | Description                                                                 | Default Value | Notes                                                   |
| ----------------------------------------- | --------------------------------------------------------------------------- | ------------- | ------------------------------------------------------- |
| `mysql-eventslog_buffer_history_size`     | Defines the size of the circular buffer in number of events.                | `0`           | Setting to `0` disables the feature.                    |
| `mysql-eventslog_table_memory_size`       | Maximum number of events in the in-memory table.                            | `10000`       | Automatic cleanup is triggered if the limit is reached. |
| `mysql-eventslog_sync_buffer_to_disk`     | Time interval (in seconds) for auto-dumping events from the buffer to disk. | `0`           | `0` disables auto-dumping.                              |
| `mysql-eventslog_buffer_max_query_length` | Maximum allowed length for tracked SQL queries.                             | Unlimited     | Longer queries are truncated.                           |

---

## Commands

The following commands control the event logging system:

1. **Dump Events**:

   - `DUMP EVENTSLOG FROM BUFFER TO MEMORY`
   - `DUMP EVENTSLOG FROM BUFFER TO DISK`
   - `DUMP EVENTSLOG FROM BUFFER TO BOTH`

2. **Applying Settings**:
   ```sql
   SET mysql-eventslog_buffer_history_size = 1000000;
   SET mysql-eventslog_default_log = 1; -- Enables query logging
   LOAD MYSQL VARIABLES TO RUNTIME; -- Applies the settings
   ```

---

## Usage Examples

### Basic Setup

Enable query logging and set a circular buffer of 1,000,000 events:

```sql
SET mysql-eventslog_buffer_history_size = 1000000;
SET mysql-eventslog_default_log = 1;
LOAD MYSQL VARIABLES TO RUNTIME;
```

### Dump and Analyze Events

Dump events from the buffer to the in-memory SQLite table and analyze them:

```sql
DUMP EVENTSLOG FROM BUFFER TO MEMORY;
SELECT * FROM stats_mysql_query_events;
```

Example query for statistical analysis:

```sql
SELECT query, COUNT(*) AS count
FROM stats_mysql_query_events
GROUP BY query
ORDER BY count DESC
LIMIT 10;
```

---

## Best Practices

- Always monitor **memory** and **disk usage** when enabling event logging.
- Use `mysql-eventslog_buffer_history_size` to control memory usage and avoid overflows.
- Disable the feature when not in use to conserve resources.
- Set appropriate retention policies based on available resources and requirements for real-time or long-term
  analysis.

---

## Performance Metrics

The following metrics are available for monitoring the event logging system. Please note that as usual,
metrics naming and unit can differ between `stats` table and Prometheus due to convention rules.

From `stats_mysql_global` in `stats` database:

| Metric Name                                     | Description                                                              | Exposure                  |
| ----------------------------------------------- | ------------------------------------------------------------------------ | ------------------------- |
| `MySQL_Logger-totalEventsCopiedToMemory`        | Number of times events were copied to the in-memory database             | Prometheus/ProxySQL stats |
| `MySQL_Logger-totalEventsCopiedToDisk`          | Number of times events were copied to the on-memory database             | Prometheus/ProxySQL stats |
| `MySQL_Logger-getAllEventsCallsCount`           | Number of times the `get_all_events` method was called                   | Prometheus/ProxySQL stats |
| `MySQL_Logger-getAllEventsEventsCount`          | Total number of events retrieved by the `get_all_events` method          | Prometheus/ProxySQL stats |
| `MySQL_Logger-totalMemoryCopyTimeMicros`        | Total time spent copying events to the in-memory database (microseconds) | Prometheus/ProxySQL stats |
| `MySQL_Logger-totalDiskCopyTimeMicros`          | Total time spent copying events to the on-disk database (microseconds)   | Prometheus/ProxySQL stats |
| `MySQL_Logger-totalGetAllEventsTimeMicros`      | Total time spent in `get_all_events` (microseconds)                      | Prometheus/ProxySQL stats |
| `MySQL_Logger-diskCopyCount`                    | Total number of events copied to the in-memory database                  | Prometheus/ProxySQL stats |
| `MySQL_Logger-memoryCopyCount`                  | Total number of events copied to the on-disk database                    | Prometheus/ProxySQL stats |
| `MySQL_Logger-circularBufferEventsAddedCount`   | The total number of events added to the circular buffer                  | Prometheus/ProxySQL stats |
| `MySQL_Logger-circularBufferEventsDroppedCount` | The total number of events dropped from the circular buffer              | Prometheus/ProxySQL stats |
| `MySQL_Logger-circularBufferEventsSize`         | Number of events currently present in the circular buffer                | Prometheus/ProxySQL stats |

From `Promethus` exporter:

| Metric Name                                          | Tags                 | Description                                                            |
| ---------------------------------------------------- | -------------------- | ---------------------------------------------------------------------- |
| `proxysql_mysql_logger_copy_total`                   | target=\{memory/disk\} | Number of times events were copied to the in-memory/on-disk databases. |
| `proxysql_mysql_logger_get_all_events_calls_total`   |                      | Number of times the 'get_all_events' method was called.                |
| `proxysql_mysql_logger_get_all_events_events_total`  |                      | Number of events retrieved by the `get_all_events` method.             |
| `proxysql_mysql_logger_get_all_events_seconds_total` |                      | Total time spent in `get_all_events` method.                           |
| `proxysql_mysql_logger_copy_seconds_total`           | target=\{memory/disk\} | Total time spent copying events to the in-memory/on-disk databases.    |
| `proxysql_mysql_logger_events_copied_total`          | target=\{memory/disk\} | Total number of events copied to the in-memory/on-disk databases.      |
| `proxysql_mysql_logger_circular_buffer_events_total` | type=\{added/dropped\} | The total number of events added/dropped to/from the circular buffer.  |
| `proxysql_mysql_logger_circular_buffer_events`       |                      | Number of events currently present in the circular buffer.             |

---

## Troubleshooting

### Common Issues

1. **Memory Overuse**:

   - Ensure `mysql-eventslog_buffer_history_size` is correctly tuned to avoid exhausting available memory.
   - Use the circular buffer's automatic overwriting to maintain stability.

2. **Disk Space**:
   - Monitor disk usage if `mysql-eventslog_sync_buffer_to_disk` is enabled.

### Monitoring Tools

Use the Prometheus exporter or ProxySQL stats tables to track performance metrics.

---

## Disabling the Feature

To disable the feature:

```sql
SET mysql-eventslog_buffer_history_size = 0;
LOAD MYSQL VARIABLES TO RUNTIME;
```

This will clear the circular buffer and stop logging.

---
