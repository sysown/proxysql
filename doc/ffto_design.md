# ProxySQL Fast Forward Traffic Observer (FFTO) - Architecture & Design

## 1. Executive Summary
The Fast Forward Traffic Observer (FFTO) is a high-performance, non-intrusive monitoring subsystem for ProxySQL. It provides deep query-level observability for connections operating in "Fast Forward" (FF) mode. In this mode, ProxySQL acts as a transparent protocol-aware pipe, bypassing the heavy query processing engine to achieve maximum throughput and minimum latency. FFTO extracts metadata—such as SQL digests, execution latency, affected rows, and error codes—from the raw protocol stream.

## 2. Design Goals and Principles
- **Passive Observation**: The FFTO operates on a zero-copy or minimal-copy basis, inspecting data without modifying the forwarded buffers.
- **Protocol Fidelity**: It accurately reconstructs protocol-level boundaries for both MySQL and PostgreSQL.
- **Performance Neutrality**: The overhead of FFTO should be negligible (<5% throughput impact).
- **Metric Parity**: Observability data must be compatible with ProxySQL's existing internal statistics (e.g., `stats_mysql_query_digest`).
- **Resilience**: The observer handles fragmentation and resource exhaustion gracefully, falling back to a session-level "bypass" if a payload exceeds defined limits.

## 3. Configuration Variables
The FFTO behavior is controlled by the following global configuration variables:
- `mysql-ffto_enabled`: (Boolean) Enables or disables FFTO for MySQL connections.
- `mysql-ffto_max_buffer_size`: (Integer) The maximum payload size (in bytes) that the MySQL FFTO will attempt to buffer for a single packet. If exceeded, FFTO is disabled for that specific session.
- `pgsql-ffto_enabled`: (Boolean) Enables or disables FFTO for PostgreSQL connections.
- `pgsql-ffto_max_buffer_size`: (Integer) The maximum payload size (in bytes) that the PostgreSQL FFTO will attempt to buffer for a single packet. If exceeded, FFTO is disabled for that specific session.

## 4. System Architecture

### 4.1. The TrafficObserver Interface
Defined in `include/TrafficObserver.hpp`. This interface decouples protocol-specific parsing from ProxySQL session management.
- **`on_client_data(const char* buf, size_t len)`**: Identifies queries, extracts SQL text, and parses prepared statement parameters.
- **`on_server_data(const char* buf, size_t len)`**: Tracks result set headers, counts rows, and identifies command completion or error packets.
- **`on_close()`**: Ensures metrics are finalized and resources are released.

### 4.2. MySQL FFTO Implementation (`MySQLFFTO`)
Implements the MySQL wire protocol (version 10) state machine.
- **States**: `IDLE`, `AWAITING_PREPARE_OK`, `AWAITING_RESPONSE`, `READING_COLUMNS`, `READING_ROWS`.
- **Prepared Statement Tracking**: Maintains a session-local map of `stmt_id` to query templates captured during the `PREPARE` phase.

### 4.3. PostgreSQL FFTO Implementation (`PgSQLFFTO`)
Handles the message-oriented PostgreSQL protocol.
- **Request Identification**: Detects `Query` ('Q'), `Parse` ('P'), `Bind` ('B'), and `Execute` ('E') messages.
- **Response Identification**: Tracks `CommandComplete` ('C'), `ReadyForQuery` ('Z'), and `ErrorResponse` ('E').
- **Extended Query Tracking**: Tracks the association between Portals and Prepared Statements, and queues pipelined executes so responses are attributed to the correct query text.

## 5. Protocol and Security Details
- **Encryption**: FFTO operates on protocol packets that are already decrypted by ProxySQL's session handler. This allows ProxySQL to mix encrypted and unencrypted backend/frontend connections while maintaining consistent monitoring in FF mode.
- **Compression**: Similarly, FFTO operates on uncompressed protocol data, as ProxySQL handles compression/decompression during the packet transfer phase.

## 6. Performance and Memory Management
- **Maximum Payload Enforcement**: If a single packet payload exceeds the `*-ffto_max_buffer_size` threshold, the FFTO instance for that session is disabled (bypassed). This prevents excessive memory usage on connections transferring large BLOBs or large result sets.
- **Fragmentation Handling**: The FFTO maintains internal buffers (`m_client_buffer`, `m_server_buffer`) to reconstruct full protocol messages from fragmented network packets.
- **Hashing Optimization**: Leverages ProxySQL's thread-local `Query_Processor` cache and `SpookyHash` to avoid redundant hashing of identical query patterns, ensuring metric parity with standard query processing.
- **Hooks**: Integration points are in `MySQL_Session::handler()` and `PgSQL_Session::handler()` within the `FAST_FORWARD` state.

## 7. Configuration and Verification

### 7.1. Global Variables
The following variables can be adjusted at runtime via the Admin interface:

```sql
-- Enable/Disable FFTO
UPDATE global_variables SET variable_value='true' WHERE variable_name='mysql-ffto_enabled';
UPDATE global_variables SET variable_value='true' WHERE variable_name='pgsql-ffto_enabled';

-- Set max buffer size (default 1MB)
UPDATE global_variables SET variable_value='2097152' WHERE variable_name='mysql-ffto_max_buffer_size';

LOAD MYSQL VARIABLES TO RUNTIME;
LOAD PGSQL VARIABLES TO RUNTIME;
```

### 7.2. Verification
To verify that FFTO is capturing traffic in Fast Forward mode:

1. Enable `debug` logging or monitor the specific debug modules:
   ```sql
   -- For MySQL
   UPDATE global_variables SET variable_value=1 WHERE variable_name='mysql-debug';
   -- For PostgreSQL
   UPDATE global_variables SET variable_value=1 WHERE variable_name='pgsql-debug';
   LOAD MYSQL VARIABLES TO RUNTIME;
   LOAD PGSQL VARIABLES TO RUNTIME;
   ```
2. Run queries through a session configured for Fast Forward (e.g., via query rules with `fast_forward=1`).
3. Check the `stats_mysql_query_digest` or `stats_pgsql_query_digest` tables:
   ```sql
   SELECT count_star, sum_time, digest_text FROM stats_mysql_query_digest;
   ```
4. Confirm that queries which were previously "invisible" in FF mode are now being recorded.

## 8. Protocol Support
- **Text and Binary Protocols**: FFTO supports both standard text-based queries and the binary protocol used by prepared statements.
- **MySQL Binary Protocol**: Correctly captures `COM_STMT_PREPARE` and `COM_STMT_EXECUTE`, tracking statement IDs to their respective SQL text.
- **PostgreSQL Extended Query**: Supports the multi-phase `Parse` -> `Bind` -> `Execute` sequence by tracking Statement and Portal mappings.

## 9. Limitations
- **Large Payloads**: Packets exceeding the `*-ffto_max_buffer_size` threshold cause FFTO to be bypassed for that session.
- **X-Protocol**: Currently optimized for classic MySQL and PostgreSQL protocols.
- **PostgreSQL Command Tags**: `sum_rows_affected`/`sum_rows_sent` are derived from `CommandComplete` tags and currently cover common commands (`INSERT`, `UPDATE`, `DELETE`, `COPY`, `MERGE`, `SELECT`, `FETCH`, `MOVE`).
