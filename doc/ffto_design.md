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
- **States**: `IDLE`, `WAITING_FOR_RESPONSE`, `READING_COLUMN_DEFS`, `READING_ROWS`, `SKIP_PREPARE_RESPONSE`.
- **Prepared Statement Tracking**: Maintains a session-local map of `stmt_id` to query templates captured during the `PREPARE` phase.

### 4.3. PostgreSQL FFTO Implementation (`PgSQLFFTO`)
Handles the message-oriented PostgreSQL protocol.
- **Request Identification**: Detects `Query` ('Q'), `Parse` ('P'), `Bind` ('B'), and `Execute` ('E') messages.
- **Response Identification**: Tracks `CommandComplete` ('C') and `ErrorResponse` ('E').
- **Extended Query Tracking**: Tracks the association between Portals and Prepared Statements.

## 5. Protocol and Security Details
- **Encryption**: FFTO operates on protocol packets that are already decrypted by ProxySQL's session handler. This allows ProxySQL to mix encrypted and unencrypted backend/frontend connections while maintaining consistent monitoring in FF mode.
- **Compression**: Similarly, FFTO operates on uncompressed protocol data, as ProxySQL handles compression/decompression during the packet transfer phase.

## 6. Performance and Memory Management
- **Maximum Payload Enforcement**: If a single packet payload exceeds the `*-ffto_max_buffer_size` threshold, the FFTO instance for that session is disabled. This prevents excessive memory usage on connections transferring large BLOBs.
- **Hashing Optimization**: Leverages ProxySQL's thread-local `Query_Processor` cache to avoid redundant hashing of identical query patterns.
- **Hooks**: Integration points are in `MySQL_Session::fast_forward()` and `PgSQL_Session::fast_forward()`.
