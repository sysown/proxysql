# ProxySQL Architecture Overview

## Executive Summary

ProxySQL is a MySQL and PostgreSQL protocol-aware proxy server written in C++11/17. It implements a multi-threaded architecture with connection pooling, query routing, caching, and monitoring.

## System Architecture

### Core Design Patterns

1. **Multi-Threaded Worker Model**
   - MySQL worker threads (`MySQL_Thread`) handle client connections
   - PgSQL worker threads (`PgSQL_Thread`) for PostgreSQL support
   - Admin threads for configuration management
   - Monitor threads for backend health checking
   - Idle connection management threads (when `IDLE_THREADS` enabled)

2. **Event-Driven I/O**
   - Uses `libev` for event loop management
   - Poll-based multiplexing handles multiple connections per thread
   - Epoll support for idle thread management on Linux

3. **Connection Pooling & Multiplexing**
   - Per-hostgroup connection pools
   - Connection multiplexing to reduce backend connections
   - Connection reuse based on session state

4. **Protocol Implementation**
   - Full MySQL protocol implementation (`MySQL_Protocol`)
   - PostgreSQL wire protocol support (`PgSQL_Protocol`)
   - Protocol-aware query parsing and routing

## Main Components and Relationships

### 1. Entry Point & Initialization
- **File**: `https://github.com/sysown/proxysql/tree/v3.0.agentics/src/main.cpp`
- **Responsibilities**:
  - Process initialization and daemonization
  - Loads configuration from `proxysql.cfg`
  - Creates global variables structure
  - Starts all subsystems

### 2. Thread Architecture

#### Thread Pool Design
- **Consumer Thread Pattern**: Generic work queue for monitoring tasks
  ```cpp
  template<typename T>
  class ConsumerThread : public Thread {
    wqueue<WorkItem<T>*>& m_queue;
  }
  ```
- **Thread-Local Storage**: `__thread` variables for per-thread configuration
- **Maintenance Threads**: Minimum 8 threads for housekeeping operations
- **Event Loop Integration**: Epoll-based event handling for scalability

#### MySQL Threads (`MySQL_Thread`)
- **Files**: `https://github.com/sysown/proxysql/tree/v3.0.agentics/lib/MySQL_Thread.cpp`, `https://github.com/sysown/proxysql/tree/v3.0.agentics/include/MySQL_Thread.h`
- **Key Features**:
  - Worker threads handle MySQL client connections
  - Session management and query processing
  - Connection pool interaction
  - Thread-local statistics for lock-free updates
  - Query cache integration

#### PgSQL Threads (`PgSQL_Thread`)
- **Files**: `https://github.com/sysown/proxysql/tree/v3.0.agentics/lib/PgSQL_Thread.cpp`, `https://github.com/sysown/proxysql/tree/v3.0.agentics/include/PgSQL_Thread.h`
- **Key Features**:
  - PostgreSQL protocol handling
  - SASL/SCRAM authentication support
  - Extended query protocol
  - Transaction state management

### 3. Session Management

#### MySQL Session (`MySQL_Session`)
- **Files**: `https://github.com/sysown/proxysql/tree/v3.0.agentics/lib/MySQL_Session.cpp`, `https://github.com/sysown/proxysql/tree/v3.0.agentics/include/MySQL_Session.h`
- **Responsibilities**:
  - Client authentication
  - Query lifecycle management
  - Backend connection assignment
  - State machine for protocol handling
  - Prepared statement management

#### PgSQL Session (`PgSQL_Session`)
- **Files**: `https://github.com/sysown/proxysql/tree/v3.0.agentics/lib/PgSQL_Session.cpp`, `https://github.com/sysown/proxysql/tree/v3.0.agentics/include/PgSQL_Session.h`
- **Features**:
  - PostgreSQL authentication methods
  - Extended query protocol
  - Transaction state tracking

### 4. Connection Pool Management

#### MySQL HostGroups Manager
- **Files**: `https://github.com/sysown/proxysql/tree/v3.0.agentics/lib/MySQL_HostGroups_Manager.cpp`, `https://github.com/sysown/proxysql/tree/v3.0.agentics/include/MySQL_HostGroups_Manager.h`
- **Key Concepts**:
  - Hostgroups logically group database servers
  - Connection pool per hostgroup
  - Server status tracking (ONLINE, SHUNNED, OFFLINE_SOFT, OFFLINE_HARD)
  - Connection health monitoring
  - Replication topology awareness (master/slave, Galera, Group Replication, Aurora)

#### Connection States
```
ONLINE → SHUNNED (temporary failures) → OFFLINE_SOFT → OFFLINE_HARD
```

### 5. Query Processing

#### MySQL Query Processor
- **Files**: `https://github.com/sysown/proxysql/tree/v3.0.agentics/lib/MySQL_Query_Processor.cpp`, `https://github.com/sysown/proxysql/tree/v3.0.agentics/include/MySQL_Query_Processor.h`
- **Functions**:
  - Rule-based query routing
  - Query rewriting capabilities
  - Query caching decisions
  - Query digest generation
  - GTID handling

#### Query Rules Engine
- Pattern matching (regex support)
- Destination hostgroup routing
- Query modification/rewriting
- Cache TTL configuration
- Query mirroring support

### 6. Database Layer & Persistence

#### SQLite3 Integration
- **Admin Database**: Runtime configuration storage
- **Stats Database**: Metrics and statistics
- **Monitor Database**: Health check results
- **Files**: `https://github.com/sysown/proxysql/tree/v3.0.agentics/lib/sqlite3db.cpp`

#### Configuration Layers
1. **Disk**: Persistent configuration in SQLite
2. **Memory**: Runtime configuration tables
3. **Runtime**: Active configuration in use

### 7. Admin & Monitoring Interfaces

#### Admin Interface (`ProxySQL_Admin`)
- **Files**: `https://github.com/sysown/proxysql/tree/v3.0.agentics/lib/ProxySQL_Admin.cpp`, `https://github.com/sysown/proxysql/tree/v3.0.agentics/include/proxysql_admin.h`
- **Features**:
  - MySQL-compatible admin interface (port 6032)
  - Configuration management via SQL
  - Runtime statistics access
  - Cluster synchronization

#### SQLite3 Server
- **Files**: `https://github.com/sysown/proxysql/tree/v3.0.agentics/src/SQLite3_Server.cpp`, `https://github.com/sysown/proxysql/tree/v3.0.agentics/include/SQLite3_Server.h`
- **Purpose**: SQL interface for admin operations

#### Monitoring (`MySQL_Monitor`, `PgSQL_Monitor`)
- Backend health checking
- Replication lag monitoring
- Read-only status detection
- GTID tracking

### 8. Network & Protocol Handling

#### Data Streams
- **MySQL_Data_Stream**: MySQL protocol communication
- **PgSQL_Data_Stream**: PostgreSQL protocol communication
- Buffer management for network I/O
- SSL/TLS support

#### Protocol Parsers
- MySQL command parsing
- PostgreSQL message format handling
- Prepared statement protocol
- Result set handling

### 9. Advanced Features

#### Query Cache
- **Files**: `https://github.com/sysown/proxysql/tree/v3.0.agentics/lib/MySQL_Query_Cache.cpp`, `https://github.com/sysown/proxysql/tree/v3.0.agentics/lib/PgSQL_Query_Cache.cpp`
- In-memory result caching
- TTL-based expiration
- Cache key generation from query digest

#### Cluster Support (`ProxySQL_Cluster`)
- **Files**: `https://github.com/sysown/proxysql/tree/v3.0.agentics/lib/ProxySQL_Cluster.cpp`
- Configuration synchronization
- Checksum-based change detection
- Peer-to-peer communication

#### Statistics & Metrics
- **Files**: `https://github.com/sysown/proxysql/tree/v3.0.agentics/lib/ProxySQL_Statistics.cpp`
- Prometheus metrics integration
- Query statistics
- Connection pool metrics
- Memory usage tracking

## Threading Model & Concurrency

### Thread Types
1. **Main Thread**: Initialization and coordination
2. **MySQL Worker Threads**: Handle MySQL client connections
3. **PgSQL Worker Threads**: Handle PostgreSQL connections
4. **Admin Thread**: Admin interface requests
5. **Monitor Threads**: Backend health monitoring
6. **Idle Threads**: Manage idle connections (optional)
7. **Cluster Threads**: Inter-proxy communication

### Synchronization Mechanisms
- Read-write locks for configuration access
- Mutexes for connection pool operations
- Lock-free structures for statistics
- Atomic operations for counters

## Configuration Management

### Configuration Sources
1. **Configuration File**: `https://github.com/sysown/proxysql/tree/v3.0.agentics/src/proxysql.cfg`
2. **Command Line**: Override options
3. **Admin Interface**: Runtime modifications
4. **Cluster Sync**: Peer configuration updates

### Key Configuration Areas
- `admin_variables`: Admin interface settings
- `mysql_variables`: MySQL protocol settings
- `pgsql_variables`: PostgreSQL settings
- `mysql_servers`: Backend server definitions
- `mysql_users`: User authentication
- `mysql_query_rules`: Query routing rules

## Build System & Dependencies

### Build Configuration
- **Makefile**: Main build configuration
- C++11/17 support detection
- Debug vs Release builds
- Platform-specific optimizations

### Key Dependencies
- **libev**: Event loop
- **libmariadbclient**: MySQL protocol
- **libpq**: PostgreSQL protocol
- **sqlite3**: Embedded database
- **jemalloc**: Memory allocator
- **re2/pcre**: Regular expressions
- **prometheus-cpp**: Metrics
- **libmicrohttpd**: HTTP server
- **clickhouse-cpp**: ClickHouse support

## Testing Framework

### Test Types
- **TAP Tests**: `https://github.com/sysown/proxysql/tree/v3.0.agentics/test/tap/`
- **Unit Tests**: Component-level testing
- **Integration Tests**: Full stack testing
- **Cluster Tests**: Multi-proxy scenarios

## Performance Optimizations

### Connection Pool Optimizations
1. **Multi-Tier Pool Management**:
   - Free connections pool per backend
   - Used connections tracking with statistics
   - Connection warming for pre-emptive establishment
   - Latency-aware connection selection
   - GTID-aware routing for consistency

2. **Pool Algorithms**:
   ```cpp
   // Connection retrieval with multiple criteria
   MySQL_Connection* get_MyConn_from_pool(
     uint32_t wait_until_ms,  // Timeout control
     bool ff_flag,             // Fast forward flag
     char* gtid_uuid,          // GTID consistency
     uint64_t gtid_trxid,      // Transaction ID
     int max_lag_ms            // Max replication lag
   )
   ```

3. **Query Processing**:
   - **Fast Digest Path**: Optimized for queries > 100KB
   - **Multi-threaded Digesting**: 4 threads for parallel processing
   - **Regex Caching**: Compiled patterns cached in `regex_engine1/2`
   - **Digest Statistics**: Low-overhead tracking

4. **Memory Management**:
   - **Buffer Pools**: Reusable buffers for packet handling
   - **Statement Cache**: Prepared statement metadata caching
   - **Result Buffering**: Configurable strategies
   - **jemalloc Integration**: Optimized memory allocation

5. **Lock-Free Structures**:
   - Thread-local statistics counters
   - Lock-free query digest maps
   - Atomic operations for global counters
   - Per-thread configuration caching

## Monitoring & Observability

### Metrics Collection
- Query response times
- Connection pool efficiency
- Backend server health
- Memory usage patterns
- Cache hit rates

### Interfaces
- Admin interface statistics tables
- Prometheus metrics endpoint
- REST API for monitoring
- Log files for debugging

## Security Features

### Authentication Architecture

#### Multi-Stage Authentication Flow
1. **Initial Handshake**: Server greeting and capability negotiation
2. **SSL Negotiation**: Optional TLS upgrade
3. **Auth Plugin Negotiation**: Select authentication method
4. **Credential Verification**: Validate user credentials
5. **Session Establishment**: Create authenticated session

#### Supported Authentication Methods
- **mysql_native_password**: SHA1-based with fast path caching
- **caching_sha2_password**: SHA256 with full/fast authentication modes
- **mysql_clear_password**: For LDAP integration
- **Auth Plugin Switching**: Dynamic protocol adaptation
- **PostgreSQL SCRAM**: SASL/SCRAM-SHA-256 support

#### Authentication Caching
- SHA1 passwords cached in `GloMyAuth`
- Passwords cached for `caching_sha2_password` fast authentication
- User attributes cached with JSON validation
- Per-user connection limits and routing rules

### Security Controls
- SSL/TLS support for client and backend connections
- Query firewall with SQL injection detection
- User-level query rules and access controls
- Connection rate limiting per user/hostgroup
- Audit logging capabilities

## Query Processing Pipeline

### Query Digest System
- **Digest Computation**: Optimized for queries > 100KB
- **Digest Structure**:
  ```cpp
  struct QP_query_digest_stats {
    uint64_t digest;
    time_t first_seen, last_seen;
    unsigned long long sum_time, min_time, max_time;
    unsigned long long rows_affected, rows_sent;
  }
  ```

### Rule Processing Engine
- **Weighted Routing**: Rules can specify multiple destinations with weights
- **Rule Chaining**: `next_query_flagIN` enables sequential processing
- **Query Mirroring**: Mirror queries to secondary hostgroups
- **Query Rewriting**: Pattern-based query transformation
- **Cache Control**: Per-rule cache TTL settings

### Advanced Rule Features
- **flagOUT Routing**: Multi-destination with load balancing
- **Regex Optimization**: Compiled patterns cached for performance
- **Conditional Logic**: Username, schema, client address matching
- **Error Injection**: Custom error messages for blocked queries
- **Sticky Sessions**: Maintain connection affinity

## High Availability Features

### Backend Management
1. **Server State Management**:
   ```cpp
   enum MySerStatus {
     MYSQL_SERVER_STATUS_ONLINE = 0,
     MYSQL_SERVER_STATUS_SHUNNED = 1,
     MYSQL_SERVER_STATUS_OFFLINE_SOFT = 2,
     MYSQL_SERVER_STATUS_OFFLINE_HARD = 3,
     MYSQL_SERVER_STATUS_SHUNNED_REPLICATION_LAG = 4
   }
   ```

2. **Automatic Server Management**:
   - Auto-shunning on connection errors
   - Weighted distribution across servers
   - Per-server connection limits
   - Compression support (0-102400 bytes)
   - Per-server SSL configuration

3. **Health Monitoring**:
   - Connect checks for basic connectivity
   - Ping checks for lightweight monitoring
   - Read-only status detection
   - Replication lag measurement
   - Group replication state tracking

### Cluster Synchronization

#### Checksum-Based Sync
- **Global Checksum**: Overall configuration state hash
- **Module Checksums**: Individual module configuration tracking
- **Epoch Tracking**: Version control for changes
- **Diff-Based Sync**: Sync triggered after N differences

#### Sync Decision Algorithm
```
IF (node_version > 1 AND 
    (own_version == 1 OR node_epoch > own_epoch))
    AND diff_check >= cluster_module_diffs_before_sync
THEN sync_from_peer
```

#### Cluster Features
- Automatic configuration propagation
- Conflict resolution based on epochs
- Selective module synchronization
- Peer discovery and health checking

## Architecture Characteristics

1. **Scalability**: Horizontal scaling via clustering
2. **Performance**: High throughput optimization
3. **Configuration**: Extensive runtime configuration options
4. **Protocol Support**: Full MySQL and PostgreSQL protocol implementation
5. **Extensibility**: Plugin architecture for authentication and web interface
6. **Monitoring**: Built-in metrics and statistics collection

## Design Decisions

1. **Multi-threaded over Multi-process**: Resource sharing
2. **SQLite for Configuration**: ACID compliance, SQL interface
3. **Connection Pooling per Hostgroup**: Isolation between hostgroups
4. **Protocol-aware Proxy**: Packet inspection and manipulation
5. **Checksum-based Clustering**: Configuration synchronization

## Architecture Extensions

Architecture supports:
- Additional database protocols
- Alternative caching strategies
- Custom routing algorithms
- Extended monitoring capabilities
- Cloud-native deployments