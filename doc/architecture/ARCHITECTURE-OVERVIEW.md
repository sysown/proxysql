# ProxySQL Architecture Overview

## Executive Summary

ProxySQL is a high-performance MySQL and PostgreSQL protocol-aware proxy server written in C++11/17. It implements a sophisticated multi-threaded architecture with connection pooling, query routing, caching, and comprehensive monitoring capabilities. The system is designed for high throughput, low latency, and horizontal scalability in database environments.

## System Architecture

### Core Design Patterns

1. **Multi-Threaded Worker Model**
   - MySQL worker threads (`MySQL_Thread`) handling client connections
   - PgSQL worker threads (`PgSQL_Thread`) for PostgreSQL support
   - Admin threads for configuration management
   - Monitor threads for backend health checking
   - Idle connection management threads (when `IDLE_THREADS` enabled)

2. **Event-Driven I/O**
   - Uses `libev` for efficient event loop management
   - Poll-based multiplexing for handling multiple connections per thread
   - Epoll support for idle thread management on Linux

3. **Connection Pooling & Multiplexing**
   - Per-hostgroup connection pools
   - Connection multiplexing to reduce backend connections
   - Smart connection reuse based on session state

4. **Protocol Implementation**
   - Full MySQL protocol implementation (`MySQL_Protocol`)
   - PostgreSQL wire protocol support (`PgSQL_Protocol`)
   - Protocol-aware query parsing and routing

## Main Components and Relationships

### 1. Entry Point & Initialization
- **File**: `/github/proxy/proxysql/src/main.cpp`
- **Responsibilities**:
  - Process initialization and daemonization
  - Loading configuration from `proxysql.cfg`
  - Creating global variables structure
  - Starting all subsystems

### 2. Thread Architecture

#### MySQL Threads (`MySQL_Thread`)
- **Files**: `/github/proxy/proxysql/lib/MySQL_Thread.cpp`, `/github/proxy/proxysql/include/MySQL_Thread.h`
- **Key Features**:
  - Worker threads handling MySQL client connections
  - Session management and query processing
  - Connection pool interaction
  - Query cache integration

#### PgSQL Threads (`PgSQL_Thread`)
- **Files**: `/github/proxy/proxysql/lib/PgSQL_Thread.cpp`, `/github/proxy/proxysql/include/PgSQL_Thread.h`
- **Key Features**:
  - PostgreSQL protocol handling
  - SASL/SCRAM authentication support
  - Extended query protocol
  - Transaction state management

### 3. Session Management

#### MySQL Session (`MySQL_Session`)
- **Files**: `/github/proxy/proxysql/lib/MySQL_Session.cpp`, `/github/proxy/proxysql/include/MySQL_Session.h`
- **Responsibilities**:
  - Client authentication
  - Query lifecycle management
  - Backend connection assignment
  - State machine for protocol handling
  - Prepared statement management

#### PgSQL Session (`PgSQL_Session`)
- **Files**: `/github/proxy/proxysql/lib/PgSQL_Session.cpp`, `/github/proxy/proxysql/include/PgSQL_Session.h`
- **Features**:
  - PostgreSQL authentication methods
  - Extended query protocol
  - Transaction state tracking

### 4. Connection Pool Management

#### MySQL HostGroups Manager
- **Files**: `/github/proxy/proxysql/lib/MySQL_HostGroups_Manager.cpp`, `/github/proxy/proxysql/include/MySQL_HostGroups_Manager.h`
- **Key Concepts**:
  - Hostgroup: logical grouping of database servers
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
- **Files**: `/github/proxy/proxysql/lib/MySQL_Query_Processor.cpp`, `/github/proxy/proxysql/include/MySQL_Query_Processor.h`
- **Features**:
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
- **Files**: `/github/proxy/proxysql/lib/sqlite3db.cpp`

#### Configuration Layers
1. **Disk**: Persistent configuration in SQLite
2. **Memory**: Runtime configuration tables
3. **Runtime**: Active configuration in use

### 7. Admin & Monitoring Interfaces

#### Admin Interface (`ProxySQL_Admin`)
- **Files**: `/github/proxy/proxysql/lib/ProxySQL_Admin.cpp`, `/github/proxy/proxysql/include/proxysql_admin.h`
- **Features**:
  - MySQL-compatible admin interface (port 6032)
  - Configuration management via SQL
  - Runtime statistics access
  - Cluster synchronization

#### SQLite3 Server
- **Files**: `/github/proxy/proxysql/src/SQLite3_Server.cpp`, `/github/proxy/proxysql/include/SQLite3_Server.h`
- **Purpose**: Provides SQL interface for admin operations

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
- **Files**: `/github/proxy/proxysql/lib/MySQL_Query_Cache.cpp`, `/github/proxy/proxysql/lib/PgSQL_Query_Cache.cpp`
- In-memory result caching
- TTL-based expiration
- Cache key generation from query digest

#### Cluster Support (`ProxySQL_Cluster`)
- **Files**: `/github/proxy/proxysql/lib/ProxySQL_Cluster.cpp`
- Configuration synchronization
- Checksum-based change detection
- Peer-to-peer communication

#### Statistics & Metrics
- **Files**: `/github/proxy/proxysql/lib/ProxySQL_Statistics.cpp`
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
1. **Configuration File**: `/github/proxy/proxysql/src/proxysql.cfg`
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
- **TAP Tests**: `/github/proxy/proxysql/test/tap/`
- **Unit Tests**: Component-level testing
- **Integration Tests**: Full stack testing
- **Cluster Tests**: Multi-proxy scenarios

## Performance Optimizations

1. **Connection Pooling**: Reduces connection overhead
2. **Query Caching**: Eliminates redundant queries
3. **Multiplexing**: Shares backend connections
4. **Fast Pattern Matching**: Optimized query routing
5. **Memory Management**: Custom allocators (jemalloc)
6. **Lock-Free Structures**: Where possible for hot paths

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

- MySQL/PostgreSQL authentication passthrough
- SSL/TLS support for client and backend connections
- LDAP authentication plugin support
- Query firewall capabilities
- User-level query rules

## High Availability Features

1. **Multiple Backend Support**: Hostgroup failover
2. **Health Checking**: Automatic backend monitoring
3. **Replication Awareness**: Topology detection
4. **Read/Write Splitting**: Automatic query routing
5. **Connection Retry Logic**: Transparent failover
6. **Cluster Mode**: Multi-proxy coordination

## Architectural Strengths

1. **Scalability**: Horizontal scaling via clustering
2. **Performance**: Optimized for high throughput
3. **Flexibility**: Extensive configuration options
4. **Protocol Compliance**: Full protocol implementation
5. **Extensibility**: Plugin architecture for auth/web interface
6. **Observability**: Comprehensive monitoring capabilities

## Key Design Decisions

1. **Multi-threaded over Multi-process**: Better resource sharing
2. **SQLite for Configuration**: ACID compliance, SQL interface
3. **Connection Pooling per Hostgroup**: Isolation and flexibility
4. **Protocol-aware Proxy**: Deep packet inspection capabilities
5. **Checksum-based Clustering**: Efficient configuration sync

## Future Considerations

The architecture supports:
- Additional database protocols
- Enhanced caching strategies
- Advanced routing algorithms
- Extended monitoring capabilities
- Cloud-native deployments

---

This architectural overview provides a comprehensive understanding of ProxySQL's design, components, and operational characteristics. The system demonstrates sophisticated engineering for database proxy requirements at scale.