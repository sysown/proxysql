# SSL/TLS Key Log Feature - Developer Guide

## Overview

ProxySQL implements SSL/TLS key logging to enable decryption of encrypted traffic for debugging purposes. This feature writes TLS secrets to a file in the NSS Key Log Format, which can be used by tools like Wireshark to decrypt and analyze TLS traffic.

**PR Reference:** #4236 - "Added support for SSLKEYLOGFILE"

---

## Variable Naming Convention

ProxySQL variables belong to **modules**. This is important for understanding how variables are referenced:

| Context | Variable Name | Module |
|---------|---------------|--------|
| **Internal code** | `ssl_keylog_file` | Admin |
| **SQL interface** | `admin-ssl_keylog_file` | Admin (with prefix) |
| **Config file** | `ssl_keylog_file` | Admin (in `admin_variables` section) |

**Code Location:** `include/proxysql_admin.h` - the variable is defined as `char* ssl_keylog_file` within the admin variables struct.

**SQL Registration:** `lib/ProxySQL_Admin.cpp` - registered as `"ssl_keylog_file"` in the `admin_variables` array.

When users set this variable via SQL, they must use the module prefix:
```sql
SET admin-ssl_keylog_file = '/path/to/file.txt';
```

---

## Architecture

### Component Diagram

```
┌─────────────────────────────────────────────────────────────────────┐
│                         ProxySQL Process                            │
│                                                                      │
│  ┌────────────────┐         ┌─────────────────────────────────┐   │
│  | ProxySQL_Admin |────────>|  Global Variables               │   │
│  |                │         |  .ssl_keylog_file = "/path/..."  │   │
│  └────────────────┘         └─────────────────────────────────┘   │
│           │                                                          │
│           | SET admin-ssl_keylog_file='/path/keylog.txt'           │
│           v                                                          │
│  ┌──────────────────────────────────────────────────────────────┐ │
│  |            proxysql_sslkeylog module                          │ │
│  │                                                               │ │
│  │  ┌──────────────┐  ┌──────────────────┐  ┌───────────────┐ │ │
│  │  | keylog_init  |  | keylog_open     |  | keylog_close  │ │ │
│  │  └──────────────┘  └──────────────────┘  └───────────────┘ │ │
│  │                                                               │ │
│  │  ┌──────────────────────────────────────────────────────────┐│ │
│  │  | proxysql_keylog_attach_callback(SSL_CTX*)                ││ │
│  │  |                                                          ││ │
│  │  |   SSL_CTX_set_keylog_callback(ctx, write_line_callback)  ││ │
│  │  └──────────────────────────────────────────────────────────┘│ │
│  └──────────────────────────────────────────────────────────────┘ │
│                              │                                      │
│                              │ Callback invoked by OpenSSL         │
│                              v                                      │
│  ┌──────────────────────────────────────────────────────────────┐ │
│  │ proxysql_keylog_write_line_callback(ssl, line)               │ │
│  │                                                              │ │
│  │   - Validate line length                                     │ │
│  │   - Acquire read lock (rwlock)                               │ │
│  │   - Write to keylog file                                    │ │
│  │   - Release lock                                            │ │
│  └──────────────────────────────────────────────────────────────┘ │
│                              │                                      │
│                              v                                      │
│  ┌──────────────────────────────────────────────────────────────┐ │
│  │           keylog_file_fp (FILE*)                             │ │
│  │           "/var/log/proxysql/sslkeys.txt"                    │ │
│  │                                                              │ │
│  │   CLIENT_RANDOM 3a4b5c... <48-byte-secret>                   │ │
│  │   CLIENT_HANDSHAKE_TRAFFIC_SECRET 3a4b... <32-byte-secret>   │ │
│  │   SERVER_HANDSHAKE_TRAFFIC_SECRET 3a4b... <32-byte-secret>   │ │
│  └──────────────────────────────────────────────────────────────┘ │
│                                                                      │
└──────────────────────────────────────────────────────────────────────┘
```

### Thread Safety Model

The keylog subsystem uses a **pthread read-write lock** for concurrent access.

**Key Points:**
- Multiple threads can write to the keylog file simultaneously during TLS handshakes
- File rotation (open/close) acquires exclusive lock
- Double-checked locking in `write_line_callback()` for performance

---

## NSS Key Log Format

### File Structure

Each line in the keylog file has the following format:

```
<LABEL> <ClientRandom> <Secret>\n
```

### Label Types

| Label | TLS Version | Description | Secret Size |
|-------|-------------|-------------|-------------|
| `CLIENT_RANDOM` | TLS 1.2 and earlier | Master secret | 48 bytes |
| `CLIENT_HANDSHAKE_TRAFFIC_SECRET` | TLS 1.3 | Client handshake traffic secret | 32 or 48 bytes |
| `SERVER_HANDSHAKE_TRAFFIC_SECRET` | TLS 1.3 | Server handshake traffic secret | 32 or 48 bytes |
| `CLIENT_TRAFFIC_SECRET_0` | TLS 1.3 | Client application data secret N | 32 or 48 bytes |
| `SERVER_TRAFFIC_SECRET_0` | TLS 1.3 | Server application data secret N | 32 or 48 bytes |

### Example Keylog File

```
# TLS 1.2 connection
CLIENT_RANDOM 3a4b5c6d7e8f... 48_byte_master_secret_here...

# TLS 1.3 connection
CLIENT_HANDSHAKE_TRAFFIC_SECRET 3a4b5c6d7e8f... 32_byte_secret_here...
SERVER_HANDSHAKE_TRAFFIC_SECRET 3a4b5c6d7e8f... 32_byte_secret_here...
CLIENT_TRAFFIC_SECRET_0 3a4b5c6d7e8f... 32_byte_secret_here...
SERVER_TRAFFIC_SECRET_0 3a4b5c6d7e8f... 32_byte_secret_here...
```

---

## API Reference

### Public Functions

#### `proxysql_keylog_init()`

```c
void proxysql_keylog_init();
```

**Purpose:** Initialize the keylog subsystem

**Called from:** `proxysql_global.cpp` during startup

**Thread-safety:** Safe (single-threaded initialization only)

---

#### `proxysql_keylog_open(const char* keylog_file)`

```c
bool proxysql_keylog_open(const char* keylog_file);
```

**Purpose:** Open/create the keylog file

**Parameters:**
- `keylog_file`: Path to the keylog file

**Returns:** `true` on success, `false` on failure

**Behavior:**
- Opens file in append mode with line buffering (4096 bytes)
- Closes existing file if open (supports rotation)
- Acquires write lock for thread safety

**Called from:**
- `ProxySQL_Admin::set_variable()` when `ssl_keylog_file` is set
- `ProxySQL_Admin::flush_logs()` for log rotation

---

#### `proxysql_keylog_close(bool lock = true)`

```c
void proxysql_keylog_close(bool lock = true);
```

**Purpose:** Close the keylog file

**Parameters:**
- `lock`: If `true`, acquires write lock before closing

**Behavior:**
- Closes the file if open
- Sets `keylog_file_fp` to `NULL`

---

#### `proxysql_keylog_attach_callback(SSL_CTX* ssl_ctx)`

```c
void proxysql_keylog_attach_callback(SSL_CTX* ssl_ctx);
```

**Purpose:** Attach keylog callback to an SSL context

**Parameters:**
- `ssl_ctx`: The SSL context to attach to

**Behavior:**
- Idempotent: only attaches if no callback already registered
- Uses `SSL_CTX_set_keylog_callback()` (OpenSSL 1.1.1+)

**Called from:**
- `MySQL_Session::handler()` for frontend MySQL connections
- `PgSQL_Session::handler()` for frontend PostgreSQL connections

---

#### `proxysql_keylog_write_line_callback(const SSL* ssl, const char* line)`

```c
void proxysql_keylog_write_line_callback(const SSL* ssl, const char* line);
```

**Purpose:** OpenSSL callback invoked during TLS handshake

**Parameters:**
- `ssl`: The SSL connection (unused)
- `line`: The keylog line generated by OpenSSL (no newline)

**Behavior:**
- Validates line length (max 254 bytes)
- Ensures newline termination
- Acquires read lock and writes to file
- Uses double-checked locking for performance

**Called by:** OpenSSL automatically during TLS handshake

---

## Configuration Variable

### `ssl_keylog_file` (internal name)

**Module:** Admin

**Internal Name:** `ssl_keylog_file`

**SQL Interface Name:** `admin-ssl_keylog_file`

**Type:** String (path)

**Default:** `""` (empty string = disabled)

**Runtime Configurable:** Yes

**Path Resolution:**
- Absolute path (starts with `/`): used as-is
- Relative path: resolved relative to ProxySQL data directory
- Empty string: disables key logging

**SQL Usage:**
```sql
-- Enable key logging
SET admin-ssl_keylog_file = '/var/log/proxysql/sslkeys.txt';

-- Disable key logging
SET admin-ssl_keylog_file = '';

-- Apply to runtime
LOAD ADMIN VARIABLES TO RUNTIME;
```

**Config File Usage:**
```ini
admin_variables=
{
    ssl_keylog_file='/var/log/proxysql/sslkeys.txt'
}
```

---

## Integration Points

### 1. Variable Definition

**File:** `include/proxysql_admin.h`

```cpp
struct {
    // ...
    char* ssl_keylog_file;  // Path to keylog file
} variables;
```

### 2. Variable Registration

**File:** `lib/ProxySQL_Admin.cpp`

```cpp
{ (char *)"ssl_keylog_file", ... }
```

### 3. Runtime Variable Setter

**File:** `lib/ProxySQL_Admin.cpp:set_variable()`

```cpp
if (!strcasecmp(name, "ssl_keylog_file")) {
    // Handle absolute vs relative paths
    // Open file or validate path
    // Set GloVars.global.ssl_keylog_enabled
}
```

### 4. Log Rotation

**File:** `lib/ProxySQL_Admin.cpp:flush_logs()`

```cpp
void ProxySQL_Admin::flush_logs() {
    // ...
    proxysql_keylog_close();  // Close current file
    proxysql_keylog_open(ssl_keylog_file);  // Reopen
}
```

### 5. SSL Context Integration

**Files:**
- `lib/MySQL_Session.cpp`
- `lib/PgSQL_Session.cpp`

```cpp
proxysql_keylog_attach_callback(GloVars.get_SSL_ctx());
```

---

## Security Considerations

### WARNING: Critical Security Implications

The keylog file contains **cryptographic secrets** that can decrypt ALL TLS traffic:

1. **What the file contains:**
   - TLS master secrets (TLS 1.2)
   - Traffic encryption keys (TLS 1.3)
   - Enough to decrypt past, present, and future connections

2. **Attack scenarios if compromised:**
   - Decryption of captured network traffic, exposing all plaintext data, including credentials, queries, and results.

3. **Recommended safeguards:**
   - **File permissions:** `0600` (owner read/write only)
   - **Directory permissions:** `0700` (owner access only)
   - **Enable only for debugging:** Disable in production
   - **Rotate regularly:** `PROXYSQL FLUSH LOGS`
   - **Secure deletion:** Shred file before deletion

### Code Review Checklist

When reviewing changes to this module:

- [ ] File permissions are set correctly
- [ ] Path validation prevents directory traversal
- [ ] Lock acquisition is correct (rdlock vs wrlock)
- [ ] Double-checked locking is properly implemented
- [ ] No sensitive data in logs/error messages
- [ ] Proper cleanup on error conditions

---

## Testing

### Unit Test Structure

**File:** `test/tap/tests/test_auth_methods-t.cpp`

```cpp
void ssl_keylog_callback(SSL*, const char* line) {
    // Verify line format
    // Verify file contents
}

// Test callback registration
mysql_options(proxy, MARIADB_OPT_SSL_KEYLOG_CALLBACK, ...);
```

### Manual Testing

1. **Enable key logging:**

```bash
mysql -h 127.0.0.1 -P 6032 -u admin -padmin -e "SET admin-ssl_keylog_file='/tmp/keylog.txt'; LOAD ADMIN VARIABLES TO RUNTIME;"
```

2. **Create TLS connection:**

```bash
mysql -h 127.0.0.1 -P 6033 -u user -ppass --ssl
```

3. **Verify keylog file:**

```bash
cat /tmp/keylog.txt
# Should see CLIENT_RANDOM or TRAFFIC_SECRET lines
```

4. **Configure Wireshark:**
   - Edit → Preferences → Protocols → TLS
   - Set "(Pre)-Master-Secret log filename" to `/tmp/keylog.txt`
   - Decrypt TLS traffic in Wireshark

---

## Performance Considerations

1. **Line buffering:** 4096 bytes minimizes syscalls
2. **Read-write lock:** Allows concurrent writes during handshakes
3. **Double-checked locking:** Avoids lock acquisition when disabled
4. **File mode:** Append mode minimizes disk seeks

---

## References

- [NSS Key Log Format](https://developer.mozilla.org/en-US/docs/Mozilla/Projects/NSS/Key_Log_Format)
- [Wireshark TLS Decryption](https://wiki.wireshark.org/TLS#TLS_Decryption)
- [OpenSSL SSL_CTX_set_keylog_callback](https://www.openssl.org/docs/man3.0/man3/SSL_CTX_set_keylog_callback.html)
- [PR #4236](https://github.com/sysown/proxysql/pull/4236)
