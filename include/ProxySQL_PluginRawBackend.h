#ifndef PROXYSQL_PLUGIN_RAW_BACKEND_H
#define PROXYSQL_PLUGIN_RAW_BACKEND_H
#ifdef PROXYSQL40

#include <cstdint>
#include <string>

enum class ProxySQL_RawBackendProtocol : uint8_t { mysql = 1, pgsql = 2 };
struct ProxySQL_RawBackend; // Core-owned actual HGM in-use connection.

struct ProxySQL_RawBackendEndpoint {
    std::string address; // Numeric IPv4/IPv6, resolved from the existing cache only.
    uint16_t port { 0 };
};

// A borrowed, process-resident service table. Only acquire may throw; callers
// contain exceptions. Each returned handle has one owner and is destroyed once.
// Calls for one handle are serialized; different handles may run concurrently.
// The plugin owns its socket. Core protocol wrappers have no connected fd and
// are registered in the existing ConnectionsUsed list until destroy(). No reuse.
// Stop/join every caller and destroy every handle before plugin stop returns.
struct ProxySQL_RawBackendServiceV2 {
    uint32_t version { 2 };
    ProxySQL_RawBackend* (*acquire)(ProxySQL_RawBackendProtocol protocol,
        uint32_t hostgroup, ProxySQL_RawBackendEndpoint& endpoint, std::string& error);
    // Exactly one actual connect outcome per attempt; duplicate reports ignored.
    // 0 means a successful TCP connect; otherwise this is a socket errno.
    void (*connect_result)(ProxySQL_RawBackend*, int socket_errno) noexcept;
    // Wire bytes: successful send to backend / successful recv from backend.
    void (*account_io)(ProxySQL_RawBackend*, uint64_t sent, uint64_t received) noexcept;
    // OFFLINE_HARD alone terminates an existing stream. No SQL/session policy.
    bool (*offline_hard)(const ProxySQL_RawBackend*) noexcept;
    // Retire under HGM -> registry locking, then destroy exactly once. The
    // return value is the final HARD latch at retirement; a true result
    // forbids retrying this accepted stream on a replacement backend.
    bool (*destroy)(ProxySQL_RawBackend*) noexcept;
};

// Process-resident accessor for the live service. Callable from Phase B too
// (there it returns nullptr through the phase-specific services table).
const ProxySQL_RawBackendServiceV2* proxysql_raw_backend_service() noexcept;

// Core-only OFFLINE_HARD transition latch.  Called while the protocol HGM lock
// is held; it only takes the bounded live-handle registry mutex, performs no
// callbacks/allocation, and marks every raw handle still pinned to the exact
// server identity passed in.  A no-op before the first raw handle registers.
void proxysql_raw_backend_mark_offline_hard(const void* server_identity) noexcept;

// Core-only raw-selection policy; zero for a native SQL thread unless a raw
// acquisition temporarily installs its handler snapshot.
int proxysql_raw_backend_latency_awareness_min_servers() noexcept;

#endif
#endif
