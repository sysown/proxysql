#pragma once
#include <array>
#include <cstddef>
#include <mutex>

namespace embedded {
// Accounts owned logical state, excluding allocator capacity, engine RSS and transient
// allocations. Frontend copies, binds and cached results require separate leases.
enum class Resource : size_t {
    native_statements,
    sql_bytes,
    metadata_bytes,
    bind_bytes,
    result_bytes,
    count
};
using ResourceUsage = std::array<size_t, static_cast<size_t>(Resource::count)>;
struct QuotaLimits {
    ResourceUsage values = {{4096, 64u * 1024u * 1024u, 64u * 1024u * 1024u, 256u * 1024u * 1024u,
                             512u * 1024u * 1024u}};
};
class QuotaLease;
class QuotaPool {
  public:
    explicit QuotaPool(QuotaLimits limits = {}) : limits_(limits.values) {}
    QuotaPool(const QuotaPool &) = delete;
    QuotaPool &operator=(const QuotaPool &) = delete;
    ResourceUsage snapshot() const noexcept;

  private:
    friend class QuotaLease;
    mutable std::mutex mutex_;
    ResourceUsage limits_;
    ResourceUsage used_{};
};
// A nondefault pool must outlive all of its leases and sessions.
QuotaPool &process_quota_pool();
class QuotaLease {
  public:
    explicit QuotaLease(QuotaPool &pool) noexcept : pool_(&pool) {}
    ~QuotaLease() noexcept;
    QuotaLease(const QuotaLease &) = delete;
    QuotaLease &operator=(const QuotaLease &) = delete;
    QuotaLease(QuotaLease &&) noexcept;
    QuotaLease &operator=(QuotaLease &&) noexcept;
    bool resize(const ResourceUsage &) noexcept;
    void reset() noexcept;
    ResourceUsage usage() const noexcept {
        return usage_;
    }

  private:
    QuotaPool *pool_;
    ResourceUsage usage_{};
};
} // namespace embedded
