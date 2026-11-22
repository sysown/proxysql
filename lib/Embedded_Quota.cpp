#include "Embedded_Quota.h"
#include <exception>
#include <utility>

namespace embedded {
ResourceUsage QuotaPool::snapshot() const noexcept {
    std::lock_guard<std::mutex> lock(mutex_);
    return used_;
}
QuotaPool &process_quota_pool() {
    static QuotaPool *pool = new QuotaPool;
    return *pool;
}
QuotaLease::~QuotaLease() noexcept {
    reset();
}
QuotaLease::QuotaLease(QuotaLease &&other) noexcept : pool_(other.pool_), usage_(other.usage_) {
    other.pool_ = nullptr;
    other.usage_ = {};
}
QuotaLease &QuotaLease::operator=(QuotaLease &&other) noexcept {
    if (this != &other) {
        reset();
        pool_ = other.pool_;
        usage_ = other.usage_;
        other.pool_ = nullptr;
        other.usage_ = {};
    }
    return *this;
}
bool QuotaLease::resize(const ResourceUsage &requested) noexcept {
    if (!pool_)
        return false;
    std::lock_guard<std::mutex> lock(pool_->mutex_);
    ResourceUsage next{};
    for (size_t i = 0; i < next.size(); ++i) {
        if (pool_->used_[i] < usage_[i])
            std::terminate();
        const size_t others = pool_->used_[i] - usage_[i];
        if (others > pool_->limits_[i])
            std::terminate();
        if (requested[i] > pool_->limits_[i] - others)
            return false;
        next[i] = others + requested[i];
    }
    pool_->used_ = next;
    usage_ = requested;
    return true;
}
void QuotaLease::reset() noexcept {
    if (!pool_)
        return;
    if (!resize(ResourceUsage{}))
        std::terminate();
}
} // namespace embedded
