#pragma once
#include "Embedded_Execution.h"
#include "ProxySQL_EmbeddedExecution.h"
#include "Embedded_Quota.h"

namespace embedded {
// Limits can be lowered by callers but never exceed these defaults. Metadata is
// bounded per provider statement and charged separately from Session copies.
struct PluginLimits {
    size_t sql = 1024 * 1024, parameters = 4096, columns = 4096;
    size_t metadata = 8 * 1024 * 1024, bind = 16 * 1024 * 1024;
    size_t fetch = 64 * 1024 * 1024;
};
// One provider owns one engine connection's adapter. Callback tables are copied;
// callback contexts remain borrowed and must outlive the provider, its statements,
// and guards. The read-only capability is a provider promise, not a sandbox.
class PluginProvider {
  public:
    virtual ~PluginProvider() = default;
    virtual Adapter &adapter() = 0;
    virtual EndpointPolicy &policy() = 0;
    virtual GuardFactory guard_factory() = 0;
    virtual uint16_t (*mysql_status() const)(void *) noexcept = 0;
    virtual void *status_context() const = 0;
    virtual uint8_t (*pgsql_status() const)(void *) noexcept = 0;
    virtual void *pgsql_status_context() const = 0;
};
using PluginProviderResult = std::unique_ptr<PluginProvider>;
Status make_plugin_provider(const ProxySQL_Embedded_RequestV1 *, bool pgsql, PluginProviderResult &,
                            PluginLimits = {}, QuotaPool * = nullptr);
} // namespace embedded
