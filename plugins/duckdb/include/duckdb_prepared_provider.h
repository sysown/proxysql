#pragma once
#include "ProxySQL_EmbeddedExecution.h"

#include "duckdb_prepared_adapter.h"
#include <duckdb.h>
#include <functional>
#include <memory>
#include <string>

namespace embedded { enum class DuckDBSourceDialect { mysql, postgresql }; }

// Per-connection native callback owner. Must outlive every registered session.
class DuckDBPreparedProvider {
  public:
    using Status = std::uint8_t (*)(void *) noexcept;
    using Failure = void (*)(void *) noexcept;
    using ResetClient = bool (*)(void *, duckdb_connection *) noexcept;
    DuckDBPreparedProvider(duckdb_connection, Status, Failure, ResetClient, void *,
                           embedded::DuckDBSourceDialect);
    ~DuckDBPreparedProvider();
    DuckDBPreparedProvider(const DuckDBPreparedProvider &) = delete;
    DuckDBPreparedProvider &operator=(const DuckDBPreparedProvider &) = delete;
    // Set before registration; PostgreSQL providers always remain native.
    void set_mysql_analytical(bool enabled) noexcept;
    // Analytical MySQL only: returns the database selected for this session
    // (empty when none is selected). The callback must be safe to call on the
    // session thread and must reflect the namespace validated by USE.
    // Without it, relative names keep resolving in DuckDB's current schema.
    void set_mysql_namespace(std::function<std::string()> current_database);
    void set_config_policy(embedded::DuckDBAdapter::BeforePrepare, embedded::DuckDBAdapter::AfterPrepare);
    void set_transaction_outcome(std::function<void(const std::string&, bool)>);
    const ProxySQL_Embedded_EngineV1 *engine() const noexcept;
    const ProxySQL_Embedded_PolicyV1 *policy() const noexcept;

  private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};
