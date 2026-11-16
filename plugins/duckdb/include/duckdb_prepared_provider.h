#pragma once
#include "ProxySQL_EmbeddedExecution.h"
#include "duckdb_prepared_policy.h"
#include <duckdb.h>
#include <memory>

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
    const ProxySQL_Embedded_EngineV1 *engine() const noexcept;
    const ProxySQL_Embedded_PolicyV1 *policy() const noexcept;

  private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};
