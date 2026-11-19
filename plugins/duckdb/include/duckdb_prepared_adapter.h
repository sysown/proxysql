#pragma once
#include "Embedded_Execution.h"
#include <duckdb.h>
#include <functional>

namespace embedded {
// Borrows connection; it must outlive the adapter and all its statements.
// Native SQL uses the same configuration policy and connection permissions as
// ordinary queries. The caller supplies that policy and manages transactions.
// Preparation never executes to describe. Unknown result types are refused;
// unknown parameter types are reported as unknown. Result metadata is checked
// after execution and before rows are exposed; no execution is replayed.
// Reset releases results and bindings without SQL or transaction control.
// Cancellation is owned by the connection and is not exposed by this interface.
class DuckDBAdapter final : public Adapter {
public:
 explicit DuckDBAdapter(duckdb_connection connection) noexcept : connection_(connection) {}
 using BeforePrepare = std::function<bool(const std::string&, std::string&, bool&, std::string&)>;
 using AfterPrepare = std::function<bool(const std::string&, duckdb_statement_type, bool, std::string&)>;
 void set_config_policy(BeforePrepare before, AfterPrepare after) { before_ = std::move(before); after_ = std::move(after); }
 // Caller must finalize every statement before replacing the borrowed connection.
 void reset_connection(duckdb_connection connection) noexcept { connection_ = connection; }
 DuckDBAdapter(const DuckDBAdapter&) = delete;
 DuckDBAdapter& operator=(const DuckDBAdapter&) = delete;
 Status prepare(const std::string&, std::unique_ptr<Statement>&) override;
 bool modifies_database(Statement&) const noexcept;
 Status describe_parameters(Statement&, std::vector<Type>&) override;
 Status describe_parameter_positions(Statement&, std::vector<uint32_t>&) override;
 Status describe_result(Statement&, std::vector<Column>&) override;
 Status bind(Statement&, const std::vector<Value>&) override;
 Status execute(Statement&, ExecInfo&) override;
 Status fetch(Statement&, Row&, bool&, size_t) override;
 Status reset(Statement&) override;
 void finalize(std::unique_ptr<Statement>) noexcept override;
private:
 struct State;
 State* checked(Statement&) const noexcept;
 duckdb_connection connection_;
 BeforePrepare before_;
 AfterPrepare after_;
};
}
