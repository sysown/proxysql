#pragma once
// Internal C++17 native SQLite adapter for the embedded prepared-statement
// engine slice. This is not a frontend, plugin ABI, or public engine contract.
//
// The adapter borrows one sqlite3 connection and owns only its native prepared
// statements. The connection must outlive the adapter, and the adapter must
// outlive every Session and statement created from it. Operations are
// synchronous and not thread-safe.
//
// Admission and metadata:
//  * prepare compiles exactly one native statement. The native prepare tail
//    must be empty or ASCII whitespace; any other tail is rejected before the
//    statement is stepped or a second statement is prepared. This adapter
//    does not recognize SQL comments, strings, or tokens itself. Comments
//    that SQLite consumes inside the first statement (before its terminator
//    or at EOF) are therefore accepted, while comments after a terminating
//    semicolon are explicitly unsupported until a suitable engine or parser
//    framing contract exists. No SQL is parsed or rewritten by this adapter
//    and parameters are never interpolated.
//  * Native prepare failures are reported conservatively as
//    ErrorKind::engine, except native resource codes. Only framing failures
//    detected by this adapter (embedded NUL, no statement, or a
//    non-whitespace tail) have syntax or unsupported kinds; error meaning is
//    never inferred from native message text.
//  * Endpoint policy authorization is separate and must run before prepare.
//    Native preparation only compiles; some PRAGMAs can still act at prepare
//    time, so native preparation is not an authorization mechanism.
//  * describe_* only reads prepare-time native metadata. It never steps or
//    executes SQL. Parameter types are reported as unknown with the native
//    parameter count. Result names are owned copies and every result type is
//    dynamic; SQLite declared affinity is not a fixed result type.
//  * The supported result slice is a read-only result or a no-result DML/DDL
//    statement. A write statement with result columns (for example DML
//    RETURNING) is rejected before execution using native stmt_readonly plus
//    column_count. This adapter has no statement-kind classifier or prepared
//    transaction-control policy: admission of transaction control, PRAGMAs,
//    and other no-result statement kinds belongs to the endpoint policy.
//
// Binding:
//  * Accepted values are NULL, int64, uint64 up to INT64_MAX, non-NaN double,
//    explicit-length Text, and explicit-length Bytes. Empty text/blob keeps a
//    non-null value and a zero byte length. NaN is rejected because SQLite
//    would turn it into NULL. Decimal and every other unsupported conversion
//    fail explicitly; the adapter does not truncate or coerce values. Text and
//    blob lengths are checked against INT_MAX before the native bind. All
//    values are bound with SQLITE_TRANSIENT ownership.
//
// Execution, fetch, and reset:
//  * The Session resets after its arity and policy checks before binding each
//    execution. Reset clears native results and bindings without BEGIN,
//    COMMIT, or ROLLBACK; explicit transaction ownership stays with the
//    endpoint. No execution is ever replayed automatically.
//  * sqlite3_reset may return the prior step error even though it successfully
//    reset the statement. If that step error was already reported by execute
//    or fetch and has the same primary SQLite code, reset acknowledges it so
//    the caller can bind and execute again. A reset error with a different
//    primary code is propagated and is not converted into success.
//  * execute steps once and records whether the first result row is ready.
//    fetch returns one owned row with done=false, or an empty row with
//    done=true at EOF, and only steps when another row is needed.
//  * Fetch copies runtime INTEGER, FLOAT, TEXT, BLOB, and NULL values while
//    preserving embedded NULs and empty-versus-NULL. Native byte lengths are
//    checked against the payload budget before large fields are copied.
//    value_payload_bytes is the consistent accounting rule.
//  * A SQLITE_TEXT column requires a non-null native text pointer even when
//    its byte length is zero; null is reported as an error because SQLite can
//    use it for conversion or allocation failure. A zero-length SQLITE_BLOB
//    may have a null data pointer and remains a valid empty value.
//  * After SQLite reprepares a statement because of a schema change, a changed
//    result column count or name is reported as ErrorKind::schema_changed
//    instead of exposing rows under stale metadata.
//
// Counters:
//  * For a no-result execution, affected_rows is reported only when
//    total_changes64 advances, and then sqlite3_changes supplies direct changes
//    so trigger changes are excluded. DDL after DML therefore does not repeat
//    a stale affected count.
//  * last_insert_id is always 0 in this initial engine slice. Statement-kind
//    semantics are not integrated here, and a stale session rowid is never
//    reported as the current statement's insert id.
//
// Unsupported or untested limits:
//  * Temporal values, Decimal conversion, cursor/portal behavior, streaming
//    memory protection, frontend type mapping, public C ABI, statement-kind
//    classification, and transaction-control admission policy are not
//    implemented by this adapter.
#include "Embedded_Execution.h"

struct sqlite3;

namespace embedded {

class SQLiteAdapter final : public Adapter {
public:
    // connection is borrowed and must outlive this adapter and its sessions.
    explicit SQLiteAdapter(sqlite3* connection) noexcept;
    ~SQLiteAdapter() override;

    SQLiteAdapter(const SQLiteAdapter&) = delete;
    SQLiteAdapter& operator=(const SQLiteAdapter&) = delete;

    Status prepare(const std::string& sql, std::unique_ptr<Statement>& out) override;
    Status describe_parameters(Statement& statement, std::vector<Type>& out) override;
    Status describe_result(Statement& statement, std::vector<Column>& out) override;
    Status bind(Statement& statement, const std::vector<Value>& values) override;
    Status execute(Statement& statement, ExecInfo& info) override;
    Status fetch(Statement& statement, Row& row, bool& done, size_t budget) override;
    Status reset(Statement& statement) override;
    void finalize(std::unique_ptr<Statement> statement) noexcept override;
    Status describe_parameter_positions(Statement&, std::vector<uint32_t>&) override;

    sqlite3* connection() const noexcept { return connection_; }

private:
    struct StatementState;

    // Returns null unless the native handle belongs to this exact adapter and
    // connection. This blocks cross-adapter and cross-connection reuse.
    StatementState* checked(Statement& statement) const noexcept;

    sqlite3* connection_;
};

}  // namespace embedded
