#include "duckdb_prepared_provider.h"
#include "tap.h"
#include <cstring>
#include <string>

struct State {
    unsigned char client = 'I';
    duckdb_connection *conn = nullptr;
    duckdb_database db = nullptr;
    bool live_statement = false;
    bool finalized_before_reconnect = false;
    bool failed = false;
    bool fail_reset = false;
};
static uint8_t status(void *p) noexcept {
    return static_cast<State *>(p)->client;
}
static void failure(void *p) noexcept {
    static_cast<State *>(p)->failed = true;
}
static bool reset_client(void *p, duckdb_connection *out) noexcept {
    auto *state = static_cast<State *>(p);
    if (state->fail_reset)
        return false;
    state->finalized_before_reconnect = !state->live_statement;
    duckdb_disconnect(state->conn);
    if (duckdb_connect(state->db, state->conn) != DuckDBSuccess)
        return false;
    *out = *state->conn;
    state->client = 'I';
    return true;
}
static ProxySQL_Embedded_BytesView bytes(const char *s) {
    return {reinterpret_cast<const uint8_t *>(s), strlen(s)};
}
static void query(duckdb_connection conn, const char *sql) {
    duckdb_result result{};
    if (duckdb_query(conn, sql, &result) != DuckDBSuccess) {
        const char *message = duckdb_result_error(&result);
        BAIL_OUT("fixture query failed: %s: %s", sql, message ? message : "unknown error");
    }
    duckdb_destroy_result(&result);
}
#define REQUIRE(test, label)                                                                       \
    do {                                                                                           \
        bool result_ = (test);                                                                     \
        ok(result_, "%s", label);                                                                  \
        if (!result_)                                                                              \
            BAIL_OUT("cannot continue: %s", label);                                                \
    } while (false)
int main() {
    plan(NO_PLAN);
    duckdb_database db = nullptr;
    duckdb_connection conn = nullptr;
    if (duckdb_open(nullptr, &db) != DuckDBSuccess || duckdb_connect(db, &conn) != DuckDBSuccess)
        BAIL_OUT("cannot open DuckDB fixture");
    {
        State state;
        state.conn = &conn;
        state.db = db;
        DuckDBPreparedProvider provider(conn, status, failure, reset_client, &state,
                                        embedded::DuckDBSourceDialect::postgresql);
        const auto *engine = provider.engine();
        ProxySQL_Embedded_Error err{};
        void *guard = nullptr, *stmt = nullptr;
        auto enter = [&](uint32_t op) {
            if (engine->guard_enter(engine->context, op, {}, &guard, &err) != 0 || !guard)
                BAIL_OUT("cannot enter guard %u", op);
        };
        auto leave = [&] {
            engine->guard_leave(engine->context, guard);
            guard = nullptr;
        };
        const char *sql = "SELECT 42 AS n, true AS b, NULL::INTEGER AS z, 12.34::DECIMAL(4,2) AS "
                          "d, '\\x00\\xFF'::BLOB AS bytes";
        enter(ProxySQL_Embedded_OPERATION_PREPARE);
        REQUIRE(engine->prepare(engine->context, bytes(sql), &stmt, &err) == 0 && stmt,
                "prepare typed constant SELECT");
        leave();
        const ProxySQL_Embedded_Column *cols = nullptr;
        size_t ncols = 0;
        ok(engine->describe_result(engine->context, stmt, &cols, &ncols, &err) == 0 && ncols == 5,
           "describe five result columns");
        enter(ProxySQL_Embedded_OPERATION_EXECUTE);
        ProxySQL_Embedded_ExecInfo info{};
        REQUIRE(engine->execute(engine->context, stmt, &info, &err) == 0 && info.has_result,
                "execute typed constant SELECT");
        leave();
        enter(ProxySQL_Embedded_OPERATION_FETCH);
        const ProxySQL_Embedded_Value *row = nullptr;
        size_t count = 0;
        uint8_t done = 0;
        REQUIRE(engine->fetch(engine->context, stmt, &row, &count, &done, 100, &err) == 0 &&
                    !done && count == 5,
                "fetch typed constant row");
        ok(row[0].kind == ProxySQL_Embedded_VALUE_INT64 && row[0].payload.int64_value == 42,
           "integer value");
        ok(row[1].kind == ProxySQL_Embedded_VALUE_BOOLEAN && row[1].payload.boolean_value,
           "boolean value");
        ok(row[2].kind == ProxySQL_Embedded_VALUE_NULL, "NULL value");
        ok(row[3].kind == ProxySQL_Embedded_VALUE_DECIMAL &&
               std::string((const char *)row[3].payload.bytes.data, row[3].payload.bytes.size) ==
                   "12.34",
           "exact decimal value");
        ok(row[4].kind == ProxySQL_Embedded_VALUE_BYTES && row[4].payload.bytes.size == 2 &&
               row[4].payload.bytes.data[0] == 0 && row[4].payload.bytes.data[1] == 255,
           "binary bytes value");
        leave();
        enter(ProxySQL_Embedded_OPERATION_RESET);
        ok(engine->reset(engine->context, stmt, &err) == 0, "reset releases result");
        leave();
        engine->finalize(engine->context, stmt);

        const char *parameter_sql =
            "SELECT $1::VARCHAR, $2::VARCHAR, $3::BLOB, $4::DECIMAL(8,4), $5::BOOLEAN, $6::VARCHAR";
        enter(ProxySQL_Embedded_OPERATION_PREPARE);
        REQUIRE(engine->prepare(engine->context, bytes(parameter_sql), &stmt, &err) == 0 && stmt,
                "prepare parameterized SELECT");
        leave();
        const char utf8[] = "h\xc3\xa9";
        const uint8_t binary[] = {0, 0xff};
        const char decimal[] = "-12.3400";
        ProxySQL_Embedded_Value values[6]{};
        values[0].kind = ProxySQL_Embedded_VALUE_NULL;
        values[1].kind = ProxySQL_Embedded_VALUE_TEXT;
        values[1].payload.bytes = {reinterpret_cast<const uint8_t *>(utf8), sizeof(utf8) - 1};
        values[2].kind = ProxySQL_Embedded_VALUE_BYTES;
        values[2].payload.bytes = {binary, sizeof(binary)};
        values[3].kind = ProxySQL_Embedded_VALUE_DECIMAL;
        values[3].payload.bytes = {reinterpret_cast<const uint8_t *>(decimal), sizeof(decimal) - 1};
        values[4].kind = ProxySQL_Embedded_VALUE_BOOLEAN;
        values[4].payload.boolean_value = 1;
        values[5].kind = ProxySQL_Embedded_VALUE_TEXT;
        values[5].payload.bytes = {nullptr, 0};
        REQUIRE(engine->bind(engine->context, stmt, values, 6, &err) == 0,
                "bind public NULL, UTF8, bytes, decimal, boolean and empty text values");
        enter(ProxySQL_Embedded_OPERATION_EXECUTE);
        REQUIRE(engine->execute(engine->context, stmt, &info, &err) == 0, "execute bound values");
        leave();
        enter(ProxySQL_Embedded_OPERATION_FETCH);
        REQUIRE(engine->fetch(engine->context, stmt, &row, &count, &done, 100, &err) == 0 &&
                    !done && count == 6,
                "fetch bound values");
        ok(row[0].kind == ProxySQL_Embedded_VALUE_NULL, "bound NULL round trips");
        ok(row[1].kind == ProxySQL_Embedded_VALUE_TEXT &&
               row[1].payload.bytes.size == sizeof(utf8) - 1 &&
               memcmp(row[1].payload.bytes.data, utf8, sizeof(utf8) - 1) == 0,
           "bound UTF8 round trips");
        ok(row[2].kind == ProxySQL_Embedded_VALUE_BYTES &&
               row[2].payload.bytes.size == sizeof(binary) &&
               memcmp(row[2].payload.bytes.data, binary, sizeof(binary)) == 0,
           "bound bytes round trip");
        ok(row[3].kind == ProxySQL_Embedded_VALUE_DECIMAL &&
               row[3].payload.bytes.size == sizeof(decimal) - 1 &&
               memcmp(row[3].payload.bytes.data, decimal, sizeof(decimal) - 1) == 0,
           "bound decimal preserves exact scale");
        ok(row[4].kind == ProxySQL_Embedded_VALUE_BOOLEAN && row[4].payload.boolean_value == 1,
           "bound boolean round trips");
        ok(row[5].kind == ProxySQL_Embedded_VALUE_TEXT && row[5].payload.bytes.size == 0,
           "bound empty text remains distinct from NULL");
        leave();
        engine->finalize(engine->context, stmt);

        query(conn, "CREATE SEQUENCE s START 1");
        query(conn, "CREATE VIEW v AS SELECT nextval('s') AS x");
        enter(ProxySQL_Embedded_OPERATION_PREPARE);
        REQUIRE(engine->prepare(engine->context, bytes("SELECT * FROM v"), &stmt, &err) == 0 &&
                    stmt,
                "prepare view hiding a sequence effect");
        leave();
        enter(ProxySQL_Embedded_OPERATION_EXECUTE);
        ok(engine->execute(engine->context, stmt, &info, &err) != 0,
           "read-only transaction rejects hidden sequence effect");
        leave();
        engine->finalize(engine->context, stmt);
        duckdb_result r{};
        if (duckdb_query(conn, "SELECT nextval('s')", &r) != DuckDBSuccess)
            BAIL_OUT("cannot inspect sequence");
        ok(duckdb_value_int64(&r, 0, 0) == 1, "rejected hidden effect did not advance sequence");
        duckdb_destroy_result(&r);
        query(conn, "BEGIN TRANSACTION");
        query(conn, "CREATE TABLE pending(i INTEGER)");
        state.client = 'T';
        guard = nullptr;
        ok(engine->guard_enter(engine->context, ProxySQL_Embedded_OPERATION_PREPARE, {}, &guard,
                               &err) != 0 &&
               !guard,
           "client transaction is refused");
        query(conn, "ROLLBACK");
        state.client = 'I';
        auto rc = duckdb_query(conn, "SELECT * FROM pending", &r);
        ok(rc == DuckDBError, "client transaction remains uncommitted");
        duckdb_destroy_result(&r);
        enter(ProxySQL_Embedded_OPERATION_PREPARE);
        REQUIRE(engine->prepare(engine->context, bytes(sql), &stmt, &err) == 0 && stmt,
                "prepare again after private transaction cleanup");
        leave();
        engine->finalize(engine->context, stmt);
        query(conn, "CREATE TABLE reset_probe(i INTEGER)");
        query(conn, "CREATE TEMP TABLE session_temp(i INTEGER)");
        query(conn, "SET scalar_subquery_error_on_multiple_rows = false");
        enter(ProxySQL_Embedded_OPERATION_PREPARE);
        REQUIRE(engine->prepare(engine->context, bytes("SELECT 1"), &stmt, &err) == 0 && stmt,
                "prepare handle before session reset");
        leave();
        state.live_statement = true;
        query(conn, "BEGIN TRANSACTION");
        query(conn, "INSERT INTO reset_probe VALUES (1)");
        state.client = 'T';
        enter(ProxySQL_Embedded_OPERATION_RESET);
        leave();
        ok(state.client == 'T', "statement reset preserves client transaction");
        duckdb_result before{};
        if (duckdb_query(conn, "SELECT count(*) FROM reset_probe", &before) != DuckDBSuccess)
            BAIL_OUT("cannot inspect uncommitted row");
        ok(duckdb_value_int64(&before, 0, 0) == 1, "statement reset retains pending write");
        duckdb_destroy_result(&before);
        enter(ProxySQL_Embedded_OPERATION_SESSION_RESET);
        engine->finalize(engine->context, stmt);
        state.live_statement = false;
        leave();
        ok(state.finalized_before_reconnect,
           "native statements finalize before connection replacement");
        ok(state.client == 'I', "session reset clears client transaction state");
        duckdb_result after{};
        if (duckdb_query(conn, "SELECT count(*) FROM reset_probe", &after) != DuckDBSuccess)
            BAIL_OUT("cannot inspect reset row count");
        ok(duckdb_value_int64(&after, 0, 0) == 0, "session reset rolls back pending write");
        duckdb_destroy_result(&after);
        duckdb_result temp{};
        auto temp_rc = duckdb_query(conn, "SELECT * FROM session_temp", &temp);
        ok(temp_rc == DuckDBError, "session reset drops temporary tables");
        duckdb_destroy_result(&temp);
        duckdb_result config{};
        if (duckdb_query(conn, "SELECT current_setting('scalar_subquery_error_on_multiple_rows')",
                         &config) != DuckDBSuccess)
            BAIL_OUT("cannot inspect connection setting");
        ok(duckdb_value_boolean(&config, 0, 0), "session reset restores connection settings");
        duckdb_destroy_result(&config);
        auto policy = provider.policy();
        ok(policy->authorize_prepare(policy->context, bytes("SELECT 42"), &err) == 0,
           "policy permits simple SELECT");
        enter(ProxySQL_Embedded_OPERATION_PREPARE);
        query(conn, "ROLLBACK");
        leave();
        ok(state.failed, "cleanup failure marks session unhealthy");
        guard = nullptr;
        ok(engine->guard_enter(engine->context, ProxySQL_Embedded_OPERATION_PREPARE, {}, &guard,
                               &err) != 0 &&
               !guard,
           "cleanup failure poisons future operations");
        enter(ProxySQL_Embedded_OPERATION_DISCONNECT);
        leave();
        ok(true, "disconnect guard succeeds after poisoning");
    }
    {
        State failed_state;
        failed_state.conn = &conn;
        failed_state.db = db;
        failed_state.client = 'T';
        failed_state.fail_reset = true;
        DuckDBPreparedProvider provider(conn, status, failure, reset_client, &failed_state,
                                        embedded::DuckDBSourceDialect::postgresql);
        query(conn, "BEGIN TRANSACTION");
        query(conn, "INSERT INTO reset_probe VALUES (2)");
        const auto *engine = provider.engine();
        ProxySQL_Embedded_Error error{};
        void *guard = nullptr;
        REQUIRE(engine->guard_enter(engine->context, ProxySQL_Embedded_OPERATION_SESSION_RESET, {},
                                    &guard, &error) == 0 &&
                    guard,
                "failed reconnect is deferred until after native finalization");
        engine->guard_leave(engine->context, guard);
        ok(failed_state.failed, "failed session reconnect marks session unhealthy");
        duckdb_result pending{};
        if (duckdb_query(conn, "SELECT count(*) FROM reset_probe", &pending) != DuckDBSuccess)
            BAIL_OUT("cannot inspect failed reset");
        ok(failed_state.client == 'T' && duckdb_value_int64(&pending, 0, 0) == 1,
           "failed reset leaves client transaction untouched");
        duckdb_destroy_result(&pending);
        query(conn, "ROLLBACK");
    }
    {
        State state;
        state.conn = &conn;
        state.db = db;
        DuckDBPreparedProvider provider(conn, status, failure, reset_client, &state,
                                        embedded::DuckDBSourceDialect::mysql);
        provider.set_mysql_analytical(true);
        const auto *engine = provider.engine();
        const auto *policy = provider.policy();
        ProxySQL_Embedded_Error err{};
        void *guard = nullptr, *stmt = nullptr;
        query(conn, "CREATE TABLE prep_a (id BIGINT, value BIGINT)");
        query(conn, "INSERT INTO prep_a VALUES (1,10),(2,20),(3,30)");
        const char *sql = "SELECT COUNT(*) FROM prep_a WHERE id > 1";
        ok(policy->authorize_prepare(policy->context, bytes(sql), &err) != 0 &&
               err.kind == ProxySQL_Embedded_ERROR_TRANSACTION,
           "analytical admission refuses calls outside a private guard");
        REQUIRE(engine->guard_enter(engine->context, ProxySQL_Embedded_OPERATION_PREPARE, {},
                                    &guard, &err) == 0,
                "analytical prepare enters guard");
        REQUIRE(policy->authorize_prepare(policy->context, bytes(sql), &err) == 0,
                "analytical policy accepts typed count");
        REQUIRE(engine->prepare(engine->context, bytes(sql), &stmt, &err) == 0 && stmt,
                "analytical provider prepares translated SQL");
        engine->guard_leave(engine->context, guard);
        guard = nullptr;
        REQUIRE(engine->guard_enter(engine->context, ProxySQL_Embedded_OPERATION_EXECUTE, {},
                                    &guard, &err) == 0,
                "analytical execute enters guard");
        REQUIRE(policy->authorize_execute(policy->context, bytes(sql), nullptr, 0, &err) == 0,
                "fresh metadata admits unchanged predicate");
        ProxySQL_Embedded_ExecInfo info{};
        REQUIRE(engine->bind(engine->context, stmt, nullptr, 0, &err) == 0,
                "bind analytical COUNT");
        ok(engine->execute(engine->context, stmt, &info, &err) == 0, "translated COUNT executes");
        engine->guard_leave(engine->context, guard);
        guard = nullptr;
        query(conn, "CREATE TABLE \"odd`name\" (id BIGINT PRIMARY KEY, \"a`b\" BIGINT)");
        query(conn, "INSERT INTO \"odd`name\" VALUES (1,10),(2,20),(3,30)");
        const char *quoted = "SELECT `a``b` FROM `odd``name` ORDER BY id LIMIT 1, 1";
        void *quoted_stmt = nullptr;
        REQUIRE(engine->guard_enter(engine->context, ProxySQL_Embedded_OPERATION_PREPARE, {},
                                    &guard, &err) == 0,
                "escaped prepare enters guard");
        REQUIRE(policy->authorize_prepare(policy->context, bytes(quoted), &err) == 0 &&
                    engine->prepare(engine->context, bytes(quoted), &quoted_stmt, &err) == 0 &&
                    quoted_stmt,
                "analytical prepare translates backticks and comma LIMIT");
        engine->guard_leave(engine->context, guard);
        guard = nullptr;
        REQUIRE(engine->guard_enter(engine->context, ProxySQL_Embedded_OPERATION_EXECUTE, {},
                                    &guard, &err) == 0,
                "escaped execute enters guard");
        REQUIRE(policy->authorize_execute(policy->context, bytes(quoted), nullptr, 0, &err) == 0 &&
                    engine->bind(engine->context, quoted_stmt, nullptr, 0, &err) == 0 &&
                    engine->execute(engine->context, quoted_stmt, &info, &err) == 0,
                "translated escaped prepared SELECT executes");
        engine->guard_leave(engine->context, guard);
        guard = nullptr;
        REQUIRE(engine->guard_enter(engine->context, ProxySQL_Embedded_OPERATION_FETCH, {}, &guard,
                                    &err) == 0,
                "escaped fetch enters guard");
        const ProxySQL_Embedded_Value *row = nullptr;
        size_t count = 0;
        uint8_t done = 0;
        REQUIRE(engine->fetch(engine->context, quoted_stmt, &row, &count, &done, 128, &err) == 0 &&
                    !done && count == 1,
                "fetch translated result");
        ok(row[0].kind == ProxySQL_Embedded_VALUE_INT64 && row[0].payload.int64_value == 20,
           "comma LIMIT returns the intended row");
        engine->guard_leave(engine->context, guard);
        guard = nullptr;
        engine->finalize(engine->context, quoted_stmt);
        query(conn, "CREATE TABLE typed_params (id BIGINT, v TINYINT)");
        query(conn, "INSERT INTO typed_params VALUES (1,5),(2,6)");
        const char *param_sql = "SELECT id FROM typed_params WHERE v = ?";
        void *param_stmt = nullptr;
        REQUIRE(engine->guard_enter(engine->context, ProxySQL_Embedded_OPERATION_PREPARE, {},
                                    &guard, &err) == 0,
                "parameter prepare guard");
        REQUIRE(policy->authorize_prepare(policy->context, bytes(param_sql), &err) == 0 &&
                    engine->prepare(engine->context, bytes(param_sql), &param_stmt, &err) == 0 &&
                    param_stmt,
                "analytical parameter prepares");
        engine->guard_leave(engine->context, guard);
        guard = nullptr;
        ProxySQL_Embedded_Value value{};
        value.kind = ProxySQL_Embedded_VALUE_INT64;
        value.payload.int64_value = 5;
        REQUIRE(engine->guard_enter(engine->context, ProxySQL_Embedded_OPERATION_EXECUTE, {},
                                    &guard, &err) == 0,
                "parameter execute guard");
        REQUIRE(policy->authorize_execute(policy->context, bytes(param_sql), &value, 1, &err) ==
                        0 &&
                    engine->bind(engine->context, param_stmt, &value, 1, &err) == 0 &&
                    engine->execute(engine->context, param_stmt, &info, &err) == 0,
                "integer parameter executes");
        engine->guard_leave(engine->context, guard);
        guard = nullptr;
        REQUIRE(engine->guard_enter(engine->context, ProxySQL_Embedded_OPERATION_FETCH, {}, &guard,
                                    &err) == 0,
                "parameter fetch guard");
        REQUIRE(engine->fetch(engine->context, param_stmt, &row, &count, &done, 128, &err) == 0 &&
                    !done && count == 1,
                "parameter result row");
        ok(row[0].kind == ProxySQL_Embedded_VALUE_INT64 && row[0].payload.int64_value == 1,
           "bound value selects expected row");
        engine->guard_leave(engine->context, guard);
        guard = nullptr;
        auto run_param = [&](uint32_t kind, int64_t number, bool want_row, int64_t expected) {
            ProxySQL_Embedded_Value v{};
            v.kind = kind;
            v.payload.int64_value = number;
            void *g = nullptr;
            if (engine->guard_enter(engine->context, ProxySQL_Embedded_OPERATION_EXECUTE, {}, &g,
                                    &err) != 0)
                return false;
            bool good =
                policy->authorize_execute(policy->context, bytes(param_sql), &v, 1, &err) == 0 &&
                engine->reset(engine->context, param_stmt, &err) == 0 &&
                engine->bind(engine->context, param_stmt, &v, 1, &err) == 0 &&
                engine->execute(engine->context, param_stmt, &info, &err) == 0;
            engine->guard_leave(engine->context, g);
            if (!good)
                return false;
            g = nullptr;
            if (engine->guard_enter(engine->context, ProxySQL_Embedded_OPERATION_FETCH, {}, &g,
                                    &err) != 0)
                return false;
            const ProxySQL_Embedded_Value *r = nullptr;
            size_t n = 0;
            uint8_t end = 0;
            good = engine->fetch(engine->context, param_stmt, &r, &n, &end, 128, &err) == 0 &&
                   (want_row ? (!end && n == 1 && r[0].kind == ProxySQL_Embedded_VALUE_INT64 &&
                                r[0].payload.int64_value == expected)
                             : end);
            engine->guard_leave(engine->context, g);
            return good;
        };
        ok(run_param(ProxySQL_Embedded_VALUE_INT64, 6, true, 2),
           "rebinding same handle selects a new row");
        ok(run_param(ProxySQL_Embedded_VALUE_INT64, 200, false, 0),
           "TINYINT compared with 200 returns no rows");
        ok(run_param(ProxySQL_Embedded_VALUE_NULL, 0, false, 0), "NULL parameter returns no rows");
        REQUIRE(engine->guard_enter(engine->context, ProxySQL_Embedded_OPERATION_EXECUTE, {},
                                    &guard, &err) == 0,
                "unsupported parameter guard");
        ProxySQL_Embedded_Value attack{};
        attack.kind = ProxySQL_Embedded_VALUE_TEXT;
        const char injection[] = "1 OR 1=1";
        attack.payload.bytes = {reinterpret_cast<const uint8_t *>(injection),
                                sizeof(injection) - 1};
        ok(policy->authorize_execute(policy->context, bytes(param_sql), &attack, 1, &err) != 0 &&
               err.kind == ProxySQL_Embedded_ERROR_UNSUPPORTED &&
               std::string(err.sqlstate) == "0A000",
           "text parameter is refused with feature SQLSTATE before binding");
        engine->guard_leave(engine->context, guard);
        guard = nullptr;
        ok(run_param(ProxySQL_Embedded_VALUE_INT64, 5, true, 1),
           "valid integer recovers after type refusal");
        REQUIRE(engine->guard_enter(engine->context, ProxySQL_Embedded_OPERATION_EXECUTE, {},
                                    &guard, &err) == 0,
                "mismatched parameter guard");
        ok(policy->authorize_execute(policy->context, bytes(param_sql), nullptr, 0, &err) != 0 &&
               err.kind == ProxySQL_Embedded_ERROR_INVALID_PARAMETER,
           "parameter count mismatch does not masquerade as schema change");
        engine->guard_leave(engine->context, guard);
        guard = nullptr;
        const char *two_sql = "SELECT id FROM typed_params WHERE (? < id AND id <= ?)";
        void *two_stmt = nullptr;
        REQUIRE(engine->guard_enter(engine->context, ProxySQL_Embedded_OPERATION_PREPARE, {},
                                    &guard, &err) == 0,
                "two-parameter prepare guard");
        REQUIRE(policy->authorize_prepare(policy->context, bytes(two_sql), &err) == 0 &&
                    engine->prepare(engine->context, bytes(two_sql), &two_stmt, &err) == 0 &&
                    two_stmt,
                "two parameter query prepares");
        engine->guard_leave(engine->context, guard);
        guard = nullptr;
        ProxySQL_Embedded_Value pair[2]{};
        pair[0].kind = pair[1].kind = ProxySQL_Embedded_VALUE_INT64;
        pair[0].payload.int64_value = 1;
        pair[1].payload.int64_value = 2;
        REQUIRE(engine->guard_enter(engine->context, ProxySQL_Embedded_OPERATION_EXECUTE, {},
                                    &guard, &err) == 0,
                "two-parameter execute guard");
        REQUIRE(policy->authorize_execute(policy->context, bytes(two_sql), pair, 2, &err) == 0 &&
                    engine->bind(engine->context, two_stmt, pair, 2, &err) == 0 &&
                    engine->execute(engine->context, two_stmt, &info, &err) == 0,
                "two distinct parameter values execute");
        engine->guard_leave(engine->context, guard);
        guard = nullptr;
        REQUIRE(engine->guard_enter(engine->context, ProxySQL_Embedded_OPERATION_FETCH, {}, &guard,
                                    &err) == 0,
                "two-parameter fetch guard");
        REQUIRE(engine->fetch(engine->context, two_stmt, &row, &count, &done, 128, &err) == 0 &&
                    !done && count == 1,
                "fetch two-parameter result");
        ok(row[0].kind == ProxySQL_Embedded_VALUE_INT64 && row[0].payload.int64_value == 2,
           "two parameter positions retain order");
        engine->guard_leave(engine->context, guard);
        guard = nullptr;
        engine->finalize(engine->context, two_stmt);
        query(conn, "ALTER TABLE typed_params ALTER v TYPE VARCHAR");
        REQUIRE(engine->guard_enter(engine->context, ProxySQL_Embedded_OPERATION_EXECUTE, {},
                                    &guard, &err) == 0,
                "parameter schema drift guard");
        ProxySQL_Embedded_Value int_value{};
        int_value.kind = ProxySQL_Embedded_VALUE_INT64;
        int_value.payload.int64_value = 5;
        ok(policy->authorize_execute(policy->context, bytes(param_sql), &int_value, 1, &err) != 0 &&
               err.kind == ProxySQL_Embedded_ERROR_SCHEMA_CHANGED,
           "signed column changed to text remains schema change");
        engine->guard_leave(engine->context, guard);
        guard = nullptr;
        engine->finalize(engine->context, param_stmt);
        query(conn, "ALTER TABLE prep_a ALTER id TYPE VARCHAR");
        REQUIRE(engine->guard_enter(engine->context, ProxySQL_Embedded_OPERATION_EXECUTE, {},
                                    &guard, &err) == 0,
                "schema drift check enters guard");
        ok(policy->authorize_execute(policy->context, bytes(sql), nullptr, 0, &err) != 0 &&
               err.kind == ProxySQL_Embedded_ERROR_SCHEMA_CHANGED,
           "predicate type drift refuses even when COUNT output type is unchanged");
        engine->guard_leave(engine->context, guard);
        guard = nullptr;
        engine->finalize(engine->context, stmt);
        REQUIRE(engine->guard_enter(engine->context, ProxySQL_Embedded_OPERATION_PREPARE, {},
                                    &guard, &err) == 0,
                "placeholder test enters guard");
        ok(policy->authorize_prepare(policy->context, bytes("SELECT ?"), &err) != 0 &&
               err.kind == ProxySQL_Embedded_ERROR_UNSUPPORTED,
           "analytical projection placeholders are refused");
        engine->guard_leave(engine->context, guard);
    }
    {
        State state;
        DuckDBPreparedProvider provider(conn, status, failure, reset_client, &state,
                                        embedded::DuckDBSourceDialect::mysql);
        provider.set_mysql_analytical(true);
        const auto *engine = provider.engine();
        const auto *policy = provider.policy();
        ProxySQL_Embedded_Error err{};
        ProxySQL_Embedded_ExecInfo info{};
        void *guard = nullptr, *stmt = nullptr;
        query(conn, "CREATE TABLE decimal_refresh(d DECIMAL(18,4))");
        const char *sql = "SELECT COUNT(*) FROM decimal_refresh WHERE d > 1.5";
        REQUIRE(engine->guard_enter(engine->context, ProxySQL_Embedded_OPERATION_PREPARE, {},
                                    &guard, &err) == 0 &&
                    policy->authorize_prepare(policy->context, bytes(sql), &err) == 0 &&
                    engine->prepare(engine->context, bytes(sql), &stmt, &err) == 0,
                "prepare decimal COUNT before schema widening");
        engine->guard_leave(engine->context, guard);
        query(conn, "ALTER TABLE decimal_refresh ALTER d TYPE DECIMAL(22,4)");
        query(conn, "INSERT INTO decimal_refresh VALUES (999999999999999999.9999)");
        REQUIRE(engine->guard_enter(engine->context, ProxySQL_Embedded_OPERATION_EXECUTE, {},
                                    &guard, &err) == 0 &&
                    policy->authorize_execute(policy->context, bytes(sql), nullptr, 0, &err) == 0 &&
                    engine->reset(engine->context, stmt, &err) == 0 &&
                    engine->bind(engine->context, stmt, nullptr, 0, &err) == 0 &&
                    engine->execute(engine->context, stmt, &info, &err) == 0,
                "decimal widening executes fresh cast without stale overflow");
        engine->guard_leave(engine->context, guard);
        REQUIRE(engine->guard_enter(engine->context, ProxySQL_Embedded_OPERATION_FETCH, {}, &guard,
                                    &err) == 0,
                "decimal COUNT fetch guard");
        const ProxySQL_Embedded_Value *row = nullptr;
        size_t count = 0;
        uint8_t done = 0;
        REQUIRE(engine->fetch(engine->context, stmt, &row, &count, &done, 128, &err) == 0 &&
                    !done && count == 1 && row[0].kind == ProxySQL_Embedded_VALUE_INT64 &&
                    row[0].payload.int64_value == 1,
                "fresh decimal COUNT returns correct row");
        engine->guard_leave(engine->context, guard);
        REQUIRE(engine->guard_enter(engine->context, ProxySQL_Embedded_OPERATION_EXECUTE, {},
                                    &guard, &err) == 0 &&
                    policy->authorize_execute(policy->context, bytes(sql), nullptr, 0, &err) == 0 &&
                    engine->reset(engine->context, stmt, &err) == 0,
                "reauthorize COUNT for missing-bind check");
        ok(engine->execute(engine->context, stmt, &info, &err) != 0,
           "analytical execute without fresh bind is rejected");
        engine->guard_leave(engine->context, guard);
        REQUIRE(engine->guard_enter(engine->context, ProxySQL_Embedded_OPERATION_EXECUTE, {},
                                    &guard, &err) == 0 &&
                    policy->authorize_execute(policy->context, bytes(sql), nullptr, 0, &err) == 0 &&
                    engine->reset(engine->context, stmt, &err) == 0 &&
                    engine->bind(engine->context, stmt, nullptr, 0, &err) == 0 &&
                    engine->execute(engine->context, stmt, &info, &err) == 0,
                "COUNT recovers after missing-bind rejection");
        engine->guard_leave(engine->context, guard);
        engine->finalize(engine->context, stmt);
        stmt = nullptr;
        query(conn, "CREATE TABLE decimal_projection(d DECIMAL(4,4))");
        const char *projection = "SELECT d FROM decimal_projection";
        REQUIRE(engine->guard_enter(engine->context, ProxySQL_Embedded_OPERATION_PREPARE, {},
                                    &guard, &err) == 0 &&
                    policy->authorize_prepare(policy->context, bytes(projection), &err) == 0 &&
                    engine->prepare(engine->context, bytes(projection), &stmt, &err) == 0,
                "prepare decimal projection before scale drift");
        engine->guard_leave(engine->context, guard);
        query(conn, "ALTER TABLE decimal_projection ALTER d TYPE DECIMAL(5,5)");
        REQUIRE(engine->guard_enter(engine->context, ProxySQL_Embedded_OPERATION_EXECUTE, {},
                                    &guard, &err) == 0 &&
                    policy->authorize_execute(policy->context, bytes(projection), nullptr, 0,
                                              &err) == 0 &&
                    engine->reset(engine->context, stmt, &err) == 0,
                "reauthorize changed fractional projection");
        ok(engine->bind(engine->context, stmt, nullptr, 0, &err) != 0 &&
               err.kind == ProxySQL_Embedded_ERROR_SCHEMA_CHANGED,
           "changed projection metadata is rejected before execute");
        ok(engine->execute(engine->context, stmt, &info, &err) != 0,
           "failed refresh cannot execute stale native statement");
        engine->guard_leave(engine->context, guard);
        engine->finalize(engine->context, stmt);
        stmt = nullptr;
        REQUIRE(engine->guard_enter(engine->context, ProxySQL_Embedded_OPERATION_PREPARE, {},
                                    &guard, &err) == 0 &&
                    policy->authorize_prepare(policy->context, bytes(projection), &err) == 0 &&
                    engine->prepare(engine->context, bytes(projection), &stmt, &err) == 0,
                "fresh prepare accepts changed decimal metadata");
        engine->guard_leave(engine->context, guard);
        engine->finalize(engine->context, stmt);
        stmt = nullptr;
        // A stale DECIMAL(3,2) cast would round .301 to .30 and silently count zero rows.
        query(conn, "CREATE TABLE decimal_rounding(d DECIMAL(2,2))");
        const char *rounding = "SELECT COUNT(*) FROM decimal_rounding WHERE d > .3";
        REQUIRE(engine->guard_enter(engine->context, ProxySQL_Embedded_OPERATION_PREPARE, {},
                                    &guard, &err) == 0 &&
                    policy->authorize_prepare(policy->context, bytes(rounding), &err) == 0 &&
                    engine->prepare(engine->context, bytes(rounding), &stmt, &err) == 0,
                "prepare decimal COUNT before scale increase");
        engine->guard_leave(engine->context, guard);
        query(conn, "ALTER TABLE decimal_rounding ALTER d TYPE DECIMAL(3,3)");
        query(conn, "INSERT INTO decimal_rounding VALUES (.301)");
        REQUIRE(engine->guard_enter(engine->context, ProxySQL_Embedded_OPERATION_EXECUTE, {},
                                    &guard, &err) == 0 &&
                    policy->authorize_execute(policy->context, bytes(rounding), nullptr, 0, &err) ==
                        0 &&
                    engine->reset(engine->context, stmt, &err) == 0 &&
                    engine->bind(engine->context, stmt, nullptr, 0, &err) == 0 &&
                    engine->execute(engine->context, stmt, &info, &err) == 0,
                "scale increase executes with fresh cast");
        engine->guard_leave(engine->context, guard);
        REQUIRE(engine->guard_enter(engine->context, ProxySQL_Embedded_OPERATION_FETCH, {}, &guard,
                                    &err) == 0,
                "decimal rounding fetch guard");
        row = nullptr;
        count = 0;
        done = 0;
        ok(engine->fetch(engine->context, stmt, &row, &count, &done, 128, &err) == 0 && !done &&
               count == 1 && row[0].kind == ProxySQL_Embedded_VALUE_INT64 &&
               row[0].payload.int64_value == 1,
           "scale increase does not silently round with a stale cast");
        engine->guard_leave(engine->context, guard);
        engine->finalize(engine->context, stmt);
        stmt = nullptr;
        for (const bool added : {true, false}) {
            const char *change = added ? "ALTER TABLE drift_columns ADD COLUMN c BIGINT"
                                       : "ALTER TABLE drift_columns RENAME COLUMN b TO c";
            query(conn, "DROP TABLE IF EXISTS drift_columns");
            query(conn, "CREATE TABLE drift_columns(a BIGINT, b BIGINT)");
            query(conn, "INSERT INTO drift_columns VALUES (1,2)");
            const char *star = "SELECT * FROM drift_columns";
            REQUIRE(engine->guard_enter(engine->context, ProxySQL_Embedded_OPERATION_PREPARE, {},
                                        &guard, &err) == 0 &&
                        policy->authorize_prepare(policy->context, bytes(star), &err) == 0 &&
                        engine->prepare(engine->context, bytes(star), &stmt, &err) == 0,
                    "prepare star projection before column drift");
            engine->guard_leave(engine->context, guard);
            query(conn, change);
            REQUIRE(engine->guard_enter(engine->context, ProxySQL_Embedded_OPERATION_EXECUTE, {},
                                        &guard, &err) == 0 &&
                        policy->authorize_execute(policy->context, bytes(star), nullptr, 0, &err) ==
                            0 &&
                        engine->reset(engine->context, stmt, &err) == 0,
                    "reauthorize star projection after column drift");
            ok(engine->bind(engine->context, stmt, nullptr, 0, &err) != 0 &&
                   err.kind == ProxySQL_Embedded_ERROR_SCHEMA_CHANGED,
               added ? "added column is rejected before execute"
                     : "renamed column is rejected before execute");
            ok(engine->execute(engine->context, stmt, &info, &err) != 0,
               added ? "added column cannot execute the stale native statement"
                     : "renamed column cannot execute the stale native statement");
            engine->guard_leave(engine->context, guard);
            engine->finalize(engine->context, stmt);
            stmt = nullptr;
        }
    }
    duckdb_disconnect(&conn);
    duckdb_close(&db);
    return exit_status();
}
