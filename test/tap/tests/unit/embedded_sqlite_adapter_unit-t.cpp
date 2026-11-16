// Real SQLite engine tests for the internal Embedded_SQLite_Adapter slice.
// This is not a protocol or public ABI test.
#include "Embedded_SQLite_Adapter.h"
#include "Embedded_Prepared.h"
#include "sqlite3db.h"
#include "tap.h"

#include <cstdint>
#include <limits>
#include <memory>
#include <string>
#include <utility>
#include <vector>

using namespace embedded;

namespace {

struct TestDb {
    sqlite3* db = nullptr;

    bool open() {
        return proxy_sqlite3_open_v2(":memory:", &db,
                                     SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE,
                                     nullptr) == SQLITE_OK;
    }
    bool exec(const char* sql) {
        return db != nullptr &&
               proxy_sqlite3_exec(db, sql, nullptr, nullptr, nullptr) == SQLITE_OK;
    }
    ~TestDb() {
        if (db != nullptr) proxy_sqlite3_close_v2(db);
    }
};

struct PermitPolicy : EndpointPolicy {
    Status authorize_prepare(const std::string&) override { return {}; }
    Status authorize_execute(const std::string&, const std::vector<Value>&) override { return {}; }
    Status authorize_fetch(const std::string&) override { return {}; }
};

using ColumnTextFn = const unsigned char* (*)(sqlite3_stmt*, int);

const unsigned char* null_column_text(sqlite3_stmt*, int) {
    return nullptr;
}

// Temporary test-only API-pointer hooks. They are always restored by scope
// exit, including when a check exits early.
struct ColumnTextHook {
    ColumnTextHook() : previous(proxy_sqlite3_column_text) {
        proxy_sqlite3_column_text = &null_column_text;
    }
    ~ColumnTextHook() { proxy_sqlite3_column_text = previous; }
    ColumnTextHook(const ColumnTextHook&) = delete;
    ColumnTextHook& operator=(const ColumnTextHook&) = delete;

    ColumnTextFn previous;
};

int (*previous_reset)(sqlite3_stmt*) = nullptr;

int reset_then_report_foreign_error(sqlite3_stmt* statement) {
    if (previous_reset != nullptr) (void)previous_reset(statement);
    return SQLITE_IOERR;
}

struct ResetErrorHook {
    ResetErrorHook() : previous(proxy_sqlite3_reset) {
        previous_reset = previous;
        proxy_sqlite3_reset = &reset_then_report_foreign_error;
    }
    ~ResetErrorHook() {
        proxy_sqlite3_reset = previous;
        previous_reset = nullptr;
    }
    ResetErrorHook(const ResetErrorHook&) = delete;
    ResetErrorHook& operator=(const ResetErrorHook&) = delete;

    int (*previous)(sqlite3_stmt*);
};

void status_ok(const Status& status, const char* message) {
    if (status) diag("unexpected error kind=%d code=%d: %s",
                     static_cast<int>(status->kind), status->native_code,
                     status->message.c_str());
    ok(!status, "%s", message);
}

void status_error(const Status& status, ErrorKind kind, const char* message) {
    if (!status) {
        ok(0, "%s (no error returned)", message);
        return;
    }
    if (status->kind != kind)
        diag("error kind=%d code=%d: %s", static_cast<int>(status->kind),
             status->native_code, status->message.c_str());
    ok(status->kind == kind, "%s", message);
}

long long scalar(TestDb& db, const char* sql) {
    sqlite3_stmt* statement = nullptr;
    long long value = -1;
    if (proxy_sqlite3_prepare_v2(db.db, sql, -1, &statement, nullptr) == SQLITE_OK &&
        statement != nullptr && proxy_sqlite3_step(statement) == SQLITE_ROW) {
        value = proxy_sqlite3_column_int64(statement, 0);
    }
    if (statement != nullptr) proxy_sqlite3_finalize(statement);
    return value;
}

bool int_value(const Value& value, int64_t expected) {
    return std::holds_alternative<int64_t>(value) &&
           std::get<int64_t>(value) == expected;
}
bool double_value(const Value& value, double expected) {
    return std::holds_alternative<double>(value) &&
           std::get<double>(value) == expected;
}
bool text_value(const Value& value, const std::string& expected) {
    return std::holds_alternative<Text>(value) &&
           std::get<Text>(value).bytes == expected;
}
bool bytes_value(const Value& value, const std::vector<uint8_t>& expected) {
    return std::holds_alternative<Bytes>(value) &&
           std::get<Bytes>(value).bytes == expected;
}

bool all_unknown(const std::vector<Type>& types) {
    for (const Type& type : types) {
        if (type.kind != TypeKind::unknown) return false;
    }
    return true;
}
bool all_dynamic(const std::vector<Column>& columns) {
    for (const Column& column : columns) {
        if (column.type.kind != TypeKind::dynamic) return false;
    }
    return true;
}

void metadata_and_admission() {
    TestDb db;
    ok(db.open(), "open engine for metadata and admission");
    if (db.db == nullptr) return;
    ok(db.exec("CREATE TABLE t(id INTEGER PRIMARY KEY, name TEXT)"),
       "create metadata table");

    {
        SQLiteAdapter adapter(db.db);
        PermitPolicy policy;
        Session session(adapter, policy);
        uint64_t id = 0;
        uint64_t cast_id = 0;
        uint64_t insert_id = 0;
        uint64_t extra_id = 99;
        uint64_t whitespace_id = 0;
        uint64_t comment_id = 0;
        uint64_t eof_comment_id = 0;
        uint64_t returning_id = 0;
        uint64_t empty_id = 0;
        std::vector<Type> parameters;
        std::vector<Column> columns;

        status_ok(session.prepare("SELECT ? AS p, id AS ident FROM t WHERE id = ?", id),
                  "prepare parameterized select");
        status_ok(session.describe(id, parameters, columns),
                  "describe without executing");
        ok(parameters.size() == 2, "native parameter count is reported");
        ok(all_unknown(parameters), "parameter types remain unknown");
        ok(columns.size() == 2, "native result column count is reported");
        ok(columns.size() == 2 && columns[0].name == "p" && columns[1].name == "ident",
           "result names are owned copies from native metadata");
        ok(all_dynamic(columns), "result types are dynamic, not declared affinity");

        status_ok(session.prepare("SELECT CAST(? AS INTEGER) AS n", cast_id),
                  "prepare expression with declared affinity");
        status_ok(session.describe(cast_id, parameters, columns),
                  "describe expression without stepping");
        ok(parameters.size() == 1 && all_unknown(parameters),
               "expression parameter type is unknown");
        ok(columns.size() == 1 && columns[0].name == "n" && all_dynamic(columns),
           "CAST result remains dynamic metadata");

        status_ok(session.prepare("INSERT INTO t(name) VALUES ('prepared')", insert_id),
                  "prepare write statement");
        ok(scalar(db, "SELECT count(*) FROM t") == 0,
           "prepare and describe never execute the write");

        auto err = session.prepare(
            "INSERT INTO t(name) VALUES ('a'); INSERT INTO t(name) VALUES ('b')", extra_id);
        status_error(err, ErrorKind::unsupported, "extra SQL statements are refused");
        ok(extra_id == 0, "failed multi-statement prepare clears id");
        ok(scalar(db, "SELECT count(*) FROM t") == 0,
           "refused multi-statement prepare has no side effect");

        err = session.prepare(
            "CREATE TABLE leaked(x); INSERT INTO t(name) VALUES ('leak')", extra_id);
        status_error(err, ErrorKind::unsupported, "DDL plus extra SQL is refused");
        ok(scalar(db, "SELECT count(*) FROM sqlite_master WHERE name = 'leaked'") == 0,
           "refused DDL plus extra SQL creates nothing");

        status_ok(session.prepare(
                      "SELECT 42 AS answer;\r\n\t\f\v ",
                      whitespace_id),
                  "trailing ASCII whitespace after the terminator is accepted");
        ExecInfo info;
        Row row;
        bool done = true;
        status_ok(session.execute(whitespace_id, {}, info), "execute trailing-whitespace select");
        ok(info.has_result && !info.affected_rows && info.last_insert_id == 0,
           "read execution has a result and no write counters");
        status_ok(session.fetch(whitespace_id, row, done), "fetch trailing-whitespace row");
        ok(!done && row.size() == 1 && int_value(row[0], 42),
           "trailing-whitespace select returns its row");
        status_ok(session.fetch(whitespace_id, row, done), "fetch EOF for single row");
        ok(done && row.empty(), "second fetch is empty EOF");

        status_ok(session.prepare("SELECT 43 /* before terminator */;", comment_id),
                  "SQLite consumes a comment before the terminator");
        status_ok(session.execute(comment_id, {}, info),
                  "execute comment-before-terminator select");
        status_ok(session.fetch(comment_id, row, done),
                  "fetch comment-before-terminator row");
        ok(!done && row.size() == 1 && int_value(row[0], 43),
           "comment-before-terminator select returns its row");

        status_ok(session.prepare("SELECT 44 -- comment at EOF", eof_comment_id),
                  "SQLite consumes a comment at EOF");
        status_ok(session.execute(eof_comment_id, {}, info),
                  "execute comment-at-EOF select");
        status_ok(session.fetch(eof_comment_id, row, done), "fetch comment-at-EOF row");
        ok(!done && row.size() == 1 && int_value(row[0], 44),
           "comment-at-EOF select returns its row");

        err = session.prepare("SELECT 42; -- after terminator", empty_id);
        status_error(err, ErrorKind::unsupported,
                     "comment after a terminating semicolon is unsupported");
        ok(empty_id == 0, "line-comment tail failure clears id");

        err = session.prepare("SELECT 42; /* after terminator */", empty_id);
        status_error(err, ErrorKind::unsupported,
                     "block comment after a terminating semicolon is unsupported");
        ok(empty_id == 0, "block-comment tail failure clears id");
        ok(scalar(db, "SELECT count(*) FROM t") == 0,
           "unsupported comment tails prepare nothing");

        err = session.prepare("INSERT INTO t(name) VALUES ('returning') RETURNING id",
                              returning_id);
        status_error(err, ErrorKind::unsupported,
                     "write statement with result columns is refused");
        ok(returning_id == 0 && scalar(db, "SELECT count(*) FROM t") == 0,
           "RETURNING refusal happens before any effect");

        err = session.prepare("   -- comment only\n\t", empty_id);
        status_error(err, ErrorKind::syntax, "comment-only SQL has no statement");
        ok(empty_id == 0, "empty prepare clears id");

        err = session.prepare("SELECT 1;;", empty_id);
        status_error(err, ErrorKind::unsupported, "trailing empty statement is refused");
        ok(empty_id == 0, "extra semicolon prepare clears id");
    }
    ok(scalar(db, "SELECT count(*) FROM t") == 0,
       "write statements were only prepared, never executed");
}

void typed_binding_and_runtime_types() {
    TestDb db;
    ok(db.open(), "open engine for typed binding");
    if (db.db == nullptr) return;
    ok(db.exec("CREATE TABLE v(id INTEGER PRIMARY KEY, i INTEGER, u INTEGER, "
               "d REAL, t TEXT, b BLOB)"),
       "create typed table");

    {
        SQLiteAdapter adapter(db.db);
        PermitPolicy policy;
        Session session(adapter, policy);
        uint64_t insert_id = 0;
        uint64_t select_id = 0;
        uint64_t type_id = 0;
        std::vector<Type> parameters;
        std::vector<Column> columns;
        ExecInfo info;
        Row row;
        bool done = true;

        status_ok(session.prepare("INSERT INTO v(i,u,d,t,b) VALUES(?,?,?,?,?)", insert_id),
                  "prepare typed insert");
        status_ok(session.describe(insert_id, parameters, columns),
                  "describe typed insert");
        ok(parameters.size() == 5 && all_unknown(parameters),
           "five native parameters are unknown types");

        Text embedded_text{std::string("a\0b", 3)};
        Bytes embedded_blob;
        embedded_blob.bytes = {0, 1, 0, 2};
        std::vector<Value> values;
        values.emplace_back(std::numeric_limits<int64_t>::min());
        values.emplace_back(static_cast<uint64_t>(std::numeric_limits<int64_t>::max()));
        values.emplace_back(-1.5);
        values.emplace_back(embedded_text);
        values.emplace_back(embedded_blob);
        status_ok(session.execute(insert_id, values, info), "execute typed insert");
        ok(info.affected_rows == 1 && info.last_insert_id == 0 && !info.has_result,
           "typed insert reports one row and the documented zero insert id");

        status_ok(session.prepare("SELECT i,u,d,t,b FROM v ORDER BY id", select_id),
                  "prepare typed select");
        status_ok(session.describe(select_id, parameters, columns),
                  "typed select metadata is dynamic");
        ok(columns.size() == 5 && all_dynamic(columns),
           "five dynamic result columns");

        status_ok(session.execute(select_id, {}, info), "execute typed select");
        ok(info.has_result && !info.affected_rows, "select has result and no affected rows");
        status_ok(session.fetch(select_id, row, done), "fetch first typed row");
        ok(!done && row.size() == 5, "first typed row has five values");
        if (row.size() == 5) {
            ok(int_value(row[0], std::numeric_limits<int64_t>::min()),
               "INT64_MIN survives native binding");
            ok(int_value(row[1], std::numeric_limits<int64_t>::max()),
               "uint64 up to INT64_MAX survives native binding");
            ok(double_value(row[2], -1.5), "double survives native binding");
            ok(text_value(row[3], std::string("a\0b", 3)),
               "text preserves embedded NUL and explicit length");
            ok(bytes_value(row[4], std::vector<uint8_t>{0, 1, 0, 2}),
               "blob preserves embedded NUL and explicit length");
        }
        status_ok(session.fetch(select_id, row, done), "fetch EOF after typed row");
        ok(done && row.empty(), "typed select reaches empty EOF");

        status_ok(session.prepare("SELECT typeof(i), typeof(u), typeof(d), typeof(t), "
                                  "typeof(b) FROM v WHERE id = 1",
                                  type_id),
                  "prepare runtime type select");
        status_ok(session.execute(type_id, {}, info), "execute runtime type select");
        status_ok(session.fetch(type_id, row, done), "fetch runtime types");
        ok(!done && row.size() == 5 &&
               text_value(row[0], "integer") && text_value(row[1], "integer") &&
               text_value(row[2], "real") && text_value(row[3], "text") &&
               text_value(row[4], "blob"),
           "SQLite runtime types are preserved");

        std::vector<Value> second;
        second.emplace_back(std::monostate{});
        second.emplace_back(uint64_t(0));
        second.emplace_back(0.0);
        second.emplace_back(Text{""});
        second.emplace_back(Bytes{});
        status_ok(session.execute(insert_id, second, info), "execute NULL and empty insert");
        ok(info.affected_rows == 1 && info.last_insert_id == 0,
           "NULL and empty insert reports one affected row");

        status_ok(session.execute(select_id, {}, info), "re-execute typed select");
        status_ok(session.fetch(select_id, row, done), "fetch row one after rebind");
        status_ok(session.fetch(select_id, row, done), "fetch row two after rebind");
        ok(!done && row.size() == 5, "second typed row has five values");
        if (row.size() == 5) {
            ok(std::holds_alternative<std::monostate>(row[0]),
               "NULL is distinct from zero");
            ok(int_value(row[1], 0), "unsigned zero remains integer zero");
            ok(double_value(row[2], 0.0), "floating zero remains real zero");
            ok(text_value(row[3], ""), "empty text is an empty value, not NULL");
            ok(bytes_value(row[4], {}), "empty blob is an empty value, not NULL");
        }
        status_ok(session.fetch(select_id, row, done), "fetch EOF after two rows");
        ok(done && row.empty(), "two-row select reaches EOF");

        uint64_t null_id = 0;
        status_ok(session.prepare("SELECT t IS NULL, b IS NULL, typeof(t), typeof(b) "
                                  "FROM v WHERE id = 2",
                                  null_id),
                  "prepare empty-versus-NULL check");
        status_ok(session.execute(null_id, {}, info), "execute empty-versus-NULL check");
        status_ok(session.fetch(null_id, row, done), "fetch empty-versus-NULL check");
        ok(!done && row.size() == 4 && int_value(row[0], 0) && int_value(row[1], 0) &&
               text_value(row[2], "text") && text_value(row[3], "blob"),
           "empty text and blob are not SQL NULL");
    }
}

void binding_ownership_and_isolation() {
    TestDb db;
    ok(db.open(), "open engine for binding ownership");
    if (db.db == nullptr) return;
    ok(db.exec("CREATE TABLE inj(v TEXT)"), "create no-interpolation table");

    {
        SQLiteAdapter adapter(db.db);
        PermitPolicy policy;
        Session session(adapter, policy);
        uint64_t insert_id = 0;
        uint64_t select_id = 0;
        ExecInfo info;
        Row row;
        bool done = true;

        status_ok(session.prepare("INSERT INTO inj(v) VALUES(?)", insert_id),
                  "prepare no-interpolation insert");
        const std::string attack = "x'); DROP TABLE inj; --";
        status_ok(session.execute(insert_id, {Text{attack}}, info),
                  "bind attacker-shaped text as a value");
        status_ok(session.prepare("SELECT v FROM inj", select_id),
                  "prepare no-interpolation select");
        status_ok(session.execute(select_id, {}, info), "execute no-interpolation select");
        status_ok(session.fetch(select_id, row, done), "fetch no-interpolation value");
        ok(!done && row.size() == 1 && text_value(row[0], attack),
           "bound text is not interpreted as SQL");
        ok(scalar(db, "SELECT count(*) FROM sqlite_master WHERE name = 'inj'") == 1,
           "injection-shaped value did not drop the table");
    }

    SQLiteAdapter adapter(db.db);
    ExecInfo info;
    Row row;
    bool done = true;

    {
        std::unique_ptr<Statement> handle;
        status_ok(adapter.prepare("SELECT ?", handle), "prepare transient text statement");
        {
            std::vector<Value> temporary;
            temporary.emplace_back(Text{std::string("transient", 9)});
            status_ok(adapter.bind(*handle, temporary), "bind transient text");
        }
        status_ok(adapter.execute(*handle, info), "execute transient text after source dies");
        status_ok(adapter.fetch(*handle, row, done, 1024), "fetch transient text");
        ok(!done && row.size() == 1 && text_value(row[0], "transient"),
           "SQLITE_TRANSIENT copied text before the source was destroyed");
        adapter.finalize(std::move(handle));
    }

    {
        std::unique_ptr<Statement> handle;
        status_ok(adapter.prepare("SELECT ?", handle), "prepare reset-binding statement");
        status_ok(adapter.bind(*handle, {int64_t(77)}), "bind value before reset");
        status_ok(adapter.execute(*handle, info), "execute before reset");
        status_ok(adapter.fetch(*handle, row, done, 1024), "fetch before reset");
        ok(!done && row.size() == 1 && int_value(row[0], 77),
           "pre-reset value is visible");
        status_ok(adapter.reset(*handle), "reset clears result and bindings");
        status_ok(adapter.execute(*handle, info), "execute after reset without rebinding");
        status_ok(adapter.fetch(*handle, row, done, 1024), "fetch after reset without rebinding");
        ok(!done && row.size() == 1 &&
               std::holds_alternative<std::monostate>(row[0]),
           "reset cleared the prior binding, leaving native NULL");
        adapter.finalize(std::move(handle));
    }
}

void unsupported_bind_values() {
    TestDb db;
    ok(db.open(), "open engine for unsupported bind values");
    if (db.db == nullptr) return;
    ok(db.exec("CREATE TABLE n(x)"), "create unsupported-bind table");

    {
        SQLiteAdapter adapter(db.db);
        PermitPolicy policy;
        Session session(adapter, policy);
        uint64_t id = 0;
        ExecInfo info;
        status_ok(session.prepare("INSERT INTO n(x) VALUES(?)", id),
                  "prepare unsupported-bind insert");

        status_error(session.execute(id, {std::numeric_limits<uint64_t>::max()}, info),
                     ErrorKind::range, "uint64 above INT64_MAX is refused");
        ok(scalar(db, "SELECT count(*) FROM n") == 0,
           "overflowing uint64 has no engine effect");

        status_error(session.execute(
                         id, {std::numeric_limits<double>::quiet_NaN()}, info),
                     ErrorKind::invalid_parameter, "NaN double is refused");
        ok(scalar(db, "SELECT count(*) FROM n") == 0,
           "NaN double has no engine effect");

        status_error(session.execute(id, {Decimal{"1.25"}}, info),
                     ErrorKind::unsupported, "decimal is explicitly unsupported");
        ok(scalar(db, "SELECT count(*) FROM n") == 0,
           "decimal has no engine effect");

        std::unique_ptr<Statement> handle;
        status_ok(adapter.prepare("SELECT ?", handle), "prepare direct arity statement");
        auto err = adapter.bind(*handle, {});
        status_error(err, ErrorKind::invalid_parameter,
                     "direct bind rejects wrong parameter count");
        adapter.finalize(std::move(handle));
    }
}

void constraint_error_recovery() {
    TestDb db;
    ok(db.open(), "open engine for constraint recovery");
    if (db.db == nullptr) return;
    ok(db.exec("CREATE TABLE u(id INTEGER PRIMARY KEY, n INTEGER UNIQUE)"),
       "create constraint table");

    {
        SQLiteAdapter adapter(db.db);
        PermitPolicy policy;
        Session session(adapter, policy);
        uint64_t id = 0;
        ExecInfo info;
        Row row;
        bool done = true;

        status_ok(session.prepare("INSERT INTO u(id,n) VALUES(?,?)", id),
                  "prepare constraint insert");
        status_ok(session.execute(id, {int64_t(1), int64_t(10)}, info),
                  "first constraint insert succeeds");
        ok(info.affected_rows == 1, "first insert affected one row");

        auto err = session.execute(id, {int64_t(2), int64_t(10)}, info);
        ok(err && (err->native_code & 0xff) == SQLITE_CONSTRAINT,
           "duplicate unique key reports native constraint error");
        ok(scalar(db, "SELECT count(*) FROM u") == 1,
           "failed constraint insert has no effect");
        ok(scalar(db, "SELECT count(*) FROM u WHERE id = 2") == 0,
           "failed constraint row is absent");
        ok(bool(session.fetch(id, row, done)),
           "failed execution leaves no fetchable result and is not replayed");
        ok(scalar(db, "SELECT count(*) FROM u") == 1,
           "fetch after failure does not replay execution");

        status_ok(session.execute(id, {int64_t(2), int64_t(20)}, info),
                  "rebinding after constraint error acknowledges reset error");
        ok(info.affected_rows == 1, "recovery insert affected one row");
        ok(scalar(db, "SELECT count(*) FROM u") == 2,
           "recovery insert committed only once");

        err = session.execute(id, {int64_t(1), int64_t(30)}, info);
        ok(err && (err->native_code & 0xff) == SQLITE_CONSTRAINT,
           "primary-key conflict reports native constraint error");
        status_ok(session.execute(id, {int64_t(3), int64_t(30)}, info),
                  "second recovery after constraint error succeeds");
        ok(scalar(db, "SELECT count(*) FROM u") == 3,
           "two recoveries produced exactly two new rows");
    }
}

void api_pointer_failure_hooks() {
    {
        TestDb db;
        ok(db.open(), "open engine for null-text pointer hook");
        if (db.db == nullptr) return;
        SQLiteAdapter adapter(db.db);
        PermitPolicy policy;
        Session session(adapter, policy);
        uint64_t id = 0;
        ExecInfo info;
        Row row;
        bool done = false;

        status_ok(session.prepare("SELECT ''", id), "prepare native empty text");
        status_ok(session.execute(id, {}, info), "execute native empty text");
        {
            ColumnTextHook hook;
            auto err = session.fetch(id, row, done);
            status_error(err, ErrorKind::internal,
                         "null text pointer at zero length is an error, not empty Text");
            ok(row.empty() && !done, "failed null-text fetch exposes no row");
        }
        status_ok(session.execute(id, {}, info), "re-execute after text hook restore");
        status_ok(session.fetch(id, row, done), "fetch native empty text after hook restore");
        ok(!done && row.size() == 1 && text_value(row[0], ""),
           "native empty text still roundtrips as empty Text");
    }

    {
        TestDb db;
        ok(db.open(), "open engine for reset-error hook");
        if (db.db == nullptr) return;
        ok(db.exec("CREATE TABLE u(id INTEGER PRIMARY KEY, n INTEGER UNIQUE)"),
           "create reset-hook constraint table");
        SQLiteAdapter adapter(db.db);
        PermitPolicy policy;
        Session session(adapter, policy);
        uint64_t id = 0;
        ExecInfo info;

        status_ok(session.prepare("INSERT INTO u(id,n) VALUES(?,?)", id),
                  "prepare reset-hook insert");
        status_ok(session.execute(id, {int64_t(1), int64_t(10)}, info),
                  "seed reset-hook row");
        auto err = session.execute(id, {int64_t(2), int64_t(10)}, info);
        ok(err && (err->native_code & 0xff) == SQLITE_CONSTRAINT,
           "reset-hook setup reports the matching constraint error");
        {
            ResetErrorHook hook;
            err = session.execute(id, {int64_t(2), int64_t(20)}, info);
            status_error(err, ErrorKind::engine,
                         "different reset error is propagated, not acknowledged");
            ok(err && (err->native_code & 0xff) == SQLITE_IOERR,
               "different reset error preserves its native code");
        }
        ok(scalar(db, "SELECT count(*) FROM u") == 1,
           "propagated reset failure has no engine effect");
        status_ok(session.execute(id, {int64_t(2), int64_t(20)}, info),
                  "rebind after reset hook restore succeeds");
        ok(info.affected_rows == 1, "post-hook recovery inserted one row");
        ok(scalar(db, "SELECT count(*) FROM u") == 2,
           "post-hook recovery produced exactly one new row");
    }
}

void result_lifecycle() {
    TestDb db;
    ok(db.open(), "open engine for result lifecycle");
    if (db.db == nullptr) return;
    ok(db.exec("CREATE TABLE t(id INTEGER PRIMARY KEY, s TEXT)"), "create lifecycle table");
    ok(db.exec("INSERT INTO t(id,s) VALUES(1,'a'),(2,'b'),(3,'c')"),
       "seed lifecycle rows");

    {
        SQLiteAdapter adapter(db.db);
        PermitPolicy policy;
        Session session(adapter, policy);
        uint64_t id = 0;
        ExecInfo info;
        Row row;
        bool done = true;

        status_ok(session.prepare(
                      "SELECT id,s FROM t WHERE id = ? ORDER BY id", id),
                  "prepare parameterized lifecycle select");

        status_ok(session.execute(id, {int64_t(1)}, info), "execute from id 1");
        status_ok(session.fetch(id, row, done), "fetch first row");
        ok(!done && row.size() == 2 && int_value(row[0], 1),
           "first row is id 1");

        status_ok(session.execute(id, {int64_t(2)}, info),
                  "rebind after a partial result resets the statement");
        status_ok(session.fetch(id, row, done), "fetch row after partial-result rebind");
        ok(!done && row.size() == 2 && int_value(row[0], 2),
           "partial-result rebind returns only the new first row");
        status_ok(session.fetch(id, row, done), "fetch EOF for rebound query");
        ok(done && row.empty(), "rebound query has one row then EOF");
        ok(bool(session.fetch(id, row, done)), "fetch after EOF is rejected");

        status_ok(session.execute(id, {int64_t(1)}, info),
                  "rebind after EOF resets the statement");
        status_ok(session.fetch(id, row, done), "fetch after EOF rebind");
        ok(!done && row.size() == 2 && int_value(row[0], 1),
           "after-EOF rebind returns the first row again");

        status_ok(session.reset(id), "explicit reset after an active result");
        ok(bool(session.fetch(id, row, done)), "reset removes the active result");
        status_ok(session.execute(id, {int64_t(3)}, info),
                  "execute after explicit reset");
        status_ok(session.fetch(id, row, done), "fetch after explicit reset");
        ok(!done && row.size() == 2 && int_value(row[0], 3),
           "explicit reset rebinds to id 3");
        status_ok(session.fetch(id, row, done), "fetch EOF for id 3");
        ok(done && row.empty(), "id 3 query reaches EOF");
        status_ok(session.close(id), "close lifecycle statement");
        ok(bool(session.execute(id, {}, info)), "closed statement cannot execute");

        uint64_t empty_result_id = 0;
        status_ok(session.prepare("SELECT id FROM t WHERE id = 999", empty_result_id),
                  "prepare zero-row select");
        status_ok(session.execute(empty_result_id, {}, info),
                  "execute zero-row select");
        ok(info.has_result && !info.affected_rows,
           "zero-row select still has a result");
        status_ok(session.fetch(empty_result_id, row, done), "fetch zero-row select EOF");
        ok(done && row.empty(), "zero-row select returns empty EOF");
        status_ok(session.execute(empty_result_id, {}, info),
                  "re-execute zero-row select after EOF");
        status_ok(session.fetch(empty_result_id, row, done),
                  "fetch zero-row select after re-execute");
        ok(done && row.empty(), "re-executed zero-row select returns empty EOF");
    }
}

void fetch_budget() {
    {
        TestDb db;
        ok(db.open(), "open engine for fetch budget");
        if (db.db == nullptr) return;
        SQLiteAdapter adapter(db.db);
        PermitPolicy policy;
        Session session(adapter, policy, 1, 7);
        uint64_t id = 0;
        ExecInfo info;
        Row row;
        bool done = true;
        status_ok(session.prepare("SELECT 'abcdefgh'", id), "prepare eight-byte text");
        status_ok(session.execute(id, {}, info), "execute eight-byte text");
        status_error(session.fetch(id, row, done), ErrorKind::resource,
                     "seven-byte budget rejects eight-byte text");
        ok(row.empty() && !done, "oversized text row is not exposed");
        ok(bool(session.fetch(id, row, done)), "budget failure invalidates result");
        status_ok(session.execute(id, {}, info), "explicit re-execute after budget error");
        status_error(session.fetch(id, row, done), ErrorKind::resource,
                     "re-executed oversized row is still rejected");
    }
    {
        TestDb db;
        ok(db.open(), "open engine for exact text budget");
        if (db.db == nullptr) return;
        SQLiteAdapter adapter(db.db);
        PermitPolicy policy;
        Session session(adapter, policy, 1, 8);
        uint64_t id = 0;
        ExecInfo info;
        Row row;
        bool done = true;
        status_ok(session.prepare("SELECT 'abcdefgh'", id), "prepare exact text budget");
        status_ok(session.execute(id, {}, info), "execute exact text budget");
        status_ok(session.fetch(id, row, done), "eight-byte text fits eight-byte budget");
        ok(!done && row.size() == 1 && text_value(row[0], "abcdefgh"),
           "exact-budget text row is exposed");
    }
    {
        TestDb db;
        ok(db.open(), "open engine for zero budget");
        if (db.db == nullptr) return;
        SQLiteAdapter adapter(db.db);
        PermitPolicy policy;
        Session session(adapter, policy, 2, 0);
        uint64_t null_id = 0;
        uint64_t empty_id = 0;
        ExecInfo info;
        Row row;
        bool done = true;
        status_ok(session.prepare("SELECT NULL", null_id), "prepare NULL with zero budget");
        status_ok(session.execute(null_id, {}, info), "execute NULL with zero budget");
        status_ok(session.fetch(null_id, row, done), "NULL fits zero budget");
        ok(!done && row.size() == 1 &&
               std::holds_alternative<std::monostate>(row[0]),
           "zero-budget NULL is exposed");
        status_ok(session.prepare("SELECT ''", empty_id),
                  "prepare empty text with zero budget");
        status_ok(session.execute(empty_id, {}, info), "execute empty text with zero budget");
        status_ok(session.fetch(empty_id, row, done), "empty text fits zero budget");
        ok(!done && row.size() == 1 && text_value(row[0], ""),
           "zero-budget empty text is exposed");
    }
    {
        TestDb db;
        ok(db.open(), "open engine for numeric budget boundary");
        if (db.db == nullptr) return;
        for (size_t budget : {size_t(7), size_t(8)}) {
            SQLiteAdapter adapter(db.db);
            PermitPolicy policy;
            Session session(adapter, policy, 1, budget);
            uint64_t id = 0;
            ExecInfo info;
            Row row;
            bool done = true;
            status_ok(session.prepare("SELECT 42", id), "prepare numeric budget select");
            status_ok(session.execute(id, {}, info), "execute numeric budget select");
            auto err = session.fetch(id, row, done);
            if (budget == 7) {
                status_error(err, ErrorKind::resource,
                             "seven-byte budget rejects eight-byte numeric");
                ok(row.empty(), "rejected numeric row is not exposed");
            } else {
                status_ok(err, "eight-byte numeric fits eight-byte budget");
                ok(!done && row.size() == 1 && int_value(row[0], 42),
                   "eight-byte numeric row is exposed");
            }
        }
    }
    {
        TestDb db;
        ok(db.open(), "open engine for blob budget boundary");
        if (db.db == nullptr) return;
        for (size_t budget : {size_t(2), size_t(3)}) {
            SQLiteAdapter adapter(db.db);
            PermitPolicy policy;
            Session session(adapter, policy, 1, budget);
            uint64_t id = 0;
            ExecInfo info;
            Row row;
            bool done = true;
            status_ok(session.prepare("SELECT x'000102'", id), "prepare three-byte blob");
            status_ok(session.execute(id, {}, info), "execute three-byte blob");
            auto err = session.fetch(id, row, done);
            if (budget == 2) {
                status_error(err, ErrorKind::resource,
                             "two-byte budget rejects three-byte blob");
                ok(row.empty(), "rejected blob row is not exposed");
            } else {
                status_ok(err, "three-byte blob fits three-byte budget");
                ok(!done && row.size() == 1 &&
                       bytes_value(row[0], std::vector<uint8_t>{0, 1, 2}),
                   "three-byte blob row is exposed");
            }
        }
    }
}

void handle_affinity() {
    TestDb first;
    TestDb second;
    ok(first.open(), "open first affinity connection");
    ok(second.open(), "open second affinity connection");
    if (first.db == nullptr || second.db == nullptr) return;

    SQLiteAdapter owner(first.db);
    SQLiteAdapter other_connection(second.db);
    SQLiteAdapter other_adapter_same_connection(first.db);
    std::unique_ptr<Statement> handle;
    status_ok(owner.prepare("SELECT ?", handle), "prepare affinity statement");

    std::vector<Type> parameters(1);
    std::vector<Column> columns(1);
    status_ok(owner.describe_parameters(*handle, parameters),
              "owner describes its statement");
    ExecInfo info;
    Row row;
    bool done = true;

    status_error(other_connection.describe_parameters(*handle, parameters),
                 ErrorKind::invalid_parameter,
                 "foreign connection adapter cannot describe the handle");
    status_error(other_connection.describe_result(*handle, columns),
                 ErrorKind::invalid_parameter,
                 "foreign connection adapter cannot read result metadata");
    status_error(other_connection.bind(*handle, {int64_t(7)}),
                 ErrorKind::invalid_parameter,
                 "foreign connection adapter cannot bind the handle");
    status_error(other_connection.execute(*handle, info),
                 ErrorKind::invalid_parameter,
                 "foreign connection adapter cannot execute the handle");
    status_error(other_connection.fetch(*handle, row, done, 1024),
                 ErrorKind::invalid_parameter,
                 "foreign connection adapter cannot fetch the handle");
    status_error(other_connection.reset(*handle), ErrorKind::invalid_parameter,
                 "foreign connection adapter cannot reset the handle");
    status_error(other_adapter_same_connection.bind(*handle, {int64_t(7)}),
                 ErrorKind::invalid_parameter,
                 "another adapter on the same connection is still foreign");

    status_ok(owner.bind(*handle, {int64_t(7)}), "owner binds its statement");
    status_ok(owner.execute(*handle, info), "owner executes its statement");
    ok(info.has_result, "owner execution has a result");
    status_ok(owner.fetch(*handle, row, done, 1024), "owner fetches its statement");
    ok(!done && row.size() == 1 && int_value(row[0], 7),
       "owner statement is unaffected by foreign rejections");
    status_ok(owner.fetch(*handle, row, done, 1024), "owner reaches EOF");
    ok(done && row.empty(), "owner affinity statement reaches EOF");
    owner.finalize(std::move(handle));
    ok(!handle, "finalize releases the statement handle");
}

void affected_rows_and_insert_id() {
    TestDb db;
    ok(db.open(), "open engine for affected rows");
    if (db.db == nullptr) return;
    ok(db.exec("CREATE TABLE a(id INTEGER PRIMARY KEY)"), "create affected table");
    ok(db.exec("CREATE TABLE audit(x INTEGER)"), "create audit table");
    ok(db.exec("CREATE TRIGGER tr AFTER INSERT ON a BEGIN "
               "INSERT INTO audit(x) VALUES (NEW.id); END"),
       "create audit trigger");

    {
        SQLiteAdapter adapter(db.db);
        PermitPolicy policy;
        Session session(adapter, policy);
        uint64_t insert_id = 0;
        uint64_t update_id = 0;
        uint64_t delete_id = 0;
        uint64_t ddl_id = 0;
        uint64_t read_id = 0;
        ExecInfo info;
        Row row;
        bool done = true;

        status_ok(session.prepare("INSERT INTO a(id) VALUES(?)", insert_id),
                  "prepare trigger insert");
        status_ok(session.execute(insert_id, {int64_t(5)}, info),
                  "execute trigger insert");
        ok(info.affected_rows == 1, "trigger changes are excluded from affected_rows");
        ok(info.last_insert_id == 0,
           "last_insert_id is zero for the initial engine slice");
        ok(scalar(db, "SELECT last_insert_rowid()") == 5,
           "native session rowid advanced but is not reported");
        ok(scalar(db, "SELECT count(*) FROM audit") == 1,
           "trigger actually ran");

        status_ok(session.prepare("UPDATE a SET id = id", update_id),
                  "prepare no-op update");
        status_ok(session.execute(update_id, {}, info), "execute no-op update");
        ok(info.affected_rows == 1, "update reports direct changes once");
        ok(info.last_insert_id == 0, "update reports zero last_insert_id");

        status_ok(session.prepare("DELETE FROM a WHERE id = 99", delete_id),
                  "prepare no-match delete");
        status_ok(session.execute(delete_id, {}, info), "execute no-match delete");
        ok(info.affected_rows == 0, "delete without matches reports zero affected rows");

        status_ok(session.prepare("CREATE TABLE b(x)", ddl_id), "prepare DDL");
        status_ok(session.execute(ddl_id, {}, info), "execute DDL");
        ok(info.affected_rows == 0,
           "DDL after DML does not repeat a stale affected count");
        ok(info.last_insert_id == 0, "DDL reports zero last_insert_id");

        status_ok(session.prepare("SELECT count(*) FROM a", read_id),
                  "prepare read after DML");
        status_ok(session.execute(read_id, {}, info), "execute read after DML");
        ok(info.has_result && info.affected_rows == 0,
           "read result does not report affected rows");
        status_ok(session.fetch(read_id, row, done), "fetch read count");
        ok(!done && row.size() == 1 && int_value(row[0], 1),
           "read count sees the committed-by-default insert");
    }
}

void transaction_ownership() {
    TestDb db;
    ok(db.open(), "open engine for transaction ownership");
    if (db.db == nullptr) return;
    ok(db.exec("CREATE TABLE tx(v INTEGER)"), "create transaction table");

    {
        SQLiteAdapter adapter(db.db);
        PermitPolicy policy;
        Session session(adapter, policy);
        uint64_t id = 0;
        ExecInfo info;
        status_ok(session.prepare("INSERT INTO tx(v) VALUES(?)", id),
                  "prepare transaction insert");

        ok(db.exec("BEGIN"), "raw BEGIN succeeds");
        ok(proxy_sqlite3_get_autocommit(db.db) == 0, "raw BEGIN disables autocommit");
        status_ok(session.execute(id, {int64_t(1)}, info),
                  "adapter insert inside raw transaction");
        ok(proxy_sqlite3_get_autocommit(db.db) == 0,
           "adapter insert does not commit the transaction");
        status_ok(session.reset(id), "reset inside raw transaction");
        ok(proxy_sqlite3_get_autocommit(db.db) == 0,
           "reset preserves the explicit transaction");
        ok(db.exec("ROLLBACK"), "raw ROLLBACK succeeds");
        ok(proxy_sqlite3_get_autocommit(db.db) == 1,
           "raw ROLLBACK restores autocommit");
        ok(scalar(db, "SELECT count(*) FROM tx") == 0,
           "rollback removes the adapter insert");

        ok(db.exec("BEGIN"), "second raw BEGIN succeeds");
        status_ok(session.execute(id, {int64_t(2)}, info),
                  "adapter insert inside second transaction");
        ok(proxy_sqlite3_get_autocommit(db.db) == 0,
           "close has not yet run; transaction is open");
        status_ok(session.close(id), "close statement inside transaction");
        ok(proxy_sqlite3_get_autocommit(db.db) == 0,
           "close does not commit or roll back");
        ok(db.exec("ROLLBACK"), "second raw ROLLBACK succeeds");
        ok(scalar(db, "SELECT count(*) FROM tx") == 0,
           "close plus rollback leaves no row");

        uint64_t commit_id = 0;
        status_ok(session.prepare("INSERT INTO tx(v) VALUES(?)", commit_id),
                  "prepare commit-path insert");
        ok(db.exec("BEGIN"), "third raw BEGIN succeeds");
        status_ok(session.execute(commit_id, {int64_t(3)}, info),
                  "adapter insert before raw commit");
        ok(db.exec("COMMIT"), "raw COMMIT succeeds");
        ok(proxy_sqlite3_get_autocommit(db.db) == 1,
           "raw COMMIT restores autocommit");
        ok(scalar(db, "SELECT count(*) FROM tx") == 1,
           "raw COMMIT keeps the adapter insert");
    }
}

void schema_changes() {
    TestDb db;
    ok(db.open(), "open engine for schema change");
    if (db.db == nullptr) return;

    {
        SQLiteAdapter adapter(db.db);
        PermitPolicy policy;
        Session session(adapter, policy);
        ExecInfo info;
        Row row;
        bool done = true;

        ok(db.exec("CREATE TABLE t(a INTEGER, b TEXT)"), "create schema-count table");
        ok(db.exec("INSERT INTO t(a,b) VALUES(1,'x')"), "seed schema-count table");
        uint64_t count_id = 0;
        status_ok(session.prepare("SELECT * FROM t", count_id),
                  "prepare select star before added column");
        std::vector<Type> parameters;
        std::vector<Column> columns;
        status_ok(session.describe(count_id, parameters, columns),
                  "describe two-column select star");
        ok(columns.size() == 2, "initial select star has two columns");
        ok(db.exec("ALTER TABLE t ADD COLUMN c INTEGER"), "add a result column");
        auto err = session.execute(count_id, {}, info);
        status_error(err, ErrorKind::schema_changed,
                     "changed result column count reports schema_changed");
        ok(bool(session.fetch(count_id, row, done)),
           "schema_changed does not expose a mismatched row");
        status_ok(session.close(count_id), "close schema-count statement");

        ok(db.exec("CREATE TABLE t2(a INTEGER, b TEXT)"), "create schema-name table");
        ok(db.exec("INSERT INTO t2(a,b) VALUES(1,'x')"), "seed schema-name table");
        uint64_t name_id = 0;
        status_ok(session.prepare("SELECT * FROM t2", name_id),
                  "prepare select star before rename");
        columns.clear();
        parameters.clear();
        status_ok(session.describe(name_id, parameters, columns),
                  "describe select star before rename");
        ok(columns.size() == 2 && columns[0].name == "a" && columns[1].name == "b",
           "initial names are a and b");
        ok(db.exec("ALTER TABLE t2 RENAME COLUMN a TO z"), "rename a result column");
        err = session.execute(name_id, {}, info);
        status_error(err, ErrorKind::schema_changed,
                     "changed result column name reports schema_changed");
        row.push_back(int64_t(123));
        done = false;
        ok(bool(session.fetch(name_id, row, done)),
           "schema_changed name mismatch does not expose a row");
        ok(row.empty() && !done, "fetch failure clears the caller row");
        status_ok(session.close(name_id), "close schema-name statement");
    }
}

void prepare_errors() {
    TestDb db;
    ok(db.open(), "open engine for prepare errors");
    if (db.db == nullptr) return;
    ok(db.exec("CREATE TABLE t(x)"), "create prepare-error table");
    SQLiteAdapter adapter(db.db);
    std::unique_ptr<Statement> handle;

    auto err = adapter.prepare("SELECT FROM", handle);
    status_error(err, ErrorKind::engine,
                 "native prepare syntax failure is reported conservatively as engine");
    ok(err && err->native_code != 0 && !err->message.empty(),
       "native prepare failure preserves native code and message");
    ok(!handle, "failed native prepare leaves no handle");

    err = adapter.prepare("SELECT * FROM missing_table", handle);
    status_error(err, ErrorKind::engine,
                 "native missing-object prepare failure is reported as engine");
    ok(err && err->native_code != 0 && !err->message.empty(),
       "missing-object prepare failure preserves native code and message");
    ok(!handle, "missing-object prepare leaves no handle");

    err = adapter.prepare("", handle);
    status_error(err, ErrorKind::syntax, "empty SQL is rejected");
    ok(!handle, "empty prepare leaves no handle");

    const std::string embedded_nul("SELECT 1\0SELECT 2", 16);
    err = adapter.prepare(embedded_nul, handle);
    status_error(err, ErrorKind::syntax, "embedded NUL SQL is rejected");
    ok(!handle, "embedded NUL prepare leaves no handle");

    status_ok(adapter.prepare("SELECT 1", handle), "valid prepare before failed replacement");
    ok(bool(handle), "valid prepare produced a handle");
    err = adapter.prepare("SELECT 1; SELECT 2", handle);
    status_error(err, ErrorKind::unsupported, "second statement is refused");
    ok(!handle, "failed prepare clears a previously supplied handle");

    err = adapter.prepare("SELECT 1;;", handle);
    status_error(err, ErrorKind::unsupported, "trailing empty statement is refused");
    err = adapter.prepare("/* unclosed", handle);
    status_error(err, ErrorKind::syntax,
                 "comment-only or unterminated input yields no prepared statement");
    ok(!handle, "unterminated/comment-only prepare leaves no handle");

    err = adapter.prepare("CREATE TABLE leaked(x); CREATE TABLE leaked2(y)", handle);
    status_error(err, ErrorKind::unsupported, "DDL with extra statement is refused");
    ok(scalar(db, "SELECT count(*) FROM sqlite_master WHERE name = 'leaked'") == 0,
       "refused DDL with tail did not execute");
}

void cleanup_and_ids() {
    TestDb db;
    ok(db.open(), "open engine for cleanup");
    if (db.db == nullptr) return;
    ok(db.exec("CREATE TABLE t(id INTEGER PRIMARY KEY)"), "create cleanup table");
    ok(db.exec("INSERT INTO t(id) VALUES(1)"), "seed cleanup table");

    {
        SQLiteAdapter adapter(db.db);
        PermitPolicy policy;
        Session session(adapter, policy);
        uint64_t first = 0;
        uint64_t second = 0;
        ExecInfo info;
        Row row;
        bool done = true;

        status_ok(session.prepare("SELECT id FROM t", first), "prepare first id statement");
        status_ok(session.prepare("SELECT id FROM t", second), "prepare second id statement");
        ok(first != 0 && second != 0 && first != second, "statement ids are distinct");
        status_ok(session.close(first), "close first statement");
        ok(bool(session.execute(first, {}, info)), "closed statement id is unknown");
        status_ok(session.execute(second, {}, info), "remaining statement still executes");
        status_ok(session.fetch(second, row, done), "remaining statement fetches");
        ok(!done && row.size() == 1 && int_value(row[0], 1),
           "remaining statement returns its row");
        status_ok(session.close(second), "close remaining statement");
        ok(bool(session.close(second)), "second close is rejected");

        std::unique_ptr<Statement> direct;
        status_ok(adapter.prepare("SELECT 1", direct), "prepare direct cleanup statement");
        adapter.finalize(std::move(direct));
        ok(!direct, "direct finalize releases the handle");
    }

    {
        SQLiteAdapter adapter(db.db);
        std::unique_ptr<Statement> live;
        status_ok(adapter.prepare("SELECT 1", live), "prepare statement for adapter finalize");
        adapter.finalize(std::move(live));
    }
    ok(scalar(db, "SELECT count(*) FROM t") == 1, "cleanup did not change data");
}

}  // namespace

int main() {
    plan(NO_PLAN);
    metadata_and_admission();
    typed_binding_and_runtime_types();
    binding_ownership_and_isolation();
    unsupported_bind_values();
    constraint_error_recovery();
    api_pointer_failure_hooks();
    result_lifecycle();
    fetch_budget();
    handle_affinity();
    affected_rows_and_insert_id();
    transaction_ownership();
    schema_changes();
    prepare_errors();
    cleanup_and_ids();
    return exit_status();
}
