// Real SQLite engine tests for the opt-in strict declared-type result profile.
// This is an internal adapter slice, not a protocol or public ABI test.
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

using DecltypeFn = const char* (*)(sqlite3_stmt*, int);

struct MissingDecltypeHook {
    MissingDecltypeHook() : previous(proxy_sqlite3_column_decltype) {
        proxy_sqlite3_column_decltype = nullptr;
    }
    ~MissingDecltypeHook() { proxy_sqlite3_column_decltype = previous; }
    MissingDecltypeHook(const MissingDecltypeHook&) = delete;
    MissingDecltypeHook& operator=(const MissingDecltypeHook&) = delete;

    DecltypeFn previous;
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
bool null_value(const Value& value) {
    return std::holds_alternative<std::monostate>(value);
}
bool column_kind(const std::vector<Column>& columns, size_t index, TypeKind kind) {
    return index < columns.size() && columns[index].type.kind == kind;
}
bool all_dynamic(const std::vector<Column>& columns) {
    for (const Column& column : columns) {
        if (column.type.kind != TypeKind::dynamic) return false;
    }
    return true;
}

void default_profile_remains_dynamic() {
    TestDb db;
    ok(db.open(), "open engine for default dynamic profile");
    if (db.db == nullptr) return;
    ok(db.exec("CREATE TABLE d(i INTEGER, t TEXT, b BLOB, r REAL)"),
       "create default-profile table");
    ok(db.exec("INSERT INTO d VALUES(7,'x',x'00ff',1.5)"),
       "seed default-profile table");

    SQLiteAdapter adapter(db.db);
    PermitPolicy policy;
    Session session(adapter, policy);
    uint64_t id = 0;
    std::vector<Type> parameters;
    std::vector<Column> columns;
    ExecInfo info;
    Row row;
    bool done = true;

    status_ok(session.prepare("SELECT i,t,b,r FROM d", id),
              "prepare default-profile select");
    status_ok(session.describe(id, parameters, columns),
              "describe default-profile select without executing");
    ok(columns.size() == 4 && all_dynamic(columns),
       "default profile keeps every result type dynamic");
    status_ok(session.execute(id, {}, info), "execute default-profile select");
    status_ok(session.fetch(id, row, done), "fetch default-profile row");
    ok(!done && row.size() == 4 && int_value(row[0], 7) &&
           text_value(row[1], "x") &&
           bytes_value(row[2], std::vector<uint8_t>{0x00, 0xff}) &&
           double_value(row[3], 1.5),
       "default profile preserves existing runtime value behavior");
}

void strict_declared_metadata() {
    TestDb db;
    ok(db.open(), "open engine for strict declared metadata");
    if (db.db == nullptr) return;
    ok(db.exec(
           "CREATE TABLE p("
           "i INTEGER, ii INT, bi BIGINT, t TEXT, bl BLOB, "
           "r REAL, d DOUBLE, f FLOAT, v VARCHAR(32), num NUMERIC, "
           "flag BOOLEAN, day DATE, i8 \"INTEGER(8)\", tsp \"TEXT \", "
           "dp \"DOUBLE PRECISION\", lower_i \"integer\", "
           "lower_blob \"blob\", lower_double \"double\")"),
       "create exact declared-type table");

    SQLiteAdapter adapter(db.db, ResultProfile::strict_declared);
    PermitPolicy policy;
    Session session(adapter, policy);
    uint64_t id = 0;
    std::vector<Type> parameters;
    std::vector<Column> columns;

    status_ok(session.prepare(
                  "SELECT i,ii,bi,t,bl,r,d,f,v,num,flag,day,i8,tsp,dp,"
                  "lower_i,lower_blob,lower_double FROM p",
                  id),
              "prepare strict declared metadata select");
    status_ok(session.describe(id, parameters, columns),
              "describe strict declared metadata without executing");
    ok(columns.size() == 18, "strict metadata reports all native columns");

    const char* names[] = {"i", "ii", "bi", "t", "bl", "r", "d", "f",
                           "v", "num", "flag", "day", "i8", "tsp", "dp",
                           "lower_i", "lower_blob", "lower_double"};
    const TypeKind expected[] = {
        TypeKind::signed_integer, TypeKind::signed_integer,
        TypeKind::signed_integer, TypeKind::text, TypeKind::bytes,
        TypeKind::floating, TypeKind::floating, TypeKind::floating,
        TypeKind::dynamic, TypeKind::dynamic, TypeKind::dynamic,
        TypeKind::dynamic, TypeKind::dynamic, TypeKind::dynamic,
        TypeKind::dynamic, TypeKind::signed_integer, TypeKind::bytes,
        TypeKind::floating};
    for (size_t i = 0; i < sizeof(expected) / sizeof(expected[0]); ++i) {
        ok(column_kind(columns, i, expected[i]),
           "declared type mapping for column %s", names[i]);
    }
    bool nullable = true;
    for (const Column& column : columns) nullable = nullable && column.type.nullable;
    ok(nullable, "strict declared columns report nullable native results");
}

void strict_alias_expression_metadata() {
    TestDb db;
    ok(db.open(), "open engine for alias and expression metadata");
    if (db.db == nullptr) return;
    ok(db.exec("CREATE TABLE q(a INTEGER, t TEXT, b BLOB, r REAL)"),
       "create alias/expression table");

    SQLiteAdapter adapter(db.db, ResultProfile::strict_declared);
    PermitPolicy policy;
    Session session(adapter, policy);
    uint64_t id = 0;
    std::vector<Type> parameters;
    std::vector<Column> columns;

    status_ok(session.prepare(
                  "SELECT a AS alias_a, t AS alias_t, b AS alias_b, "
                  "r AS alias_r, a+1 AS expr_i, t || 'x' AS expr_t, "
                  "CAST(a AS TEXT) AS expr_cast, r*2 AS expr_r FROM q",
                  id),
              "prepare strict alias/expression select");
    status_ok(session.describe(id, parameters, columns),
              "describe strict alias/expression select");
    ok(columns.size() == 8, "alias/expression select has eight columns");
    ok(columns.size() == 8 && columns[0].name == "alias_a" &&
           columns[1].name == "alias_t" && columns[2].name == "alias_b" &&
           columns[3].name == "alias_r",
       "strict result names are owned native aliases");
    ok(column_kind(columns, 0, TypeKind::signed_integer),
       "aliased INTEGER keeps native origin declared type");
    ok(column_kind(columns, 1, TypeKind::text),
       "aliased TEXT keeps native origin declared type");
    ok(column_kind(columns, 2, TypeKind::bytes),
       "aliased BLOB keeps native origin declared type");
    ok(column_kind(columns, 3, TypeKind::floating),
       "aliased REAL keeps native origin declared type");
    ok(column_kind(columns, 4, TypeKind::dynamic) &&
           column_kind(columns, 5, TypeKind::dynamic) &&
           column_kind(columns, 6, TypeKind::dynamic) &&
           column_kind(columns, 7, TypeKind::dynamic),
       "expressions have NULL declared type and remain dynamic");
}

void strict_typed_runtime() {
    TestDb db;
    ok(db.open(), "open engine for strict typed runtime");
    if (db.db == nullptr) return;
    ok(db.exec("CREATE TABLE typed(i INTEGER, t TEXT, r REAL, bi BIGINT)"),
       "create strict typed table");
    ok(db.exec("INSERT INTO typed VALUES("
               "-7,'hello',1.5,9007199254740993)"),
       "seed strict typed row");
    ok(db.exec("INSERT INTO typed(t) VALUES('a' || char(0) || 'b')"),
       "seed strict typed text with embedded NUL");

    SQLiteAdapter adapter(db.db, ResultProfile::strict_declared);
    PermitPolicy policy;
    Session session(adapter, policy);
    uint64_t id = 0;
    std::vector<Type> parameters;
    std::vector<Column> columns;
    ExecInfo info;
    Row row;
    bool done = true;

    status_ok(session.prepare("SELECT i,t,r,bi FROM typed ORDER BY rowid", id),
              "prepare strict typed select");
    status_ok(session.describe(id, parameters, columns),
              "describe strict typed select");
    ok(column_kind(columns, 0, TypeKind::signed_integer) &&
           column_kind(columns, 1, TypeKind::text) &&
           column_kind(columns, 2, TypeKind::floating) &&
           column_kind(columns, 3, TypeKind::signed_integer),
       "strict typed metadata advertises fixed scalar kinds");
    status_ok(session.execute(id, {}, info), "execute strict typed select");
    status_ok(session.fetch(id, row, done), "fetch strict typed first row");
    ok(!done && row.size() == 4 && int_value(row[0], -7) &&
           text_value(row[1], "hello") && double_value(row[2], 1.5),
       "strict typed row returns exact int, text, and float values");
    ok(!done && row.size() == 4 && int_value(row[3], 9007199254740993LL),
       "strict BIGINT keeps its full int64 value without double casting");

    status_ok(session.fetch(id, row, done), "fetch strict typed second row");
    ok(!done && row.size() == 4 && null_value(row[0]) &&
           text_value(row[1], std::string("a\0b", 3)) &&
           null_value(row[2]) && null_value(row[3]),
       "strict nullable columns accept NULL and TEXT preserves embedded NUL");
    status_ok(session.fetch(id, row, done), "fetch strict typed EOF");
    ok(done && row.empty(), "strict typed select reaches empty EOF");
}

void strict_blob_roundtrip() {
    TestDb db;
    ok(db.open(), "open engine for strict BLOB roundtrip");
    if (db.db == nullptr) return;
    ok(db.exec("CREATE TABLE blobs(v BLOB, label TEXT)"),
       "create strict BLOB table");
    ok(db.exec("INSERT INTO blobs VALUES"
               "(x'00ff1000','nulff'),(x'','empty'),"
               "(NULL,'null'),(x'ff','ff')"),
       "seed strict BLOB rows");

    SQLiteAdapter adapter(db.db, ResultProfile::strict_declared);
    PermitPolicy policy;
    Session session(adapter, policy);
    uint64_t id = 0;
    std::vector<Type> parameters;
    std::vector<Column> columns;
    ExecInfo info;
    Row row;
    bool done = true;

    status_ok(session.prepare("SELECT v,label FROM blobs ORDER BY rowid", id),
              "prepare strict BLOB select");
    status_ok(session.describe(id, parameters, columns),
              "describe strict BLOB select");
    ok(column_kind(columns, 0, TypeKind::bytes) &&
           column_kind(columns, 1, TypeKind::text),
       "strict BLOB metadata is bytes and label is text");

    status_ok(session.execute(id, {}, info), "execute strict BLOB select");
    status_ok(session.fetch(id, row, done), "fetch BLOB with NUL and 0xff");
    ok(!done && row.size() == 2 &&
           bytes_value(row[0], std::vector<uint8_t>{0x00, 0xff, 0x10, 0x00}) &&
           text_value(row[1], "nulff"),
       "declared BLOB preserves arbitrary NUL and 0xff bytes");
    status_ok(session.fetch(id, row, done), "fetch empty BLOB");
    ok(!done && row.size() == 2 &&
           bytes_value(row[0], std::vector<uint8_t>{}) &&
           text_value(row[1], "empty"),
       "declared BLOB preserves empty bytes as a non-NULL value");
    status_ok(session.fetch(id, row, done), "fetch NULL BLOB");
    ok(!done && row.size() == 2 && null_value(row[0]) &&
           text_value(row[1], "null"),
       "declared BLOB accepts NULL separately from empty bytes");
    status_ok(session.fetch(id, row, done), "fetch single 0xff BLOB");
    ok(!done && row.size() == 2 &&
           bytes_value(row[0], std::vector<uint8_t>{0xff}) &&
           text_value(row[1], "ff"),
       "declared BLOB returns Bytes with exact byte length");
    status_ok(session.fetch(id, row, done), "fetch strict BLOB EOF");
    ok(done && row.empty(), "strict BLOB select reaches empty EOF");
}

void strict_mixed_runtime_rejected() {
    TestDb db;
    ok(db.open(), "open engine for strict mixed storage classes");
    if (db.db == nullptr) return;
    ok(db.exec("CREATE TABLE mixed(v BLOB)"), "create mixed BLOB table");
    ok(db.exec("INSERT INTO mixed VALUES(x'0102'),(7),('text'),(NULL)"),
       "seed mixed BLOB storage classes");
    ok(db.exec("CREATE TABLE intmix(i INTEGER)"), "create mixed INTEGER table");
    ok(db.exec("INSERT INTO intmix VALUES(5),('abc')"),
       "seed mixed INTEGER storage classes");
    ok(db.exec("CREATE TABLE realmix(r REAL)"), "create mixed REAL table");
    ok(db.exec("INSERT INTO realmix VALUES(1.25),('not-a-number')"),
       "seed mixed REAL storage classes");
    ok(db.exec("CREATE TABLE textmix(t TEXT)"), "create mixed TEXT table");
    ok(db.exec("INSERT INTO textmix VALUES('ok'),(x'00ff')"),
       "seed mixed TEXT storage classes");

    SQLiteAdapter adapter(db.db, ResultProfile::strict_declared);
    PermitPolicy policy;
    Session session(adapter, policy);
    ExecInfo info;
    Row row;
    bool done = false;

    {
        uint64_t id = 0;
        status_ok(session.prepare("SELECT v FROM mixed ORDER BY rowid", id),
                  "prepare mixed BLOB select");
        status_ok(session.execute(id, {}, info), "execute mixed BLOB select");
        status_ok(session.fetch(id, row, done), "fetch valid BLOB storage");
        ok(!done && row.size() == 1 &&
               bytes_value(row[0], std::vector<uint8_t>{0x01, 0x02}),
           "valid BLOB row is exposed under the declared descriptor");
        auto err = session.fetch(id, row, done);
        status_error(err, ErrorKind::schema_changed,
                     "INTEGER storage under declared BLOB is refused");
        ok(row.empty() && !done,
           "refused mixed BLOB row exposes no value under the wrong descriptor");

        status_ok(session.execute(id, {}, info),
                  "re-execute mixed BLOB select after refusal");
        status_ok(session.fetch(id, row, done),
                  "fetch valid BLOB row after refusal");
        ok(!done && row.size() == 1 &&
               bytes_value(row[0], std::vector<uint8_t>{0x01, 0x02}),
           "strict result can restart after a refused mixed row");
    }

    {
        uint64_t id = 0;
        status_ok(session.prepare("SELECT i FROM intmix ORDER BY rowid", id),
                  "prepare mixed INTEGER select");
        status_ok(session.execute(id, {}, info), "execute mixed INTEGER select");
        status_ok(session.fetch(id, row, done), "fetch valid INTEGER storage");
        ok(!done && row.size() == 1 && int_value(row[0], 5),
           "valid INTEGER row is exposed as int64");
        auto err = session.fetch(id, row, done);
        status_error(err, ErrorKind::schema_changed,
                     "TEXT storage under declared INTEGER is refused");
        ok(row.empty() && !done,
           "refused INTEGER column row exposes no coerced value");
    }

    {
        uint64_t id = 0;
        status_ok(session.prepare("SELECT r FROM realmix ORDER BY rowid", id),
                  "prepare mixed REAL select");
        status_ok(session.execute(id, {}, info), "execute mixed REAL select");
        status_ok(session.fetch(id, row, done), "fetch valid REAL storage");
        ok(!done && row.size() == 1 && double_value(row[0], 1.25),
           "valid REAL row is exposed as double");
        auto err = session.fetch(id, row, done);
        status_error(err, ErrorKind::schema_changed,
                     "TEXT storage under declared REAL is refused without coercion");
        ok(row.empty() && !done,
           "refused REAL column row exposes no converted value");
    }

    {
        uint64_t id = 0;
        status_ok(session.prepare("SELECT t FROM textmix ORDER BY rowid", id),
                  "prepare mixed TEXT select");
        status_ok(session.execute(id, {}, info), "execute mixed TEXT select");
        status_ok(session.fetch(id, row, done), "fetch valid TEXT storage");
        ok(!done && row.size() == 1 && text_value(row[0], "ok"),
           "valid TEXT row is exposed as Text");
        auto err = session.fetch(id, row, done);
        status_error(err, ErrorKind::schema_changed,
                     "BLOB storage under declared TEXT is refused");
        ok(row.empty() && !done,
           "refused TEXT column row exposes no blob-to-text conversion");
    }
}

void strict_schema_reprepare() {
    TestDb db;
    ok(db.open(), "open engine for strict schema reprepare");
    if (db.db == nullptr) return;
    ok(db.exec("CREATE TABLE s(a INTEGER)"), "create reprepare table");
    ok(db.exec("INSERT INTO s VALUES(11)"), "seed reprepare table");

    SQLiteAdapter adapter(db.db, ResultProfile::strict_declared);
    PermitPolicy policy;
    Session session(adapter, policy);
    uint64_t id = 0;
    std::vector<Type> parameters;
    std::vector<Column> columns;
    ExecInfo info;
    Row row;
    bool done = true;

    status_ok(session.prepare("SELECT a FROM s", id),
              "prepare strict reprepare select");
    status_ok(session.describe(id, parameters, columns),
              "describe strict reprepare select");
    ok(column_kind(columns, 0, TypeKind::signed_integer),
       "initial declared type is signed_integer");
    status_ok(session.execute(id, {}, info), "execute initial reprepare select");
    status_ok(session.fetch(id, row, done), "fetch initial reprepare row");
    ok(!done && row.size() == 1 && int_value(row[0], 11),
       "initial declared INTEGER row is exposed as int64");
    status_ok(session.fetch(id, row, done), "finish initial reprepare result");
    ok(done && row.empty(), "initial reprepare select reaches EOF");
    status_ok(session.reset(id), "reset reprepare statement before schema change");

    ok(db.exec("DROP TABLE s"), "drop reprepare table");
    ok(db.exec("CREATE TABLE s(a TEXT)"), "recreate reprepare table as TEXT");
    ok(db.exec("INSERT INTO s VALUES('changed')"), "seed changed TEXT row");
    auto err = session.execute(id, {}, info);
    status_error(err, ErrorKind::schema_changed,
                 "reprepared declared type change is rejected before a row");
    row.push_back(int64_t(99));
    done = false;
    err = session.fetch(id, row, done);
    ok(bool(err), "fetch after reprepare rejection has no active result");
    ok(row.empty() && !done,
       "reprepare rejection exposes no stale or mismatched row");
    status_ok(session.reset(id), "reset rejected reprepare statement");

    ok(db.exec("DROP TABLE s"), "drop TEXT reprepare table");
    ok(db.exec("CREATE TABLE s(a INT)"), "recreate reprepare table as INT synonym");
    ok(db.exec("INSERT INTO s VALUES(22)"), "seed INT synonym row");
    status_ok(session.execute(id, {}, info),
              "same mapped kind under INT synonym is accepted");
    status_ok(session.fetch(id, row, done), "fetch INT synonym row");
    ok(!done && row.size() == 1 && int_value(row[0], 22),
       "mapped-kind comparison accepts INTEGER to INT without a raw-name change");
}

void missing_decltype_symbol_is_unsupported() {
    TestDb db;
    ok(db.open(), "open engine for missing decltype symbol");
    if (db.db == nullptr) return;

    {
        MissingDecltypeHook hook;
        SQLiteAdapter strict(db.db, ResultProfile::strict_declared);
        std::unique_ptr<Statement> statement;
        auto err = strict.prepare("SELECT 1", statement);
        status_error(err, ErrorKind::unsupported,
                     "strict prepare is unsupported without column_decltype");
        ok(!statement, "missing column_decltype leaves no strict statement");

        SQLiteAdapter dynamic(db.db);
        status_ok(dynamic.prepare("SELECT 1", statement),
                  "default dynamic prepare does not require column_decltype");
        ok(bool(statement), "dynamic prepare still works without column_decltype");
        if (statement) dynamic.finalize(std::move(statement));
    }

    SQLiteAdapter strict(db.db, ResultProfile::strict_declared);
    std::unique_ptr<Statement> statement;
    status_ok(strict.prepare("SELECT 1 AS expression", statement),
              "strict prepare works again after the symbol is restored");
    if (statement) {
        std::vector<Column> columns;
        status_ok(strict.describe_result(*statement, columns),
                  "describe restored strict expression");
        ok(columns.size() == 1 && column_kind(columns, 0, TypeKind::dynamic),
           "NULL declared type remains dynamic after symbol restore");
        strict.finalize(std::move(statement));
    }
}

void strict_metadata_no_execute() {
    TestDb db;
    ok(db.open(), "open engine for strict metadata no-execute");
    if (db.db == nullptr) return;
    ok(db.exec("CREATE TABLE side(v INTEGER)"), "create strict side table");

    SQLiteAdapter adapter(db.db, ResultProfile::strict_declared);
    std::unique_ptr<Statement> statement;
    std::vector<Column> columns;

    status_ok(adapter.prepare("INSERT INTO side(v) VALUES (1)", statement),
              "prepare strict write statement");
    status_ok(adapter.describe_result(*statement, columns),
              "describe strict write result");
    ok(columns.empty(), "strict write statement advertises no result columns");
    ok(scalar(db, "SELECT count(*) FROM side") == 0,
       "prepare and describe strict write never execute it");
    adapter.finalize(std::move(statement));

    status_ok(adapter.prepare("SELECT v FROM side", statement),
              "prepare strict read metadata statement");
    status_ok(adapter.describe_result(*statement, columns),
              "describe strict read metadata statement");
    ok(columns.size() == 1 && column_kind(columns, 0, TypeKind::signed_integer),
       "strict read metadata is captured without stepping");
    ok(scalar(db, "SELECT count(*) FROM side") == 0,
       "strict read description has no side effect");
    adapter.finalize(std::move(statement));

    auto err = adapter.prepare("INSERT INTO side(v) VALUES (2) RETURNING v",
                               statement);
    status_error(err, ErrorKind::unsupported,
                 "strict profile still refuses write statements with result columns");
    ok(!statement && scalar(db, "SELECT count(*) FROM side") == 0,
       "strict RETURNING refusal happens before any effect");
}

}  // namespace

int main() {
    plan(NO_PLAN);
    default_profile_remains_dynamic();
    strict_declared_metadata();
    strict_alias_expression_metadata();
    strict_typed_runtime();
    strict_blob_roundtrip();
    strict_mixed_runtime_rejected();
    strict_schema_reprepare();
    missing_decltype_symbol_is_unsupported();
    strict_metadata_no_execute();
    return exit_status();
}
