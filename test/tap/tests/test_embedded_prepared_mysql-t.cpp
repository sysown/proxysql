#include "prepared_owned_fixture.h"
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cerrno>
#include <unistd.h>
#include <string>
#include <string_view>
#include <vector>
#include <cstdint>
#include <memory>

#include "mysql.h"
#include "mysqld_error.h"

#include "tap.h"

struct ConnDeleter {
    void operator()(MYSQL* p) const { if (p) mysql_close(p); }
};
struct StmtDeleter {
    void operator()(MYSQL_STMT* p) const { if (p) mysql_stmt_close(p); }
};
struct ResDeleter {
    void operator()(MYSQL_RES* p) const { if (p) mysql_free_result(p); }
};

using ConnPtr = std::unique_ptr<MYSQL, ConnDeleter>;
using StmtPtr = std::unique_ptr<MYSQL_STMT, StmtDeleter>;
using ResPtr = std::unique_ptr<MYSQL_RES, ResDeleter>;

static long count_rows(MYSQL* mysql, const std::string& table) {
    std::string q = "SELECT COUNT(*) FROM " + table;
    if (mysql_query(mysql, q.c_str()) != 0) return -1;
    MYSQL_RES* raw = mysql_store_result(mysql);
    if (raw == nullptr) return -1;
    ResPtr res(raw);
    MYSQL_ROW row = mysql_fetch_row(res.get());
    if (row == nullptr || row[0] == nullptr) return -1;
    char* end = nullptr;
    errno = 0;
    long v = std::strtol(row[0], &end, 10);
    if (errno != 0 || end == row[0] || *end != '\0') return -1;
    return v;
}

int main() {
    prepared_owned_fixture::Fixture fixture;
    plan(NO_PLAN);

    const char* host_env = std::getenv("TAP_HOST");
    std::string host = (host_env != nullptr && host_env[0] != '\0') ? host_env : "127.0.0.1";

    const char* port_env = std::getenv("TAP_SQLITE_PORT");
    int port = 6030;
    if (port_env != nullptr) {
        char* end = nullptr;
        errno = 0;
        long v = std::strtol(port_env, &end, 10);
        if (errno != 0 || end == port_env || *end != '\0' || v <= 0 || v > 65535) {
            BAIL_OUT("invalid TAP_SQLITE_PORT: %s", port_env);
        }
        port = static_cast<int>(v);
    }

    const char* user_env = std::getenv("TAP_USERNAME");
    if (user_env == nullptr || user_env[0] == '\0') {
        BAIL_OUT("TAP_USERNAME is required");
    }
    std::string user = user_env;

    const char* pass_env = std::getenv("TAP_PASSWORD");
    std::string password = (pass_env != nullptr) ? pass_env : "";

    MYSQL* raw_conn = mysql_init(nullptr);
    if (raw_conn == nullptr) BAIL_OUT("mysql_init failed");
    ConnPtr conn(raw_conn);

    if (mysql_real_connect(conn.get(), host.c_str(), user.c_str(), password.c_str(),
                           nullptr, port, nullptr, 0) == nullptr) {
        BAIL_OUT("connect failed: %s", mysql_error(conn.get()));
    }

    if (mysql_query(conn.get(), "SELECT sqlite_version()") != 0) {
        BAIL_OUT("sqlite_version query failed: %s", mysql_error(conn.get()));
    }
    {
        MYSQL_RES* raw_res = mysql_store_result(conn.get());
        if (raw_res == nullptr) BAIL_OUT("sqlite_version result missing");
        ResPtr res(raw_res);
        MYSQL_ROW row = mysql_fetch_row(res.get());
        if (row == nullptr || row[0] == nullptr) BAIL_OUT("sqlite_version row missing");
        ok(true, "native SQLite identity: %s", row[0]);
    }

    const std::string table = std::string("embedded_prep_") + std::to_string(static_cast<long>(getpid()));

    auto exec_sql = [&](const std::string& q) {
        if (mysql_query(conn.get(), q.c_str()) != 0) {
            BAIL_OUT("SQL failed '%s': %s", q.c_str(), mysql_error(conn.get()));
        }
    };

    exec_sql("DROP TABLE IF EXISTS " + table);
    exec_sql("CREATE TABLE " + table + " (id INTEGER PRIMARY KEY, txt TEXT, bin BLOB, num INTEGER)");

    const std::string insert_sql = "INSERT INTO " + table + " (id, txt, bin, num) VALUES (?, ?, ?, ?)";
    const std::string select_sql = "SELECT id, txt, bin, num FROM " + table + " WHERE id=?";

    StmtPtr ins(mysql_stmt_init(conn.get()));
    if (!ins) BAIL_OUT("mysql_stmt_init failed");
    if (mysql_stmt_prepare(ins.get(), insert_sql.c_str(), static_cast<unsigned long>(insert_sql.size())) != 0) {
        BAIL_OUT("prepare INSERT failed: %s", mysql_stmt_error(ins.get()));
    }

    unsigned long param_count = mysql_stmt_param_count(ins.get());
    ok(param_count == 4, "INSERT param_count expected 4, got %lu", param_count);
    if (param_count != 4) BAIL_OUT("bad INSERT param_count");

    {
        ResPtr meta(mysql_stmt_result_metadata(ins.get()));
        ok(meta.get() == nullptr, "INSERT result_metadata is NULL");
        if (meta.get() != nullptr) BAIL_OUT("INSERT unexpectedly returned result metadata");
    }

    long long id1 = 42;
    const char text_bytes[] = "a\0b'\"; DROP TABLE x; --";
    const size_t text_len = sizeof(text_bytes) - 1;
    std::string text1(text_bytes, text_len);
    const unsigned char blob_bytes[] = {0x00, 0xFF, 0x01, 0x00, 'A'};
    const size_t blob_len = sizeof(blob_bytes);
    std::string blob1(reinterpret_cast<const char*>(blob_bytes), blob_len);
    long long num1 = 1234567890123456789LL;

    unsigned long text_len_ul = static_cast<unsigned long>(text_len);
    unsigned long blob_len_ul = static_cast<unsigned long>(blob_len);

    MYSQL_BIND iparams[4];
    std::memset(iparams, 0, sizeof(iparams));

    iparams[0].buffer_type = MYSQL_TYPE_LONGLONG;
    iparams[0].buffer = &id1;
    iparams[0].buffer_length = sizeof(id1);
    iparams[0].is_null = 0;
    iparams[0].length = 0;

    iparams[1].buffer_type = MYSQL_TYPE_VAR_STRING;
    iparams[1].buffer = const_cast<char*>(text1.data());
    iparams[1].buffer_length = text_len;
    iparams[1].is_null = 0;
    iparams[1].length = &text_len_ul;

    iparams[2].buffer_type = MYSQL_TYPE_BLOB;
    iparams[2].buffer = const_cast<char*>(blob1.data());
    iparams[2].buffer_length = blob_len;
    iparams[2].is_null = 0;
    iparams[2].length = &blob_len_ul;

    iparams[3].buffer_type = MYSQL_TYPE_LONGLONG;
    iparams[3].buffer = &num1;
    iparams[3].buffer_length = sizeof(num1);
    iparams[3].is_null = 0;
    iparams[3].length = 0;

    if (mysql_stmt_bind_param(ins.get(), iparams) != 0) {
        BAIL_OUT("bind INSERT params failed: %s", mysql_stmt_error(ins.get()));
    }
    if (mysql_stmt_execute(ins.get()) != 0) {
        BAIL_OUT("execute INSERT failed: %s", mysql_stmt_error(ins.get()));
    }
    ok(mysql_stmt_affected_rows(ins.get()) == 1, "INSERT affected rows expected 1");

    StmtPtr sel(mysql_stmt_init(conn.get()));
    if (!sel) BAIL_OUT("mysql_stmt_init failed");
    if (mysql_stmt_prepare(sel.get(), select_sql.c_str(), static_cast<unsigned long>(select_sql.size())) != 0) {
        BAIL_OUT("prepare SELECT failed: %s", mysql_stmt_error(sel.get()));
    }

    MYSQL_BIND sparam[1];
    std::memset(sparam, 0, sizeof(sparam));
    sparam[0].buffer_type = MYSQL_TYPE_LONGLONG;
    sparam[0].buffer = &id1;
    sparam[0].buffer_length = sizeof(id1);
    sparam[0].is_null = 0;
    sparam[0].length = 0;
    if (mysql_stmt_bind_param(sel.get(), sparam) != 0) {
        BAIL_OUT("bind SELECT param failed: %s", mysql_stmt_error(sel.get()));
    }
    if (mysql_stmt_execute(sel.get()) != 0) {
        BAIL_OUT("execute SELECT failed: %s", mysql_stmt_error(sel.get()));
    }

    std::vector<char> text_buf(text_len > 0 ? text_len : 1);
    std::vector<char> blob_buf(blob_len > 0 ? blob_len : 1);
    long long res_id = 0;
    long long res_num = 0;
    my_bool is_null[4] = {0, 0, 0, 0};
    unsigned long lengths[4] = {0, 0, 0, 0};
    my_bool errors[4] = {0, 0, 0, 0};

    MYSQL_BIND rbind[4];
    std::memset(rbind, 0, sizeof(rbind));

    rbind[0].buffer_type = MYSQL_TYPE_LONGLONG;
    rbind[0].buffer = &res_id;
    rbind[0].buffer_length = sizeof(res_id);
    rbind[0].is_null = &is_null[0];
    rbind[0].length = &lengths[0];
    rbind[0].error = &errors[0];

    rbind[1].buffer_type = MYSQL_TYPE_VAR_STRING;
    rbind[1].buffer = text_buf.data();
    rbind[1].buffer_length = text_buf.size();
    rbind[1].is_null = &is_null[1];
    rbind[1].length = &lengths[1];
    rbind[1].error = &errors[1];

    rbind[2].buffer_type = MYSQL_TYPE_BLOB;
    rbind[2].buffer = blob_buf.data();
    rbind[2].buffer_length = blob_buf.size();
    rbind[2].is_null = &is_null[2];
    rbind[2].length = &lengths[2];
    rbind[2].error = &errors[2];

    rbind[3].buffer_type = MYSQL_TYPE_LONGLONG;
    rbind[3].buffer = &res_num;
    rbind[3].buffer_length = sizeof(res_num);
    rbind[3].is_null = &is_null[3];
    rbind[3].length = &lengths[3];
    rbind[3].error = &errors[3];

    if (mysql_stmt_bind_result(sel.get(), rbind) != 0) {
        BAIL_OUT("bind SELECT result failed: %s", mysql_stmt_error(sel.get()));
    }
    if (mysql_stmt_store_result(sel.get()) != 0) {
        BAIL_OUT("store SELECT result failed: %s", mysql_stmt_error(sel.get()));
    }

    ok(mysql_stmt_num_rows(sel.get()) == 1, "SELECT returned exactly one row");
    int fetch_rc = mysql_stmt_fetch(sel.get());
    ok(fetch_rc == 0, "fetch first row succeeded");
    if (fetch_rc != 0) BAIL_OUT("fetch failed: %s", mysql_stmt_error(sel.get()));

    ok(!is_null[0] && res_id == id1, "id round-trips: %lld", res_id);
    ok(!is_null[1] && lengths[1] == text_len &&
       std::memcmp(text_buf.data(), text1.data(), text_len) == 0,
       "text exact bytes/length round-trip");
    ok(!is_null[2] && lengths[2] == blob_len &&
       std::memcmp(blob_buf.data(), blob1.data(), blob_len) == 0,
       "blob exact bytes/length round-trip");
    ok(!is_null[3] && res_num == num1, "signed64 value round-trips: %lld", res_num);

    int eof_rc = mysql_stmt_fetch(sel.get());
    ok(eof_rc == MYSQL_NO_DATA, "fetch reaches EOF");

    mysql_stmt_close(sel.release());

    long long id2 = 7;
    my_bool text_is_null = 1;
    const char empty_blob[] = "";
    unsigned long empty_blob_len = 0;
    long long num2 = -987654321098765432LL;

    iparams[0].buffer = &id2;
    iparams[1].buffer_type = MYSQL_TYPE_VAR_STRING;
    iparams[1].buffer = nullptr;
    iparams[1].buffer_length = 0;
    iparams[1].is_null = &text_is_null;
    iparams[1].length = 0;
    iparams[2].buffer_type = MYSQL_TYPE_BLOB;
    iparams[2].buffer = const_cast<char*>(empty_blob);
    iparams[2].buffer_length = 0;
    iparams[2].is_null = 0;
    iparams[2].length = &empty_blob_len;
    iparams[3].buffer = &num2;

    if (mysql_stmt_bind_param(ins.get(), iparams) != 0) {
        BAIL_OUT("rebind INSERT params failed: %s", mysql_stmt_error(ins.get()));
    }
    if (mysql_stmt_execute(ins.get()) != 0) {
        BAIL_OUT("execute reused INSERT failed: %s", mysql_stmt_error(ins.get()));
    }
    ok(count_rows(conn.get(), table) == 2, "reused insert added second row");

    long long id_dup = id1;
    iparams[0].buffer = &id_dup;
    if (mysql_stmt_bind_param(ins.get(), iparams) != 0) {
        BAIL_OUT("bind duplicate params failed: %s", mysql_stmt_error(ins.get()));
    }
    int dup_rc = mysql_stmt_execute(ins.get());
    ok(dup_rc != 0, "duplicate key insert fails");
    ok(count_rows(conn.get(), table) == 2, "duplicate key had no effect");

    long long id3 = 99;
    iparams[0].buffer = &id3;
    text_is_null = 0;
    std::string text3 = "recovered";
    unsigned long text3_len = static_cast<unsigned long>(text3.size());
    iparams[1].buffer_type = MYSQL_TYPE_VAR_STRING;
    iparams[1].buffer = const_cast<char*>(text3.data());
    iparams[1].buffer_length = text3.size();
    iparams[1].is_null = 0;
    iparams[1].length = &text3_len;
    if (mysql_stmt_bind_param(ins.get(), iparams) != 0) {
        BAIL_OUT("bind recovered params failed: %s", mysql_stmt_error(ins.get()));
    }
    if (mysql_stmt_execute(ins.get()) != 0) {
        BAIL_OUT("execute recovered insert failed: %s", mysql_stmt_error(ins.get()));
    }
    ok(count_rows(conn.get(), table) == 3, "recovered insert added third row");

    unsigned long long uint_max = ~0ULL;
    long long id_um = 0;
    iparams[0].buffer_type = MYSQL_TYPE_LONGLONG;
    iparams[0].buffer = &uint_max;
    iparams[0].buffer_length = sizeof(uint_max);
    iparams[0].is_unsigned = 1;
    iparams[0].is_null = 0;
    iparams[0].length = 0;
    if (mysql_stmt_bind_param(ins.get(), iparams) != 0) {
        BAIL_OUT("bind UINT64_MAX params failed: %s", mysql_stmt_error(ins.get()));
    }
    int um_rc = mysql_stmt_execute(ins.get());
    ok(um_rc != 0, "UINT64_MAX bound to SQLite integer is rejected");
    ok(count_rows(conn.get(), table) == 3, "rejected UINT64_MAX had no effect");

    long long id4 = 100;
    iparams[0].buffer = &id4;
    iparams[0].is_unsigned = 0;
    iparams[0].buffer_length = sizeof(id4);
    if (mysql_stmt_bind_param(ins.get(), iparams) != 0) {
        BAIL_OUT("bind valid signed params failed: %s", mysql_stmt_error(ins.get()));
    }
    if (mysql_stmt_execute(ins.get()) != 0) {
        BAIL_OUT("execute valid signed insert failed: %s", mysql_stmt_error(ins.get()));
    }
    ok(count_rows(conn.get(), table) == 4, "valid signed insert added fourth row");

    if (mysql_stmt_reset(ins.get()) != 0) {
        BAIL_OUT("mysql_stmt_reset failed: %s", mysql_stmt_error(ins.get()));
    }
    mysql_stmt_close(ins.release());
    ok(count_rows(conn.get(), table) == 4, "connection remains synchronized after close");

    StmtPtr long_stmt(mysql_stmt_init(conn.get()));
    if (!long_stmt) BAIL_OUT("mysql_stmt_init failed");
    if (mysql_stmt_prepare(long_stmt.get(), insert_sql.c_str(), static_cast<unsigned long>(insert_sql.size())) != 0) {
        BAIL_OUT("prepare long INSERT failed: %s", mysql_stmt_error(long_stmt.get()));
    }

    long long long_id = 200;
    my_bool long_text_null = 1;
    std::string normal_blob = "normal-bin";
    unsigned long normal_blob_len = static_cast<unsigned long>(normal_blob.size());
    long long long_num = 0;

    MYSQL_BIND lparams[4];
    std::memset(lparams, 0, sizeof(lparams));
    lparams[0].buffer_type = MYSQL_TYPE_LONGLONG;
    lparams[0].buffer = &long_id;
    lparams[0].buffer_length = sizeof(long_id);
    lparams[0].is_null = 0;
    lparams[0].length = 0;

    lparams[1].buffer_type = MYSQL_TYPE_VAR_STRING;
    lparams[1].buffer = nullptr;
    lparams[1].buffer_length = 0;
    lparams[1].is_null = &long_text_null;
    lparams[1].length = 0;

    lparams[2].buffer_type = MYSQL_TYPE_BLOB;
    lparams[2].buffer = const_cast<char*>(normal_blob.data());
    lparams[2].buffer_length = normal_blob.size();
    lparams[2].is_null = 0;
    lparams[2].length = &normal_blob_len;

    lparams[3].buffer_type = MYSQL_TYPE_LONGLONG;
    lparams[3].buffer = &long_num;
    lparams[3].buffer_length = sizeof(long_num);
    lparams[3].is_null = 0;
    lparams[3].length = 0;

    if (mysql_stmt_bind_param(long_stmt.get(), lparams) != 0) {
        BAIL_OUT("bind long params failed: %s", mysql_stmt_error(long_stmt.get()));
    }

    std::string chunk1 = std::string("ab\0c", 4);
    std::string chunk2 = std::string("d\xFF", 2);
    std::string empty_chunk;
    if (mysql_stmt_send_long_data(long_stmt.get(), 2, chunk1.data(), static_cast<unsigned long>(chunk1.size())) != 0) {
        BAIL_OUT("send_long_data chunk1 failed: %s", mysql_stmt_error(long_stmt.get()));
    }
    if (mysql_stmt_send_long_data(long_stmt.get(), 2, chunk2.data(), static_cast<unsigned long>(chunk2.size())) != 0) {
        BAIL_OUT("send_long_data chunk2 failed: %s", mysql_stmt_error(long_stmt.get()));
    }
    if (mysql_stmt_send_long_data(long_stmt.get(), 2, empty_chunk.data(), 0) != 0) {
        BAIL_OUT("send_long_data empty chunk failed: %s", mysql_stmt_error(long_stmt.get()));
    }

    if (mysql_stmt_execute(long_stmt.get()) != 0) {
        BAIL_OUT("execute long-data insert failed: %s", mysql_stmt_error(long_stmt.get()));
    }

    {
        long long qid = long_id;
        StmtPtr qsel(mysql_stmt_init(conn.get()));
        if (!qsel) BAIL_OUT("mysql_stmt_init failed");
        if (mysql_stmt_prepare(qsel.get(), select_sql.c_str(), static_cast<unsigned long>(select_sql.size())) != 0) {
            BAIL_OUT("prepare long SELECT failed: %s", mysql_stmt_error(qsel.get()));
        }
        MYSQL_BIND qp[1]; std::memset(qp, 0, sizeof(qp));
        qp[0].buffer_type = MYSQL_TYPE_LONGLONG;
        qp[0].buffer = &qid;
        qp[0].buffer_length = sizeof(qid);
        qp[0].is_null = 0;
        qp[0].length = 0;
        if (mysql_stmt_bind_param(qsel.get(), qp) != 0) BAIL_OUT("bind long SELECT failed: %s", mysql_stmt_error(qsel.get()));
        if (mysql_stmt_execute(qsel.get()) != 0) BAIL_OUT("execute long SELECT failed: %s", mysql_stmt_error(qsel.get()));

        std::string concat = chunk1 + chunk2;
        std::vector<char> lbuf(concat.size() > 0 ? concat.size() : 1);
        long long rid = 0, rnum = 0;
        my_bool inull[4] = {0,0,0,0};
        unsigned long rlens[4] = {0,0,0,0};
        my_bool rerrs[4] = {0,0,0,0};
        MYSQL_BIND rb[4]; std::memset(rb, 0, sizeof(rb));
        rb[0].buffer_type = MYSQL_TYPE_LONGLONG; rb[0].buffer = &rid; rb[0].buffer_length = sizeof(rid); rb[0].is_null = &inull[0]; rb[0].length = &rlens[0]; rb[0].error = &rerrs[0];
        rb[1].buffer_type = MYSQL_TYPE_VAR_STRING; rb[1].buffer = nullptr; rb[1].buffer_length = 0; rb[1].is_null = &inull[1]; rb[1].length = &rlens[1]; rb[1].error = &rerrs[1];
        rb[2].buffer_type = MYSQL_TYPE_BLOB; rb[2].buffer = lbuf.data(); rb[2].buffer_length = lbuf.size(); rb[2].is_null = &inull[2]; rb[2].length = &rlens[2]; rb[2].error = &rerrs[2];
        rb[3].buffer_type = MYSQL_TYPE_LONGLONG; rb[3].buffer = &rnum; rb[3].buffer_length = sizeof(rnum); rb[3].is_null = &inull[3]; rb[3].length = &rlens[3]; rb[3].error = &rerrs[3];
        if (mysql_stmt_bind_result(qsel.get(), rb) != 0) BAIL_OUT("bind long result failed: %s", mysql_stmt_error(qsel.get()));
        if (mysql_stmt_store_result(qsel.get()) != 0) BAIL_OUT("store long result failed: %s", mysql_stmt_error(qsel.get()));
        if (mysql_stmt_fetch(qsel.get()) != 0) BAIL_OUT("fetch long row failed: %s", mysql_stmt_error(qsel.get()));
        ok(!inull[2] && rlens[2] == concat.size() &&
           std::memcmp(lbuf.data(), concat.data(), concat.size()) == 0,
           "SEND_LONG_DATA chunks concatenated exactly");
        ok(inull[1] != 0, "null text remains distinct in long-data row");
        mysql_stmt_close(qsel.release());
    }

    long long long_id2 = 201;
    long_id = long_id2;
    if (mysql_stmt_reset(long_stmt.get()) != 0) {
        BAIL_OUT("mysql_stmt_reset failed: %s", mysql_stmt_error(long_stmt.get()));
    }
    if (mysql_stmt_execute(long_stmt.get()) != 0) {
        BAIL_OUT("execute after reset failed: %s", mysql_stmt_error(long_stmt.get()));
    }
    {
        long long qid = long_id2;
        StmtPtr qsel(mysql_stmt_init(conn.get()));
        if (!qsel) BAIL_OUT("mysql_stmt_init failed");
        if (mysql_stmt_prepare(qsel.get(), select_sql.c_str(), static_cast<unsigned long>(select_sql.size())) != 0) {
            BAIL_OUT("prepare post-reset SELECT failed: %s", mysql_stmt_error(qsel.get()));
        }
        MYSQL_BIND qp[1]; std::memset(qp, 0, sizeof(qp));
        qp[0].buffer_type = MYSQL_TYPE_LONGLONG;
        qp[0].buffer = &qid;
        qp[0].buffer_length = sizeof(qid);
        qp[0].is_null = 0;
        qp[0].length = 0;
        if (mysql_stmt_bind_param(qsel.get(), qp) != 0) BAIL_OUT("bind post-reset SELECT failed: %s", mysql_stmt_error(qsel.get()));
        if (mysql_stmt_execute(qsel.get()) != 0) BAIL_OUT("execute post-reset SELECT failed: %s", mysql_stmt_error(qsel.get()));
        std::vector<char> lbuf(normal_blob.size() > 0 ? normal_blob.size() : 1);
        long long rid = 0, rnum = 0;
        my_bool inull[4] = {0,0,0,0};
        unsigned long rlens[4] = {0,0,0,0};
        my_bool rerrs[4] = {0,0,0,0};
        MYSQL_BIND rb[4]; std::memset(rb, 0, sizeof(rb));
        rb[0].buffer_type = MYSQL_TYPE_LONGLONG; rb[0].buffer = &rid; rb[0].buffer_length = sizeof(rid); rb[0].is_null = &inull[0]; rb[0].length = &rlens[0]; rb[0].error = &rerrs[0];
        rb[1].buffer_type = MYSQL_TYPE_VAR_STRING; rb[1].buffer = nullptr; rb[1].buffer_length = 0; rb[1].is_null = &inull[1]; rb[1].length = &rlens[1]; rb[1].error = &rerrs[1];
        rb[2].buffer_type = MYSQL_TYPE_BLOB; rb[2].buffer = lbuf.data(); rb[2].buffer_length = lbuf.size(); rb[2].is_null = &inull[2]; rb[2].length = &rlens[2]; rb[2].error = &rerrs[2];
        rb[3].buffer_type = MYSQL_TYPE_LONGLONG; rb[3].buffer = &rnum; rb[3].buffer_length = sizeof(rnum); rb[3].is_null = &inull[3]; rb[3].length = &rlens[3]; rb[3].error = &rerrs[3];
        if (mysql_stmt_bind_result(qsel.get(), rb) != 0) BAIL_OUT("bind post-reset result failed: %s", mysql_stmt_error(qsel.get()));
        if (mysql_stmt_store_result(qsel.get()) != 0) BAIL_OUT("store post-reset result failed: %s", mysql_stmt_error(qsel.get()));
        if (mysql_stmt_fetch(qsel.get()) != 0) BAIL_OUT("fetch post-reset row failed: %s", mysql_stmt_error(qsel.get()));
        ok(!inull[2] && rlens[2] == normal_blob.size() &&
           std::memcmp(lbuf.data(), normal_blob.data(), normal_blob.size()) == 0,
           "after reset normal bound buffer is used");
        mysql_stmt_close(qsel.release());
    }

    mysql_stmt_close(long_stmt.release());

    {
        const char* bad_sqls[] = {
            "PRAGMA foreign_keys=ON",
            "ATTACH DATABASE ':memory:' AS aux",
            "SELECT readfile('/tmp/proxysql-embedded-prepared')",
            "SELECT load_extension('libfoo')"
        };
        for (const char* s : bad_sqls) {
            StmtPtr st(mysql_stmt_init(conn.get()));
            if (!st) BAIL_OUT("mysql_stmt_init failed");
            int rc = mysql_stmt_prepare(st.get(), s,
                                        static_cast<unsigned long>(std::string_view(s).size()));
            ok(rc != 0, "unsupported prepare rejected: %s", s);
        }
        StmtPtr safe(mysql_stmt_init(conn.get()));
        if (!safe) BAIL_OUT("mysql_stmt_init failed");
        constexpr std::string_view safe_sql = "SELECT 1";
        if (mysql_stmt_prepare(safe.get(), safe_sql.data(),
                               static_cast<unsigned long>(safe_sql.size())) != 0) {
            BAIL_OUT("safe prepare failed after unsupported: %s", mysql_stmt_error(safe.get()));
        }
        mysql_stmt_close(safe.release());
    }

    {
        StmtPtr cstmt(mysql_stmt_init(conn.get()));
        if (!cstmt) BAIL_OUT("mysql_stmt_init failed");
        std::string cursor_sql = std::string("SELECT id, txt FROM ") + table;
        if (mysql_stmt_prepare(cstmt.get(), cursor_sql.c_str(), static_cast<unsigned long>(cursor_sql.size())) != 0) {
            BAIL_OUT("prepare cursor SELECT failed: %s", mysql_stmt_error(cstmt.get()));
        }
        unsigned long cursor_type = CURSOR_TYPE_READ_ONLY;
        ok(mysql_stmt_attr_set(cstmt.get(), STMT_ATTR_CURSOR_TYPE, &cursor_type) == 0,
           "set read-only cursor attribute");
        int crc = mysql_stmt_execute(cstmt.get());
        ok(crc != 0, "read-only cursor execute fails");
        ok(mysql_stmt_errno(cstmt.get()) == ER_NOT_SUPPORTED_YET,
           "read-only cursor unsupported error is 1235 (got %u)", mysql_stmt_errno(cstmt.get()));

        unsigned long no_cursor = CURSOR_TYPE_NO_CURSOR;
        if (mysql_stmt_attr_set(cstmt.get(), STMT_ATTR_CURSOR_TYPE, &no_cursor) != 0) {
            BAIL_OUT("clear cursor attribute failed: %s", mysql_stmt_error(cstmt.get()));
        }
        if (mysql_stmt_execute(cstmt.get()) != 0) {
            BAIL_OUT("execute after clearing cursor failed: %s", mysql_stmt_error(cstmt.get()));
        }
        if (mysql_stmt_store_result(cstmt.get()) != 0) {
            BAIL_OUT("store cursor result failed: %s", mysql_stmt_error(cstmt.get()));
        }
        while (mysql_stmt_fetch(cstmt.get()) == 0) {}
        mysql_stmt_close(cstmt.release());
    }

    {
        exec_sql("SET autocommit=1");
        exec_sql("SET autocommit=0");
        ok((conn->server_status & SERVER_STATUS_AUTOCOMMIT) == 0, "autocommit=0 clears AUTOCOMMIT");
        ok((conn->server_status & SERVER_STATUS_IN_TRANS) == 0, "no transaction before execute");

        const std::string tx_insert_sql = "INSERT INTO " + table + " (id, txt, bin, num) VALUES (?, ?, ?, ?)";
        StmtPtr txins(mysql_stmt_init(conn.get()));
        if (!txins) BAIL_OUT("mysql_stmt_init failed");
        if (mysql_stmt_prepare(txins.get(), tx_insert_sql.c_str(), static_cast<unsigned long>(tx_insert_sql.size())) != 0) {
            BAIL_OUT("prepare tx INSERT failed: %s", mysql_stmt_error(txins.get()));
        }
        ok((conn->server_status & SERVER_STATUS_IN_TRANS) == 0, "native prepare does not start TX");

        long long txid = 300;
        std::string txtext = "tx";
        unsigned long txtext_len = static_cast<unsigned long>(txtext.size());
        std::string txbin = "txbin";
        unsigned long txbin_len = static_cast<unsigned long>(txbin.size());
        long long txnum = 7;
        MYSQL_BIND tp[4]; std::memset(tp, 0, sizeof(tp));
        tp[0].buffer_type = MYSQL_TYPE_LONGLONG; tp[0].buffer = &txid; tp[0].buffer_length = sizeof(txid); tp[0].is_null = 0; tp[0].length = 0;
        tp[1].buffer_type = MYSQL_TYPE_VAR_STRING; tp[1].buffer = const_cast<char*>(txtext.data()); tp[1].buffer_length = txtext.size(); tp[1].is_null = 0; tp[1].length = &txtext_len;
        tp[2].buffer_type = MYSQL_TYPE_BLOB; tp[2].buffer = const_cast<char*>(txbin.data()); tp[2].buffer_length = txbin.size(); tp[2].is_null = 0; tp[2].length = &txbin_len;
        tp[3].buffer_type = MYSQL_TYPE_LONGLONG; tp[3].buffer = &txnum; tp[3].buffer_length = sizeof(txnum); tp[3].is_null = 0; tp[3].length = 0;
        if (mysql_stmt_bind_param(txins.get(), tp) != 0) BAIL_OUT("bind tx insert failed: %s", mysql_stmt_error(txins.get()));
        if (mysql_stmt_execute(txins.get()) != 0) BAIL_OUT("execute tx insert failed: %s", mysql_stmt_error(txins.get()));
        ok((conn->server_status & SERVER_STATUS_IN_TRANS) == 1, "prepared INSERT begins deferred TX on execute");

        StmtPtr txsel(mysql_stmt_init(conn.get()));
        if (!txsel) BAIL_OUT("mysql_stmt_init failed");
        std::string txsel_sql = "SELECT id FROM " + table + " WHERE id=?";
        if (mysql_stmt_prepare(txsel.get(), txsel_sql.c_str(), static_cast<unsigned long>(txsel_sql.size())) != 0) {
            BAIL_OUT("prepare tx SELECT failed: %s", mysql_stmt_error(txsel.get()));
        }
        ok((conn->server_status & SERVER_STATUS_IN_TRANS) == 1, "prepare SELECT does not clear TX");
        long long sid = 1;
        MYSQL_BIND sp[1]; std::memset(sp, 0, sizeof(sp));
        sp[0].buffer_type = MYSQL_TYPE_LONGLONG; sp[0].buffer = &sid; sp[0].buffer_length = sizeof(sid); sp[0].is_null = 0; sp[0].length = 0;
        if (mysql_stmt_bind_param(txsel.get(), sp) != 0) BAIL_OUT("bind tx SELECT failed: %s", mysql_stmt_error(txsel.get()));
        if (mysql_stmt_execute(txsel.get()) != 0) BAIL_OUT("execute tx SELECT failed: %s", mysql_stmt_error(txsel.get()));
        if (mysql_stmt_store_result(txsel.get()) != 0) BAIL_OUT("store tx SELECT failed: %s", mysql_stmt_error(txsel.get()));
        while (mysql_stmt_fetch(txsel.get()) == 0) {}
        ok((conn->server_status & SERVER_STATUS_IN_TRANS) == 1, "IN_TRANS after result drain");

        if (mysql_query(conn.get(), "ROLLBACK") != 0) BAIL_OUT("ROLLBACK failed: %s", mysql_error(conn.get()));
        ok((conn->server_status & SERVER_STATUS_AUTOCOMMIT) == 0, "ROLLBACK preserves autocommit=0");
        ok((conn->server_status & SERVER_STATUS_IN_TRANS) == 0, "ROLLBACK clears IN_TRANS");
        {
            std::string q = "SELECT COUNT(*) FROM " + table + " WHERE id=300";
            if (mysql_query(conn.get(), q.c_str()) != 0) BAIL_OUT("count tx row failed: %s", mysql_error(conn.get()));
            MYSQL_RES* raw = mysql_store_result(conn.get());
            if (raw == nullptr) BAIL_OUT("count tx result missing");
            ResPtr r(raw);
            MYSQL_ROW row = mysql_fetch_row(r.get());
            ok(row && row[0] && std::strtol(row[0], nullptr, 10) == 0, "rolled-back insertion disappears");
        }

        mysql_stmt_close(txsel.release());
        mysql_stmt_close(txins.release());

        exec_sql("SET autocommit=1");
        ok((conn->server_status & SERVER_STATUS_AUTOCOMMIT) != 0, "autocommit restored to 1");
    }

    exec_sql("DROP TABLE IF EXISTS " + table);

    return exit_status();
}
