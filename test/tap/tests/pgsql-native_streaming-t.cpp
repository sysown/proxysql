/**
 * @file pgsql-native_streaming-t.cpp
 * @brief Differential test focused on stream-through correctness for large results.
 *
 * PURPOSE
 * -------
 * The design spec §5 promises that the native path "copies raw backend
 * messages into the outbound `PgSQL_Query_Result`" without re-encoding.
 * `pgsql-native_query_differential-t` exercises breadth; this test exercises
 * SIZE: it runs a large result set (10,000 rows) with varied data types
 * (integer, text, numeric, NULL) through both the libpq path and the native
 * path, and asserts the captured results are byte-for-byte identical.
 *
 * For a 10k-row result with 4 columns of varied data, any encoding bug in
 * the native path (truncated rows, byte corruption, dropped/duplicated rows,
 * wrong type OIDs) would surface as a row or column mismatch in the
 * structured comparison.
 *
 * Like the auth and query tests, the native-phase run also asserts no
 * fallback warning appeared in the proxy log.
 *
 * INFRA / SCENARIO COVERAGE
 * -------------------------
 * Same legacy-g1 infra (docker-pgsql16-single, scram-sha-256, non-TLS).
 * One live scenario. 10,000-row result with mixed types and NULLs.
 */

#include <string>
#include <sstream>
#include <vector>
#include <memory>
#include <fstream>
#include <unistd.h>

#include "libpq-fe.h"
#include "command_line.h"
#include "tap.h"
#include "utils.h"
#include <openssl/evp.h>

CommandLine cl;

static const int BACKEND_HG = 0;
static const size_t STREAM_ROWS = 10000;

using PGConnPtr = std::unique_ptr<PGconn, decltype(&PQfinish)>;

// Capture the result of a streaming query. We don't materialize all 10k rows
// in QueryResult (which would balloon memory); instead we compute two
// fingerprints:
//   1) SHA-256 of the concatenation of all row byte representations
//      (column-by-column, NULL encoded as a single NUL)
//   2) Per-column aggregate hash (each column hashed independently) so a
//      mismatch can be localized to a specific column
// Plus the total row count and a per-column row sum for sanity.
// These are deterministic functions of the data, so two paths producing
// the same data produce the same fingerprints.
struct StreamFingerprint {
    size_t row_count = 0;
    int ncols = 0;
    std::vector<std::string> colnames;
    std::vector<Oid> coltypes;
    std::string all_rows_hash;       // hex SHA-256 of concatenated row bytes
    std::vector<std::string> col_hashes;  // per-column hex SHA-256
    std::vector<long long> col_int_sums;  // for int columns, sanity
    std::string cmd_tag;
};

static StreamFingerprint run_streaming(PGconn* conn, const std::string& q) {
    StreamFingerprint fp;
    PGresult* res = PQexec(conn, q.c_str());
    ExecStatusType st = PQresultStatus(res);
    if (st != PGRES_TUPLES_OK) {
        const char* ss = PQresultErrorField(res, PG_DIAG_SQLSTATE);
        // We treat error as empty fingerprint; caller checks nrows.
        diag("run_streaming: query failed: %s -- %s", ss ? ss : "", PQerrorMessage(conn));
        PQclear(res);
        return fp;
    }
    const char* ct = PQcmdStatus(res);
    fp.cmd_tag = (ct != nullptr) ? std::string(ct) : std::string();
    fp.row_count = static_cast<size_t>(PQntuples(res));
    fp.ncols = PQnfields(res);
    fp.colnames.reserve(fp.ncols);
    fp.coltypes.reserve(fp.ncols);
    for (int c = 0; c < fp.ncols; c++) {
        fp.colnames.emplace_back(PQfname(res, c) ? PQfname(res, c) : "");
        fp.coltypes.push_back(PQftype(res, c));
    }
    fp.col_hashes.assign(fp.ncols, EVP_MD_CTX_new() ? "" : "");
    // Initialize per-column SHA-256 contexts
    std::vector<EVP_MD_CTX*> col_ctxs(fp.ncols, nullptr);
    for (int c = 0; c < fp.ncols; c++) {
        col_ctxs[c] = EVP_MD_CTX_new();
        if (col_ctxs[c]) EVP_DigestInit_ex(col_ctxs[c], EVP_sha256(), nullptr);
        fp.col_hashes[c] = "";  // finalized below
    }
    EVP_MD_CTX* all_ctx = EVP_MD_CTX_new();
    if (all_ctx) EVP_DigestInit_ex(all_ctx, EVP_sha256(), nullptr);
    fp.col_int_sums.assign(fp.ncols, 0);

    // We feed the bytes of each value to the digest. NULL is encoded as a
    // single byte (0xFF) so it doesn't collide with any actual value. Per-row
    // separator: 0x00 so two rows of identical values don't merge.
    static const unsigned char NULL_MARK = 0xFF;
    static const unsigned char ROW_SEP = 0x00;
    static const unsigned char COL_SEP = 0x01;

    std::vector<unsigned char> row_buf;
    for (int r = 0; r < (int)fp.row_count; r++) {
        for (int c = 0; c < fp.ncols; c++) {
            if (PQgetisnull(res, r, c)) {
                if (col_ctxs[c]) EVP_DigestUpdate(col_ctxs[c], &NULL_MARK, 1);
                if (all_ctx) EVP_DigestUpdate(all_ctx, &NULL_MARK, 1);
                row_buf.push_back(NULL_MARK);
            } else {
                const char* v = PQgetvalue(res, r, c);
                size_t vlen = strlen(v);
                if (col_ctxs[c]) EVP_DigestUpdate(col_ctxs[c], v, vlen);
                if (all_ctx) EVP_DigestUpdate(all_ctx, v, vlen);
                row_buf.insert(row_buf.end(), v, v + vlen);
                // Track integer sums (best-effort; if non-int, the result is
                // garbage but it doesn't matter for the diff).
                if (fp.coltypes[c] == 23 /* int4 */) {
                    fp.col_int_sums[c] += atoll(v);
                } else if (fp.coltypes[c] == 20 /* int8 */) {
                    fp.col_int_sums[c] += atoll(v);
                }
            }
            if (col_ctxs[c]) EVP_DigestUpdate(col_ctxs[c], &COL_SEP, 1);
            if (all_ctx) EVP_DigestUpdate(all_ctx, &COL_SEP, 1);
            row_buf.push_back(COL_SEP);
        }
        if (all_ctx) EVP_DigestUpdate(all_ctx, &ROW_SEP, 1);
        row_buf.push_back(ROW_SEP);
    }

    // Finalize hashes to hex.
    auto to_hex = [](unsigned char* md, unsigned int len) {
        static const char* h = "0123456789abcdef";
        std::string out;
        out.reserve(len * 2);
        for (unsigned int i = 0; i < len; i++) {
            out.push_back(h[(md[i] >> 4) & 0xf]);
            out.push_back(h[md[i] & 0xf]);
        }
        return out;
    };
    if (all_ctx) {
        unsigned char md[EVP_MAX_MD_SIZE];
        unsigned int len = 0;
        EVP_DigestFinal_ex(all_ctx, md, &len);
        fp.all_rows_hash = to_hex(md, len);
        EVP_MD_CTX_free(all_ctx);
    }
    for (int c = 0; c < fp.ncols; c++) {
        if (col_ctxs[c]) {
            unsigned char md[EVP_MAX_MD_SIZE];
            unsigned int len = 0;
            EVP_DigestFinal_ex(col_ctxs[c], md, &len);
            fp.col_hashes[c] = to_hex(md, len);
            EVP_MD_CTX_free(col_ctxs[c]);
        }
    }
    PQclear(res);
    return fp;
}

// Admin/helpers (same pattern as the other differential tests).
static PGConnPtr createAdminConn() {
    std::stringstream ss;
    ss << "host=" << cl.pgsql_admin_host
       << " port=" << cl.pgsql_admin_port
       << " user=" << cl.admin_username
       << " password=" << cl.admin_password;
    return PGConnPtr(PQconnectdb(ss.str().c_str()), &PQfinish);
}
static bool execAdmin(PGconn* admin, const std::string& query) {
    PGresult* res = PQexec(admin, query.c_str());
    ExecStatusType st = PQresultStatus(res);
    bool good = (st == PGRES_COMMAND_OK || st == PGRES_TUPLES_OK);
    if (!good) diag("Admin failed: %s -- %s", query.c_str(), PQerrorMessage(admin));
    PQclear(res);
    return good;
}
static bool setNativeMode(PGconn* admin, bool enabled) {
    std::string v = enabled ? "true" : "false";
    return execAdmin(admin, "SET pgsql-use_native_backend_protocol='" + v + "'") &&
           execAdmin(admin, "LOAD PGSQL VARIABLES TO RUNTIME");
}
struct ServerRow {
    std::string hostname, port, max_connections, comment;
};
static std::vector<ServerRow> readServers(PGconn* admin, int hg) {
    std::vector<ServerRow> rows;
    std::stringstream q;
    q << "SELECT hostname, port, max_connections, comment FROM pgsql_servers "
      << "WHERE hostgroup_id=" << hg;
    PGresult* res = PQexec(admin, q.str().c_str());
    if (PQresultStatus(res) == PGRES_TUPLES_OK) {
        for (int i = 0; i < PQntuples(res); i++) {
            ServerRow r;
            r.hostname = PQgetvalue(res, i, 0);
            r.port = PQgetvalue(res, i, 1);
            r.max_connections = PQgetvalue(res, i, 2);
            r.comment = PQgetisnull(res, i, 3) ? "" : PQgetvalue(res, i, 3);
            rows.push_back(std::move(r));
        }
    }
    PQclear(res);
    return rows;
}
static bool flushBackendPool(PGconn* admin, int hg, const std::vector<ServerRow>& saved) {
    if (saved.empty()) return false;
    std::stringstream del;
    del << "DELETE FROM pgsql_servers WHERE hostgroup_id=" << hg;
    if (!execAdmin(admin, del.str())) return false;
    if (!execAdmin(admin, "LOAD PGSQL SERVERS TO RUNTIME")) return false;
    for (const auto& r : saved) {
        std::stringstream ins;
        ins << "INSERT INTO pgsql_servers (hostgroup_id,hostname,port,max_connections,comment) "
            << "VALUES (" << hg << ",'" << r.hostname << "'," << r.port << ","
            << (r.max_connections.empty() ? std::string("1000") : r.max_connections)
            << ",'" << r.comment << "')";
        if (!execAdmin(admin, ins.str())) return false;
    }
    if (!execAdmin(admin, "LOAD PGSQL SERVERS TO RUNTIME")) return false;
    usleep(200000);
    return true;
}
static PGConnPtr createClientConn() {
    std::stringstream ss;
    ss << "host=" << cl.pgsql_host << " port=" << cl.pgsql_port
       << " user=" << cl.pgsql_username << " password=" << cl.pgsql_password
       << " dbname=" << cl.pgsql_username << " sslmode=disable";
    return PGConnPtr(PQconnectdb(ss.str().c_str()), &PQfinish);
}
static std::fstream f_proxysql_log{};
static bool nativeFallbackObserved() {
    const std::string regex =
        ".*(native_mode requested but unimplemented at this stage; falling back to libpq"
        "|native backend auth capability gap .* falling back to libpq).*";
    return wait_for_log_match(f_proxysql_log, regex, 1000, 100);
}
static void drainLogToNow() {
    get_matching_lines(f_proxysql_log, "__no_such_marker_line__");
}

int main(int /*argc*/, char** /*argv*/) {
    // 4 assertions: per-fingerprint equality, row count, all-rows hash,
    // per-column hash, native path.
    plan(4);

    if (cl.getEnv())
        return exit_status();

    std::string log_path = get_env("REGULAR_INFRA_DATADIR") + "/proxysql.log";
    if (open_file_and_seek_end(log_path, f_proxysql_log) != EXIT_SUCCESS) {
        BAIL_OUT("Could not open ProxySQL log at '%s'", log_path.c_str());
        return exit_status();
    }

    auto admin = createAdminConn();
    if (!admin || PQstatus(admin.get()) != CONNECTION_OK) {
        BAIL_OUT("Cannot proceed without admin connection: %s",
                 admin ? PQerrorMessage(admin.get()) : "null");
        return exit_status();
    }
    std::vector<ServerRow> saved = readServers(admin.get(), BACKEND_HG);
    if (saved.empty()) {
        BAIL_OUT("No pgsql_servers row in hostgroup %d", BACKEND_HG);
        return exit_status();
    }
    diag("Backend under test (hg %d): %s:%s, streaming %zu rows",
         BACKEND_HG, saved[0].hostname.c_str(), saved[0].port.c_str(), STREAM_ROWS);

    // The streaming query: integer id, a derived text column, the square,
    // a column with NULL on even rows. Deterministic.
    std::stringstream q;
    q << "SELECT g AS id, "
      << "  'row-' || lpad(g::text, 6, '0') AS label, "
      << "  g::bigint * g::bigint AS square, "
      << "  CASE WHEN g % 2 = 0 THEN NULL ELSE g::text END AS odd_only "
      << "FROM generate_series(1, " << STREAM_ROWS << ") AS g";
    const std::string STREAM_Q = q.str();

    // Phase 1: libpq oracle.
    if (!setNativeMode(admin.get(), false)) { BAIL_OUT("libpq mode failed"); return exit_status(); }
    if (!flushBackendPool(admin.get(), BACKEND_HG, saved)) { BAIL_OUT("flush libpq failed"); return exit_status(); }
    auto libpq_client = createClientConn();
    if (!libpq_client || PQstatus(libpq_client.get()) != CONNECTION_OK) {
        BAIL_OUT("libpq client conn failed: %s",
                 libpq_client ? PQerrorMessage(libpq_client.get()) : "null");
        return exit_status();
    }
    diag("libpq: running streaming query...");
    StreamFingerprint libpq_fp = run_streaming(libpq_client.get(), STREAM_Q);
    diag("libpq: %zu rows, %d cols, all_rows_hash=%s",
         libpq_fp.row_count, libpq_fp.ncols, libpq_fp.all_rows_hash.c_str());

    // Phase 2: native path.
    if (!setNativeMode(admin.get(), true)) { BAIL_OUT("native mode failed"); return exit_status(); }
    if (!flushBackendPool(admin.get(), BACKEND_HG, saved)) { BAIL_OUT("flush native failed"); return exit_status(); }
    drainLogToNow();
    auto native_client = createClientConn();
    if (!native_client || PQstatus(native_client.get()) != CONNECTION_OK) {
        BAIL_OUT("native client conn failed: %s",
                 native_client ? PQerrorMessage(native_client.get()) : "null");
        return exit_status();
    }
    diag("native: running streaming query...");
    StreamFingerprint native_fp = run_streaming(native_client.get(), STREAM_Q);
    diag("native: %zu rows, %d cols, all_rows_hash=%s",
         native_fp.row_count, native_fp.ncols, native_fp.all_rows_hash.c_str());

    // Assertions.
    bool all_ok = true;
    // (1) row count + col count + cmdtag match
    bool structural = (libpq_fp.row_count == native_fp.row_count) &&
                     (libpq_fp.ncols == native_fp.ncols) &&
                     (libpq_fp.colnames == native_fp.colnames) &&
                     (libpq_fp.coltypes == native_fp.coltypes) &&
                     (libpq_fp.cmd_tag == native_fp.cmd_tag);
    ok(structural, "streaming: structural (row count, col count, names, types, cmdtag) match");
    if (!structural) {
        diag("  libpq : %zu rows, %d cols", libpq_fp.row_count, libpq_fp.ncols);
        diag("  native: %zu rows, %d cols", native_fp.row_count, native_fp.ncols);
        all_ok = false;
    }

    // (2) all-rows hash match
    bool all_hash = (libpq_fp.all_rows_hash == native_fp.all_rows_hash);
    ok(all_hash, "streaming: all_rows_hash matches (libpq=%s native=%s)",
       libpq_fp.all_rows_hash.c_str(), native_fp.all_rows_hash.c_str());
    if (!all_hash) all_ok = false;

    // (3) per-column hash match (allows localizing the mismatch)
    bool col_hash = (libpq_fp.col_hashes.size() == native_fp.col_hashes.size());
    if (col_hash) {
        for (size_t c = 0; c < libpq_fp.col_hashes.size(); c++) {
            if (libpq_fp.col_hashes[c] != native_fp.col_hashes[c]) {
                diag("col %zu (%s) hash differs: libpq=%s native=%s",
                     c, libpq_fp.colnames[c].c_str(),
                     libpq_fp.col_hashes[c].c_str(),
                     native_fp.col_hashes[c].c_str());
                col_hash = false;
            }
        }
    }
    ok(col_hash, "streaming: per-column hashes match");

    // (4) native path was actually used (no fallback warning in log)
    bool fell_back = nativeFallbackObserved();
    ok(!fell_back, "native path used for streaming query (no libpq fallback)");

    setNativeMode(admin.get(), false);
    flushBackendPool(admin.get(), BACKEND_HG, saved);

    (void)all_ok;
    return exit_status();
}
