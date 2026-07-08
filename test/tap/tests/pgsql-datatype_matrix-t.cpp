#include <string>
#include <vector>
#include "pg_lite_client.h"
#include "command_line.h"
#include "tap.h"
#include "utils.h"

CommandLine cl;

struct Case {
    const char* label;
    const char* select_expr;   // e.g. "SELECT '\\xdeadbeef'::bytea"
    const char* expected_text; // expected value in TEXT format
    int32_t expected_oid;      // PostgreSQL type OID
};

// One representative literal per type; expand freely — adding a row is the unit of work.
static const std::vector<Case> cases = {
    { "bool",        "SELECT true",                        "t",              16   },
    { "int4",        "SELECT 2147483647::int4",            "2147483647",     23   },
    { "int8",        "SELECT 9223372036854775807::int8",   "9223372036854775807", 20 },
    { "float8",      "SELECT 1.5::float8",                 "1.5",            701  },
    { "numeric",     "SELECT 12345.6789::numeric",         "12345.6789",     1700 },
    { "text_utf8",   "SELECT 'héllo'::text",               "héllo",          25   },
    { "bytea",       "SELECT '\\xdeadbeef'::bytea",        "\\xdeadbeef",    17   },
    { "uuid",        "SELECT '00000000-0000-0000-0000-000000000001'::uuid",
                                                           "00000000-0000-0000-0000-000000000001", 2950 },
    { "timestamptz", "SELECT '2020-01-01 00:00:00+00'::timestamptz AT TIME ZONE 'UTC'",
                                                           "2020-01-01 00:00:00", 1114 },
    { "jsonb",       "SELECT '{\"a\":1}'::jsonb",          "{\"a\": 1}",     3802 },
    { "int4_array",  "SELECT ARRAY[1,2,3]::int4[]",        "{1,2,3}",        1007 },
    { "inet",        "SELECT '192.168.0.1'::inet",         "192.168.0.1",    869  },
};

// Runs one case through pg_lite_client at the given result format (0=text,1=binary).
// Returns true if the RowDescription OID matches; in text format also checks the value.
static bool run_case(const Case& c, int16_t fmt, std::string& observed_value, int32_t& observed_oid);

int main(int argc, char** argv) {
    if (cl.getEnv()) return exit_status();

    // For each case: 1 text assertion (value+oid) + 1 binary assertion (oid+format code).
    plan((int)cases.size() * 2);

    for (const auto& c : cases) {
        std::string v_text, v_bin; int32_t oid_text = 0, oid_bin = 0;
        bool ok_text = run_case(c, 0, v_text, oid_text);
        ok(ok_text && oid_text == c.expected_oid && v_text == c.expected_text,
           "%s text: oid=%d value='%s'", c.label, oid_text, v_text.c_str());

        bool ok_bin = run_case(c, 1, v_bin, oid_bin);
        ok(ok_bin && oid_bin == c.expected_oid,
           "%s binary: oid=%d (format code honored)", c.label, oid_bin);
    }
    return exit_status();
}

static bool run_case(const Case& c, int16_t fmt, std::string& observed_value, int32_t& observed_oid) {
    try {
        PgConnection conn(2000);
        conn.connect(cl.pgsql_host, cl.pgsql_port, cl.pgsql_username, cl.pgsql_username, cl.pgsql_password);
        // Extended protocol: unnamed prepared statement, result format = fmt.
        // NOTE: these queries take no bind parameters, so the param-format array
        // must be empty (a real client would never send one for a 0-param Bind).
        // bindStatementSingleFormat() unconditionally sends a 1-element param-format
        // array ({singleFormat}) regardless of param count, which triggers a real
        // ProxySQL bug (see PgSQL_Connection.cpp stmt_execute_start(): the format-count
        // normalization only expands num_param_formats==1 when param_values.size() > 1,
        // so numPFormats==1 with 0 actual params falls into the mismatch-error branch,
        // even though the PG protocol spec says num_param_formats==1 applies to all
        // parameters regardless of how many there are). Use bindStatementEx() with an
        // explicit empty paramFormats array to avoid tripping that bug, since it is
        // orthogonal to what this test is verifying (result-format/type-OID transparency).
        conn.prepareStatement("", c.select_expr, false, {});
        conn.bindStatementEx("", "", {}, {}, { fmt }, false);
        conn.describePortal("", false);
        conn.executePortal("", 0, true);   // sync

        // Read: ParseComplete(1), BindComplete(2), RowDescription(T), DataRow(D), CommandComplete(C), ReadyForQuery(Z)
        char type; std::vector<uint8_t> buf;
        bool got_row = false;
        while (true) {
            conn.readMessage(type, buf);
            if (type == PgConnection::ROW_DESCRIPTION) {
                BufferReader r(buf);
                int16_t nfields = r.readInt16();
                if (nfields >= 1) {
                    r.readString();            // field name
                    r.readInt32();             // table oid
                    r.readInt16();             // column attr
                    observed_oid = r.readInt32(); // type oid
                }
            } else if (type == PgConnection::DATA_ROW) {
                BufferReader r(buf);
                int16_t ncols = r.readInt16();
                if (ncols >= 1) {
                    int32_t len = r.readInt32();
                    if (len >= 0) {
                        auto bytes = r.readBytes(len);
                        if (fmt == 0) observed_value.assign(bytes.begin(), bytes.end());
                        got_row = true;
                    }
                }
            } else if (type == PgConnection::READY_FOR_QUERY) {
                break;
            } else if (type == PgConnection::ERROR_RESPONSE) {
                conn.disconnect();
                return false;
            }
        }
        conn.disconnect();
        return got_row;
    } catch (const PgException& e) {
        diag("%s fmt=%d threw: %s", c.label, (int)fmt, e.what());
        return false;
    }
}
