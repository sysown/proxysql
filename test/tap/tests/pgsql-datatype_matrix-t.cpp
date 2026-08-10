#include <string>
#include <vector>
#include <cstdint>
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
    const char* expected_binary_hex; // expected wire bytes in BINARY format
};

// One representative literal per type; expand freely — adding a row is the unit of work.
//
// expected_binary_hex is the exact payload PostgreSQL's *_send() function emits for
// the literal in the same row. Asserting it (rather than merely asserting that *some*
// non-null payload came back) is what makes the binary half of this test meaningful:
// a silent text fallback, a truncated payload, or a byte-order regression anywhere in
// ProxySQL's PG result path all produce different bytes and are therefore caught.
// Encodings are per src/backend/utils/adt in PostgreSQL and are stable across versions:
//   numeric     -> int16 ndigits, int16 weight, uint16 sign, uint16 dscale, base-10000 digits
//   timestamptz -> int64 microseconds since 2000-01-01 00:00:00 UTC
//   jsonb       -> 1-byte format version (0x01) followed by the jsonb text rendering
//   int4[]      -> int32 ndim, int32 hasnull, int32 elemtype, then (dim, lbound), then len+value per element
//   inet        -> family (2 = AF_INET), netmask bits, is_cidr, address length, address bytes
static const std::vector<Case> cases = {
    { "bool",        "SELECT true",                        "t",              16,
      "01" },
    { "int4",        "SELECT 2147483647::int4",            "2147483647",     23,
      "7fffffff" },
    { "int8",        "SELECT 9223372036854775807::int8",   "9223372036854775807", 20,
      "7fffffffffffffff" },
    { "float8",      "SELECT 1.5::float8",                 "1.5",            701,
      "3ff8000000000000" },
    { "numeric",     "SELECT 12345.6789::numeric",         "12345.6789",     1700,
      "0003000100000004000109291a85" },
    { "text_utf8",   "SELECT 'héllo'::text",               "héllo",          25,
      "68c3a96c6c6f" },
    { "bytea",       "SELECT '\\xdeadbeef'::bytea",        "\\xdeadbeef",    17,
      "deadbeef" },
    { "uuid",        "SELECT '00000000-0000-0000-0000-000000000001'::uuid",
                                                           "00000000-0000-0000-0000-000000000001", 2950,
      "00000000000000000000000000000001" },
    // A genuine timestamptz (OID 1184). The earlier form applied AT TIME ZONE 'UTC',
    // which yields timestamp *without* time zone (OID 1114) and so never exercised
    // timestamptz at all. Text rendering of timestamptz depends on the session
    // TimeZone GUC, which is why every case forces UTC before running (see run_case).
    { "timestamptz", "SELECT '2020-01-01 00:00:00+00'::timestamptz",
                                                           "2020-01-01 00:00:00+00", 1184,
      "00023e0786c26000" },
    { "jsonb",       "SELECT '{\"a\":1}'::jsonb",          "{\"a\": 1}",     3802,
      "017b2261223a20317d" },
    { "int4_array",  "SELECT ARRAY[1,2,3]::int4[]",        "{1,2,3}",        1007,
      "0000000100000000000000170000000300000001000000040000000100000004000000020000000400000003" },
    { "inet",        "SELECT '192.168.0.1'::inet",         "192.168.0.1",    869,
      "02200004c0a80001" },
};

// Lowercase hex rendering of a raw payload, for both comparison and diagnostics.
static std::string to_hex(const std::vector<uint8_t>& bytes) {
    static const char* digits = "0123456789abcdef";
    std::string out;
    out.reserve(bytes.size() * 2);
    for (uint8_t b : bytes) {
        out.push_back(digits[b >> 4]);
        out.push_back(digits[b & 0x0f]);
    }
    return out;
}

// Everything observed for one round-trip of a case at a given result format.
struct Observed {
    bool got_result = false;      // a RowDescription+DataRow was returned (no ErrorResponse)
    int32_t oid = 0;              // type OID from RowDescription
    int16_t col_format = -1;      // per-column result FORMAT CODE from RowDescription:
                                  // this is what ProxySQL actually applied (0=text,1=binary),
                                  // and is the load-bearing check for binary transparency.
    bool is_null = true;          // DataRow value length == -1 ?
    std::string text_value;       // value decoded as text (meaningful when col_format==0)
    std::vector<uint8_t> raw_bytes; // raw DataRow payload for column 0 (both formats)
};

// Runs one case through ProxySQL's PG frontend via pg_lite_client's extended-query
// protocol, requesting the given single result format (0=text, 1=binary) for column 0.
//
// We parse RowDescription(T)/DataRow(D) directly rather than calling readResult():
// readResult() DISCARDS the type OID (pg_lite_client.cpp reads and drops it) and
// PgResult exposes no OID accessor, but this test must assert the OID. So we read the
// full RowDescription field layout ourselves — the SAME layout readResult() uses,
// including the trailing per-column format code that readResult() stores into
// columnFormat() — and additionally keep the OID. The format-code field is the whole
// point of the binary assertions: it proves ProxySQL honored the requested format
// rather than silently downgrading binary to text.
static bool run_case(const Case& c, int16_t fmt, Observed& obs);

int main(int argc, char** argv) {
    if (cl.getEnv()) return exit_status();

    // For each case: 1 text assertion + 1 binary assertion.
    plan((int)cases.size() * 2);

    for (const auto& c : cases) {
        // TEXT: format code must be 0, OID must match, value (as text) must match.
        Observed t;
        bool ran_t = run_case(c, 0, t);
        ok(ran_t && t.got_result && t.col_format == 0 && t.oid == c.expected_oid
               && !t.is_null && t.text_value == c.expected_text,
           "%s text: fmt=%d oid=%d value='%s'",
           c.label, (int)t.col_format, t.oid, t.text_value.c_str());

        // BINARY: format code must be 1 (ProxySQL actually honored binary), OID must
        // match, and the payload must be byte-for-byte what PostgreSQL's binary output
        // function produces. Checking the exact bytes — not just "a non-null value came
        // back" — is what rules out a silent text fallback or a corrupted payload.
        Observed b;
        bool ran_b = run_case(c, 1, b);
        const std::string got_hex = to_hex(b.raw_bytes);
        bool binary_ok = ran_b && b.got_result && b.col_format == 1
                         && b.oid == c.expected_oid && !b.is_null
                         && got_hex == c.expected_binary_hex;
        ok(binary_ok,
           "%s binary: format honored (columnFormat==%d), oid=%d, payload=%s (expected %s)",
           c.label, (int)b.col_format, b.oid, got_hex.c_str(), c.expected_binary_hex);
    }
    return exit_status();
}

static bool run_case(const Case& c, int16_t fmt, Observed& obs) {
    try {
        PgConnection conn(2000);
        conn.connect(cl.pgsql_host, cl.pgsql_port, cl.pgsql_username, cl.pgsql_username, cl.pgsql_password);

        // Pin the session time zone so the text rendering of timestamptz is
        // deterministic regardless of the backend's configured TimeZone. Harmless for
        // every other case, so it runs unconditionally rather than per-case.
        conn.execute("SET TIME ZONE 'UTC'");
        conn.consumeInputUntilReady();

        // Extended protocol: unnamed prepared statement, single result format = fmt.
        // NOTE: these queries take no bind parameters, so the param-format array must be
        // empty. bindStatementSingleFormat() would unconditionally send a 1-element
        // param-format array even for a 0-param Bind, which trips a real ProxySQL bug
        // (issue #5899: PgSQL_Connection.cpp stmt_execute_start() rejects num_param_formats==1
        // with num_params==0, though the PG protocol spec allows it). bindStatementEx() with
        // an explicit empty paramFormats array is the protocol-correct 0-param bind and
        // is orthogonal to the result-format/OID transparency under test here.
        conn.prepareStatement("", c.select_expr, false, {});
        conn.bindStatementEx("", "", {}, {}, { fmt }, false);
        conn.describePortal("", false);
        conn.executePortal("", 0, true);   // sync

        // Read: ParseComplete(1), BindComplete(2), RowDescription(T), DataRow(D),
        //       CommandComplete(C), ReadyForQuery(Z)
        char type; std::vector<uint8_t> buf;
        while (true) {
            conn.readMessage(type, buf);
            if (type == PgConnection::ROW_DESCRIPTION) {
                BufferReader r(buf);
                int16_t nfields = r.readInt16();
                if (nfields >= 1) {
                    r.readString();               // field name
                    r.readInt32();                // table oid
                    r.readInt16();                // column attr num
                    obs.oid = r.readInt32();      // type oid
                    r.readInt16();                // type size
                    r.readInt32();                // type modifier
                    obs.col_format = r.readInt16(); // per-column result FORMAT CODE
                }
            } else if (type == PgConnection::DATA_ROW) {
                BufferReader r(buf);
                int16_t ncols = r.readInt16();
                if (ncols >= 1) {
                    int32_t len = r.readInt32();
                    if (len >= 0) {
                        obs.raw_bytes = r.readBytes(len);
                        obs.is_null = false;
                        // Decode to text for the text-format value assertion. In binary
                        // format the payload is opaque bytes and text_value is unused.
                        obs.text_value.assign(obs.raw_bytes.begin(), obs.raw_bytes.end());
                        obs.got_result = true;
                    } else {
                        obs.is_null = true;
                        obs.got_result = true;
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
        return obs.got_result;
    } catch (const PgException& e) {
        diag("%s fmt=%d threw: %s", c.label, (int)fmt, e.what());
        return false;
    }
}
