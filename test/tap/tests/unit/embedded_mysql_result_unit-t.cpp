// Focused TAP tests for the internal MySQL binary-result codec. This is not a
// protocol endpoint, session, or public ABI test.
#include "Embedded_MySQL_Result.h"
#include "tap.h"

#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <limits>
#include <string>
#include <type_traits>
#include <utility>
#include <vector>

using namespace embedded;

namespace {

using Wire = std::vector<unsigned char>;

constexpr size_t kDefaultBudget = 64u * 1024u * 1024u;

Column column(const char* name, TypeKind kind, bool nullable = true,
              int32_t precision = 0, int32_t scale = 0) {
    return Column{name, Type{kind, precision, scale, nullable}};
}

std::vector<MySQLColumn> descriptor(TypeKind kind, bool nullable = true,
                                    int32_t precision = 0,
                                    int32_t scale = 0) {
    std::vector<Column> columns{column("c", kind, nullable, precision, scale)};
    std::vector<MySQLColumn> described;
    Status status = mysql_describe_columns(columns, described);
    if (status) {
        diag("descriptor setup failed kind=%d: %s",
             static_cast<int>(kind), status->message.c_str());
    }
    return described;
}

std::string hex_of(const Wire& bytes) {
    static const char digits[] = "0123456789abcdef";
    std::string result;
    const size_t shown = bytes.size() < 96 ? bytes.size() : 96;
    for (size_t i = 0; i < shown; ++i) {
        if (i != 0) result.push_back(' ');
        result.push_back(digits[bytes[i] >> 4]);
        result.push_back(digits[bytes[i] & 0x0f]);
    }
    if (shown != bytes.size()) result += " ...";
    return result;
}

bool same_bytes(const Wire& actual, const Wire& expected) {
    if (actual == expected) return true;
    diag("actual:   %s", hex_of(actual).c_str());
    diag("expected: %s", hex_of(expected).c_str());
    return false;
}

void expect_describe_error(const std::vector<Column>& columns, ErrorKind kind,
                           const char* label) {
    std::vector<MySQLColumn> out(1);
    Status status = mysql_describe_columns(columns, out);
    if (!status) {
        ok(0, "%s (no error returned)", label);
        return;
    }
    if (status->kind != kind) {
        diag("kind=%d message=%s", static_cast<int>(status->kind),
             status->message.c_str());
    }
    ok(status->kind == kind && out.empty(), "%s", label);
}

void expect_encode_error(const std::vector<MySQLColumn>& columns,
                         const Row& row, ErrorKind kind, const char* label,
                         size_t max_payload = kDefaultBudget) {
    Wire payload{0xaa, 0xbb};
    Status status = mysql_encode_binary_row(columns, row, payload, max_payload);
    if (!status) {
        ok(0, "%s (no error returned)", label);
        return;
    }
    if (status->kind != kind) {
        diag("kind=%d message=%s", static_cast<int>(status->kind),
             status->message.c_str());
    }
    ok(status->kind == kind && payload.empty(), "%s", label);
}

void metadata_mapping() {
    std::vector<Column> columns{
        column("dyn", TypeKind::dynamic),
        column("signed", TypeKind::signed_integer),
        column("unsigned", TypeKind::unsigned_integer),
        column("float", TypeKind::floating),
        column("text", TypeKind::text),
        column("bytes", TypeKind::bytes),
        column("decimal", TypeKind::decimal, false, 10, 2),
        column("decimal_int", TypeKind::decimal, true, 5, 0),
        column("decimal_all_scale", TypeKind::decimal, true, 5, 5),
    };
    std::vector<MySQLColumn> out;
    Status status = mysql_describe_columns(columns, out);
    if (status) diag("describe failed: %s", status->message.c_str());
    ok(!status && out.size() == columns.size(), "describe maps every column");

    if (out.size() != columns.size()) return;

    ok(out[0].kind == TypeKind::dynamic &&
           out[0].wire_type == MYSQL_TYPE_VAR_STRING &&
           out[0].charset == 63 && out[0].length == 0 &&
           out[0].decimals == 0 && out[0].flags == BINARY_FLAG,
       "dynamic metadata is binary VAR_STRING with charset 63");
    ok(out[1].kind == TypeKind::signed_integer &&
           out[1].wire_type == MYSQL_TYPE_LONGLONG &&
           out[1].charset == 63 && out[1].length == 20 &&
           out[1].decimals == 0 && out[1].flags == 0,
       "signed metadata is LONGLONG 20");
    ok(out[2].kind == TypeKind::unsigned_integer &&
           out[2].wire_type == MYSQL_TYPE_LONGLONG &&
           out[2].charset == 63 && out[2].length == 20 &&
           out[2].flags == UNSIGNED_FLAG,
       "unsigned metadata is LONGLONG 20 with UNSIGNED_FLAG");
    ok(out[3].kind == TypeKind::floating &&
           out[3].wire_type == MYSQL_TYPE_DOUBLE &&
           out[3].charset == 63 && out[3].length == 22 &&
           out[3].decimals == 31 && out[3].flags == 0,
       "floating metadata is DOUBLE 22 decimals 31");
    ok(out[4].kind == TypeKind::text &&
           out[4].wire_type == MYSQL_TYPE_VAR_STRING &&
           out[4].charset == 45 && out[4].length == 0 &&
           out[4].decimals == 0 && out[4].flags == 0,
       "text metadata is VAR_STRING charset 45");
    ok(out[5].kind == TypeKind::bytes &&
           out[5].wire_type == MYSQL_TYPE_BLOB &&
           out[5].charset == 63 && out[5].length == 0 &&
           out[5].flags == BINARY_FLAG,
       "bytes metadata is BLOB with BINARY_FLAG");
    ok(out[6].kind == TypeKind::decimal &&
           out[6].wire_type == MYSQL_TYPE_NEWDECIMAL &&
           out[6].charset == 63 && out[6].length == 12 &&
           out[6].decimals == 2 &&
           out[6].flags == NOT_NULL_FLAG,
       "decimal metadata carries scale, display length, and NOT_NULL_FLAG");
    ok(out[7].length == 6 && out[7].decimals == 0,
       "integer decimal display length omits point and includes sign");
    ok(out[8].length == 7 && out[8].decimals == 5,
       "fraction-only decimal display length includes point and sign");
    ok(out[0].name == "dyn" && out[6].name == "decimal" &&
           out[0].nullable && !out[6].nullable,
       "description preserves names and nullability");
}

void metadata_errors() {
    expect_describe_error(
        {column("unknown", TypeKind::unknown)}, ErrorKind::unsupported,
        "unknown result type is rejected");

    expect_describe_error({column("d", TypeKind::decimal, true, 0, 0)},
                          ErrorKind::invalid_parameter,
                          "decimal precision zero is rejected");
    expect_describe_error({column("d", TypeKind::decimal, true, 66, 0)},
                          ErrorKind::invalid_parameter,
                          "decimal precision above 65 is rejected");
    expect_describe_error({column("d", TypeKind::decimal, true, 5, -1)},
                          ErrorKind::invalid_parameter,
                          "negative decimal scale is rejected");
    expect_describe_error({column("d", TypeKind::decimal, true, 65, 31)},
                          ErrorKind::invalid_parameter,
                          "decimal scale above 30 is rejected");
    expect_describe_error({column("d", TypeKind::decimal, true, 5, 6)},
                          ErrorKind::invalid_parameter,
                          "decimal scale above precision is rejected");

    std::string nul_name("a\0b", 3);
    expect_describe_error({Column{nul_name, Type{TypeKind::text, 0, 0, true}}},
                          ErrorKind::invalid_parameter,
                          "embedded NUL in a column name is rejected");

    std::vector<Column> too_many(65536);
    expect_describe_error(too_many, ErrorKind::invalid_parameter,
                          "more than 65535 result columns is rejected");

    std::vector<Column> empty_name{Column{"", Type{TypeKind::text, 0, 0, true}}};
    std::vector<MySQLColumn> out;
    Status status = mysql_describe_columns(empty_name, out);
    ok(!status && out.size() == 1 && out[0].name.empty(),
       "an empty column name is preserved");
}

void null_bitmap_crosses_bytes() {
    std::vector<Column> columns;
    for (int i = 0; i < 8; ++i) {
        columns.push_back(column(("c" + std::to_string(i)).c_str(),
                                 TypeKind::dynamic));
    }
    std::vector<MySQLColumn> meta;
    Status status = mysql_describe_columns(columns, meta);
    if (status) diag("describe failed: %s", status->message.c_str());
    ok(!status && meta.size() == 8, "eight-column descriptor is available");
    if (status) return;

    Row row{std::monostate{}, int64_t{1}, int64_t{2}, std::monostate{},
            int64_t{4}, std::monostate{}, std::monostate{}, int64_t{7}};
    Wire payload;
    status = mysql_encode_binary_row(meta, row, payload);
    if (status) diag("encode failed: %s", status->message.c_str());

    // Bit positions are column index + 2. NULLs at 0, 3, 5, 6 produce
    // bitmap byte 0 = 0xa4 and byte 1 = 0x01.
    const Wire expected{0x00, 0xa4, 0x01,
                        0x01, '1', 0x01, '2', 0x01, '4', 0x01, '7'};
    ok(!status && same_bytes(payload, expected),
       "NULL bitmap crosses a byte boundary with exact payload bytes");
}

void fixed_width_values() {
    const auto signed_meta = descriptor(TypeKind::signed_integer);
    Wire payload;
    Status status =
        mysql_encode_binary_row(signed_meta, Row{std::numeric_limits<int64_t>::min()},
                                payload);
    if (status) diag("signed encode failed: %s", status->message.c_str());
    const Wire signed_min{0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                          0x00, 0x00, 0x00, 0x80};
    ok(!status && same_bytes(payload, signed_min),
       "signed INT64_MIN is eight little-endian bytes");

    const auto unsigned_meta = descriptor(TypeKind::unsigned_integer);
    status = mysql_encode_binary_row(
        unsigned_meta, Row{std::numeric_limits<uint64_t>::max()}, payload);
    if (status) diag("unsigned encode failed: %s", status->message.c_str());
    const Wire unsigned_max{0x00, 0x00, 0xff, 0xff, 0xff, 0xff,
                            0xff, 0xff, 0xff, 0xff};
    ok(!status && same_bytes(payload, unsigned_max),
       "unsigned UINT64_MAX is eight little-endian bytes");

    const auto float_meta = descriptor(TypeKind::floating);
    status = mysql_encode_binary_row(float_meta, Row{1.5}, payload);
    if (status) diag("floating encode failed: %s", status->message.c_str());
    const Wire double_1_5{0x00, 0x00, 0x00, 0x00, 0x00,
                          0x00, 0x00, 0x00, 0xf8, 0x3f};
    ok(!status && same_bytes(payload, double_1_5),
       "double 1.5 is eight little-endian IEEE-754 bytes");
}

void variable_payloads() {
    std::vector<Column> columns{
        column("t", TypeKind::text),
        column("b", TypeKind::bytes),
    };
    std::vector<MySQLColumn> meta;
    Status status = mysql_describe_columns(columns, meta);
    if (status) diag("describe failed: %s", status->message.c_str());
    if (status) return;

    const std::string embedded_nul("a\0b", 3);
    Row row{Text{embedded_nul}, Bytes{{0x00, 0x00, 0xff, 0x7f}}};
    Wire payload;
    status = mysql_encode_binary_row(meta, row, payload);
    if (status) diag("encode failed: %s", status->message.c_str());
    const Wire expected{0x00, 0x00,
                        0x03, 'a', 0x00, 'b',
                        0x04, 0x00, 0x00, 0xff, 0x7f};
    ok(!status && same_bytes(payload, expected),
       "text and blob preserve embedded NUL and zero bytes exactly");

    status = mysql_encode_binary_row(
        meta, Row{Text{std::string{}}, std::monostate{}}, payload);
    const Wire empty_vs_null{0x00, 0x08, 0x00};
    ok(!status && same_bytes(payload, empty_vs_null),
       "empty text is a zero-length value while NULL adds only a bitmap bit");
}

void aliased_bytes_output() {
    static_assert(std::is_same_v<uint8_t, unsigned char>,
                  "alias regression requires uint8_t and unsigned char to match");

    // The caller's payload can be the very Bytes::bytes vector held by row[0].
    // The codec must read those bytes before it is allowed to replace the
    // output, not clear the output on entry.
    const auto meta = descriptor(TypeKind::bytes);
    Row row{Bytes{{0x00, 0x61, 0xff}}};
    Wire& payload = std::get<Bytes>(row[0]).bytes;

    Status status = mysql_encode_binary_row(meta, row, payload);
    if (status) diag("aliased encode failed: %s", status->message.c_str());
    const Wire expected{0x00, 0x00, 0x03, 0x00, 0x61, 0xff};
    ok(!status && same_bytes(payload, expected),
       "aliased Bytes input is encoded before the output is swapped");

    // Failure cleanup still empties the output, but only after input reads.
    // Three data bytes need header + bitmap + 1-byte prefix + data = 6 bytes.
    Row failing_row{Bytes{{0x10, 0x20, 0x30}}};
    Wire& failing_payload = std::get<Bytes>(failing_row[0]).bytes;
    status = mysql_encode_binary_row(meta, failing_row, failing_payload, 5);
    if (!status) ok(0, "aliased one-byte-short budget is rejected");
    else if (status->kind != ErrorKind::resource)
        diag("kind=%d message=%s", static_cast<int>(status->kind),
             status->message.c_str());
    ok(status && status->kind == ErrorKind::resource &&
           failing_payload.empty(),
       "aliased output is cleared only when encoding fails");
}

void decimal_payload() {
    const auto meta = descriptor(TypeKind::decimal, false, 8, 3);
    Wire payload;
    Status status = mysql_encode_binary_row(meta, Row{Decimal{"12.300"}}, payload);
    if (status) diag("decimal encode failed: %s", status->message.c_str());
    const Wire exact_scale{0x00, 0x00, 0x06, '1', '2', '.', '3', '0', '0'};
    ok(!status && same_bytes(payload, exact_scale),
       "decimal payload preserves the exact scale text");

    status = mysql_encode_binary_row(meta, Row{Decimal{"-0.001"}}, payload);
    const Wire negative{0x00, 0x00, 0x06, '-', '0', '.', '0', '0', '1'};
    ok(!status && same_bytes(payload, negative),
       "negative decimal text is length-encoded without conversion");
}

void dynamic_mixed_row() {
    std::vector<Column> columns;
    for (int i = 0; i < 7; ++i) {
        columns.push_back(column(("d" + std::to_string(i)).c_str(),
                                 TypeKind::dynamic));
    }
    std::vector<MySQLColumn> meta;
    Status status = mysql_describe_columns(columns, meta);
    if (status) diag("describe failed: %s", status->message.c_str());
    if (status) return;

    Row row{
        int64_t{-42},
        std::numeric_limits<uint64_t>::max(),
        1.5,
        Text{"x"},
        Bytes{{0x00, 0xff}},
        Decimal{"12.30"},
        std::monostate{},
    };
    Wire payload;
    status = mysql_encode_binary_row(meta, row, payload);
    if (status) diag("encode failed: %s", status->message.c_str());

    const Wire expected{
        0x00, 0x00, 0x01,
        0x03, '-', '4', '2',
        0x14, '1', '8', '4', '4', '6', '7', '4', '4', '0', '7', '3', '7',
        '0', '9', '5', '5', '1', '6', '1', '5',
        0x03, '1', '.', '5',
        0x01, 'x',
        0x02, 0x00, 0xff,
        0x05, '1', '2', '.', '3', '0',
    };
    ok(!status && same_bytes(payload, expected),
       "dynamic mixed row renders typed values as exact text");
}

void dynamic_double_text_roundtrip() {
    const auto meta = descriptor(TypeKind::dynamic);
    const double cases[] = {
        1.5,
        0.1,
        1.0000000000000002,
        std::numeric_limits<double>::max(),
        std::numeric_limits<double>::min(),
        std::numeric_limits<double>::denorm_min(),
        -0.0,
    };
    for (double value : cases) {
        Wire payload;
        Status status = mysql_encode_binary_row(meta, Row{value}, payload);
        if (status) {
            diag("dynamic double encode failed: %s", status->message.c_str());
            ok(0, "dynamic double text round-trips");
            continue;
        }
        if (payload.size() <= 3 || payload[0] != 0x00 || payload[1] != 0x00 ||
            payload[2] != payload.size() - 3) {
            diag("unexpected payload: %s", hex_of(payload).c_str());
            ok(0, "dynamic double has a short length-encoded text value");
            continue;
        }
        const std::string text(payload.begin() + 3, payload.end());
        char* end = nullptr;
        const double parsed = std::strtod(text.c_str(), &end);
        const bool complete = end == text.c_str() + text.size();
        ok(complete && std::memcmp(&parsed, &value, sizeof value) == 0,
           "dynamic double text round-trips exactly");
    }
}

void length_prefix_thresholds() {
    const auto meta = descriptor(TypeKind::text);
    struct PrefixCase {
        size_t length;
        Wire prefix;
    };
    const PrefixCase cases[] = {
        {250, {0xfa}},
        {251, {0xfc, 0xfb, 0x00}},
        {65535, {0xfc, 0xff, 0xff}},
        {65536, {0xfd, 0x00, 0x00, 0x01}},
    };

    for (const PrefixCase& test : cases) {
        const std::string value(test.length, 'a');
        Wire payload;
        Status status = mysql_encode_binary_row(meta, Row{Text{value}}, payload);
        if (status) diag("encode failed at length %zu: %s", test.length,
                         status->message.c_str());

        Wire expected{0x00, 0x00};
        expected.insert(expected.end(), test.prefix.begin(), test.prefix.end());
        expected.insert(expected.end(), value.begin(), value.end());
        ok(!status && same_bytes(payload, expected),
           "length prefix threshold %zu has exact bytes", test.length);
    }
}

void budgets_and_error_clearing() {
    const auto text_meta = descriptor(TypeKind::text);
    const std::string value(250, 'q');
    const Row row{Text{value}};
    // Header + bitmap + one-byte prefix + 250 data bytes.
    const size_t exact_size = 253;

    Wire payload{0xde, 0xad};
    Status status =
        mysql_encode_binary_row(text_meta, row, payload, exact_size);
    ok(!status && payload.size() == exact_size,
       "payload budget equal to the exact size succeeds");
    ok(payload.size() >= 4 && payload[0] == 0x00 && payload[1] == 0x00 &&
           payload[2] == 0xfa,
       "exact-budget payload has marker, bitmap, and threshold prefix");

    payload.assign({0xde, 0xad});
    status = mysql_encode_binary_row(text_meta, row, payload, exact_size - 1);
    if (!status) ok(0, "one-byte-short budget is rejected");
    else if (status->kind != ErrorKind::resource)
        diag("kind=%d message=%s", static_cast<int>(status->kind),
             status->message.c_str());
    ok(status && status->kind == ErrorKind::resource && payload.empty(),
       "one-byte-short budget fails and clears the output");

    const auto signed_meta = descriptor(TypeKind::signed_integer);
    payload.assign({0xde, 0xad});
    status = mysql_encode_binary_row(signed_meta, Row{int64_t{0}}, payload, 10);
    ok(!status && payload.size() == 10,
       "fixed-value budget equal to the exact size succeeds");
    payload.assign({0xde, 0xad});
    status = mysql_encode_binary_row(signed_meta, Row{int64_t{0}}, payload, 9);
    ok(status && status->kind == ErrorKind::resource && payload.empty(),
       "fixed-value budget one byte short fails and clears the output");
}

void value_and_arity_errors() {
    const auto signed_meta = descriptor(TypeKind::signed_integer);
    const auto unsigned_meta = descriptor(TypeKind::unsigned_integer);
    const auto float_meta = descriptor(TypeKind::floating);
    const auto text_meta = descriptor(TypeKind::text);
    const auto bytes_meta = descriptor(TypeKind::bytes);
    const auto decimal_meta = descriptor(TypeKind::decimal, true, 5, 2);
    const auto not_null_meta =
        descriptor(TypeKind::signed_integer, false);

    expect_encode_error(signed_meta, Row{}, ErrorKind::invalid_parameter,
                        "short row arity is rejected");
    expect_encode_error(signed_meta, Row{int64_t{1}, int64_t{2}},
                        ErrorKind::invalid_parameter,
                        "long row arity is rejected");

    expect_encode_error(signed_meta, Row{uint64_t{1}},
                        ErrorKind::invalid_parameter,
                        "signed descriptor rejects an unsigned value");
    expect_encode_error(unsigned_meta, Row{int64_t{-1}},
                        ErrorKind::invalid_parameter,
                        "unsigned descriptor rejects a signed value");
    expect_encode_error(signed_meta, Row{Text{"1"}},
                        ErrorKind::invalid_parameter,
                        "signed descriptor rejects text without conversion");
    expect_encode_error(float_meta, Row{int64_t{1}},
                        ErrorKind::invalid_parameter,
                        "floating descriptor rejects an integer value");
    expect_encode_error(text_meta, Row{Bytes{{0x31}}},
                        ErrorKind::invalid_parameter,
                        "text descriptor rejects bytes");
    expect_encode_error(bytes_meta, Row{Text{"1"}},
                        ErrorKind::invalid_parameter,
                        "bytes descriptor rejects text");
    expect_encode_error(decimal_meta, Row{Text{"1.00"}},
                        ErrorKind::invalid_parameter,
                        "decimal descriptor rejects text");
    expect_encode_error(not_null_meta, Row{std::monostate{}},
                        ErrorKind::invalid_parameter,
                        "NULL in a NOT NULL column is rejected");

    MySQLColumn unknown{};
    unknown.kind = TypeKind::unknown;
    unknown.nullable = true;
    unknown.name = "u";
    unknown.wire_type = MYSQL_TYPE_VAR_STRING;
    expect_encode_error({unknown}, Row{int64_t{1}}, ErrorKind::unsupported,
                        "unknown descriptor kind is rejected during encoding");
    expect_encode_error({unknown}, Row{std::monostate{}},
                        ErrorKind::unsupported,
                        "unknown descriptor kind is rejected even for NULL");
}

}  // namespace

int main() {
    plan(NO_PLAN);
    { auto c = descriptor(TypeKind::boolean); Wire p;
      ok(c.size() == 1 && c[0].wire_type == MYSQL_TYPE_TINY && c[0].length == 1, "boolean metadata");
      ok(!mysql_encode_binary_row(c, Row{true}, p) && p == Wire({0, 0, 1}), "boolean true binary");
      ok(!mysql_encode_binary_row(c, Row{false}, p) && p == Wire({0, 0, 0}), "boolean false binary");
      ok(!mysql_encode_binary_row(c, Row{std::monostate{}}, p) && p == Wire({0, 4}), "boolean NULL bitmap");
      auto d = descriptor(TypeKind::dynamic);
      ok(!mysql_encode_binary_row(d, Row{true}, p) && p == Wire({0, 0, 1, '1'}), "dynamic boolean text"); }
    metadata_mapping();
    metadata_errors();
    null_bitmap_crosses_bytes();
    fixed_width_values();
    variable_payloads();
    aliased_bytes_output();
    decimal_payload();
    dynamic_mixed_row();
    dynamic_double_text_roundtrip();
    length_prefix_thresholds();
    budgets_and_error_clearing();
    value_and_arity_errors();
    return exit_status();
}
