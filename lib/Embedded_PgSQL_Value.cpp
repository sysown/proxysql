#include "Embedded_PgSQL_Value.h"

#include <cerrno>
#include <charconv>
#include <cmath>
#include <cstdlib>
#include <cstring>
#include <locale.h>
#include <limits>
#include <new>
#include <stdexcept>
#include <string>
#include <system_error>
#include <utility>
#include <vector>

#ifdef __APPLE__
#include <xlocale.h>
#endif

namespace embedded {
namespace {

// The binary wire formats below are reconstructed through their exact bit
// patterns. This is portable only on hosts whose float/double are IEEE-754
// with matching integer/float byte order, which the supported Linux targets
// are. The decoder must not silently guess another representation.
static_assert(sizeof(float) == 4 && sizeof(double) == 8 &&
                  std::numeric_limits<float>::is_iec559 &&
                  std::numeric_limits<double>::is_iec559,
              "binary parameter decoding requires IEEE-754 float/double");

Status fail(ErrorKind kind, const char* sqlstate, std::string message) {
    return Error{kind, 0, std::move(message), std::string(sqlstate)};
}

// `out` is not cleared on entry because the caller-provided input pointer may
// alias its Text/Bytes storage. Only a successful call commits a new local
// Value; every failure path (including exceptions) clears `out` as this guard
// goes out of scope, after all input reads have completed.
class OutputFailureGuard {
  public:
    explicit OutputFailureGuard(Value& out) : out_(out) {}

    ~OutputFailureGuard() noexcept {
        if (!committed_) {
            out_ = std::monostate{};
        }
    }

    void commit() noexcept { committed_ = true; }

    OutputFailureGuard(const OutputFailureGuard&) = delete;
    OutputFailureGuard& operator=(const OutputFailureGuard&) = delete;

  private:
    Value& out_;
    bool committed_ = false;
};

bool supported_oid(uint32_t oid) {
    switch (oid) {
        case pgsql_oid_bool:
        case pgsql_oid_bytea:
        case pgsql_oid_int8:
        case pgsql_oid_int2:
        case pgsql_oid_int4:
        case pgsql_oid_text:
        case pgsql_oid_float4:
        case pgsql_oid_float8:
        case pgsql_oid_bpchar:
        case pgsql_oid_varchar:
        case pgsql_oid_numeric:
            return true;
        default:
            return false;
    }
}

bool is_ascii_space(unsigned char value) {
    return value == ' ' || value == '\t' || value == '\n' || value == '\r' ||
           value == '\v' || value == '\f';
}

bool is_ascii_digit(unsigned char value) {
    return value >= '0' && value <= '9';
}

bool ascii_ieq(const unsigned char* data, size_t length,
               const char* lowercase_literal) {
    const size_t literal_length = std::strlen(lowercase_literal);
    if (length != literal_length) {
        return false;
    }
    for (size_t index = 0; index < length; ++index) {
        unsigned char value = data[index];
        if (value >= 'A' && value <= 'Z') {
            value = static_cast<unsigned char>(value - 'A' + 'a');
        }
        if (value != static_cast<unsigned char>(lowercase_literal[index])) {
            return false;
        }
    }
    return true;
}

bool checked_add(size_t& total, size_t amount) {
    if (amount > std::numeric_limits<size_t>::max() - total) {
        return false;
    }
    total += amount;
    return true;
}

uint64_t read_big_endian(const unsigned char* data, size_t length) {
    uint64_t value = 0;
    for (size_t index = 0; index < length; ++index) {
        value = (value << 8) | static_cast<uint64_t>(data[index]);
    }
    return value;
}

int64_t sign_extend(uint64_t bits, unsigned width) {
    const uint64_t mask =
        width == 64 ? ~uint64_t{0} : ((uint64_t{1} << width) - 1);
    bits &= mask;
    const uint64_t sign_bit = uint64_t{1} << (width - 1);
    if ((bits & sign_bit) == 0) {
        return static_cast<int64_t>(bits);
    }
    return -static_cast<int64_t>((~bits) & mask) - 1;
}

bool valid_utf8(const unsigned char* data, size_t length) {
    size_t index = 0;
    while (index < length) {
        const unsigned char lead = data[index];
        if (lead == 0x00) {
            return false;
        }
        if (lead < 0x80) {
            ++index;
            continue;
        }

        size_t continuation_count = 0;
        uint32_t code_point = 0;
        uint32_t minimum = 0;
        if ((lead & 0xe0) == 0xc0) {
            continuation_count = 1;
            code_point = lead & 0x1f;
            minimum = 0x80;
        } else if ((lead & 0xf0) == 0xe0) {
            continuation_count = 2;
            code_point = lead & 0x0f;
            minimum = 0x800;
        } else if ((lead & 0xf8) == 0xf0) {
            continuation_count = 3;
            code_point = lead & 0x07;
            minimum = 0x10000;
        } else {
            // Continuation bytes, C0/C1 overlong leads, F5-FF and FE/FF all
            // fail here.
            return false;
        }

        if (length - index - 1 < continuation_count) {
            return false;
        }
        for (size_t offset = 1; offset <= continuation_count; ++offset) {
            const unsigned char continuation = data[index + offset];
            if ((continuation & 0xc0) != 0x80) {
                return false;
            }
            code_point = (code_point << 6) | (continuation & 0x3f);
        }
        if (code_point < minimum || code_point > 0x10ffff ||
            (code_point >= 0xd800 && code_point <= 0xdfff)) {
            return false;
        }
        index += continuation_count + 1;
    }
    return true;
}

Status decode_text_value(const unsigned char* data, size_t length,
                         Value& local) {
    if (!valid_utf8(data, length)) {
        return fail(ErrorKind::invalid_parameter, "22021",
                    "text parameter is not valid UTF-8");
    }
    local = Text{std::string(reinterpret_cast<const char*>(data), length)};
    return {};
}

Status decode_binary_integer(uint32_t oid, const unsigned char* data,
                             size_t length, Value& local) {
    size_t expected = 0;
    if (oid == pgsql_oid_int2) {
        expected = 2;
    } else if (oid == pgsql_oid_int4) {
        expected = 4;
    } else {
        expected = 8;
    }
    if (length != expected) {
        return fail(ErrorKind::invalid_parameter, "08P01",
                    "binary integer parameter has an invalid width");
    }
    local = sign_extend(read_big_endian(data, length),
                        static_cast<unsigned>(expected * 8));
    return {};
}

Status decode_integer_text(const unsigned char* data, size_t length,
                           int64_t minimum, int64_t maximum, Value& local) {
    size_t begin = 0;
    size_t end = length;
    while (begin < end && is_ascii_space(data[begin])) {
        ++begin;
    }
    while (end > begin && is_ascii_space(data[end - 1])) {
        --end;
    }
    if (begin == end) {
        return fail(ErrorKind::invalid_parameter, "22P02",
                    "invalid integer text for parameter type");
    }

    bool negative = false;
    if (data[begin] == '+' || data[begin] == '-') {
        negative = data[begin] == '-';
        ++begin;
    }
    if (begin == end) {
        return fail(ErrorKind::invalid_parameter, "22P02",
                    "invalid integer text for parameter type");
    }

    uint64_t limit = 0;
    if (negative) {
        limit = minimum == std::numeric_limits<int64_t>::min()
                    ? (uint64_t{1} << 63)
                    : static_cast<uint64_t>(-minimum);
    } else {
        limit = static_cast<uint64_t>(maximum);
    }

    unsigned base = 10;
    if (end - begin >= 2 && data[begin] == '0') {
        switch (data[begin + 1]) {
            case 'x': case 'X': base = 16; break;
            case 'o': case 'O': base = 8; break;
            case 'b': case 'B': base = 2; break;
        }
        if (base != 10) begin += 2;
    }
    auto digit_value = [](unsigned char ch) -> unsigned {
        if (ch >= '0' && ch <= '9') return ch - '0';
        if (ch >= 'a' && ch <= 'f') return ch - 'a' + 10;
        if (ch >= 'A' && ch <= 'F') return ch - 'A' + 10;
        return 255;
    };
    bool have_digit = false;
    bool overflow = false;
    uint64_t magnitude = 0;
    for (size_t index = begin; index < end; ++index) {
        const unsigned char character = data[index];
        if (character == '_') {
            if ((base == 10 && !have_digit) || index + 1 == end ||
                digit_value(data[index + 1]) >= base) {
                return fail(ErrorKind::invalid_parameter, "22P02",
                            "invalid integer text for parameter type");
            }
            continue;
        }
        const unsigned digit = digit_value(character);
        if (digit >= base) {
            return fail(ErrorKind::invalid_parameter, "22P02",
                        "invalid integer text for parameter type");
        }
        have_digit = true;
        if (!overflow && (magnitude > limit / base ||
            (magnitude == limit / base && digit > limit % base))) {
            overflow = true;
        } else if (!overflow) {
            magnitude = magnitude * base + digit;
        }
    }
    if (!have_digit) {
        return fail(ErrorKind::invalid_parameter, "22P02",
                    "invalid integer text for parameter type");
    }
    if (overflow) {
        return fail(ErrorKind::range, "22003",
                    "integer parameter value is out of range");
    }

    int64_t value = 0;
    if (negative) {
        if (magnitude == (uint64_t{1} << 63)) {
            value = std::numeric_limits<int64_t>::min();
        } else {
            value = -static_cast<int64_t>(magnitude);
        }
    } else {
        value = static_cast<int64_t>(magnitude);
    }
    local = value;
    return {};
}

Status decode_binary_float(uint32_t oid, const unsigned char* data,
                           size_t length, Value& local) {
    if (oid == pgsql_oid_float4) {
        if (length != 4) {
            return fail(ErrorKind::invalid_parameter, "08P01",
                        "binary float4 parameter has an invalid width");
        }
        const uint32_t bits = static_cast<uint32_t>(read_big_endian(data, 4));
        float value = 0.0f;
        std::memcpy(&value, &bits, sizeof(value));
        local = static_cast<double>(value);
        return {};
    }

    if (length != 8) {
        return fail(ErrorKind::invalid_parameter, "08P01",
                    "binary float8 parameter has an invalid width");
    }
    const uint64_t bits = read_big_endian(data, 8);
    double value = 0.0;
    std::memcpy(&value, &bits, sizeof(value));
    local = value;
    return {};
}

Status decode_float_text(const unsigned char* data, size_t length,
                         bool single_precision, Value& local) {
    size_t begin = 0;
    size_t end = length;
    while (begin < end && is_ascii_space(data[begin])) {
        ++begin;
    }
    while (end > begin && is_ascii_space(data[end - 1])) {
        --end;
    }
    if (begin == end) {
        return fail(ErrorKind::invalid_parameter, "22P02",
                    "invalid floating-point text for parameter type");
    }

    bool negative = false;
    if (data[begin] == '+' || data[begin] == '-') {
        negative = data[begin] == '-';
        ++begin;
    }
    if (begin == end) {
        return fail(ErrorKind::invalid_parameter, "22P02",
                    "invalid floating-point text for parameter type");
    }

    const size_t token_length = end - begin;
    // Linux libc accepts NaN payloads; this decoder does not preserve them.
    if (token_length >= 5 && data[begin + 3] == '(' &&
        ascii_ieq(data + begin, 3, "nan")) {
        return fail(ErrorKind::unsupported, "0A000",
                    "floating-point NaN payloads are not supported");
    }
    if (ascii_ieq(data + begin, token_length, "nan")) {
        double value = single_precision
                           ? static_cast<double>(
                                 std::numeric_limits<float>::quiet_NaN())
                           : std::numeric_limits<double>::quiet_NaN();
        if (negative) {
            value = -value;
        }
        local = value;
        return {};
    }
    if (ascii_ieq(data + begin, token_length, "inf") ||
        ascii_ieq(data + begin, token_length, "infinity")) {
        double value = 0.0;
        if (single_precision) {
            const float infinity = negative
                                       ? -std::numeric_limits<float>::infinity()
                                       : std::numeric_limits<float>::infinity();
            value = static_cast<double>(infinity);
        } else {
            value = negative ? -std::numeric_limits<double>::infinity()
                             : std::numeric_limits<double>::infinity();
        }
        local = value;
        return {};
    }

    // Linux PostgreSQL accepts hexadecimal input through strtof/strtod.
    const bool hexadecimal = end - begin >= 2 && data[begin] == '0' &&
                             (data[begin + 1] == 'x' || data[begin + 1] == 'X');
    if (hexadecimal) begin += 2;
    auto mantissa_digit = [hexadecimal](unsigned char ch) {
        return is_ascii_digit(ch) || (hexadecimal &&
            ((ch >= 'a' && ch <= 'f') || (ch >= 'A' && ch <= 'F')));
    };
    size_t index = begin;
    bool have_mantissa_digit = false;
    while (index < end && mantissa_digit(data[index])) {
        have_mantissa_digit = true;
        ++index;
    }
    if (index < end && data[index] == '.') {
        ++index;
        while (index < end && mantissa_digit(data[index])) {
            have_mantissa_digit = true;
            ++index;
        }
    }
    if (!have_mantissa_digit) {
        return fail(ErrorKind::invalid_parameter, "22P02",
                    "invalid floating-point text for parameter type");
    }
    if (index < end && (hexadecimal ? (data[index] == 'p' || data[index] == 'P')
                                    : (data[index] == 'e' || data[index] == 'E'))) {
        ++index;
        if (index < end && (data[index] == '+' || data[index] == '-')) ++index;
        const size_t exponent_start = index;
        while (index < end && is_ascii_digit(data[index])) ++index;
        if (index == exponent_start) {
            return fail(ErrorKind::invalid_parameter, "22P02",
                        "invalid floating-point text for parameter type");
        }
    }
    if (index != end) {
        return fail(ErrorKind::invalid_parameter, "22P02",
                    "invalid floating-point text for parameter type");
    }
#if defined(__APPLE__) || defined(EMBEDDED_PGSQL_TEST_C_LOCALE_FLOAT)
    // Apple libc++ does not provide floating-point from_chars on all supported
    // versions. Use a private C locale, leaving the process locale untouched.
    const size_t number_begin = begin - (hexadecimal ? 2 : 0);
    const std::string number(reinterpret_cast<const char*>(data + number_begin),
                             end - number_begin);
    locale_t locale = newlocale(LC_NUMERIC_MASK, "C", nullptr);
    if (!locale) {
        return fail(ErrorKind::resource, "53200",
                    "unable to create numeric locale for parameter conversion");
    }
    char* parsed_end = nullptr;
    errno = 0;
    const double value = single_precision
        ? static_cast<double>(strtof_l(number.c_str(), &parsed_end, locale))
        : strtod_l(number.c_str(), &parsed_end, locale);
    const int parse_errno = errno;
    freelocale(locale);
    if (parse_errno == ERANGE && (value == 0.0 || std::isinf(value))) {
        return fail(ErrorKind::range, "22003",
                    "floating-point parameter value is out of range");
    }
    if (parsed_end != number.c_str() + number.size()) {
        return fail(ErrorKind::invalid_parameter, "22P02",
                    "invalid floating-point text for parameter type");
    }
    local = negative ? -value : value;
    return {};
#else
    const auto format = hexadecimal ? std::chars_format::hex : std::chars_format::general;

    const char* first = reinterpret_cast<const char*>(data + begin);
    const char* last = reinterpret_cast<const char*>(data + end);
    if (single_precision) {
        float value = 0.0f;
        const auto result =
            std::from_chars(first, last, value, format);
        if (result.ec == std::errc::result_out_of_range) {
            return fail(ErrorKind::range, "22003",
                        "floating-point parameter value is out of range");
        }
        if (result.ec != std::errc{} || result.ptr != last) {
            return fail(ErrorKind::invalid_parameter, "22P02",
                        "invalid floating-point text for parameter type");
        }
        double widened = static_cast<double>(value);
        if (negative) {
            widened = -widened;
        }
        local = widened;
        return {};
    }

    double value = 0.0;
    const auto result =
        std::from_chars(first, last, value, format);
    if (result.ec == std::errc::result_out_of_range) {
        return fail(ErrorKind::range, "22003",
                    "floating-point parameter value is out of range");
    }
    if (result.ec != std::errc{} || result.ptr != last) {
        return fail(ErrorKind::invalid_parameter, "22P02",
                    "invalid floating-point text for parameter type");
    }
    if (negative) {
        value = -value;
    }
    local = value;
    return {};
#endif
}

int hex_value(unsigned char value) {
    if (value >= '0' && value <= '9') {
        return static_cast<int>(value - '0');
    }
    if (value >= 'a' && value <= 'f') {
        return static_cast<int>(value - 'a' + 10);
    }
    if (value >= 'A' && value <= 'F') {
        return static_cast<int>(value - 'A' + 10);
    }
    return -1;
}

bool valid_prefixed_integer(const unsigned char* data, size_t begin,
                            size_t end, unsigned base) {
    if (begin >= end) {
        return false;
    }
    bool previous_was_digit = false;
    bool saw_digit = false;
    for (size_t index = begin; index < end; ++index) {
        const unsigned char character = data[index];
        if (character == '_') {
            if (!previous_was_digit || index + 1 >= end) {
                return false;
            }
            const unsigned char next = data[index + 1];
            bool next_is_digit = false;
            if (base == 16) {
                next_is_digit = hex_value(next) >= 0;
            } else if (base == 8) {
                next_is_digit = next >= '0' && next <= '7';
            } else {
                next_is_digit = next == '0' || next == '1';
            }
            if (!next_is_digit) {
                return false;
            }
            previous_was_digit = false;
            continue;
        }
        bool is_digit = false;
        if (base == 16) {
            is_digit = hex_value(character) >= 0;
        } else if (base == 8) {
            is_digit = character >= '0' && character <= '7';
        } else {
            is_digit = character == '0' || character == '1';
        }
        if (!is_digit) {
            return false;
        }
        previous_was_digit = true;
        saw_digit = true;
    }
    return saw_digit && previous_was_digit;
}

bool valid_exponent(const unsigned char* data, size_t exponent_position,
                    size_t end) {
    size_t index = exponent_position + 1;
    if (index < end && (data[index] == '+' || data[index] == '-')) {
        ++index;
    }
    if (index >= end) {
        return false;
    }
    for (; index < end; ++index) {
        if (!is_ascii_digit(data[index])) {
            return false;
        }
    }
    return true;
}

Status decode_numeric_text(const unsigned char* data, size_t length,
                           size_t budget, Value& local) {
    size_t begin = 0;
    size_t end = length;
    while (begin < end && is_ascii_space(data[begin])) {
        ++begin;
    }
    while (end > begin && is_ascii_space(data[end - 1])) {
        --end;
    }
    if (begin == end) {
        return fail(ErrorKind::invalid_parameter, "22P02",
                    "invalid numeric text for parameter type");
    }

    bool negative = false;
    bool had_sign = false;
    if (data[begin] == '+' || data[begin] == '-') {
        had_sign = true;
        negative = data[begin] == '-';
        ++begin;
    }
    if (begin == end) {
        return fail(ErrorKind::invalid_parameter, "22P02",
                    "invalid numeric text for parameter type");
    }

    // Separator-bearing NUMERIC forms are outside the fixed-point subset.
    // This deliberately classifies the family without validating its grammar.
    for (size_t index = begin; index < end; ++index) {
        if (data[index] == '_') {
            return fail(ErrorKind::unsupported, "0A000",
                        "NUMERIC digit separators are not supported");
        }
    }

    if (!is_ascii_digit(data[begin]) && data[begin] != '.') {
        const size_t token_length = end - begin;
        if (ascii_ieq(data + begin, token_length, "nan")) {
            if (had_sign) {
                return fail(ErrorKind::invalid_parameter, "22P02",
                            "invalid numeric text for parameter type");
            }
            return fail(ErrorKind::unsupported, "0A000",
                        "non-finite NUMERIC parameters are not supported");
        }
        if (ascii_ieq(data + begin, token_length, "inf") ||
            ascii_ieq(data + begin, token_length, "infinity")) {
            return fail(ErrorKind::unsupported, "0A000",
                        "non-finite NUMERIC parameters are not supported");
        }
        return fail(ErrorKind::invalid_parameter, "22P02",
                    "invalid numeric text for parameter type");
    }

    if (begin + 1 < end && data[begin] == '0') {
        unsigned base = 0;
        if (data[begin + 1] == 'x' || data[begin + 1] == 'X') {
            base = 16;
        } else if (data[begin + 1] == 'o' || data[begin + 1] == 'O') {
            base = 8;
        } else if (data[begin + 1] == 'b' || data[begin + 1] == 'B') {
            base = 2;
        }
        if (base != 0) {
            if (!valid_prefixed_integer(data, begin + 2, end, base)) {
                return fail(ErrorKind::invalid_parameter, "22P02",
                            "invalid numeric text for parameter type");
            }
            return fail(ErrorKind::unsupported, "0A000",
                        "non-decimal NUMERIC integer forms are not supported");
        }
    }

    const size_t integer_begin = begin;
    size_t integer_count = 0;
    while (begin < end && is_ascii_digit(data[begin])) {
        ++begin;
        ++integer_count;
    }
    size_t fraction_begin = 0;
    size_t fraction_count = 0;
    if (begin < end && data[begin] == '.') {
        ++begin;
        fraction_begin = begin;
        while (begin < end && is_ascii_digit(data[begin])) {
            ++begin;
            ++fraction_count;
        }
    }
    if (integer_count == 0 && fraction_count == 0) {
        return fail(ErrorKind::invalid_parameter, "22P02",
                    "invalid numeric text for parameter type");
    }
    if (begin < end) {
        if (data[begin] == 'e' || data[begin] == 'E') {
            if (!valid_exponent(data, begin, end)) {
                return fail(ErrorKind::invalid_parameter, "22P02",
                            "invalid numeric text for parameter type");
            }
            return fail(ErrorKind::unsupported, "0A000",
                        "exponent NUMERIC parameters are not supported");
        }
        return fail(ErrorKind::invalid_parameter, "22P02",
                    "invalid numeric text for parameter type");
    }

    size_t leading_zeroes = 0;
    while (leading_zeroes < integer_count &&
           data[integer_begin + leading_zeroes] == '0') {
        ++leading_zeroes;
    }
    const size_t significant_integer = integer_count - leading_zeroes;

    bool is_zero = significant_integer == 0;
    if (is_zero) {
        for (size_t index = 0; index < fraction_count; ++index) {
            if (data[fraction_begin + index] != '0') {
                is_zero = false;
                break;
            }
        }
    }
    const bool output_negative = negative && !is_zero;

    size_t output_length = 0;
    if (output_negative && !checked_add(output_length, 1)) {
        return fail(ErrorKind::resource, "54000",
                    "normalized numeric length overflows");
    }
    const size_t integer_output =
        significant_integer == 0 ? 1 : significant_integer;
    if (!checked_add(output_length, integer_output)) {
        return fail(ErrorKind::resource, "54000",
                    "normalized numeric length overflows");
    }
    if (fraction_count != 0) {
        if (!checked_add(output_length, 1) ||
            !checked_add(output_length, fraction_count)) {
            return fail(ErrorKind::resource, "54000",
                        "normalized numeric length overflows");
        }
    }
    if (output_length > budget) {
        return fail(ErrorKind::resource, "54000",
                    "normalized numeric payload exceeds the configured budget");
    }

    std::string canonical;
    canonical.reserve(output_length);
    if (output_negative) {
        canonical.push_back('-');
    }
    if (significant_integer == 0) {
        canonical.push_back('0');
    } else {
        canonical.append(
            reinterpret_cast<const char*>(data + integer_begin + leading_zeroes),
            significant_integer);
    }
    if (fraction_count != 0) {
        canonical.push_back('.');
        canonical.append(reinterpret_cast<const char*>(data + fraction_begin),
                         fraction_count);
    }
    if (canonical.size() != output_length) {
        return fail(ErrorKind::internal, "XX000",
                    "numeric normalization length changed unexpectedly");
    }
    local = Decimal{std::move(canonical)};
    return {};
}

Status decode_bytea_binary(const unsigned char* data, size_t length,
                           Value& local) {
    std::vector<uint8_t> bytes(length);
    if (length != 0) {
        std::memcpy(bytes.data(), data, length);
    }
    local = Bytes{std::move(bytes)};
    return {};
}

Status decode_bytea_text(const unsigned char* data, size_t length,
                         Value& local) {
    std::vector<uint8_t> bytes;
    if (length >= 2 && data[0] == '\\' && data[1] == 'x') {
        bytes.reserve((length - 2) / 2);
        size_t index = 2;
        while (index < length) {
            const unsigned char first = data[index];
            if (first == ' ' || first == '\n' || first == '\t' ||
                first == '\r') {
                ++index;
                continue;
            }
            const int high = hex_value(first);
            if (high < 0) {
                return fail(ErrorKind::invalid_parameter, "22P02",
                            "invalid bytea hex text representation");
            }
            if (index + 1 >= length) {
                return fail(ErrorKind::invalid_parameter, "22P02",
                            "invalid bytea hex text representation");
            }
            const int low = hex_value(data[index + 1]);
            if (low < 0) {
                return fail(ErrorKind::invalid_parameter, "22P02",
                            "invalid bytea hex text representation");
            }
            bytes.push_back(
                static_cast<uint8_t>((static_cast<unsigned>(high) << 4) |
                                     static_cast<unsigned>(low)));
            index += 2;
        }
    } else {
        bytes.reserve(length);
        size_t index = 0;
        while (index < length) {
            const unsigned char character = data[index];
            if (character == 0x00) {
                return fail(ErrorKind::invalid_parameter, "22P02",
                            "invalid bytea escaped text representation");
            }
            if (character != '\\') {
                bytes.push_back(character);
                ++index;
                continue;
            }
            if (index + 1 >= length) {
                return fail(ErrorKind::invalid_parameter, "22P02",
                            "invalid bytea escaped text representation");
            }
            const unsigned char next = data[index + 1];
            if (next == '\\') {
                bytes.push_back('\\');
                index += 2;
                continue;
            }
            if (next >= '0' && next <= '3' && index + 3 < length &&
                data[index + 2] >= '0' && data[index + 2] <= '7' &&
                data[index + 3] >= '0' && data[index + 3] <= '7') {
                const unsigned value = (static_cast<unsigned>(next - '0') << 6) |
                                       (static_cast<unsigned>(data[index + 2] - '0')
                                        << 3) |
                                       static_cast<unsigned>(data[index + 3] - '0');
                bytes.push_back(static_cast<uint8_t>(value));
                index += 4;
                continue;
            }
            return fail(ErrorKind::invalid_parameter, "22P02",
                        "invalid bytea escaped text representation");
        }
    }
    local = Bytes{std::move(bytes)};
    return {};
}

Status decode_value(uint32_t oid, int16_t format, const unsigned char* data,
                    size_t length, size_t budget, Value& local) {
    switch (oid) {
        case pgsql_oid_bool: {
            if (format == 1) {
                if (length != 1) return fail(ErrorKind::invalid_parameter, "08P01", "invalid binary BOOL length");
                local = data[0] != 0;
                return {};
            }
            size_t start = 0, end = length;
            while (start < end && is_ascii_space(data[start])) ++start;
            while (end > start && is_ascii_space(data[end - 1])) --end;
            const size_t n = end - start;
            const char* words[] = {"true", "false", "yes", "no", "on", "off", "1", "0"};
            for (size_t i = 0; i < 8; ++i) {
                const size_t m = std::strlen(words[i]);
                if (!n || n > m || (i >= 4 && i <= 5 && n < 2) || (i >= 6 && n != 1)) continue;
                bool match = true;
                for (size_t j = 0; j < n; ++j) {
                    unsigned char c = data[start + j];
                    if (c >= 'A' && c <= 'Z') c += 'a' - 'A';
                    if (c != static_cast<unsigned char>(words[i][j])) { match = false; break; }
                }
                if (match) { local = (i % 2 == 0); return {}; }
            }
            return fail(ErrorKind::invalid_parameter, "22P02", "invalid BOOL text");
        }
        case pgsql_oid_int2:
        case pgsql_oid_int4:
        case pgsql_oid_int8:
            if (format == 1) {
                return decode_binary_integer(oid, data, length, local);
            }
            if (oid == pgsql_oid_int2) {
                return decode_integer_text(data, length, -32768, 32767, local);
            }
            if (oid == pgsql_oid_int4) {
                return decode_integer_text(data, length, -2147483648LL,
                                           2147483647LL, local);
            }
            return decode_integer_text(data, length,
                                       std::numeric_limits<int64_t>::min(),
                                       std::numeric_limits<int64_t>::max(),
                                       local);

        case pgsql_oid_float4:
        case pgsql_oid_float8:
            if (format == 1) {
                return decode_binary_float(oid, data, length, local);
            }
            return decode_float_text(data, length,
                                     oid == pgsql_oid_float4, local);

        case pgsql_oid_text:
        case pgsql_oid_varchar:
        case pgsql_oid_bpchar:
            return decode_text_value(data, length, local);

        case pgsql_oid_bytea:
            if (format == 1) {
                return decode_bytea_binary(data, length, local);
            }
            return decode_bytea_text(data, length, local);

        case pgsql_oid_numeric:
            return decode_numeric_text(data, length, budget, local);

        default:
            return fail(ErrorKind::unsupported, "0A000",
                        "unsupported PostgreSQL parameter OID");
    }
}

}  // namespace

bool pgsql_utf8_text_valid(const unsigned char* data, size_t length) noexcept {
    return (!length || data) && valid_utf8(data, length);
}

Status pgsql_decode_parameter(uint32_t oid, int16_t format,
                              const unsigned char* data, int32_t length,
                              Value& out, size_t budget) {
    OutputFailureGuard guard(out);
    try {
        if (!supported_oid(oid)) {
            return fail(ErrorKind::unsupported, "0A000",
                        "unsupported PostgreSQL parameter OID " +
                            std::to_string(oid));
        }
        if (format != 0 && format != 1) {
            return fail(ErrorKind::invalid_parameter, "08P01",
                        "parameter format must be 0 (text) or 1 (binary)");
        }
        if (oid == pgsql_oid_numeric && format == 1) {
            return fail(ErrorKind::unsupported, "0A000",
                        "binary NUMERIC parameters are not supported");
        }
        if (length < -1) {
            return fail(ErrorKind::invalid_parameter, "08P01",
                        "parameter length must be -1 or non-negative");
        }
        if (length == -1) {
            out = std::monostate{};
            guard.commit();
            return {};
        }
        if (length > 0 && data == nullptr) {
            return fail(ErrorKind::invalid_parameter, "08P01",
                        "non-NULL parameter has a null data pointer");
        }

        const size_t size = static_cast<size_t>(length);
        // This check must precede every read through `data`: an over-budget
        // attacker-controlled length can otherwise be used to probe memory.
        if (size > budget) {
            return fail(ErrorKind::resource, "54000",
                        "parameter payload exceeds the configured budget");
        }

        static const unsigned char empty_datum = 0;
        const unsigned char* bytes = data != nullptr ? data : &empty_datum;
        Value local;
        Status status = decode_value(oid, format, bytes, size, budget, local);
        if (status) {
            return status;
        }
        out = std::move(local);
        guard.commit();
        return {};
    } catch (const std::bad_alloc&) {
        return fail(ErrorKind::resource, "53200",
                    "could not allocate parameter value");
    } catch (const std::length_error&) {
        return fail(ErrorKind::resource, "54000",
                    "parameter value length exceeds implementation limits");
    }
}

}  // namespace embedded
