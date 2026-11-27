#include "Embedded_MySQL_Result.h"
#include "Embedded_Float_Text.h"

#include <charconv>
#include <cstring>
#include <limits>
#include <new>
#include <system_error>
#include <utility>

namespace embedded {
namespace {

Status fail(ErrorKind kind, std::string message) {
    return Error{kind, 0, std::move(message), std::string{}};
}

Status add_bounded(size_t& total, size_t amount, size_t max_payload) {
    if (total > max_payload || amount > max_payload - total) {
        return fail(ErrorKind::resource,
                    "binary row payload exceeds the configured budget");
    }
    total += amount;
    return {};
}

// The caller's output buffer may alias a Bytes value owned by `row` because
// both are vector<uint8_t>/vector<unsigned char>.  The output therefore must
// not be cleared on entry: every validation and encoding pass must observe the
// original input bytes.  This guard clears a failed call's output as the
// function exits, after all input reads are complete, while the success path
// commits the already-swapped local buffer and leaves the result intact.
class FailureClearGuard {
  public:
    explicit FailureClearGuard(std::vector<unsigned char>& output)
        : output_(output) {}

    ~FailureClearGuard() {
        if (!committed_) {
            output_.clear();
        }
    }

    void commit() noexcept { committed_ = true; }

    FailureClearGuard(const FailureClearGuard&) = delete;
    FailureClearGuard& operator=(const FailureClearGuard&) = delete;

  private:
    std::vector<unsigned char>& output_;
    bool committed_ = false;
};

Status variable_size(size_t length, size_t& wire_size) {
    char prefix = 0;
    const uint8_t prefix_size =
        mysql_encode_length(static_cast<uint64_t>(length), &prefix);
    if (length > std::numeric_limits<size_t>::max() - prefix_size) {
        return fail(ErrorKind::resource, "length-encoded value size overflows");
    }
    wire_size = static_cast<size_t>(prefix_size) + length;
    return {};
}

template <typename Integer>
Status integer_text_size(Integer value, size_t& length) {
    char text[32];
    const auto result = std::to_chars(text, text + sizeof(text), value);
    if (result.ec != std::errc{}) {
        return fail(ErrorKind::internal, "could not render integer text");
    }
    length = static_cast<size_t>(result.ptr - text);
    return {};
}

Status double_text_size(double value, size_t& length) {
    char text[64];
    const auto result = format_embedded_double(text, text + sizeof(text), value);
    if (result.ec != std::errc{}) {
        return fail(ErrorKind::internal, "could not render floating-point text");
    }
    length = static_cast<size_t>(result.ptr - text);
    return {};
}

Status dynamic_text_size(const Value& value, size_t& length) {
    return std::visit(
        [&length](const auto& item) -> Status {
            using T = std::decay_t<decltype(item)>;
            if constexpr (std::is_same_v<T, std::monostate>) {
                return fail(ErrorKind::internal,
                            "NULL reached dynamic text rendering");
            } else if constexpr (std::is_same_v<T, bool>) {
                length = 1;
                return {};
            } else if constexpr (std::is_same_v<T, int64_t> ||
                                 std::is_same_v<T, uint64_t>) {
                return integer_text_size(item, length);
            } else if constexpr (std::is_same_v<T, double>) {
                return double_text_size(item, length);
            } else if constexpr (std::is_same_v<T, Text> ||
                                 std::is_same_v<T, Bytes>) {
                length = item.bytes.size();
                return {};
            } else {
                static_assert(std::is_same_v<T, Decimal>);
                length = item.exact.size();
                return {};
            }
        },
        value);
}

void append_le64(std::vector<unsigned char>& out, uint64_t value) {
    for (unsigned shift = 0; shift < 64; shift += 8) {
        out.push_back(static_cast<unsigned char>(value >> shift));
    }
}

void append_variable(std::vector<unsigned char>& out,
                     const unsigned char* data, size_t length) {
    char prefix = 0;
    const uint8_t prefix_size =
        mysql_encode_length(static_cast<uint64_t>(length), &prefix);
    const size_t offset = out.size();
    out.resize(offset + prefix_size + length);
    write_encoded_length(out.data() + offset, static_cast<uint64_t>(length),
                         prefix_size, prefix);
    if (length != 0) {
        std::memcpy(out.data() + offset + prefix_size, data, length);
    }
}

Status append_dynamic(std::vector<unsigned char>& out, const Value& value) {
    return std::visit(
        [&out](const auto& item) -> Status {
            using T = std::decay_t<decltype(item)>;
            if constexpr (std::is_same_v<T, std::monostate>) {
                return fail(ErrorKind::internal,
                            "NULL reached dynamic value encoding");
            } else if constexpr (std::is_same_v<T, bool>) {
                const unsigned char digit = item ? '1' : '0';
                append_variable(out, &digit, 1);
                return {};
            } else if constexpr (std::is_same_v<T, int64_t> ||
                                 std::is_same_v<T, uint64_t>) {
                char text[32];
                const auto result =
                    std::to_chars(text, text + sizeof(text), item);
                if (result.ec != std::errc{}) {
                    return fail(ErrorKind::internal,
                                "could not render integer text");
                }
                append_variable(
                    out, reinterpret_cast<const unsigned char*>(text),
                    static_cast<size_t>(result.ptr - text));
                return {};
            } else if constexpr (std::is_same_v<T, double>) {
                char text[64];
                const auto result =
                    format_embedded_double(text, text + sizeof(text), item);
                if (result.ec != std::errc{}) {
                    return fail(ErrorKind::internal,
                                "could not render floating-point text");
                }
                append_variable(
                    out, reinterpret_cast<const unsigned char*>(text),
                    static_cast<size_t>(result.ptr - text));
                return {};
            } else if constexpr (std::is_same_v<T, Text> ||
                                 std::is_same_v<T, Bytes>) {
                append_variable(
                    out,
                    reinterpret_cast<const unsigned char*>(item.bytes.data()),
                    item.bytes.size());
                return {};
            } else {
                static_assert(std::is_same_v<T, Decimal>);
                append_variable(
                    out,
                    reinterpret_cast<const unsigned char*>(item.exact.data()),
                    item.exact.size());
                return {};
            }
        },
        value);
}

Status fixed_value_size(const MySQLColumn& column, const Value& value,
                        size_t& wire_size) {
    switch (column.kind) {
        case TypeKind::boolean:
            if (!std::holds_alternative<bool>(value)) return fail(ErrorKind::invalid_parameter, "boolean column requires a bool value");
            wire_size = 1;
            return {};
        case TypeKind::signed_integer:
            if (!std::holds_alternative<int64_t>(value)) {
                return fail(ErrorKind::invalid_parameter,
                            "signed integer column requires an int64 value");
            }
            wire_size = 8;
            return {};
        case TypeKind::unsigned_integer:
            if (!std::holds_alternative<uint64_t>(value)) {
                return fail(ErrorKind::invalid_parameter,
                            "unsigned integer column requires a uint64 value");
            }
            wire_size = 8;
            return {};
        case TypeKind::floating:
            if (!std::holds_alternative<double>(value)) {
                return fail(ErrorKind::invalid_parameter,
                            "floating column requires a double value");
            }
            wire_size = 8;
            return {};
        default:
            return fail(ErrorKind::unsupported,
                        "descriptor kind has no fixed-width wire encoding");
    }
}

Status variable_value_size(const MySQLColumn& column, const Value& value,
                           size_t& wire_size) {
    size_t length = 0;
    switch (column.kind) {
        case TypeKind::dynamic:
            if (auto status = dynamic_text_size(value, length)) return status;
            break;
        case TypeKind::text:
            if (!std::holds_alternative<Text>(value)) {
                return fail(ErrorKind::invalid_parameter,
                            "text column requires a Text value");
            }
            length = std::get<Text>(value).bytes.size();
            break;
        case TypeKind::bytes:
            if (!std::holds_alternative<Bytes>(value)) {
                return fail(ErrorKind::invalid_parameter,
                            "bytes column requires a Bytes value");
            }
            length = std::get<Bytes>(value).bytes.size();
            break;
        case TypeKind::decimal:
            if (!std::holds_alternative<Decimal>(value)) {
                return fail(ErrorKind::invalid_parameter,
                            "decimal column requires a Decimal value");
            }
            length = std::get<Decimal>(value).exact.size();
            break;
        default:
            return fail(ErrorKind::unsupported,
                        "descriptor kind has no variable-width wire encoding");
    }
    return variable_size(length, wire_size);
}

Status append_fixed(std::vector<unsigned char>& out,
                    const MySQLColumn& column, const Value& value) {
    switch (column.kind) {
        case TypeKind::boolean:
            out.push_back(std::get<bool>(value) ? 1 : 0);
            return {};
        case TypeKind::signed_integer:
            append_le64(out,
                        static_cast<uint64_t>(std::get<int64_t>(value)));
            return {};
        case TypeKind::unsigned_integer:
            append_le64(out, std::get<uint64_t>(value));
            return {};
        case TypeKind::floating: {
            uint64_t bits = 0;
            const double native = std::get<double>(value);
            static_assert(sizeof(bits) == sizeof(native));
            std::memcpy(&bits, &native, sizeof(bits));
            append_le64(out, bits);
            return {};
        }
        default:
            return fail(ErrorKind::internal,
                        "fixed value reached an unsupported descriptor kind");
    }
}

Status append_variable_value(std::vector<unsigned char>& out,
                             const MySQLColumn& column, const Value& value) {
    switch (column.kind) {
        case TypeKind::dynamic:
            return append_dynamic(out, value);
        case TypeKind::text: {
            const Text& text = std::get<Text>(value);
            append_variable(
                out, reinterpret_cast<const unsigned char*>(text.bytes.data()),
                text.bytes.size());
            return {};
        }
        case TypeKind::bytes: {
            const Bytes& bytes = std::get<Bytes>(value);
            append_variable(
                out, reinterpret_cast<const unsigned char*>(bytes.bytes.data()),
                bytes.bytes.size());
            return {};
        }
        case TypeKind::decimal: {
            const Decimal& decimal = std::get<Decimal>(value);
            append_variable(
                out,
                reinterpret_cast<const unsigned char*>(decimal.exact.data()),
                decimal.exact.size());
            return {};
        }
        default:
            return fail(ErrorKind::internal,
                        "variable value reached an unsupported descriptor kind");
    }
}

bool variable_kind(TypeKind kind) {
    return kind == TypeKind::dynamic || kind == TypeKind::text ||
           kind == TypeKind::bytes || kind == TypeKind::decimal;
}

bool known_kind(TypeKind kind) {
    switch (kind) {
        case TypeKind::dynamic:
        case TypeKind::signed_integer:
        case TypeKind::unsigned_integer:
        case TypeKind::floating:
        case TypeKind::text:
        case TypeKind::bytes:
        case TypeKind::decimal:
        case TypeKind::boolean:
            return true;
        case TypeKind::unknown:
        default:
            return false;
    }
}

}  // namespace

Status mysql_describe_columns(const std::vector<Column>& columns,
                              std::vector<MySQLColumn>& out) {
    out.clear();
    try {
        constexpr size_t kMaxColumns = 65535;
        if (columns.size() > kMaxColumns) {
            return fail(ErrorKind::invalid_parameter,
                        "result has more than 65535 columns");
        }

        std::vector<MySQLColumn> described;
        described.reserve(columns.size());
        for (size_t index = 0; index < columns.size(); ++index) {
            const Column& source = columns[index];
            if (source.name.find('\0') != std::string::npos) {
                return fail(ErrorKind::invalid_parameter,
                            "column " + std::to_string(index) +
                                " has an embedded NUL in its name");
            }

            MySQLColumn target{};
            target.kind = source.type.kind;
            target.nullable = source.type.nullable;
            target.name = source.name;
            target.decimals = 0;
            target.length = 0;
            target.flags = 0;

            switch (source.type.kind) {
                case TypeKind::boolean:
                    target.wire_type = MYSQL_TYPE_TINY;
                    target.charset = 63;
                    target.flags = NUM_FLAG;
                    target.length = 1;
                    break;
                case TypeKind::dynamic:
                    target.wire_type = MYSQL_TYPE_VAR_STRING;
                    target.charset = 63;
                    target.flags = BINARY_FLAG;
                    break;
                case TypeKind::signed_integer:
                    target.wire_type = MYSQL_TYPE_LONGLONG;
                    target.charset = 63;
                    target.length = 20;
                    break;
                case TypeKind::unsigned_integer:
                    target.wire_type = MYSQL_TYPE_LONGLONG;
                    target.charset = 63;
                    target.flags = UNSIGNED_FLAG;
                    target.length = 20;
                    break;
                case TypeKind::floating:
                    target.wire_type = MYSQL_TYPE_DOUBLE;
                    target.charset = 63;
                    target.length = 22;
                    target.decimals = 31;
                    break;
                case TypeKind::text:
                    target.wire_type = MYSQL_TYPE_VAR_STRING;
                    target.charset = 45;
                    break;
                case TypeKind::bytes:
                    target.wire_type = MYSQL_TYPE_BLOB;
                    target.charset = 63;
                    target.flags = BINARY_FLAG;
                    break;
                case TypeKind::decimal: {
                    const int32_t precision = source.type.precision;
                    const int32_t scale = source.type.scale;
                    if (precision < 1 || precision > 65 || scale < 0 ||
                        scale > 30 || scale > precision) {
                        return fail(
                            ErrorKind::invalid_parameter,
                            "column " + std::to_string(index) +
                                " has invalid decimal precision/scale");
                    }
                    target.wire_type = MYSQL_TYPE_NEWDECIMAL;
                    target.charset = 63;
                    target.decimals = static_cast<uint8_t>(scale);
                    // Precision counts digits. The display length adds one
                    // byte for the decimal point when a fraction is present
                    // and one for the sign. This internal decimal model has no
                    // unsigned decimal variant, so the sign is always present
                    // in the metadata width.
                    target.length = static_cast<uint32_t>(
                        precision + (scale > 0 ? 1 : 0) + 1);
                    break;
                }
                case TypeKind::unknown:
                default:
                    return fail(ErrorKind::unsupported,
                                "column " + std::to_string(index) +
                                    " has an unsupported result type");
            }

            if (!source.type.nullable) {
                target.flags = static_cast<uint16_t>(
                    target.flags | NOT_NULL_FLAG);
            }
            described.push_back(std::move(target));
        }

        out.swap(described);
        return {};
    } catch (const std::bad_alloc&) {
        out.clear();
        return fail(ErrorKind::resource,
                    "could not allocate result metadata");
    }
}

Status mysql_encode_binary_row(const std::vector<MySQLColumn>& columns,
                               const Row& row,
                               std::vector<unsigned char>& payload,
                               size_t max_payload) {
    // Do not clear `payload` here. It can alias row data (Bytes::bytes), and
    // clearing before reading would turn an aliased input into an empty blob.
    FailureClearGuard failure_clear(payload);
    try {
        constexpr size_t kMaxColumns = 65535;
        if (columns.size() > kMaxColumns) {
            return fail(ErrorKind::invalid_parameter,
                        "result row has more than 65535 columns");
        }
        if (columns.size() != row.size()) {
            return fail(ErrorKind::invalid_parameter,
                        "row arity does not match the result descriptor");
        }

        // MySQL binary rows reserve the two low bitmap bits for the row
        // marker and a future command/status slot, so the bitmap is sized for
        // column index + 2.
        const size_t bitmap_size = (columns.size() + 9) / 8;
        size_t total = 0;
        if (auto status = add_bounded(total, 1, max_payload)) return status;
        if (auto status = add_bounded(total, bitmap_size, max_payload))
            return status;

        // Validate every value and bound the complete payload before
        // allocating the output buffer.
        for (size_t index = 0; index < columns.size(); ++index) {
            const MySQLColumn& column = columns[index];
            const Value& value = row[index];
            if (!known_kind(column.kind)) {
                return fail(ErrorKind::unsupported,
                            "column " + std::to_string(index) +
                                " has an unsupported result type");
            }
            if (std::holds_alternative<std::monostate>(value)) {
                if (!column.nullable) {
                    return fail(ErrorKind::invalid_parameter,
                                "column " + std::to_string(index) +
                                    " is NOT NULL but the value is NULL");
                }
                continue;
            }

            size_t wire_size = 0;
            if (variable_kind(column.kind)) {
                if (auto status =
                        variable_value_size(column, value, wire_size)) {
                    return status;
                }
            } else {
                if (auto status = fixed_value_size(column, value, wire_size)) {
                    return status;
                }
            }
            if (auto status = add_bounded(total, wire_size, max_payload)) {
                return status;
            }
        }

        std::vector<unsigned char> buffer;
        buffer.reserve(total);
        buffer.push_back(0x00);
        buffer.insert(buffer.end(), bitmap_size, 0x00);

        for (size_t index = 0; index < columns.size(); ++index) {
            const MySQLColumn& column = columns[index];
            const Value& value = row[index];
            if (std::holds_alternative<std::monostate>(value)) {
                const size_t bit = index + 2;
                buffer[1 + bit / 8] = static_cast<unsigned char>(
                    buffer[1 + bit / 8] | (1u << (bit % 8)));
                continue;
            }
            if (variable_kind(column.kind)) {
                if (auto status =
                        append_variable_value(buffer, column, value)) {
                    return status;
                }
            } else {
                if (auto status = append_fixed(buffer, column, value)) {
                    return status;
                }
            }
        }

        if (buffer.size() != total) {
            return fail(ErrorKind::internal,
                        "binary row payload size changed during encoding");
        }
        payload.swap(buffer);
        failure_clear.commit();
        return {};
    } catch (const std::bad_alloc&) {
        return fail(ErrorKind::resource,
                    "could not allocate binary row payload");
    }
}

}  // namespace embedded
