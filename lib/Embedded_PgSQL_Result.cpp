#include "Embedded_PgSQL_Result.h"

#include <charconv>
#include <cmath>
#include <cstring>
#include <limits>
#include <new>
#include <stdexcept>
namespace embedded {
// Provided by Embedded_PgSQL_Value.cpp.
bool pgsql_utf8_text_valid(const unsigned char*, size_t) noexcept;
namespace {
Status error(ErrorKind k, const char* state, const char* message) {
    return Error{k, 0, message, state};
}
Status unsupported() {
    return error(ErrorKind::unsupported, "0A000",
                 "unsupported PostgreSQL result type or format");
}
Status invalid() {
    return error(ErrorKind::invalid_parameter, "22P02",
                 "invalid result value or descriptor");
}
Status size_error() {
    return error(ErrorKind::resource, "54000", "result field exceeds budget");
}
Status memory_error() {
    return error(ErrorKind::resource, "53200", "allocation failure");
}
bool valid_text(const std::string& s) {
    return pgsql_utf8_text_valid(reinterpret_cast<const unsigned char*>(s.data()),
                                 s.size());
}
bool descriptor(const PgSQLColumn& c) {
    switch (c.kind) {
        case TypeKind::signed_integer:
            return c.oid == 20 && c.length == 8 && c.modifier == -1;
        case TypeKind::unsigned_integer:
            return c.oid == 1700 && c.length == -1 && c.modifier == ((20 << 16) + 4);
        case TypeKind::floating:
            return c.oid == 701 && c.length == 8 && c.modifier == -1;
        case TypeKind::text:
        case TypeKind::dynamic:
            return c.oid == 25 && c.length == -1 && c.modifier == -1;
        case TypeKind::bytes:
            return c.oid == 17 && c.length == -1 && c.modifier == -1;
        case TypeKind::decimal: {
            if (c.oid != 1700 || c.length != -1 || c.modifier < 4)
                return false;
            auto m = static_cast<uint32_t>(c.modifier - 4);
            auto p = m >> 16, s = m & 65535;
            return p >= 1 && p <= 1000 && s <= p;
        }
        default:
            return false;
    }
}
Status decimal_valid(const std::string& s, int p, int scale) {
    if (s.empty())
        return invalid();
    size_t i = (s[0] == '-' || s[0] == '+') ? 1 : 0;
    bool dot = false, digit = false;
    size_t integer = 0, fraction = 0, first_nonzero = std::string::npos;
    for (; i < s.size(); ++i) {
        char ch = s[i];
        if (ch == '.' && !dot) {
            dot = true;
            continue;
        }
        if (ch < '0' || ch > '9') {
            if (ch == 'e' || ch == 'E' || ch == 'N' || ch == 'n' || ch == 'I' ||
                ch == 'i')
                return unsupported();
            return invalid();
        }
        digit = true;
        if (dot) {
            ++fraction;
            if (p && fraction > static_cast<size_t>(scale) && ch != '0')
                return error(ErrorKind::range, "22003", "decimal scale exceeded");
        } else {
            if (ch != '0' && first_nonzero == std::string::npos)
                first_nonzero = integer;
            ++integer;
        }
    }
    if (!digit)
        return invalid();
    if (p && first_nonzero != std::string::npos &&
        integer - first_nonzero > static_cast<size_t>(p - scale))
        return error(ErrorKind::range, "22003", "decimal precision exceeded");
    return {};
}
}  // namespace
Status pgsql_describe_columns(const std::vector<Column>& in,
                              std::vector<PgSQLColumn>& out) {
    try {
        std::vector<PgSQLColumn> tmp;
        if (in.size() > 65535) {
            out.clear();
            return size_error();
        }
        tmp.reserve(in.size());
        for (const auto& c : in) {
            if (!valid_text(c.name)) {
                out.clear();
                return error(ErrorKind::invalid_parameter, "22021",
                             "invalid column name");
            }
            PgSQLColumn d{c.type.kind, c.type.nullable, c.name, 0, -1, -1};
            switch (c.type.kind) {
                case TypeKind::signed_integer:
                    d.oid = 20;
                    d.length = 8;
                    break;
                case TypeKind::unsigned_integer:
                    d.oid = 1700;
                    d.modifier = (20 << 16) + 4;
                    break;
                case TypeKind::floating:
                    d.oid = 701;
                    d.length = 8;
                    break;
                case TypeKind::text:
                case TypeKind::dynamic:
                    d.oid = 25;
                    break;
                case TypeKind::bytes:
                    d.oid = 17;
                    break;
                case TypeKind::decimal:
                    if (c.type.precision < 1 || c.type.precision > 1000 ||
                        c.type.scale < 0 || c.type.scale > c.type.precision) {
                        out.clear();
                        return invalid();
                    }
                    d.oid = 1700;
                    d.modifier = (c.type.precision << 16) + c.type.scale + 4;
                    break;
                default:
                    out.clear();
                    return unsupported();
            }
            tmp.push_back(std::move(d));
        }
        out.swap(tmp);
        return {};
    } catch (const std::bad_alloc&) {
        out.clear();
        return memory_error();
    } catch (const std::length_error&) {
        out.clear();
        return size_error();
    }
}
Status pgsql_result_format_supported(const PgSQLColumn& c, int16_t f) {
    if (f != 0 && f != 1)
        return error(ErrorKind::invalid_parameter, "08P01", "invalid result format");
    if (!descriptor(c))
        return invalid();
    if (f == 1 && (c.kind == TypeKind::unsigned_integer || c.kind == TypeKind::decimal))
        return unsupported();
    return {};
}
Status pgsql_encode_field(const PgSQLColumn& c, int16_t f, const Value& v,
                          std::vector<unsigned char>& out, bool& is_null, size_t budget) {
    is_null = false;
    try {
        std::vector<unsigned char> tmp;
        auto fail = [&](Status s) {
            out.clear();
            return s;
        };
        if (auto s = pgsql_result_format_supported(c, f))
            return fail(s);
        if (std::holds_alternative<std::monostate>(v)) {
            if (!c.nullable)
                return fail(invalid());
            out.clear();
            is_null = true;
            return {};
        }
        auto append = [&](const unsigned char* p, size_t n) -> Status {
            if (n > budget)
                return size_error();
            if (n)
                tmp.assign(p, p + n);
            return {};
        };
        auto str = [&](const std::string& s) -> Status {
            return append(reinterpret_cast<const unsigned char*>(s.data()), s.size());
        };
        auto kind = c.kind;
        Status s;
        char buf[128];
        if (auto x = std::get_if<int64_t>(&v);
            x && (kind == TypeKind::signed_integer || kind == TypeKind::dynamic)) {
            if (f == 1 && kind == TypeKind::signed_integer) {
                if (budget < 8)
                    return fail(size_error());
                uint64_t u = static_cast<uint64_t>(*x);
                for (int i = 7; i >= 0; --i)
                    tmp.push_back(static_cast<unsigned char>(u >> (i * 8)));
            } else {
                auto r = std::to_chars(buf, buf + sizeof(buf), *x);
                s = append(reinterpret_cast<unsigned char*>(buf), r.ptr - buf);
            }
        } else if (auto x = std::get_if<uint64_t>(&v);
                   x &&
                   (kind == TypeKind::unsigned_integer || kind == TypeKind::dynamic)) {
            auto r = std::to_chars(buf, buf + sizeof(buf), *x);
            s = append(reinterpret_cast<unsigned char*>(buf), r.ptr - buf);
        } else if (auto x = std::get_if<double>(&v);
                   x && (kind == TypeKind::floating || kind == TypeKind::dynamic)) {
            if (f == 1 && kind == TypeKind::floating) {
                if (budget < 8)
                    return fail(size_error());
                uint64_t u;
                static_assert(sizeof(u) == sizeof(*x), "double size");
                std::memcpy(&u, x, 8);
                for (int i = 7; i >= 0; --i)
                    tmp.push_back(static_cast<unsigned char>(u >> (i * 8)));
            } else {
                const char* special = std::isnan(*x) ? "NaN"
                                      : std::isinf(*x)
                                          ? (std::signbit(*x) ? "-Infinity" : "Infinity")
                                          : nullptr;
                if (special)
                    s = append(reinterpret_cast<const unsigned char*>(special),
                               std::strlen(special));
                else {
                    auto r = std::to_chars(buf, buf + sizeof(buf), *x);
                    if (r.ec != std::errc())
                        return fail(invalid());
                    s = append(reinterpret_cast<unsigned char*>(buf), r.ptr - buf);
                }
            }
        } else if (auto x = std::get_if<Text>(&v);
                   x && (kind == TypeKind::text || kind == TypeKind::dynamic)) {
            if (!valid_text(x->bytes))
                return fail(error(ErrorKind::invalid_parameter, "22021", "invalid text"));
            s = str(x->bytes);
        } else if (auto x = std::get_if<Bytes>(&v); x && kind == TypeKind::bytes) {
            if (f == 1)
                s = append(x->bytes.data(), x->bytes.size());
            else {
                if (budget < 2 || x->bytes.size() > (budget - 2) / 2)
                    return fail(size_error());
                static const char hex[] = "0123456789abcdef";
                tmp.reserve(2 + 2 * x->bytes.size());
                tmp.push_back('\\');
                tmp.push_back('x');
                for (auto b : x->bytes) {
                    tmp.push_back(hex[b >> 4]);
                    tmp.push_back(hex[b & 15]);
                }
            }
        } else if (auto x = std::get_if<Decimal>(&v);
                   x && (kind == TypeKind::decimal || kind == TypeKind::dynamic)) {
            int m = c.modifier - 4;
            if (auto e = decimal_valid(x->exact, kind == TypeKind::decimal ? m >> 16 : 0,
                                       kind == TypeKind::decimal ? m & 65535 : 0))
                return fail(e);
            s = str(x->exact);
        } else if (std::holds_alternative<Bytes>(v) && kind == TypeKind::dynamic)
            return fail(unsupported());
        else
            return fail(invalid());
        if (s)
            return fail(s);
        out.swap(tmp);
        return {};
    } catch (const std::bad_alloc&) {
        out.clear();
        return memory_error();
    } catch (const std::length_error&) {
        out.clear();
        return size_error();
    }
}
}  // namespace embedded
