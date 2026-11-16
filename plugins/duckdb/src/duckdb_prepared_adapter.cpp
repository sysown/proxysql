#include "duckdb_prepared_adapter.h"
#include <algorithm>
#include <cstring>
#include <limits>
#include <cmath>
#include <type_traits>

namespace embedded {
namespace {
struct ExtractedStatementsDeleter {
    void operator()(duckdb_extracted_statements handle) const noexcept {
        if (handle) duckdb_destroy_extracted(&handle);
    }
};
using ExtractedStatementsHandle =
    std::unique_ptr<std::remove_pointer_t<duckdb_extracted_statements>, ExtractedStatementsDeleter>;
struct LogicalTypeDeleter {
    void operator()(duckdb_logical_type handle) const noexcept {
        if (handle) duckdb_destroy_logical_type(&handle);
    }
};
using LogicalTypeHandle = std::unique_ptr<std::remove_pointer_t<duckdb_logical_type>, LogicalTypeDeleter>;
struct AllocatedTextDeleter {
    void operator()(const char* text) const noexcept {
        if (text) duckdb_free(const_cast<char*>(text));
    }
};
using AllocatedTextHandle = std::unique_ptr<const char, AllocatedTextDeleter>;
Status error(ErrorKind kind, const char* message) { return Error{kind, 0, message ? message : "DuckDB error", {}}; }
Type map_type(duckdb_logical_type t) {
 Type x; if (!t) return x;
 switch (duckdb_get_type_id(t)) {
 case DUCKDB_TYPE_BOOLEAN: x.kind=TypeKind::boolean; break;
 case DUCKDB_TYPE_TINYINT: case DUCKDB_TYPE_SMALLINT: case DUCKDB_TYPE_INTEGER: case DUCKDB_TYPE_BIGINT: x.kind=TypeKind::signed_integer; break;
 case DUCKDB_TYPE_UTINYINT: case DUCKDB_TYPE_USMALLINT: case DUCKDB_TYPE_UINTEGER: case DUCKDB_TYPE_UBIGINT: x.kind=TypeKind::unsigned_integer; break;
 case DUCKDB_TYPE_FLOAT: case DUCKDB_TYPE_DOUBLE: x.kind=TypeKind::floating; break;
 case DUCKDB_TYPE_VARCHAR: x.kind=TypeKind::text; break;
 case DUCKDB_TYPE_BLOB: x.kind=TypeKind::bytes; break;
 case DUCKDB_TYPE_DECIMAL: x.kind=TypeKind::decimal; x.precision=duckdb_decimal_width(t); x.scale=duckdb_decimal_scale(t); break;
 default: break;
 }
 return x;
}
// Parse a fixed-point literal without rounding; DuckDB DECIMAL is limited to 38 digits.
struct DecimalLiteral {
    duckdb_decimal value{};
    // Storage width has a minimum of one even for zero; DECIMAL range checks
    // must instead use the significant integer digits before the point.
    unsigned integer_digits = 0;
};
bool decimal_value(const std::string& text, DecimalLiteral& out) {
    size_t i = 0;
    bool neg = false, dot = false, saw_digit = false, significant = false;
    unsigned digits = 0, scale = 0, integer_digits = 0;
    unsigned __int128 magnitude = 0;
    if (i < text.size() && (text[i] == '-' || text[i] == '+')) neg = text[i++] == '-';
    for (; i < text.size(); ++i) {
        char c = text[i];
        if (c == '.' && !dot) {
            dot = true;
            continue;
        }
        if (c < '0' || c > '9') return false;
        saw_digit = true;
        if (dot && ++scale > 38) return false;
        if (c != '0') significant = true;
        if (significant) {
            if (++digits > 38) return false;
            if (!dot) ++integer_digits;
            magnitude = magnitude * 10 + (c - '0');
        }
    }
    if (!saw_digit) return false;
    out.value.width = std::max<unsigned>({digits, scale, 1});
    out.value.scale = scale;
    out.integer_digits = integer_digits;
    unsigned __int128 bits = neg ? (~magnitude + 1) : magnitude;
    out.value.value.lower = uint64_t(bits);
    out.value.value.upper = int64_t(uint64_t(bits >> 64));
    return true;
}
size_t decimal_length(__int128 value, unsigned scale) {
 bool neg=value<0; unsigned __int128 u=neg ? (unsigned __int128)(-(value+1))+1 : (unsigned __int128)value;
 size_t digits=1; while (u>=10) { u/=10; ++digits; }
 return std::max<size_t>(digits,scale+1)+(scale ? 1 : 0)+(neg ? 1 : 0);
}
std::string decimal_string(__int128 value, unsigned scale) {
 bool neg=value<0; unsigned __int128 u=neg ? (unsigned __int128)(-(value+1))+1 : (unsigned __int128)value;
 std::string s; do { s.push_back(char('0'+u%10)); u/=10; } while(u);
 while (s.size()<=scale) s.push_back('0');
 std::reverse(s.begin(),s.end()); if (scale) s.insert(s.size()-scale,1,'.'); if (neg) s.insert(s.begin(),'-'); return s;
}

}
struct DuckDBAdapter::State final : Statement {
 const DuckDBAdapter* owner; duckdb_prepared_statement stmt=nullptr; duckdb_result result{};
 bool has_result=false, bound=false, executed=false, ready=false; idx_t row=0;
 std::vector<Type> params; std::vector<Column> columns; std::vector<duckdb_type> native_types; duckdb_data_chunk chunk=nullptr; idx_t chunk_index=0, chunk_row=0;
 explicit State(const DuckDBAdapter* p):owner(p) {}
 ~State() override { if (chunk) duckdb_destroy_data_chunk(&chunk); if (has_result) duckdb_destroy_result(&result); if (stmt) duckdb_destroy_prepare(&stmt); }
};
DuckDBAdapter::State* DuckDBAdapter::checked(Statement& s) const noexcept { auto p=dynamic_cast<State*>(&s); return p && p->owner==this ? p : nullptr; }
Status DuckDBAdapter::prepare(const std::string& sql, std::unique_ptr<Statement>& out) {
    out.reset();
    if (!connection_) return error(ErrorKind::internal, "missing connection");
    if (sql.find('\0') != std::string::npos) return error(ErrorKind::syntax, "embedded NUL in SQL");
    duckdb_extracted_statements raw_extracted = nullptr;
    const auto statement_count = duckdb_extract_statements(connection_, sql.c_str(), &raw_extracted);
    ExtractedStatementsHandle extracted(raw_extracted);
    if (statement_count != 1) {
        std::string message = "expected exactly one statement";
        if (statement_count == 0 && extracted) {
            const char* extract_error = duckdb_extract_statements_error(extracted.get());
            if (extract_error) message = extract_error;
        }
        return error(statement_count > 1 ? ErrorKind::unsupported : ErrorKind::syntax, message.c_str());
    }
    auto p = std::make_unique<State>(this);
    const auto rc = duckdb_prepare_extracted_statement(connection_, extracted.get(), 0, &p->stmt);
    if (rc != DuckDBSuccess) return error(ErrorKind::engine, duckdb_prepare_error(p->stmt));
    if (duckdb_prepared_statement_type(p->stmt) != DUCKDB_STATEMENT_TYPE_SELECT) {
        return error(ErrorKind::unsupported, "only native SELECT statements are supported");
    }
    for (idx_t i = 1; i <= duckdb_nparams(p->stmt); ++i) {
        LogicalTypeHandle logical(duckdb_param_logical_type(p->stmt, i));
        p->params.push_back(map_type(logical.get()));
    }
    for (idx_t i = 0; i < duckdb_prepared_statement_column_count(p->stmt); ++i) {
        LogicalTypeHandle logical(duckdb_prepared_statement_column_logical_type(p->stmt, i));
        const auto type = map_type(logical.get());
        if (type.kind == TypeKind::unknown) {
            return error(ErrorKind::unsupported, "unsupported or unresolved result type");
        }
        AllocatedTextHandle name(duckdb_prepared_statement_column_name(p->stmt, i));
        if (!name) return error(ErrorKind::internal, "missing result name");
        p->columns.push_back({name.get(), type});
        p->native_types.push_back(duckdb_prepared_statement_column_type(p->stmt, i));
    }
    out = std::move(p);
    return {};
}
Status DuckDBAdapter::describe_parameters(Statement& s,std::vector<Type>& out) { auto p=checked(s); if (!p) return error(ErrorKind::internal,"foreign statement"); out=p->params; return {}; }
Status DuckDBAdapter::describe_parameter_positions(Statement& statement,
                                                   std::vector<uint32_t>& out) {
    out.clear();
    auto* prepared = checked(statement);
    if (!prepared) return error(ErrorKind::internal, "foreign statement");
    std::vector<uint32_t> positions;
    for (idx_t i = 1; i <= duckdb_nparams(prepared->stmt); ++i) {
        const char* name = duckdb_parameter_name(prepared->stmt, i);
        if (!name) return error(ErrorKind::engine, "missing parameter name");
        auto free_name = [](const char* value) {
            duckdb_free(const_cast<char*>(value));
        };
        std::unique_ptr<const char, decltype(free_name)> owned(name, free_name);
        const char* digits = name;
        if (*digits == '$') ++digits;
        bool numeric = *digits != '\0';
        for (const char* c = digits; *c; ++c) {
            if (*c < '0' || *c > '9') {
                numeric = false;
                break;
            }
        }
        uint32_t value = 0;
        if (numeric) {
            for (const char* c = digits; *c; ++c) {
                const unsigned digit = *c - '0';
                if (value > (std::numeric_limits<uint32_t>::max() - digit) / 10)
                    return error(ErrorKind::range, "parameter position overflow");
                value = value * 10 + digit;
            }
            if (!value)
                return error(ErrorKind::invalid_parameter, "zero parameter position");
        }
        positions.push_back(value);
    }
    out = std::move(positions);
    return {};
}
Status DuckDBAdapter::describe_result(Statement& s,std::vector<Column>& out) { auto p=checked(s); if (!p) return error(ErrorKind::internal,"foreign statement"); out=p->columns; return {}; }
Status DuckDBAdapter::bind(Statement& s,const std::vector<Value>& values) {
    auto p = checked(s);
    if (!p) return error(ErrorKind::internal, "foreign statement");
    p->bound = false;
    if (values.size() != p->params.size()) {
        return error(ErrorKind::invalid_parameter, "parameter count mismatch");
    }
    if (duckdb_clear_bindings(p->stmt) != DuckDBSuccess) {
        return error(ErrorKind::engine, "clear bindings failed");
    }
    for (size_t i = 0; i < values.size(); ++i) {
        auto rc = std::visit([&](const auto& v) -> duckdb_state {
            using T = std::decay_t<decltype(v)>;
            auto idx = i + 1;
            if constexpr (std::is_same_v<T, std::monostate>) return duckdb_bind_null(p->stmt, idx);
            else if constexpr (std::is_same_v<T, bool>) return duckdb_bind_boolean(p->stmt, idx, v);
            else if constexpr (std::is_same_v<T, int64_t>) return duckdb_bind_int64(p->stmt, idx, v);
            else if constexpr (std::is_same_v<T, uint64_t>) return duckdb_bind_uint64(p->stmt, idx, v);
            else if constexpr (std::is_same_v<T, double>) return duckdb_bind_double(p->stmt, idx, v);
            else if constexpr (std::is_same_v<T, Text>) return duckdb_bind_varchar_length(p->stmt, idx, v.bytes.data(), v.bytes.size());
            else if constexpr (std::is_same_v<T, Bytes>) return duckdb_bind_blob(p->stmt, idx, v.bytes.empty() ? "" : reinterpret_cast<const char*>(v.bytes.data()), v.bytes.size());
            else {
                DecimalLiteral literal;
                if (!decimal_value(v.exact, literal)) return DuckDBError;
                const auto& target = p->params[i];
                const int integer_capacity = target.precision - target.scale;
                if (target.kind == TypeKind::decimal &&
                    (literal.value.scale > target.scale ||
                     integer_capacity < 0 ||
                     literal.integer_digits > static_cast<unsigned>(integer_capacity))) {
                    return DuckDBError;
                }
                return duckdb_bind_decimal(p->stmt, idx, literal.value);
            }
        }, values[i]);
        if (rc != DuckDBSuccess) {
            duckdb_clear_bindings(p->stmt);
            return error(ErrorKind::invalid_parameter, "unsupported or invalid parameter");
        }
    }
    p->bound = true;
    return {};
}
Status DuckDBAdapter::execute(Statement& s,ExecInfo& info) {
    auto p = checked(s);
    info = {};
    if (!p) return error(ErrorKind::internal, "foreign statement");
    if (!p->bound && !p->params.empty()) {
        return error(ErrorKind::invalid_parameter, "parameters not bound");
    }
    if (p->executed) return error(ErrorKind::internal, "reset required");
    p->executed = true;
    p->has_result = true;
    if (duckdb_execute_prepared(p->stmt, &p->result) != DuckDBSuccess) {
        return error(ErrorKind::engine, duckdb_result_error(&p->result));
    }
    if (duckdb_column_count(&p->result) != p->columns.size()) {
        return error(ErrorKind::schema_changed, "result column count changed");
    }
    for (idx_t i = 0; i < p->columns.size(); ++i) {
        LogicalTypeHandle logical(duckdb_column_logical_type(&p->result, i));
        const auto type = map_type(logical.get());
        const char* name = duckdb_column_name(&p->result, i);
        const auto expected = p->columns[i].type;
        if (!name || p->columns[i].name != name || type.kind != expected.kind ||
            type.precision != expected.precision || type.scale != expected.scale ||
            duckdb_column_type(&p->result, i) != p->native_types[i]) {
            return error(ErrorKind::schema_changed, "result metadata changed");
        }
    }
    p->ready = true;
    info.has_result = true;
    return {};
}
Status DuckDBAdapter::fetch(Statement& s,Row& row,bool& done,size_t budget) {
 auto p=checked(s); row.clear(); done=false; if (!p || !p->has_result || !p->ready) return error(ErrorKind::internal,"statement not executed");
 if (!p->chunk || p->chunk_row>=duckdb_data_chunk_get_size(p->chunk)) {
  if (p->chunk) duckdb_destroy_data_chunk(&p->chunk);
  if (p->chunk_index>=duckdb_result_chunk_count(p->result)) { done=true; return {}; }
  p->chunk=duckdb_result_get_chunk(p->result,p->chunk_index++); p->chunk_row=0;
  if (!p->chunk) return error(ErrorKind::engine,"failed to retrieve result chunk");
 }
 auto r=p->chunk_row;
 for (idx_t i=0;i<p->columns.size();++i) {
  auto vec=duckdb_data_chunk_get_vector(p->chunk,i); auto mask=duckdb_vector_get_validity(vec);
  if (mask && !duckdb_validity_row_is_valid(mask,r)) { row.emplace_back(std::monostate{}); continue; }
  auto data=duckdb_vector_get_data(vec); Value v;
  switch (p->native_types[i]) {
   case DUCKDB_TYPE_BOOLEAN: v=static_cast<bool*>(data)[r]; break;
   case DUCKDB_TYPE_TINYINT: v=int64_t(((int8_t*)data)[r]); break;
   case DUCKDB_TYPE_SMALLINT: v=int64_t(((int16_t*)data)[r]); break;
   case DUCKDB_TYPE_INTEGER: v=int64_t(((int32_t*)data)[r]); break;
   case DUCKDB_TYPE_BIGINT: v=int64_t(((int64_t*)data)[r]); break;
   case DUCKDB_TYPE_UTINYINT: v=uint64_t(((uint8_t*)data)[r]); break;
   case DUCKDB_TYPE_USMALLINT: v=uint64_t(((uint16_t*)data)[r]); break;
   case DUCKDB_TYPE_UINTEGER: v=uint64_t(((uint32_t*)data)[r]); break;
   case DUCKDB_TYPE_UBIGINT: v=uint64_t(((uint64_t*)data)[r]); break;
   case DUCKDB_TYPE_FLOAT: v=double(((float*)data)[r]); break;
   case DUCKDB_TYPE_DOUBLE: v=((double*)data)[r]; break;
   case DUCKDB_TYPE_VARCHAR: case DUCKDB_TYPE_BLOB: {
    auto str=((duckdb_string_t*)data)[r]; size_t n=duckdb_string_t_length(str);
    if (n>budget) { row.clear(); return error(ErrorKind::resource,"row payload exceeds budget"); }
    auto bytes=duckdb_string_t_data(&str);
    if (p->native_types[i]==DUCKDB_TYPE_VARCHAR) v=Text{std::string(bytes,n)};
    else { Bytes b; if (n) b.bytes.assign((const uint8_t*)bytes,(const uint8_t*)bytes+n); v=std::move(b); } break;
   }
   case DUCKDB_TYPE_DECIMAL: {
    auto precision=p->columns[i].type.precision; __int128 val;
    if (precision<=4) val=((int16_t*)data)[r]; else if (precision<=9) val=((int32_t*)data)[r]; else if (precision<=18) val=((int64_t*)data)[r];
    else { auto h=((duckdb_hugeint*)data)[r]; unsigned __int128 bits=((unsigned __int128)(uint64_t)h.upper<<64)|h.lower; val=(__int128)bits; }
    auto scale=p->columns[i].type.scale; if (decimal_length(val,scale)>budget) { row.clear(); return error(ErrorKind::resource,"row payload exceeds budget"); } v=Decimal{decimal_string(val,scale)}; break;
   }
   default: row.clear(); return error(ErrorKind::unsupported,"unsupported result type");
  }
  auto n=value_payload_bytes(v); if (n>budget) { row.clear(); return error(ErrorKind::resource,"row payload exceeds budget"); } budget-=n; row.push_back(std::move(v));
 }
 ++p->chunk_row; return {};
}
Status DuckDBAdapter::reset(Statement& s) { auto p=checked(s); if (!p) return error(ErrorKind::internal,"foreign statement"); if (p->chunk) duckdb_destroy_data_chunk(&p->chunk); p->chunk_index=0; p->chunk_row=0; if (p->has_result) { duckdb_destroy_result(&p->result); p->has_result=false; } p->row=0; p->bound=false; p->executed=false; p->ready=false; if (duckdb_clear_bindings(p->stmt)!=DuckDBSuccess) return error(ErrorKind::engine,"clear bindings failed"); return {}; }
void DuckDBAdapter::finalize(std::unique_ptr<Statement> s) noexcept { s.reset(); }
}
