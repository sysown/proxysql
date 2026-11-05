#include "duckdb_result.h"
#include "sqlite3db.h"
#include <mysql.h>
#include <limits>

#include <algorithm>
#include <cmath>
#include <cstdint>
#include <cstdio>
#include <string>
#include <vector>

namespace {

DuckDBMySQLColumn mysql_column(duckdb_logical_type logical) {
	DuckDBMySQLColumn c;
	const auto type = duckdb_get_type_id(logical);
	c.charset = 63;
	c.flags = NUM_FLAG;
	switch (type) {
	case DUCKDB_TYPE_BOOLEAN:
		c.type = MYSQL_TYPE_TINY;
		c.length = 1;
		break;
	case DUCKDB_TYPE_UTINYINT:
		c.flags |= UNSIGNED_FLAG;
		[[fallthrough]];
	case DUCKDB_TYPE_TINYINT:
		c.type = MYSQL_TYPE_TINY;
		c.length = (c.flags & UNSIGNED_FLAG) ? 3 : 4;
		break;
	case DUCKDB_TYPE_USMALLINT:
		c.flags |= UNSIGNED_FLAG;
		[[fallthrough]];
	case DUCKDB_TYPE_SMALLINT:
		c.type = MYSQL_TYPE_SHORT;
		c.length = (c.flags & UNSIGNED_FLAG) ? 5 : 6;
		break;
	case DUCKDB_TYPE_UINTEGER:
		c.flags |= UNSIGNED_FLAG;
		[[fallthrough]];
	case DUCKDB_TYPE_INTEGER:
		c.type = MYSQL_TYPE_LONG;
		c.length = (c.flags & UNSIGNED_FLAG) ? 10 : 11;
		break;
	case DUCKDB_TYPE_UBIGINT:
		c.flags |= UNSIGNED_FLAG;
		[[fallthrough]];
	case DUCKDB_TYPE_BIGINT:
		c.type = MYSQL_TYPE_LONGLONG;
		c.length = 20;
		break;
	case DUCKDB_TYPE_UHUGEINT:
		c.flags |= UNSIGNED_FLAG;
		[[fallthrough]];
	case DUCKDB_TYPE_HUGEINT:
		c.type = MYSQL_TYPE_NEWDECIMAL;
		c.length = (c.flags & UNSIGNED_FLAG) ? 39 : 40;
		break;
	case DUCKDB_TYPE_DECIMAL:
		c.type = MYSQL_TYPE_NEWDECIMAL;
		c.decimals = duckdb_decimal_scale(logical);
		c.length = duckdb_decimal_width(logical) + (c.decimals ? 1 : 0) + 1;
		break;
	case DUCKDB_TYPE_FLOAT:
		c.type = MYSQL_TYPE_FLOAT;
		c.length = 15;
		c.decimals = 31;
		break;
	case DUCKDB_TYPE_DOUBLE:
		c.type = MYSQL_TYPE_DOUBLE;
		c.length = 24;
		c.decimals = 31;
		break;
	case DUCKDB_TYPE_DATE:
		c.type = MYSQL_TYPE_DATE;
		c.length = 10;
		c.flags = 0;
		break;
	case DUCKDB_TYPE_TIME:
		c.type = MYSQL_TYPE_TIME;
		c.length = 15;
		c.decimals = 6;
		c.flags = 0;
		break;
	case DUCKDB_TYPE_TIMESTAMP:
		c.type = MYSQL_TYPE_DATETIME;
		c.length = 26;
		c.decimals = 6;
		c.flags = 0;
		break;
	case DUCKDB_TYPE_BLOB:
		c.type = MYSQL_TYPE_BLOB;
		c.flags = BINARY_FLAG | BLOB_FLAG;
		break;
	case DUCKDB_TYPE_SQLNULL:
		c.type = MYSQL_TYPE_NULL;
		c.flags = 0;
		break;
	default:
		return DuckDBMySQLColumn{};
	}
	return c;
}

bool requires_mysql_text(duckdb_type type, duckdb_vector vector, idx_t row) {
	auto* validity = duckdb_vector_get_validity(vector);
	if (validity && !duckdb_validity_row_is_valid(validity, row))
		return false;
	void* data = duckdb_vector_get_data(vector);
	if (!data)
		return false;
	if (type == DUCKDB_TYPE_FLOAT)
		return !std::isfinite(static_cast<float*>(data)[row]);
	if (type == DUCKDB_TYPE_DOUBLE)
		return !std::isfinite(static_cast<double*>(data)[row]);
	if (type == DUCKDB_TYPE_DATE) {
		const auto value = static_cast<duckdb_date*>(data)[row];
		if (!duckdb_is_finite_date(value))
			return true;
		const int year = duckdb_from_date(value).year;
		return year < 1 || year > 9999;
	}
	if (type == DUCKDB_TYPE_TIMESTAMP) {
		const auto value = static_cast<duckdb_timestamp*>(data)[row];
		if (!duckdb_is_finite_timestamp(value))
			return true;
		const int year = duckdb_from_timestamp(value).date.year;
		return year < 1 || year > 9999;
	}
	return false;
}

bool cell_is_valid(uint64_t* validity, idx_t row) {
	return validity == nullptr || duckdb_validity_row_is_valid(validity, row);
}

void assign_string_t(duckdb_string_t str, std::string& out) {
	out.assign(duckdb_string_t_data(&str), static_cast<size_t>(duckdb_string_t_length(str)));
}

std::string format_double(double v, int precision = 15) {
	if (std::isnan(v)) return "nan";
	if (std::isinf(v)) return v > 0 ? "inf" : "-inf";
	char buf[64];
	std::snprintf(buf, sizeof(buf), "%.*g", precision, v);
	return buf;
}

std::string add_decimal_point(std::string digits, bool neg, uint8_t scale) {
	if (scale == 0) {
		return neg ? "-" + digits : digits;
	}
	if (digits.size() <= scale) {
		digits.insert(0, scale - digits.size() + 1, '0');
	}
	digits.insert(digits.size() - scale, ".");
	return neg ? "-" + digits : digits;
}

std::string format_decimal_int(int64_t raw, uint8_t scale) {
	const bool neg = raw < 0;
	// Avoid negating INT64_MIN in its signed type.
	const uint64_t mag = neg
		? static_cast<uint64_t>(-(raw + 1)) + 1
		: static_cast<uint64_t>(raw);
	return add_decimal_point(std::to_string(mag), neg, scale);
}

#if defined(__SIZEOF_INT128__)
std::string format_uint128(unsigned __int128 value) {
	if (value == 0) return "0";
	std::string s;
	while (value > 0) {
		s.push_back(static_cast<char>('0' + static_cast<int>(value % 10)));
		value /= 10;
	}
	std::reverse(s.begin(), s.end());
	return s;
}

unsigned __int128 hugeint_bits(duckdb_hugeint h) {
	return (static_cast<unsigned __int128>(static_cast<uint64_t>(h.upper)) << 64) |
		static_cast<unsigned __int128>(h.lower);
}

std::string format_hugeint(duckdb_hugeint h, uint8_t scale = 0) {
	const bool neg = h.upper < 0;
	const unsigned __int128 bits = hugeint_bits(h);
	// Two's-complement magnitude works for the minimum signed HUGEINT too.
	const unsigned __int128 mag = neg ? (~bits + 1) : bits;
	return add_decimal_point(format_uint128(mag), neg, scale);
}

std::string format_uhugeint(duckdb_uhugeint h) {
	const unsigned __int128 value =
		(static_cast<unsigned __int128>(h.upper) << 64) | h.lower;
	return format_uint128(value);
}
#endif

bool render_cell(duckdb_type type, duckdb_vector vector, idx_t row, std::string& out, bool mysql_booleans, bool mysql_types) {
	uint64_t* validity = duckdb_vector_get_validity(vector);
	if (!cell_is_valid(validity, row)) return false;
	void* data = duckdb_vector_get_data(vector);
	if (data == nullptr) return false;

	char buf[64];
	switch (type) {
	case DUCKDB_TYPE_BOOLEAN:
		out = static_cast<bool*>(data)[row] ? (mysql_booleans ? "1" : "true") : (mysql_booleans ? "0" : "false");
		return true;
	case DUCKDB_TYPE_TINYINT:
		out = std::to_string(static_cast<int8_t*>(data)[row]);
		return true;
	case DUCKDB_TYPE_SMALLINT:
		out = std::to_string(static_cast<int16_t*>(data)[row]);
		return true;
	case DUCKDB_TYPE_INTEGER:
		out = std::to_string(static_cast<int32_t*>(data)[row]);
		return true;
	case DUCKDB_TYPE_BIGINT:
		out = std::to_string(static_cast<int64_t*>(data)[row]);
		return true;
	case DUCKDB_TYPE_UTINYINT:
		out = std::to_string(static_cast<uint8_t*>(data)[row]);
		return true;
	case DUCKDB_TYPE_USMALLINT:
		out = std::to_string(static_cast<uint16_t*>(data)[row]);
		return true;
	case DUCKDB_TYPE_UINTEGER:
		out = std::to_string(static_cast<uint32_t*>(data)[row]);
		return true;
	case DUCKDB_TYPE_UBIGINT:
		out = std::to_string(static_cast<uint64_t*>(data)[row]);
		return true;
	case DUCKDB_TYPE_FLOAT:
		out = format_double(static_cast<float*>(data)[row], mysql_types ? std::numeric_limits<float>::max_digits10 : 15);
		return true;
	case DUCKDB_TYPE_DOUBLE:
		out = format_double(static_cast<double*>(data)[row], mysql_types ? std::numeric_limits<double>::max_digits10 : 15);
		return true;
	case DUCKDB_TYPE_DATE: {
		const duckdb_date value = static_cast<duckdb_date*>(data)[row];
		if (!duckdb_is_finite_date(value)) {
			out = value.days < 0 ? "-infinity" : "infinity";
			return true;
		}
		const duckdb_date_struct s = duckdb_from_date(value);
		std::snprintf(buf, sizeof(buf), "%04d-%02d-%02d", s.year, s.month, s.day);
		out = buf;
		return true;
	}
	case DUCKDB_TYPE_TIME: {
		const duckdb_time_struct s = duckdb_from_time(static_cast<duckdb_time*>(data)[row]);
		if (s.micros == 0) {
			std::snprintf(buf, sizeof(buf), "%02d:%02d:%02d", s.hour, s.min, s.sec);
		} else {
			std::snprintf(buf, sizeof(buf), "%02d:%02d:%02d.%06d", s.hour, s.min, s.sec, s.micros);
		}
		out = buf;
		return true;
	}
	case DUCKDB_TYPE_TIMESTAMP: {
		const duckdb_timestamp value = static_cast<duckdb_timestamp*>(data)[row];
		if (!duckdb_is_finite_timestamp(value)) {
			out = value.micros < 0 ? "-infinity" : "infinity";
			return true;
		}
		const duckdb_timestamp_struct s = duckdb_from_timestamp(value);
		if (s.time.micros == 0) {
			std::snprintf(buf, sizeof(buf), "%04d-%02d-%02d %02d:%02d:%02d",
				s.date.year, s.date.month, s.date.day, s.time.hour, s.time.min, s.time.sec);
		} else {
			std::snprintf(buf, sizeof(buf), "%04d-%02d-%02d %02d:%02d:%02d.%06d",
				s.date.year, s.date.month, s.date.day,
				s.time.hour, s.time.min, s.time.sec, s.time.micros);
		}
		out = buf;
		return true;
	}
	case DUCKDB_TYPE_VARCHAR:
	case DUCKDB_TYPE_BLOB:
		assign_string_t(static_cast<duckdb_string_t*>(data)[row], out);
		return true;
	case DUCKDB_TYPE_DECIMAL: {
		duckdb_logical_type lt = duckdb_vector_get_column_type(vector);
		const uint8_t scale = duckdb_decimal_scale(lt);
		const duckdb_type intern = duckdb_decimal_internal_type(lt);
		duckdb_destroy_logical_type(&lt);
		switch (intern) {
		case DUCKDB_TYPE_SMALLINT:
			out = format_decimal_int(static_cast<int16_t*>(data)[row], scale);
			return true;
		case DUCKDB_TYPE_INTEGER:
			out = format_decimal_int(static_cast<int32_t*>(data)[row], scale);
			return true;
		case DUCKDB_TYPE_BIGINT:
			out = format_decimal_int(static_cast<int64_t*>(data)[row], scale);
			return true;
		case DUCKDB_TYPE_HUGEINT:
#if defined(__SIZEOF_INT128__)
			out = format_hugeint(static_cast<duckdb_hugeint*>(data)[row], scale);
			return true;
#else
			out = format_double(duckdb_hugeint_to_double(static_cast<duckdb_hugeint*>(data)[row]));
			return true;
#endif
		default:
			return false;
		}
	}
	case DUCKDB_TYPE_INTERVAL: {
		const duckdb_interval iv = static_cast<duckdb_interval*>(data)[row];
		if (iv.months == 0 && iv.micros == 0) {
			out = std::to_string(iv.days) + (iv.days == 1 || iv.days == -1 ? " day" : " days");
		} else if (iv.days == 0 && iv.micros == 0) {
			out = std::to_string(iv.months) + (iv.months == 1 || iv.months == -1 ? " month" : " months");
		} else {
			std::snprintf(buf, sizeof(buf), "%d months %d days %lld microseconds",
				iv.months, iv.days, static_cast<long long>(iv.micros));
			out = buf;
		}
		return true;
	}
	case DUCKDB_TYPE_HUGEINT:
#if defined(__SIZEOF_INT128__)
		out = format_hugeint(static_cast<duckdb_hugeint*>(data)[row]);
#else
		out = format_double(duckdb_hugeint_to_double(static_cast<duckdb_hugeint*>(data)[row]));
#endif
		return true;
	case DUCKDB_TYPE_UHUGEINT:
#if defined(__SIZEOF_INT128__)
		out = format_uhugeint(static_cast<duckdb_uhugeint*>(data)[row]);
#else
		out = format_double(duckdb_uhugeint_to_double(static_cast<duckdb_uhugeint*>(data)[row]));
#endif
		return true;
	default:
		return false;
	}
}

} // namespace

bool duckdb_append_sqlite3_row(SQLite3_result& out, char** fields,
                               const unsigned long* sizes, std::string& error) {
	const int rc = out.add_row(fields, sizes);
	if (rc == SQLITE_ROW) return true;
	if (rc == SQLITE_TOOBIG) {
		error = "DuckDB result row exceeds ProxySQL's INT_MAX row-size limit";
	} else {
		error = "failed to append DuckDB result row: SQLite status " + std::to_string(rc);
	}
	return false;
}

SQLite3_result* duckdb_result_to_sqlite3(duckdb_result* res, std::string* error, bool mysql_booleans, std::vector<DuckDBMySQLColumn>* mysql_columns) {
	if (mysql_columns) mysql_columns->clear();
	if (error != nullptr) error->clear();
	if (res == nullptr) return nullptr;

	const idx_t ncols = duckdb_column_count(res);
	if (ncols == 0) return nullptr;

	SQLite3_result* out = new SQLite3_result(static_cast<int>(ncols));
	std::vector<duckdb_type> types(static_cast<size_t>(ncols));
	for (idx_t c = 0; c < ncols; c++) {
		const char* name = duckdb_column_name(res, c);
		out->add_column_definition(SQLITE_TEXT, name != nullptr ? name : "");
		types[c] = duckdb_column_type(res, c);
		if (mysql_columns) {
			duckdb_logical_type logical = duckdb_column_logical_type(res, c);
			mysql_columns->push_back(mysql_column(logical));
			duckdb_destroy_logical_type(&logical);
		}
	}

	std::vector<uint32_t> max_lengths(static_cast<size_t>(ncols), 0);
	std::vector<char*> fields(static_cast<size_t>(ncols), nullptr);
	std::vector<unsigned long> sizes(static_cast<size_t>(ncols), 0);
	std::vector<std::string> rendered(static_cast<size_t>(ncols));
	std::vector<duckdb_vector> vectors(static_cast<size_t>(ncols), nullptr);

	// The legacy duckdb_value_* materialisation stores VARCHARs as C strings;
	// even duckdb_value_string() therefore loses bytes after an embedded NUL in
	// DuckDB 1.4.5. Read materialised chunks and C API string_t lengths instead.
	// Result metadata is collected above before entering the chunk API, as
	// required by DuckDB's no-mixed-data-access rule.
	for (idx_t chunk_index = 0; ; chunk_index++) {
		duckdb_data_chunk chunk = duckdb_result_get_chunk(*res, chunk_index);
		if (chunk == nullptr) break;
		const idx_t nrows = duckdb_data_chunk_get_size(chunk);
		for (idx_t c = 0; c < ncols; c++) {
			vectors[c] = duckdb_data_chunk_get_vector(chunk, c);
		}

		for (idx_t r = 0; r < nrows; r++) {
			for (idx_t c = 0; c < ncols; c++) {
				fields[c] = nullptr;
				sizes[c] = 0;
				if (!duckdb_type_renders_as_text(types[c]) || vectors[c] == nullptr) continue;
				if (!render_cell(types[c], vectors[c], r, rendered[c], mysql_booleans || mysql_columns != nullptr, mysql_columns != nullptr)) continue;
				if (mysql_columns) {
					if (requires_mysql_text(types[c], vectors[c], r)) (*mysql_columns)[c] = DuckDBMySQLColumn{};
					max_lengths[c] = std::max(max_lengths[c], static_cast<uint32_t>(std::min<size_t>(rendered[c].size(), UINT32_MAX)));
				}
				fields[c] = rendered[c].data();
				sizes[c] = static_cast<unsigned long>(rendered[c].size());
			}
			std::string row_error;
			if (!duckdb_append_sqlite3_row(*out, fields.data(), sizes.data(), row_error)) {
				duckdb_destroy_data_chunk(&chunk);
				delete out;
				if (error != nullptr) *error = row_error;
				return nullptr;
			}
		}
		duckdb_destroy_data_chunk(&chunk);
	}
	if (mysql_columns) for (idx_t c = 0; c < ncols; ++c) {
		if ((*mysql_columns)[c].type == MYSQL_TYPE_VAR_STRING || (*mysql_columns)[c].type == MYSQL_TYPE_BLOB)
			(*mysql_columns)[c].length = max_lengths[c];
	}
	return out;
}

// Mirrors -- deliberately as an allowlist, not a hand-maintained denylist
// -- GetInternalCValue's switch on deprecated_type in
// duckdb/src/include/duckdb/main/capi/cast/generic.hpp, the sole
// authoritative source for which duckdb_type values duckdb_value_string()
// can actually render (it calls through GetInternalCValue<duckdb_string,
// ToCStringCastWrapper<StringCast>>, which uses this exact switch). Every
// case listed there is reproduced here; anything else -- whether a type
// this file's author thought to consider or not -- falls to `default:` in
// both switches and is treated as unrenderable. That symmetry is the
// point: mirroring the switch's positive list means a duckdb_type this
// switch doesn't yet have a case for (a future DuckDB version's new type,
// for instance) is safely treated as unrenderable by default, rather than
// silently passing through undetected the way a denylist would.
//
// Confirmed against every duckdb_type enumerator DuckDB 1.4.5 defines
// (duckdb.h:62-140, DUCKDB_TYPE_INVALID through DUCKDB_TYPE_TIME_NS) and
// empirically: a standalone probe compiled against the built duckdb_static
// archives confirmed duckdb_value_string() returns a null data pointer (regardless of
// duckdb_value_is_null()) for representatives of every type NOT in this
// list, including nested/composite types (LIST, STRUCT, MAP, ARRAY, UNION)
// and non-nested scalars that are easy to assume "just work" (UUID, ENUM,
// BIT, TIME_TZ, TIMESTAMP_TZ, BIGNUM, TIMESTAMP_S/MS/NS).
bool duckdb_type_renders_as_text(duckdb_type t) {
	switch (t) {
		case DUCKDB_TYPE_BOOLEAN:
		case DUCKDB_TYPE_TINYINT:
		case DUCKDB_TYPE_SMALLINT:
		case DUCKDB_TYPE_INTEGER:
		case DUCKDB_TYPE_BIGINT:
		case DUCKDB_TYPE_UTINYINT:
		case DUCKDB_TYPE_USMALLINT:
		case DUCKDB_TYPE_UINTEGER:
		case DUCKDB_TYPE_UBIGINT:
		case DUCKDB_TYPE_FLOAT:
		case DUCKDB_TYPE_DOUBLE:
		case DUCKDB_TYPE_DATE:
		case DUCKDB_TYPE_TIME:
		case DUCKDB_TYPE_TIMESTAMP:
		case DUCKDB_TYPE_HUGEINT:
		case DUCKDB_TYPE_UHUGEINT:
		case DUCKDB_TYPE_DECIMAL:
		case DUCKDB_TYPE_INTERVAL:
		case DUCKDB_TYPE_VARCHAR:
		case DUCKDB_TYPE_BLOB:
			return true;
		default:
			return false;
	}
}

bool duckdb_result_has_unrenderable_column(duckdb_result* res) {
	if (res == nullptr) return false;

	const idx_t ncols = duckdb_column_count(res);
	for (idx_t c = 0; c < ncols; c++) {
		if (!duckdb_type_renders_as_text(duckdb_column_type(res, c))) {
			return true;
		}
	}
	return false;
}
