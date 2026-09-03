#include "duckdb_result.h"
#include "sqlite3db.h"

#include <algorithm>
#include <cmath>
#include <cstdint>
#include <cstdio>
#include <string>
#include <vector>

namespace {

bool cell_is_valid(uint64_t* validity, idx_t row) {
	return validity == nullptr || duckdb_validity_row_is_valid(validity, row);
}

void assign_string_t(duckdb_string_t str, std::string& out) {
	out.assign(duckdb_string_t_data(&str), static_cast<size_t>(duckdb_string_t_length(str)));
}

std::string format_double(double v) {
	if (std::isnan(v)) return "nan";
	if (std::isinf(v)) return v > 0 ? "inf" : "-inf";
	char buf[64];
	std::snprintf(buf, sizeof(buf), "%.15g", v);
	return buf;
}

std::string format_decimal_int(int64_t raw, uint8_t scale) {
	const bool neg = raw < 0;
	uint64_t mag = neg ? static_cast<uint64_t>(-raw) : static_cast<uint64_t>(raw);
	std::string digits = std::to_string(mag);
	if (scale == 0) {
		return neg ? "-" + digits : digits;
	}
	if (digits.size() <= scale) {
		digits.insert(0, scale - digits.size() + 1, '0');
	}
	digits.insert(digits.size() - scale, ".");
	return neg ? "-" + digits : digits;
}

#if defined(__SIZEOF_INT128__)
std::string format_hugeint(duckdb_hugeint h) {
	__int128 v = (static_cast<__int128>(h.upper) << 64) | h.lower;
	if (v == 0) return "0";
	const bool neg = v < 0;
	if (neg) v = -v;
	std::string s;
	while (v > 0) {
		s.push_back(static_cast<char>('0' + static_cast<int>(v % 10)));
		v /= 10;
	}
	if (neg) s.push_back('-');
	std::reverse(s.begin(), s.end());
	return s;
}
#endif

bool render_cell(duckdb_type type, duckdb_vector vector, idx_t row, std::string& out) {
	uint64_t* validity = duckdb_vector_get_validity(vector);
	if (!cell_is_valid(validity, row)) return false;
	void* data = duckdb_vector_get_data(vector);
	if (data == nullptr) return false;

	char buf[64];
	switch (type) {
	case DUCKDB_TYPE_BOOLEAN:
		out = static_cast<bool*>(data)[row] ? "true" : "false";
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
		out = format_double(static_cast<float*>(data)[row]);
		return true;
	case DUCKDB_TYPE_DOUBLE:
		out = format_double(static_cast<double*>(data)[row]);
		return true;
	case DUCKDB_TYPE_DATE: {
		const duckdb_date_struct s = duckdb_from_date(static_cast<duckdb_date*>(data)[row]);
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
		const duckdb_timestamp_struct s =
			duckdb_from_timestamp(static_cast<duckdb_timestamp*>(data)[row]);
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
		int64_t raw = 0;
		switch (intern) {
		case DUCKDB_TYPE_SMALLINT:
			raw = static_cast<int16_t*>(data)[row];
			break;
		case DUCKDB_TYPE_INTEGER:
			raw = static_cast<int32_t*>(data)[row];
			break;
		case DUCKDB_TYPE_BIGINT:
			raw = static_cast<int64_t*>(data)[row];
			break;
		case DUCKDB_TYPE_HUGEINT:
#if defined(__SIZEOF_INT128__)
			{
				const duckdb_hugeint h = static_cast<duckdb_hugeint*>(data)[row];
				__int128 v = (static_cast<__int128>(h.upper) << 64) | h.lower;
				raw = static_cast<int64_t>(v);
			}
			break;
#else
			out = format_double(duckdb_hugeint_to_double(static_cast<duckdb_hugeint*>(data)[row]));
			return true;
#endif
		default:
			return false;
		}
		out = format_decimal_int(raw, scale);
		return true;
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
		out = std::to_string(static_cast<duckdb_uhugeint*>(data)[row].lower);
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

SQLite3_result* duckdb_result_to_sqlite3(duckdb_result* res, std::string* error) {
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
	}

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
				if (!render_cell(types[c], vectors[c], r, rendered[c])) continue;
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
