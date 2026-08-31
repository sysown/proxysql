#include "duckdb_result.h"
#include "sqlite3db.h"

#include "duckdb/common/types/vector.hpp"

#include <string>
#include <vector>

SQLite3_result* duckdb_result_to_sqlite3(duckdb_result* res) {
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
	// DuckDB 1.4.5. Read materialised chunks instead, where Vector::GetValue()
	// retains the real string length. Result metadata is collected above before
	// entering the chunk API, as required by DuckDB's no-mixed-data-access rule.
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

				auto* vector = reinterpret_cast<duckdb::Vector*>(vectors[c]);
				const duckdb::Value value = vector->GetValue(r);
				if (value.IsNull()) continue;

				rendered[c] = value.ToString();
				fields[c] = rendered[c].data();
				sizes[c] = static_cast<unsigned long>(rendered[c].size());
			}
			out->add_row(fields.data(), sizes.data());
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
