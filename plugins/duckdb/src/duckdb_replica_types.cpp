#include "duckdb_replica.h"

#include <cctype>
#include <string>

namespace {

std::string lower_copy(std::string value) {
	for (char& c : value) {
		c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
	}
	return value;
}

bool is_unsigned(const std::string& column_type) {
	return lower_copy(column_type).find("unsigned") != std::string::npos;
}

bool charset_ok(const std::string& charset) {
	const std::string c = lower_copy(charset);
	return c.empty() || c == "utf8mb4" || c == "utf8" || c == "ascii" || c == "binary";
}

bool parse_decimal_spec(const std::string& column_type, uint8_t& width, uint8_t& scale) {
	const std::string t = lower_copy(column_type);
	const size_t open = t.find('(');
	const size_t comma = t.find(',');
	const size_t close = t.find(')');
	if (open == std::string::npos || comma == std::string::npos || close == std::string::npos) return false;
	if (!(open < comma && comma < close)) return false;
	try {
		const int w = std::stoi(t.substr(open + 1, comma - open - 1));
		const int s = std::stoi(t.substr(comma + 1, close - comma - 1));
		if (w < 1 || w > 38 || s < 0 || s > w) return false;
		width = static_cast<uint8_t>(w);
		scale = static_cast<uint8_t>(s);
		return true;
	} catch (...) {
		return false;
	}
}

} // namespace

std::string duckdb_quote_mysql_ident(const std::string& name) {
	std::string out("`");
	for (char c : name) {
		out.push_back(c);
		if (c == '`') out.push_back('`');
	}
	out.push_back('`');
	return out;
}

std::string duckdb_quote_duckdb_ident(const std::string& name) {
	std::string out("\"");
	for (char c : name) {
		out.push_back(c);
		if (c == '"') out.push_back('"');
	}
	out.push_back('"');
	return out;
}

std::string duckdb_replica_map_column(const std::string& name,
                                      const std::string& data_type,
                                      const std::string& column_type,
                                      const std::string& charset,
                                      const std::string& column_key,
                                      bool nullable,
                                      DuckDBReplicaMappedColumn& out) {
	out = DuckDBReplicaMappedColumn {};
	out.name = name;
	if (name.empty()) return "snapshot column has an empty name";
	const std::string type = lower_copy(data_type);
	const bool uns = is_unsigned(column_type);
	out.primary_key = lower_copy(column_key) == "pri";
	out.not_null = out.primary_key || !nullable;

	auto set_int = [&](DuckDBReplicaTypeKind kind, const char* sql) {
		out.kind = kind;
		out.duckdb_type = sql;
	};

	if (type == "tinyint") {
		set_int(uns ? DuckDBReplicaTypeKind::uint8 : DuckDBReplicaTypeKind::int8,
		        uns ? "UTINYINT" : "TINYINT");
	} else if (type == "smallint") {
		set_int(uns ? DuckDBReplicaTypeKind::uint16 : DuckDBReplicaTypeKind::int16,
		        uns ? "USMALLINT" : "SMALLINT");
	} else if (type == "mediumint") {
		set_int(uns ? DuckDBReplicaTypeKind::uint32 : DuckDBReplicaTypeKind::int32,
		        uns ? "UINTEGER" : "INTEGER");
	} else if (type == "int" || type == "integer") {
		set_int(uns ? DuckDBReplicaTypeKind::uint32 : DuckDBReplicaTypeKind::int32,
		        uns ? "UINTEGER" : "INTEGER");
	} else if (type == "bigint") {
		set_int(uns ? DuckDBReplicaTypeKind::uint64 : DuckDBReplicaTypeKind::int64,
		        uns ? "UBIGINT" : "BIGINT");
	} else if (type == "year") {
		set_int(DuckDBReplicaTypeKind::int16, "SMALLINT");
	} else if (type == "float") {
		out.kind = DuckDBReplicaTypeKind::float32;
		out.duckdb_type = "FLOAT";
	} else if (type == "double" || type == "real") {
		out.kind = DuckDBReplicaTypeKind::float64;
		out.duckdb_type = "DOUBLE";
	} else if (type == "decimal" || type == "numeric") {
		if (!parse_decimal_spec(column_type, out.width, out.scale)) {
			return "column " + name + " has a decimal type DuckDB cannot store (width must be 1..38)";
		}
		out.kind = DuckDBReplicaTypeKind::decimal;
		out.duckdb_type = "DECIMAL(" + std::to_string(out.width) + "," + std::to_string(out.scale) + ")";
	} else if (type == "date") {
		out.kind = DuckDBReplicaTypeKind::date;
		out.duckdb_type = "DATE";
	} else if (type == "datetime" || type == "timestamp") {
		out.kind = DuckDBReplicaTypeKind::timestamp;
		out.duckdb_type = "TIMESTAMP";
	} else if (type == "time") {
		// MySQL TIME can be negative and wider than 24 hours. DuckDB TIME cannot.
		out.kind = DuckDBReplicaTypeKind::varchar;
		out.duckdb_type = "VARCHAR";
	} else if (type == "json") {
		// The vendored replication API leaves MYSQL_TYPE_JSON undecoded, so a
		// JSON column would be silently written as zero bytes. Refuse it
		// until the decoder handles it.
		return "column " + name + " is JSON; the replica does not decode JSON row images yet";
	} else if (type == "enum" || type == "set") {
		// Snapshot reads the label; the binlog gives the numeric index. Without
		// the optional TABLE_MAP label metadata the two would disagree.
		return "column " + name + " is " + type + "; the replica does not reconcile label and index yet";
	} else if (type == "char" || type == "varchar" || type == "text" || type == "tinytext" ||
	           type == "mediumtext" || type == "longtext" || type == "bit") {
		if (!charset_ok(charset) && type != "bit") {
			return "column " + name + " uses charset '" + charset +
				"'; snapshot requires utf8mb4, utf8, ascii, or binary";
		}
		if (charset == "binary" && type != "bit") {
			// Raw bytes are not necessarily valid UTF-8, which DuckDB VARCHAR
			// requires.
			out.kind = DuckDBReplicaTypeKind::blob;
			out.duckdb_type = "BLOB";
		} else {
			out.kind = DuckDBReplicaTypeKind::varchar;
			out.duckdb_type = "VARCHAR";
		}
	} else if (type == "binary" || type == "varbinary" || type == "blob" || type == "tinyblob" ||
	           type == "mediumblob" || type == "longblob") {
		out.kind = DuckDBReplicaTypeKind::blob;
		out.duckdb_type = "BLOB";
	} else {
		return "column " + name + " has unsupported MySQL type '" + data_type + "'";
	}
	return "";
}

std::string duckdb_replica_create_table_sql(const std::string& schema,
                                            const std::string& table,
                                            const std::vector<DuckDBReplicaMappedColumn>& columns) {
	std::string sql = "CREATE TABLE " + duckdb_quote_duckdb_ident(schema) + "." +
		duckdb_quote_duckdb_ident(table) + " (";
	std::string keys;
	for (size_t i = 0; i < columns.size(); ++i) {
		if (i != 0) sql += ", ";
		const auto& column = columns[i];
		sql += duckdb_quote_duckdb_ident(column.name) + " " + column.duckdb_type;
		if (column.not_null) sql += " NOT NULL";
		if (column.primary_key) {
			if (!keys.empty()) keys += ", ";
			keys += duckdb_quote_duckdb_ident(column.name);
		}
	}
	if (!keys.empty()) sql += ", PRIMARY KEY (" + keys + ")";
	sql += ")";
	return sql;
}
