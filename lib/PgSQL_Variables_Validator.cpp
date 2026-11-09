
#include "PgSQL_Variables_Validator.h"
#include "PgSQL_Session.h"
#include "PgSQL_Data_Stream.h"
#include "cpp.h"
#include <cmath>
#include <string_view>

/**
 * @brief Validates a boolean variable for PostgreSQL.
 *
 * This function checks if the provided value is a valid boolean representation
 * and transforms it if necessary. The valid representations for false are "0", "f", "false", and "off".
 * The valid representations for true are "1", "t", "true", and "on".
 *
 * @param value The value to validate.
 * @param params Unused parameter.
 * @param session Unused parameter.
 * @param transformed_value If not null, will be set to the transformed value ("on" for false inputs, "off" for true inputs).
 * @return true if the value is a valid boolean representation, false otherwise.
 */
bool pgsql_variable_validate_bool(const char* value, const params_t* params, PgSQL_Session* session, char** transformed_value) {
    (void)params;
    (void)session;
    bool result = false;
    if (transformed_value) *transformed_value = nullptr;
    if (
        (strcasecmp(value, (char*)"0") == 0) ||
        (strcasecmp(value, (char*)"f") == 0) ||
        (strcasecmp(value, (char*)"false") == 0) ||
        (strcasecmp(value, (char*)"off") == 0) ||
		(strcasecmp(value, (char*)"no") == 0)) {
        if (transformed_value)
            *transformed_value = strdup("off");
        result = true;
    } else if (
        (strcasecmp(value, (char*)"1") == 0) ||
        (strcasecmp(value, (char*)"t") == 0) ||
        (strcasecmp(value, (char*)"true") == 0) ||
        (strcasecmp(value, (char*)"on") == 0) ||
		(strcasecmp(value, (char*)"yes") == 0)) {
        if (transformed_value)
            *transformed_value = strdup("on");
        result = true;
    }
    return result;
}

// The number at the start of a value, read as PostgreSQL's parse_int() reads it: a whole number
// in decimal, octal (leading 0) or hex (0x), else a decimal fraction or exponent. Read any other
// way, ProxySQL records a value the backend does not hold ('-010' is -8 to PostgreSQL).
// *rest is set past the spaces that follow the number.
static bool pg_parse_number(const char* value, double* out, const char** rest) {
	char* end = nullptr;
	errno = 0;
	double v = (double)strtol(value, &end, 0);
	if (*end == '.' || *end == 'e' || *end == 'E' || errno == ERANGE) {
		errno = 0;
		v = strtod(value, &end);
	}
	if (end == value || errno == ERANGE || std::isnan(v)) return false;
	while (fast_isspace((unsigned char)*end)) end++;
	*out = v;
	*rest = end;
	return true;
}

bool pgsql_variable_validate_integer(const char* value, const params_t* params, PgSQL_Session* session, char** transformed_value);

/**
 * @brief Validates a string variable for PostgreSQL.
 *
 * This function checks if the provided value is a valid string representation
 * based on the allowed strings specified in the params parameter.
 *
 * @param value The value to validate.
 * @param params The parameter structure containing the allowed strings.
 * @param session Unused parameter.
 * @param transformed_value If not null, will be set to the validated value.
 * @return true if the value is a valid string representation, false otherwise.
 */
bool pgsql_variable_validate_string(const char* value, const params_t* params, PgSQL_Session* session, char** transformed_value) {
    (void)session;
    if (transformed_value) *transformed_value = nullptr;
    if (params->string_allowed) {
        const char** allowed_ptr = params->string_allowed;
        while (*allowed_ptr) {
            if (strcasecmp(value, *allowed_ptr) == 0) {
                if (transformed_value)
                    *transformed_value = strdup(*allowed_ptr);
                return true;
            }
            allowed_ptr++;
        }
    }
    return false;
}

/**
 * @brief Validates a DateStyle variable for PostgreSQL.
 *
 * This function checks if the provided value is a valid DateStyle representation.
 * If the session is null, it parses the DateStyle value directly. If the session is not null,
 * it uses the current DateStyle from the session to fill in any missing parts of the provided value.
 *
 * @param value The value to validate.
 * @param params Unused parameter.
 * @param session The current session, which holds the current DateStyle.
 * @param transformed_value If not null, will be set to the transformed value.
 * @return true if the value is a valid DateStyle representation, false otherwise.
 */
bool pgsql_variable_validate_datestyle(const char* value, const params_t* params, PgSQL_Session* session, char** transformed_value) {
	(void)params;
	if (transformed_value) *transformed_value = nullptr;

	if (session == nullptr) {
		PgSQL_DateStyle_t datestyle = PgSQL_DateStyle_Util::parse_datestyle(value);
		if (datestyle.format == DATESTYLE_FORMAT_NONE || datestyle.order == DATESTYLE_ORDER_NONE) {
			return false;
		}

		if (transformed_value) {
			PgSQL_DateStyle_t current_datestyle = { .format = DATESTYLE_FORMAT_NONE, .order = DATESTYLE_ORDER_NONE };
			const std::string& value_tmp = PgSQL_DateStyle_Util::datestyle_to_string(value, current_datestyle);
			// if something goes wrong, the value will be empty
			if (value_tmp.empty()) {
				return false;
			}

			*transformed_value = strdup(value_tmp.c_str());
		}
		return true;
	}

	const PgSQL_DateStyle_t& current_datestyle = session->current_datestyle;
	assert(current_datestyle.format != DATESTYLE_FORMAT_NONE);
	assert(current_datestyle.order != DATESTYLE_ORDER_NONE);

	// Especial case:
	// PostgreSQL strangely accepts an empty value for datestyle, but it does not alter previously set value.
	if (strlen(value) == 0) {
		if (transformed_value) *transformed_value = strdup("");
		return true;
	}
	//------------------------------------------------------------------------------------------------------

	// The word DEFAULT in the list means the session's reset value, as in PostgreSQL: the client's
	// connect-time DateStyle, or pgsql-default_datestyle while the client is still logging in.
	const PgSQL_Connection* client_conn = session->client_myds ? session->client_myds->myconn : nullptr;
	const char* reset_text = (client_conn && client_conn->startup_parameters_hash[PGSQL_DATESTYLE] != 0)
		? client_conn->startup_parameters[PGSQL_DATESTYLE] : pgsql_thread___default_variables[PGSQL_DATESTYLE];
	const PgSQL_DateStyle_t reset_datestyle = PgSQL_DateStyle_Util::parse_datestyle(reset_text);

	// Convert DateStyle to a string. Any missing parts will be filled using the current DateStyle value.
	// For example:
	// If current DateStyle is 'ISO, MDY' and the user sets 'DMY' the resulting DateStyle will be 'ISO, DMY'
	const std::string& value_tmp = PgSQL_DateStyle_Util::datestyle_to_string(
		PgSQL_DateStyle_Util::parse_datestyle(value, &reset_datestyle), current_datestyle);
	// if something goes wrong, the value will be empty
	if (value_tmp.empty()) {
		return false;
	}
	if (transformed_value)
		*transformed_value = strdup(value_tmp.c_str());
	return true;
}

/**
 * @brief Validates the maintenance_work_mem variable for PostgreSQL.
 *
 * This function checks if the provided value is a valid representation of memory size
 * with optional units. The valid units are 'kB', 'MB', 'GB', and 'TB'. If no unit is
 * specified, 'kB' is assumed by default. The function also normalizes the value to
 * always include the unit in lowercase.
 *
 * @param value The value to validate.
 * @param params Unused parameter.
 * @param session Unused parameter.
 * @param transformed_value If not null, will be set to the normalized value.
 * @return true if the value is a valid memory size representation, false otherwise.
 */
bool pgsql_variable_validate_maintenance_work_mem(const char* value, const params_t* params, PgSQL_Session* session, char** transformed_value) {
	(void)params;
	(void)session;
	const char* p = value;
	char* endptr;
	long long num;
	char unit = 'k';  // Default unit is 'k' (kB)
	bool has_unit = false;
	
	if (transformed_value) *transformed_value = nullptr;

	// Skip leading whitespace
	while (fast_isspace((unsigned char)*p)) p++;

	// Parse numeric part
	num = strtoll(p, &endptr, 10);
	if (p == endptr || num <= 0) return false;

	if (errno == ERANGE && (num == LLONG_MAX || num == LLONG_MIN)) {
		return false;
	}

	p = endptr;

	// Skip whitespace after number
	while (fast_isspace((unsigned char)*p)) p++;

	// Parse unit
	if (*p != '\0') {
		char tmp_unit = ::tolower(*p);
		switch (tmp_unit) {
		case 'k': 
		case 'm': 
		case 'g': 
		case 't':
			if (tmp_unit != 'k')
				unit = toupper(*p++);
			has_unit = true;
			// Check optional 'b'/'B'
			if (::tolower(*p) == 'b') p++;
			break;
		default:
			return false;
		}
	}

	// Skip trailing whitespace
	while (fast_isspace((unsigned char)*p)) p++;

	// Validate entire string consumed
	if (*p != '\0') return false;

	char output[128];
	// Format normalized string (always show unit in lowercase)
	int written = snprintf(output, sizeof(output), has_unit ? "%lld%cB" : "%lldkB",
		num, unit);

	if (written < 0 || written >= (int)sizeof(output)) return false;

	if (transformed_value)
		*transformed_value = strdup(output);

	return true;
}

bool pgsql_variable_validate_maintenance_work_mem_v2(const char* value, const params_t* params, PgSQL_Session* session, char** transformed_value) {
	(void)session;
	const char* input = value;

	/* Trim leading whitespace */
	while (fast_isspace((unsigned char)*input)) input++;

	/* Parse numeric part */
	uint64_t number;
	char* endptr;
	//size_t num_len = 0;
	errno = 0;
	number = strtoull(input, &endptr, 10);

	if (endptr == input || errno == ERANGE || number == 0)
		return false;

	//num_len = endptr - input;

	// Skip whitespace after number
	while (fast_isspace((unsigned char)*endptr)) endptr++;

	/* Parse unit part */
	const char* unit_ptr = endptr;
	uint64_t multiplier;
	const char* unit = "kB"; // default unit
	size_t unit_len = strlen(unit_ptr);
	size_t actual_unit_len = 2;

	/* Handle default unit (kB) if no unit specified */
	if (unit_len == 0) {
		multiplier = 1024;
	}
	else {
		/* Convert unit to lowercase for validation */
		char u[3] = { 0 };
		for (int i = 0; i < 2 && unit_ptr[i]; i++)
			u[i] = ::tolower((unsigned char)unit_ptr[i]);

		/* Validate unit and set multiplier */
		if (unit_len == 1 && u[0] == 'b') {
			unit = "B";
			actual_unit_len = 1;
			multiplier = 1;
		}
		else if (strcmp(u, "kb") == 0) {
			unit = "kB";
			multiplier = 1024;
		}
		else if (strcmp(u, "mb") == 0) {
			unit = "MB";
			actual_unit_len = 2;
			multiplier = 1024 * 1024;
		}
		else if (strcmp(u, "gb") == 0) {
			unit = "GB";
			actual_unit_len = 2;
			multiplier = 1024ULL * 1024 * 1024;
		}
		else if (strcmp(u, "tb") == 0) {
			unit = "TB";
			actual_unit_len = 2;
			multiplier = 1024ULL * 1024 * 1024 * 1024;
		}
		else {
			return false;
		}

		/* Validate unit length matches parsed characters */
		if (strlen(unit_ptr) != actual_unit_len)
			return false;
	}

	/* Check for multiplication overflow */
	if (number > UINT64_MAX / multiplier)
		return false;

	uint64_t total_bytes = number * multiplier;

	/* Validate PostgreSQL's requirements */
	if ((total_bytes / 1024ULL) < params->uint_range.min || (total_bytes / 1024ULL) > params->uint_range.max)
		return false;

	char output[128];
	/* Format output without leading zeros */
	int needed = snprintf(output, sizeof(output), "%lu%s", number, unit);

	if (needed < 0 || needed >= (int)sizeof(output)) return false;

	if (transformed_value)
		*transformed_value = strdup(output);

	return true;
}

bool pgsql_variable_validate_maintenance_work_mem_v3(const char* value, const params_t* params, PgSQL_Session* session, char** transformed_value) {
	(void)session;
	if (transformed_value) *transformed_value = nullptr;

	// PostgreSQL's memory units in kB, largest first. Matched in any case, as ProxySQL always
	// did (PostgreSQL wants the exact case); the stored value carries PostgreSQL's spelling.
	static const struct { const char* name; double kb; } units[] = {
		{ "TB", 1024.0 * 1024 * 1024 }, { "GB", 1024.0 * 1024 }, { "MB", 1024.0 }, { "kB", 1.0 }, { "B", 1.0 / 1024 },
	};
	const size_t n_units = sizeof(units) / sizeof(units[0]);

	double kb = 0;
	const char* rest = nullptr;
	if (!pg_parse_number(value, &kb, &rest)) return false;
	if (*rest != '\0') {
		size_t len = 0;
		while (rest[len] && !fast_isspace((unsigned char)rest[len])) len++;
		const char* tail = rest + len;
		while (fast_isspace((unsigned char)*tail)) tail++;
		if (*tail != '\0') return false;
		size_t u = 0;
		while (u < n_units && (strlen(units[u].name) != len || strncasecmp(rest, units[u].name, len) != 0)) u++;
		if (u == n_units) return false;
		kb *= units[u].kb;
		// As PostgreSQL: a fraction ('1.5GB') is rounded to a whole number of the next smaller unit.
		if (u + 1 < n_units) kb = rint(kb / units[u + 1].kb) * units[u + 1].kb;
	}
	kb = rint(kb);
	if (kb < params->uint_range.min || kb > params->uint_range.max) return false;

	// Stored as PostgreSQL prints it, in the largest unit that divides it exactly: '1024MB' and
	// '1GB' are one value and must hash alike, or pooled connections carrying them never match.
	if (transformed_value) {
		const uint64_t v = (uint64_t)kb;
		size_t u = 0;
		while (units[u].kb > 1.0 && v % (uint64_t)units[u].kb != 0) u++;
		*transformed_value = strdup((std::to_string(v / (uint64_t)units[u].kb) + units[u].name).c_str());
	}
	return true;
}

bool pgsql_variable_validate_client_encoding(const char* value, const params_t* params, PgSQL_Session* session, char** transformed_value) {
	(void)params;
	if (transformed_value) *transformed_value = nullptr;

	int charset_encoding = PgSQL_Connection::char_to_encoding(value);

	if (charset_encoding == -1) {
		return false;
	}

	if (transformed_value) {
		// Store the standard name, as PostgreSQL does (check_client_encoding()). The lookup
		// ignores punctuation, so a value like "'utf-8'" (asyncpg) is valid, and keeping that
		// spelling put the quotes into the SET sent to the backend. PostgreSQL keeps exactly
		// "UNICODE" as written, because pre-9.1 JDBC drivers expect to read it back.
		*transformed_value = strdup(strcmp(value, "UNICODE") == 0 ? value :
			PgSQL_Connection::encoding_to_char(charset_encoding));
	}

	return true;
}

// A zone name, a POSIX rule or a number of hours. PostgreSQL decides whether the zone
// exists; this only refuses what can never be one (quotes, spaces, ';' ...), so the
// mistake fails where the client makes it, not on a later query when ProxySQL applies it.
bool pgsql_variable_validate_timezone(const char* value, const params_t* params, PgSQL_Session* session, char** transformed_value) {
	(void)params;
	(void)session;
	if (transformed_value) *transformed_value = nullptr;
	if (value == nullptr || *value == '\0' || strlen(value) > 255) return false;
	// PostgreSQL reads any value starting with "interval" as an INTERVAL. Such a value cannot be
	// applied again on another backend connection: a SET with one is forwarded to the backend
	// and keeps its connection, but at login or as pgsql-default_timezone it is refused.
	if (strncasecmp(value, "INTERVAL", 8) == 0) return false;
	// LOCAL is only a keyword of SET TIME ZONE, meaning DEFAULT; as a value PostgreSQL refuses it.
	// So is a quoted 'DEFAULT': it is no zone, and stored it would fail every later sync.
	if (strcasecmp(value, "LOCAL") == 0 || strcasecmp(value, "DEFAULT") == 0) return false;
	for (const char* c = value; *c; c++) {
		if (!isalnum((unsigned char)*c) && strchr("/_-+,.:<>", *c) == nullptr) return false;
	}
	// A value that is entirely a number is read by PostgreSQL as hours east of UTC: it
	// refuses infinity, NaN and anything from 168 hours on.
	char* end = nullptr;
	const double hours = strtod(value, &end);
	if (end != value && *end == '\0') return std::isfinite(hours) && std::fabs(hours) < 168;
	// In a POSIX rule '<' opens a quoted abbreviation such as <+03>. PostgreSQL refuses a value
	// whose last '<' is never closed by a '>'.
	const char* last_lt = strrchr(value, '<');
	if (last_lt && strchr(last_lt, '>') == nullptr) return false;
	// A zone name is a file path under PostgreSQL's zone directory, read with one leading
	// ':' dropped. An empty path, or one that starts at '/' or ':' or has an empty or hidden
	// part, is never a zone.
	const char* name = value + (value[0] == ':');
	return name[0] != '\0' && name[0] != '/' && name[0] != ':' && name[0] != '.' &&
		strstr(name, "//") == nullptr && strstr(name, "/.") == nullptr;
}

bool pgsql_variable_validate_search_path(const char* value, const params_t* params, PgSQL_Session* session, char** transformed_value) {
	(void)params;
	(void)session;

	if (transformed_value) *transformed_value = nullptr;
	if (value == nullptr) return false;

	// NOSONAR: strlen is safe here 
	size_t value_len = strlen(value); // NOSONAR
	if (value_len > SIZE_MAX - 1) return false;

	std::string normalized;
	normalized.reserve(value_len + 1);

	bool first = true;
	bool result = true;

	const char* token = value;

	while (*token && result) {
		/* skip leading whitespace */
		while (*token && fast_isspace((unsigned char)*token)) token++;
		if (*token == '\0') break;

		const char* part_start = token;
		size_t part_len = 0;
		int effective_len = 0;  // for length check after de-escaping

		if (*token == '"' || *token == '\'') {
			// quoted identifier (preserve quotes in normalized output)
			char quote = *token++;
			const char* search = token;
			while (*search) {
				if (*search == quote) {
					if (*(search + 1) == quote) {
						search += 2;
						effective_len++;  // doubled quote counts as one char
						continue;
					} else {
						break;
					}
				}
				search++;
				effective_len++;
			}

			if (*search != quote) {
				result = false;
				break;  // unclosed quote
			}
			part_len = (size_t)(search - part_start + 1);
			token = search + 1;  // skip closing quote
			if (effective_len > 63) {
				result = false;
				break;
			}
		} else {
			// unquoted identifier or $user
			while (*token && *token != ',' && !fast_isspace(*token)) token++;
			part_len = (size_t)(token - part_start);
			if (part_len == 0 || part_len > 63) {
				result = false;
				break;
			}

			// validate as identifier
			if (!isalpha(part_start[0]) && part_start[0] != '_') {
				result = false;
				break;
			}
			for (size_t i = 1; i < part_len; ++i) {
				if (!isalnum(part_start[i]) && part_start[i] != '_' && part_start[i] != '$') {
					result = false;
					break;
				}
			}
			if (!result) break;
		}

		if (!first) {
			// ", " is how PostgreSQL itself re-renders a search_path list. Joining without
			// the space made every value that reaches a backend as a SET come back spaced
			// while ProxySQL kept tracking the unspaced form, so the two disagreed on a
			// string they both considered current.
			normalized.append(", ");
		}
		first = false;

		// append the part bytes
		if (part_len > 0) {
			normalized.append(part_start, part_len);
		}

		// skip whitespace after part
		while (*token && fast_isspace(*token)) token++;

		// expect comma or end
		if (*token == ',') {
			token++;
		} else if (*token != '\0') {
			// if there's more content without comma, invalid
			result = false;
			break;
		}
	}

	if (result) {
		if (transformed_value) {
			*transformed_value = strdup(normalized.c_str());
		} else {
			// no output requested; keep as no-op
		}
	}

	return result;
}

const pgsql_variable_validator pgsql_variable_validator_bool = {
	.type = VARIABLE_TYPE_BOOL,
	.validate = &pgsql_variable_validate_bool,
	.params = {}
};

const pgsql_variable_validator pgsql_variable_validator_extra_float_digits = {
	.type = VARIABLE_TYPE_INT,
	.validate = &pgsql_variable_validate_integer,
	.params = {
		.int_range = { .min = -15, .max = 3 }
	}
};

const pgsql_variable_validator pgsql_variable_validator_intervalstyle = {
	.type = VARIABLE_TYPE_STRING,
	.validate = &pgsql_variable_validate_string,
	.params = {
		.string_allowed = (const char* []){ "postgres", "sql_standard", "postgres_verbose", "iso_8601", nullptr } 
	}
};

const pgsql_variable_validator pgsql_variable_validator_synchronous_commit = {
	.type = VARIABLE_TYPE_STRING,
	.validate = &pgsql_variable_validate_string,
	.params = { 
		.string_allowed = (const char* []){ "local", "remote_write", "remote_apply", "on", "off", nullptr } 
	}
};

const pgsql_variable_validator pgsql_variable_validator_client_min_messages = {
	.type = VARIABLE_TYPE_STRING,
	.validate = &pgsql_variable_validate_string,
	.params = {
		.string_allowed = (const char* []){ "debug5", "debug4", "debug3", "debug2", "debug1", "log", "notice", "warning", "error", nullptr }
	}
};

const pgsql_variable_validator pgsql_variable_validator_bytea_output = {
	.type = VARIABLE_TYPE_STRING,
	.validate = &pgsql_variable_validate_string,
	.params = {
		.string_allowed = (const char* []){ "hex", "escape", nullptr }
	}
};

const pgsql_variable_validator pgsql_variable_validator_datestyle = {
	.type = VARIABLE_TYPE_DATESTYLE,
	.validate = &pgsql_variable_validate_datestyle,
	.params = {}
};

const pgsql_variable_validator pgsql_variable_validator_maintenance_work_mem = {
	.type = VARIABLE_TYPE_MAINTENANCE_WORK_MEM,
	.validate = &pgsql_variable_validate_maintenance_work_mem_v3,
	.params = {
		.uint_range = {.min = 1024, .max = 2147483647 } // this range is in kB
	}
};

const pgsql_variable_validator pgsql_variable_validator_client_encoding = {
	.type = VARIABLE_TYPE_CLIENT_ENCODING,
	.validate = &pgsql_variable_validate_client_encoding,
	.params = {}
};

const pgsql_variable_validator pgsql_variable_validator_search_path = {
	.type = VARIABLE_TYPE_STRING,
	.validate = &pgsql_variable_validate_search_path,
	.params = {}
};

const pgsql_variable_validator pgsql_variable_validator_timezone = {
	.type = VARIABLE_TYPE_STRING,
	.validate = &pgsql_variable_validate_timezone,
	.params = {}
};

/**
 * @brief Validates an integer variable for PostgreSQL.
 *
 * This function checks if the provided value is a valid integer representation
 * and falls within the specified range. The range is defined by the params
 * parameter.
 *
 * @param value The value to validate.
 * @param params The parameter structure containing the integer range.
 * @param session Unused parameter.
 * @param transformed_value If not null, will be set to the integer as PostgreSQL prints it.
 * @return true if the value is a valid integer representation within the specified range, false otherwise.
 */
bool pgsql_variable_validate_integer(const char* value, const params_t* params, PgSQL_Session* session, char** transformed_value) {
	(void)session;
	if (transformed_value) *transformed_value = nullptr;
	double num = 0;
	const char* rest = nullptr;
	// No unit: anything after the number and its spaces is refused, as PostgreSQL does.
	if (!pg_parse_number(value, &num, &rest) || *rest != '\0') return false;
	num = rint(num); // a fraction is rounded half to even, as PostgreSQL does
	if (num < params->int_range.min || num > params->int_range.max) return false;
	// Stored as PostgreSQL prints it: '03' and '3' are one value and must hash alike.
	if (transformed_value) *transformed_value = strdup(std::to_string((long long)num).c_str());
	return true;
}

const pgsql_variable_validator pgsql_variable_validator_integer = {
	.type = VARIABLE_TYPE_INT,
	.validate = &pgsql_variable_validate_integer,
	.params = {}
};
