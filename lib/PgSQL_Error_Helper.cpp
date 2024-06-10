#include "../deps/json/json.hpp"
using json = nlohmann::json;
#define PROXYJSON

#include "PgSQL_Error_Helper.h"
#include "proxysql.h"
#include "cpp.h"
#include "libpq-fe.h"

constexpr const char* PgSQL_Error_Helper::error_code_str[];

PGSQL_ERROR_CODES PgSQL_Error_Helper::identify_error_code(const char* errorCode) {
	if (strlen(errorCode) != 5) 
		return PGSQL_ERROR_CODES::ERRCODE_UNKNOWN;

	for (uint8_t i = 0; i < static_cast<uint8_t>(PGSQL_ERROR_CODES::PGSQL_ERROR_CODES_COUNT); i++) {
		if (strncmp(errorCode, error_code_str[i], 5) == 0) {
			return static_cast<PGSQL_ERROR_CODES>(i);
		}
	}

	return PGSQL_ERROR_CODES::ERRCODE_UNKNOWN;
}

PGSQL_ERROR_CLASS PgSQL_Error_Helper::identify_error_class(const char* errorCode) {
	if (strncmp(errorCode, "00", 2) == 0) {
		return PGSQL_ERROR_CLASS::ERRCLASS_SUCCESS;
	}
	else if (strncmp(errorCode, "01", 2) == 0) {
		return PGSQL_ERROR_CLASS::ERRCLASS_WARNING;
	}
	else if (strncmp(errorCode, "02", 2) == 0) {
		return PGSQL_ERROR_CLASS::ERRCLASS_NO_DATA;
	}
	else if (strncmp(errorCode, "03", 2) == 0) {
		return PGSQL_ERROR_CLASS::ERRCLASS_SQL_STATEMENT_NOT_YET_COMPLETE;
	}
	else if (strncmp(errorCode, "08", 2) == 0) {
		return PGSQL_ERROR_CLASS::ERRCLASS_CONNECTION_EXCEPTION;
	}
	else if (strncmp(errorCode, "09", 2) == 0) {
		return PGSQL_ERROR_CLASS::ERRCLASS_TRIGGERED_ACTION_EXCEPTION;
	}
	else if (strncmp(errorCode, "0A", 2) == 0) {
		return PGSQL_ERROR_CLASS::ERRCLASS_FEATURE_NOT_SUPPORTED;
	}
	else if (strncmp(errorCode, "0B", 2) == 0) {
		return PGSQL_ERROR_CLASS::ERRCLASS_INVALID_TRANSACTION_INITIATION;
	}
	else if (strncmp(errorCode, "0F", 2) == 0) {
		return PGSQL_ERROR_CLASS::ERRCLASS_LOCATOR_EXCEPTION;
	}
	else if (strncmp(errorCode, "0L", 2) == 0) {
		return PGSQL_ERROR_CLASS::ERRCLASS_INVALID_GRANTOR;
	}
	else if (strncmp(errorCode, "0P", 2) == 0) {
		return PGSQL_ERROR_CLASS::ERRCLASS_INVALID_ROLE_SPECIFICATION;
	}
	else if (strncmp(errorCode, "0Z", 2) == 0) {
		return PGSQL_ERROR_CLASS::ERRCLASS_DIAGNOSTICS_EXCEPTION;
	}
	else if (strncmp(errorCode, "20", 2) == 0) {
		return PGSQL_ERROR_CLASS::ERRCLASS_CASE_NOT_FOUND;
	}
	else if (strncmp(errorCode, "21", 2) == 0) {
		return PGSQL_ERROR_CLASS::ERRCLASS_CARDINALITY_VIOLATION;
	}
	else if (strncmp(errorCode, "22", 2) == 0) {
		return PGSQL_ERROR_CLASS::ERRCLASS_DATA_EXCEPTION;
	}
	else if (strncmp(errorCode, "23", 2) == 0) {
		return PGSQL_ERROR_CLASS::ERRCLASS_INTEGRITY_CONSTRAINT_VIOLATION;
	}
	else if (strncmp(errorCode, "24", 2) == 0) {
		return PGSQL_ERROR_CLASS::ERRCLASS_INVALID_CURSOR_STATE;
	}
	else if (strncmp(errorCode, "25", 2) == 0) {
		return PGSQL_ERROR_CLASS::ERRCLASS_INVALID_TRANSACTION_STATE;
	}
	else if (strncmp(errorCode, "26", 2) == 0) {
		return PGSQL_ERROR_CLASS::ERRCLASS_INVALID_SQL_STATEMENT_NAME;
	}
	else if (strncmp(errorCode, "27", 2) == 0) {
		return PGSQL_ERROR_CLASS::ERRCLASS_TRIGGERED_DATA_CHANGE_VIOLATION;
	}
	else if (strncmp(errorCode, "28", 2) == 0) {
		return PGSQL_ERROR_CLASS::ERRCLASS_INVALID_AUTHORIZATION_SPECIFICATION;
	}
	else if (strncmp(errorCode, "2B", 2) == 0) {
		return PGSQL_ERROR_CLASS::ERRCLASS_DEPENDENT_PRIVILEGE_DESCRIPTORS_STILL_EXIST;
	}
	else if (strncmp(errorCode, "2D", 2) == 0) {
		return PGSQL_ERROR_CLASS::ERRCLASS_INVALID_TRANSACTION_TERMINATION;
	}
	else if (strncmp(errorCode, "2F", 2) == 0) {
		return PGSQL_ERROR_CLASS::ERRCLASS_SQL_ROUTINE_EXCEPTION;
	}
	else if (strncmp(errorCode, "34", 2) == 0) {
		return PGSQL_ERROR_CLASS::ERRCLASS_INVALID_CURSOR_NAME;
	}
	else if (strncmp(errorCode, "38", 2) == 0) {
		return PGSQL_ERROR_CLASS::ERRCLASS_EXTERNAL_ROUTINE_EXCEPTION;
	}
	else if (strncmp(errorCode, "39", 2) == 0) {
		return PGSQL_ERROR_CLASS::ERRCLASS_EXTERNAL_ROUTINE_INVOCATION_EXCEPTION;
	}
	else if (strncmp(errorCode, "3B", 2) == 0) {
		return PGSQL_ERROR_CLASS::ERRCLASS_SAVEPOINT_EXCEPTION;
	}
	else if (strncmp(errorCode, "3D", 2) == 0) {
		return PGSQL_ERROR_CLASS::ERRCLASS_INVALID_CATALOG_NAME;
	}
	else if (strncmp(errorCode, "3F", 2) == 0) {
		return PGSQL_ERROR_CLASS::ERRCLASS_INVALID_SCHEMA_NAME;
	}
	else if (strncmp(errorCode, "40", 2) == 0) {
		return PGSQL_ERROR_CLASS::ERRCLASS_TRANSACTION_ROLLBACK;
	}
	else if (strncmp(errorCode, "42", 2) == 0) {
		return PGSQL_ERROR_CLASS::ERRCLASS_SYNTAX_ERROR_OR_ACCESS_RULE_VIOLATION;
	}
	else if (strncmp(errorCode, "44", 2) == 0) {
		return PGSQL_ERROR_CLASS::ERRCLASS_WITH_CHECK_OPTION_VIOLATION;
	}
	else if (strncmp(errorCode, "53", 2) == 0) {
		return PGSQL_ERROR_CLASS::ERRCLASS_INSUFFICIENT_RESOURCES;
	}
	else if (strncmp(errorCode, "54", 2) == 0) {
		return PGSQL_ERROR_CLASS::ERRCLASS_PROGRAM_LIMIT_EXCEEDED;
	}
	else if (strncmp(errorCode, "55", 2) == 0) {
		return PGSQL_ERROR_CLASS::ERRCLASS_OBJECT_NOT_IN_PREREQUISITE_STATE;
	}
	else if (strncmp(errorCode, "57", 2) == 0) {
		return PGSQL_ERROR_CLASS::ERRCLASS_OPERATOR_INTERVENTION;
	}
	else if (strncmp(errorCode, "58", 2) == 0) {
		return PGSQL_ERROR_CLASS::ERRCLASS_SYSTEM_ERROR_UNSPECIFIED;
	}
	else if (strncmp(errorCode, "72", 2) == 0) {
		return PGSQL_ERROR_CLASS::ERRCLASS_CRASH_SHUTDOWN;
	}
	else if (strncmp(errorCode, "F0", 2) == 0) {
		return PGSQL_ERROR_CLASS::ERRCLASS_CONFIG_FILE_ERROR;
	}
	else if (strncmp(errorCode, "HV", 2) == 0) {
		return PGSQL_ERROR_CLASS::ERRCLASS_FOREIGN_DATA_WRAPPER_ERROR;
	}
	else if (strncmp(errorCode, "P0", 2) == 0) {
		return PGSQL_ERROR_CLASS::ERRCLASS_PLPGSQL_ERROR;
	}
	else if (strncmp(errorCode, "XX", 2) == 0) {
		return PGSQL_ERROR_CLASS::ERRCLASS_INTERNAL_ERROR;
	}
	else {
		return PGSQL_ERROR_CLASS::ERRCLASS_UNKNOWN_ERROR;
	}
}

PGSQL_ERROR_CATEGORY PgSQL_Error_Helper::categorize_error_class(PGSQL_ERROR_CLASS err_class) {
	switch (err_class) {
	case PGSQL_ERROR_CLASS::ERRCLASS_SUCCESS:
	case PGSQL_ERROR_CLASS::ERRCLASS_WARNING:
	case PGSQL_ERROR_CLASS::ERRCLASS_NO_DATA:
	case PGSQL_ERROR_CLASS::ERRCLASS_SQL_STATEMENT_NOT_YET_COMPLETE:
		return PGSQL_ERROR_CATEGORY::ERRCATEGORY_STATUS;

	case PGSQL_ERROR_CLASS::ERRCLASS_CONNECTION_EXCEPTION:
		return PGSQL_ERROR_CATEGORY::ERRCATEGORY_CONNECTION_ERROR;

	case PGSQL_ERROR_CLASS::ERRCLASS_INVALID_AUTHORIZATION_SPECIFICATION:
	case PGSQL_ERROR_CLASS::ERRCLASS_INVALID_GRANTOR:
	case PGSQL_ERROR_CLASS::ERRCLASS_INVALID_ROLE_SPECIFICATION:
		return PGSQL_ERROR_CATEGORY::ERRCATEGORY_AUTHORIZATION_ERROR;

	case PGSQL_ERROR_CLASS::ERRCLASS_INSUFFICIENT_RESOURCES:
		return PGSQL_ERROR_CATEGORY::ERRCATEGORY_RESOURCE_ERROR;

	case PGSQL_ERROR_CLASS::ERRCLASS_CONFIG_FILE_ERROR:
		return PGSQL_ERROR_CATEGORY::ERRCATEGORY_CONFIGURATION_ERROR;

	case PGSQL_ERROR_CLASS::ERRCLASS_SYNTAX_ERROR_OR_ACCESS_RULE_VIOLATION:
		return PGSQL_ERROR_CATEGORY::ERRCATEGORY_SYNTAX_ERROR;

	case PGSQL_ERROR_CLASS::ERRCLASS_FEATURE_NOT_SUPPORTED:
		return PGSQL_ERROR_CATEGORY::ERRCATEGORY_FEATURE_NOT_SUPPORTED;

	case PGSQL_ERROR_CLASS::ERRCLASS_TRIGGERED_ACTION_EXCEPTION:
	case PGSQL_ERROR_CLASS::ERRCLASS_INVALID_TRANSACTION_INITIATION:
	case PGSQL_ERROR_CLASS::ERRCLASS_INVALID_TRANSACTION_STATE:
	case PGSQL_ERROR_CLASS::ERRCLASS_INVALID_TRANSACTION_TERMINATION:
	case PGSQL_ERROR_CLASS::ERRCLASS_TRANSACTION_ROLLBACK:
	case PGSQL_ERROR_CLASS::ERRCLASS_SAVEPOINT_EXCEPTION:
		return PGSQL_ERROR_CATEGORY::ERRCATEGORY_TRANSACTION_ERROR;

	case PGSQL_ERROR_CLASS::ERRCLASS_CASE_NOT_FOUND:
	case PGSQL_ERROR_CLASS::ERRCLASS_CARDINALITY_VIOLATION:
	case PGSQL_ERROR_CLASS::ERRCLASS_DATA_EXCEPTION:
	case PGSQL_ERROR_CLASS::ERRCLASS_INTEGRITY_CONSTRAINT_VIOLATION:
	case PGSQL_ERROR_CLASS::ERRCLASS_WITH_CHECK_OPTION_VIOLATION:
		return PGSQL_ERROR_CATEGORY::ERRCATEGORY_DATA_ERROR;

	case PGSQL_ERROR_CLASS::ERRCLASS_SQL_ROUTINE_EXCEPTION:
	case PGSQL_ERROR_CLASS::ERRCLASS_TRIGGERED_DATA_CHANGE_VIOLATION:
		return PGSQL_ERROR_CATEGORY::ERRCATEGORY_ROUTINE_ERROR;

	case PGSQL_ERROR_CLASS::ERRCLASS_INVALID_CURSOR_STATE:
	case PGSQL_ERROR_CLASS::ERRCLASS_INVALID_CURSOR_NAME:
		return PGSQL_ERROR_CATEGORY::ERRCATEGORY_CURSOR_ERROR;

	case PGSQL_ERROR_CLASS::ERRCLASS_EXTERNAL_ROUTINE_EXCEPTION:
	case PGSQL_ERROR_CLASS::ERRCLASS_EXTERNAL_ROUTINE_INVOCATION_EXCEPTION:
		return PGSQL_ERROR_CATEGORY::ERRCATEGORY_EXTERNAL_ROUTINE_ERROR;

	case PGSQL_ERROR_CLASS::ERRCLASS_PROGRAM_LIMIT_EXCEEDED:
		return PGSQL_ERROR_CATEGORY::ERRCATEGORY_RESOURCE_LIMIT_ERROR;

	case PGSQL_ERROR_CLASS::ERRCLASS_OBJECT_NOT_IN_PREREQUISITE_STATE:
		return PGSQL_ERROR_CATEGORY::ERRCATEGORY_OBJECT_STATE_ERROR;

	case PGSQL_ERROR_CLASS::ERRCLASS_OPERATOR_INTERVENTION:
		return PGSQL_ERROR_CATEGORY::ERRCATEGORY_OPERATOR_INTERVENTION_ERROR;

	case PGSQL_ERROR_CLASS::ERRCLASS_FOREIGN_DATA_WRAPPER_ERROR:
		return PGSQL_ERROR_CATEGORY::ERRCATEGORY_FDW_ERROR;

	case PGSQL_ERROR_CLASS::ERRCLASS_PLPGSQL_ERROR:
		return PGSQL_ERROR_CATEGORY::ERRCATEGORY_PLPGSQL_ERROR;

	case PGSQL_ERROR_CLASS::ERRCLASS_INTERNAL_ERROR:
		return PGSQL_ERROR_CATEGORY::ERRCATEGORY_INTERNAL_ERROR_CATEGORY;

	default:
		return PGSQL_ERROR_CATEGORY::ERRCATEGORY_UNKNOWN_CATEGORY;
	}
}

PGSQL_ERROR_SEVERITY PgSQL_Error_Helper::identify_error_severity(const char* severity) {

	PGSQL_ERROR_SEVERITY ret = PGSQL_ERROR_SEVERITY::ERRSEVERITY_UNKNOWN_SEVERITY;

	if (strcasecmp(severity, "PANIC") == 0) {
		ret = PGSQL_ERROR_SEVERITY::ERRSEVERITY_PANIC;
	} else if (strcasecmp(severity, "FATAL") == 0) {
		ret = PGSQL_ERROR_SEVERITY::ERRSEVERITY_FATAL;
	} else if (strcasecmp(severity, "ERROR") == 0) {
		ret = PGSQL_ERROR_SEVERITY::ERRSEVERITY_ERROR;
	} else if (strcasecmp(severity, "WARNING") == 0) {
		ret = PGSQL_ERROR_SEVERITY::ERRSEVERITY_WARNING;
	} else if (strcasecmp(severity, "NOTICE") == 0) {
		ret = PGSQL_ERROR_SEVERITY::ERRSEVERITY_NOTICE;
	} else if (strcasecmp(severity, "DEBUG") == 0) {
		ret = PGSQL_ERROR_SEVERITY::ERRSEVERITY_DEBUG;
	} else if (strcasecmp(severity, "LOG") == 0) {
		ret = PGSQL_ERROR_SEVERITY::ERRSEVERITY_LOG;
	}
	return ret;
}


void PgSQL_ErrorInfo_Ext::reset() {
	text = PGSQL_ERROR_SEVERITY::ERRSEVERITY_UNKNOWN_SEVERITY;
	detail.clear();
	hint.clear();
	position.clear();
	internal_position.clear();
	internal_query.clear();
	context.clear();
	schema_name.clear();
	table_name.clear();
	column_name.clear();
	datatype_name.clear();
	constraint_name.clear();
	source_file.clear();
	source_line.clear();
	source_function.clear();
}

void PgSQL_Error_Helper::fill_error_info(PgSQL_ErrorInfo& err_info, const char* code, const char* msg, const char* severity) {
	strncpy(err_info.sqlstate, code, 5);
	err_info.sqlstate[5] = '\0';
	err_info.severity = PgSQL_Error_Helper::identify_error_severity(severity);
	err_info.code = PgSQL_Error_Helper::identify_error_code(code);
	err_info.type = PgSQL_Error_Helper::identify_error_class(code);
	err_info.category = PgSQL_Error_Helper::categorize_error_class(err_info.type);
	err_info.message = msg;
}

void reset_error_info(PgSQL_ErrorInfo& err_info, bool release_extented) {
	err_info.sqlstate[0] = '\0';
	err_info.code = PGSQL_ERROR_CODES::ERRCODE_SUCCESSFUL_COMPLETION;
	err_info.severity = PGSQL_ERROR_SEVERITY::ERRSEVERITY_UNKNOWN_SEVERITY;
	err_info.type = PGSQL_ERROR_CLASS::ERRCLASS_UNKNOWN_ERROR;
	err_info.category = PGSQL_ERROR_CATEGORY::ERRCATEGORY_UNKNOWN_CATEGORY;
	err_info.message.clear();
	if (err_info.ext_info) {
		if (release_extented) {
			delete err_info.ext_info;
			err_info.ext_info = NULL;
		} else {
			err_info.ext_info->reset();
		}
	}
}

void PgSQL_Error_Helper::fill_extended_error_info(PgSQL_ErrorInfo& err_info, const PGresult* result, uint16_t ext_fields) {

	if (ext_fields == 0) {
		if (err_info.ext_info != NULL) {
			delete err_info.ext_info;
			err_info.ext_info = NULL;
		}
		return;
	}

	char* val = NULL;

	if (err_info.ext_info == NULL) {
		err_info.ext_info = new PgSQL_ErrorInfo_Ext();
	} else {
		err_info.ext_info->reset();
	}

	if (ext_fields & PGSQL_ERROR_FIELD_TEXT) {
		val = PQresultErrorField(result, PG_DIAG_SEVERITY_NONLOCALIZED);
		err_info.ext_info->text = identify_error_severity(val ? val : "");
	}

	if (ext_fields & PGSQL_ERROR_FIELD_DETAIL) {
		val = PQresultErrorField(result, PG_DIAG_MESSAGE_DETAIL);
		err_info.ext_info->detail = val ? val : "";
	}

	if (ext_fields & PGSQL_ERROR_FIELD_HINT) {
		val = PQresultErrorField(result, PG_DIAG_MESSAGE_HINT);
		err_info.ext_info->hint = val ? val : "";
	}

	if (ext_fields & PGSQL_ERROR_FIELD_POSITION) {
		val = PQresultErrorField(result, PG_DIAG_STATEMENT_POSITION);
		err_info.ext_info->position = val ? val : "";
	}

	if (ext_fields & PGSQL_ERROR_FIELD_INTERNAL_POSITION) {
		val = PQresultErrorField(result, PG_DIAG_INTERNAL_POSITION);
		err_info.ext_info->internal_position = val ? val : "";
	}

	if (ext_fields & PGSQL_ERROR_FIELD_INTERNAL_QUERY) {
		val = PQresultErrorField(result, PG_DIAG_INTERNAL_QUERY);
		err_info.ext_info->internal_query = val ? val : "";
	}

	if (ext_fields & PGSQL_ERROR_FIELD_CONTEXT) {
		val = PQresultErrorField(result, PG_DIAG_CONTEXT);
		err_info.ext_info->context = val ? val : "";
	}

	if (ext_fields & PGSQL_ERROR_FIELD_SCHEMA_NAME) {
		val = PQresultErrorField(result, PG_DIAG_SCHEMA_NAME);
		err_info.ext_info->schema_name = val ? val : "";
	}

	if (ext_fields & PGSQL_ERROR_FIELD_TABLE_NAME) {
		val = PQresultErrorField(result, PG_DIAG_TABLE_NAME);
		err_info.ext_info->table_name = val ? val : "";
	}

	if (ext_fields & PGSQL_ERROR_FIELD_COLUMN_NAME) {
		val = PQresultErrorField(result, PG_DIAG_COLUMN_NAME);
		err_info.ext_info->column_name = val ? val : "";
	}

	if (ext_fields & PGSQL_ERROR_FIELD_DATA_TYPE_NAME) {
		val = PQresultErrorField(result, PG_DIAG_DATATYPE_NAME);
		err_info.ext_info->datatype_name = val ? val : "";
	}

	if (ext_fields & PGSQL_ERROR_FIELD_CONSTRAINT_NAME) {
		val = PQresultErrorField(result, PG_DIAG_CONSTRAINT_NAME);
		err_info.ext_info->constraint_name = val ? val : "";
	}

	if (ext_fields & PGSQL_ERROR_FIELD_FILE) {
		val = PQresultErrorField(result, PG_DIAG_SOURCE_FILE);
		err_info.ext_info->source_file = val ? val : "";
	}

	if (ext_fields & PGSQL_ERROR_FIELD_LINE) {
		val = PQresultErrorField(result, PG_DIAG_SOURCE_LINE);
		err_info.ext_info->source_line = val ? val : "";
	}

	if (ext_fields & PGSQL_ERROR_FIELD_ROUTINE) {
		val = PQresultErrorField(result, PG_DIAG_SOURCE_FUNCTION);
		err_info.ext_info->source_function = val ? val : "";
	}
}

void PgSQL_Error_Helper::fill_error_info(PgSQL_ErrorInfo& err_info, const PGresult* result, uint16_t ext_fields) {
	if (result == nullptr) {
		return;
	}
	const char* sqlstate = PQresultErrorField(result, PG_DIAG_SQLSTATE);
	const char* message = PQresultErrorField(result, PG_DIAG_MESSAGE_PRIMARY);
	const char* severity = PQresultErrorField(result, PG_DIAG_SEVERITY);
	fill_error_info(err_info, sqlstate ? sqlstate : "00000", message ? message : "", severity ? severity : "");
	fill_extended_error_info(err_info, result, ext_fields);
}
