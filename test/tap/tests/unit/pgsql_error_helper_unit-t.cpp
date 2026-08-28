/**
 * @file pgsql_error_helper_unit-t.cpp
 * @brief Unit tests for PgSQL_Error_Helper — SQLSTATE mapping, severity,
 *        error classification, and category mapping.
 *
 * All private methods (identify_error_code, identify_error_class,
 * categorize_error_class, identify_error_severity) are tested indirectly
 * through the public fill_error_info() overloads. The public constexpr
 * get_error_code() and get_severity() are tested directly.
 */

#include "tap.h"
#include "test_globals.h"
#include "test_init.h"
#include "proxysql.h"
#include "PgSQL_Error_Helper.h"

#include <cstring>
#include <string>

// ============================================================
// get_error_code() — constexpr SQLSTATE string lookup
// ============================================================

static void test_get_error_code() {
	ok(strcmp(PgSQL_Error_Helper::get_error_code(PGSQL_ERROR_CODES::ERRCODE_SUCCESSFUL_COMPLETION), "00000") == 0,
	   "get_error_code: ERRCODE_SUCCESSFUL_COMPLETION = 00000");
	ok(strcmp(PgSQL_Error_Helper::get_error_code(PGSQL_ERROR_CODES::ERRCODE_SYNTAX_ERROR), "42601") == 0,
	   "get_error_code: ERRCODE_SYNTAX_ERROR = 42601");
	ok(strcmp(PgSQL_Error_Helper::get_error_code(PGSQL_ERROR_CODES::ERRCODE_UNIQUE_VIOLATION), "23505") == 0,
	   "get_error_code: ERRCODE_UNIQUE_VIOLATION = 23505");
	ok(strcmp(PgSQL_Error_Helper::get_error_code(PGSQL_ERROR_CODES::ERRCODE_CONNECTION_EXCEPTION), "08000") == 0,
	   "get_error_code: ERRCODE_CONNECTION_EXCEPTION = 08000");
	ok(strcmp(PgSQL_Error_Helper::get_error_code(PGSQL_ERROR_CODES::ERRCODE_UNDEFINED_TABLE), "42P01") == 0,
	   "get_error_code: ERRCODE_UNDEFINED_TABLE = 42P01");
	ok(strcmp(PgSQL_Error_Helper::get_error_code(PGSQL_ERROR_CODES::ERRCODE_DIVISION_BY_ZERO), "22012") == 0,
	   "get_error_code: ERRCODE_DIVISION_BY_ZERO = 22012");
	ok(strcmp(PgSQL_Error_Helper::get_error_code(PGSQL_ERROR_CODES::ERRCODE_INTERNAL_ERROR), "XX000") == 0,
	   "get_error_code: ERRCODE_INTERNAL_ERROR = XX000");
	ok(strcmp(PgSQL_Error_Helper::get_error_code(PGSQL_ERROR_CODES::ERRCODE_PROTOCOL_VIOLATION), "08P01") == 0,
	   "get_error_code: ERRCODE_PROTOCOL_VIOLATION = 08P01");
}

// ============================================================
// get_severity() — constexpr severity string lookup
// ============================================================

static void test_get_severity() {
	ok(strcmp(PgSQL_Error_Helper::get_severity(PGSQL_ERROR_SEVERITY::ERRSEVERITY_FATAL), "FATAL") == 0,
	   "get_severity: ERRSEVERITY_FATAL = FATAL");
	ok(strcmp(PgSQL_Error_Helper::get_severity(PGSQL_ERROR_SEVERITY::ERRSEVERITY_ERROR), "ERROR") == 0,
	   "get_severity: ERRSEVERITY_ERROR = ERROR");
	ok(strcmp(PgSQL_Error_Helper::get_severity(PGSQL_ERROR_SEVERITY::ERRSEVERITY_WARNING), "WARNING") == 0,
	   "get_severity: ERRSEVERITY_WARNING = WARNING");
	ok(strcmp(PgSQL_Error_Helper::get_severity(PGSQL_ERROR_SEVERITY::ERRSEVERITY_PANIC), "PANIC") == 0,
	   "get_severity: ERRSEVERITY_PANIC = PANIC");
	ok(strcmp(PgSQL_Error_Helper::get_severity(PGSQL_ERROR_SEVERITY::ERRSEVERITY_NOTICE), "NOTICE") == 0,
	   "get_severity: ERRSEVERITY_NOTICE = NOTICE");
	ok(strcmp(PgSQL_Error_Helper::get_severity(PGSQL_ERROR_SEVERITY::ERRSEVERITY_DEBUG), "DEBUG") == 0,
	   "get_severity: ERRSEVERITY_DEBUG = DEBUG");
	ok(strcmp(PgSQL_Error_Helper::get_severity(PGSQL_ERROR_SEVERITY::ERRSEVERITY_INFO), "INFO") == 0,
	   "get_severity: ERRSEVERITY_INFO = INFO");
	ok(strcmp(PgSQL_Error_Helper::get_severity(PGSQL_ERROR_SEVERITY::ERRSEVERITY_LOG), "LOG") == 0,
	   "get_severity: ERRSEVERITY_LOG = LOG");
	ok(strcmp(PgSQL_Error_Helper::get_severity(PGSQL_ERROR_SEVERITY::ERRSEVERITY_UNKNOWN_SEVERITY), "UNKNOWN") == 0,
	   "get_severity: ERRSEVERITY_UNKNOWN_SEVERITY = UNKNOWN");
}

// ============================================================
// fill_error_info(info, sqlstate_str, msg, severity_str)
// Tests identify_error_code, identify_error_class,
// categorize_error_class, and identify_error_severity indirectly
// ============================================================

static void test_fill_error_info_syntax_error() {
	PgSQL_ErrorInfo info;
	PgSQL_Error_Helper::fill_error_info(info, "42601", "syntax error at or near \"foo\"", "ERROR");

	ok(info.code == PGSQL_ERROR_CODES::ERRCODE_SYNTAX_ERROR,
	   "fill(42601): code = ERRCODE_SYNTAX_ERROR");
	ok(info.type == PGSQL_ERROR_CLASS::ERRCLASS_SYNTAX_ERROR_OR_ACCESS_RULE_VIOLATION,
	   "fill(42601): type = ERRCLASS_SYNTAX_ERROR_OR_ACCESS_RULE_VIOLATION");
	ok(info.category == PGSQL_ERROR_CATEGORY::ERRCATEGORY_SYNTAX_ERROR,
	   "fill(42601): category = ERRCATEGORY_SYNTAX_ERROR");
	ok(info.severity == PGSQL_ERROR_SEVERITY::ERRSEVERITY_ERROR,
	   "fill(42601): severity = ERRSEVERITY_ERROR");
	ok(strcmp(info.sqlstate, "42601") == 0,
	   "fill(42601): sqlstate field = '42601'");
	ok(info.message == "syntax error at or near \"foo\"",
	   "fill(42601): message stored correctly");
}

static void test_fill_error_info_connection_exception() {
	PgSQL_ErrorInfo info;
	PgSQL_Error_Helper::fill_error_info(info, "08000", "connection exception", "FATAL");

	ok(info.code == PGSQL_ERROR_CODES::ERRCODE_CONNECTION_EXCEPTION,
	   "fill(08000): code = ERRCODE_CONNECTION_EXCEPTION");
	ok(info.type == PGSQL_ERROR_CLASS::ERRCLASS_CONNECTION_EXCEPTION,
	   "fill(08000): type = ERRCLASS_CONNECTION_EXCEPTION");
	ok(info.category == PGSQL_ERROR_CATEGORY::ERRCATEGORY_CONNECTION_ERROR,
	   "fill(08000): category = ERRCATEGORY_CONNECTION_ERROR");
	ok(info.severity == PGSQL_ERROR_SEVERITY::ERRSEVERITY_FATAL,
	   "fill(08000): severity = ERRSEVERITY_FATAL");
}

static void test_fill_error_info_unique_violation() {
	PgSQL_ErrorInfo info;
	PgSQL_Error_Helper::fill_error_info(info, "23505", "duplicate key value violates unique constraint", "ERROR");

	ok(info.code == PGSQL_ERROR_CODES::ERRCODE_UNIQUE_VIOLATION,
	   "fill(23505): code = ERRCODE_UNIQUE_VIOLATION");
	ok(info.type == PGSQL_ERROR_CLASS::ERRCLASS_INTEGRITY_CONSTRAINT_VIOLATION,
	   "fill(23505): type = ERRCLASS_INTEGRITY_CONSTRAINT_VIOLATION");
	ok(info.category == PGSQL_ERROR_CATEGORY::ERRCATEGORY_DATA_ERROR,
	   "fill(23505): category = ERRCATEGORY_DATA_ERROR");
}

static void test_fill_error_info_successful_completion() {
	PgSQL_ErrorInfo info;
	PgSQL_Error_Helper::fill_error_info(info, "00000", "success", "NOTICE");

	ok(info.code == PGSQL_ERROR_CODES::ERRCODE_SUCCESSFUL_COMPLETION,
	   "fill(00000): code = ERRCODE_SUCCESSFUL_COMPLETION");
	ok(info.type == PGSQL_ERROR_CLASS::ERRCLASS_SUCCESS,
	   "fill(00000): type = ERRCLASS_SUCCESS");
	ok(info.category == PGSQL_ERROR_CATEGORY::ERRCATEGORY_STATUS,
	   "fill(00000): category = ERRCATEGORY_STATUS");
	ok(info.severity == PGSQL_ERROR_SEVERITY::ERRSEVERITY_NOTICE,
	   "fill(00000): severity = ERRSEVERITY_NOTICE");
}

static void test_fill_error_info_internal_error() {
	PgSQL_ErrorInfo info;
	PgSQL_Error_Helper::fill_error_info(info, "XX000", "internal error", "PANIC");

	ok(info.code == PGSQL_ERROR_CODES::ERRCODE_INTERNAL_ERROR,
	   "fill(XX000): code = ERRCODE_INTERNAL_ERROR");
	ok(info.type == PGSQL_ERROR_CLASS::ERRCLASS_INTERNAL_ERROR,
	   "fill(XX000): type = ERRCLASS_INTERNAL_ERROR");
	ok(info.category == PGSQL_ERROR_CATEGORY::ERRCATEGORY_INTERNAL_ERROR_CATEGORY,
	   "fill(XX000): category = ERRCATEGORY_INTERNAL_ERROR_CATEGORY");
	ok(info.severity == PGSQL_ERROR_SEVERITY::ERRSEVERITY_PANIC,
	   "fill(XX000): severity = ERRSEVERITY_PANIC");
}

// ============================================================
// Error class coverage via fill_error_info — exercise more
// class branches in identify_error_class()
// ============================================================

static void test_fill_error_class_branches() {
	PgSQL_ErrorInfo info;

	// 01xxx -> WARNING class -> STATUS category
	PgSQL_Error_Helper::fill_error_info(info, "01000", "warning", "WARNING");
	ok(info.type == PGSQL_ERROR_CLASS::ERRCLASS_WARNING,
	   "fill(01000): type = ERRCLASS_WARNING");
	ok(info.category == PGSQL_ERROR_CATEGORY::ERRCATEGORY_STATUS,
	   "fill(01000): category = ERRCATEGORY_STATUS");

	// 02xxx -> NO_DATA class -> STATUS category
	PgSQL_Error_Helper::fill_error_info(info, "02000", "no data", "WARNING");
	ok(info.type == PGSQL_ERROR_CLASS::ERRCLASS_NO_DATA,
	   "fill(02000): type = ERRCLASS_NO_DATA");
	ok(info.category == PGSQL_ERROR_CATEGORY::ERRCATEGORY_STATUS,
	   "fill(02000): category = ERRCATEGORY_STATUS");

	// 03xxx -> SQL_STATEMENT_NOT_YET_COMPLETE -> STATUS
	PgSQL_Error_Helper::fill_error_info(info, "03000", "not yet complete", "ERROR");
	ok(info.type == PGSQL_ERROR_CLASS::ERRCLASS_SQL_STATEMENT_NOT_YET_COMPLETE,
	   "fill(03000): type = ERRCLASS_SQL_STATEMENT_NOT_YET_COMPLETE");
	ok(info.category == PGSQL_ERROR_CATEGORY::ERRCATEGORY_STATUS,
	   "fill(03000): category = ERRCATEGORY_STATUS");

	// 09xxx -> TRIGGERED_ACTION_EXCEPTION -> TRANSACTION_ERROR
	PgSQL_Error_Helper::fill_error_info(info, "09000", "triggered action", "ERROR");
	ok(info.type == PGSQL_ERROR_CLASS::ERRCLASS_TRIGGERED_ACTION_EXCEPTION,
	   "fill(09000): type = ERRCLASS_TRIGGERED_ACTION_EXCEPTION");
	ok(info.category == PGSQL_ERROR_CATEGORY::ERRCATEGORY_TRANSACTION_ERROR,
	   "fill(09000): category = ERRCATEGORY_TRANSACTION_ERROR");

	// 0Axxx -> FEATURE_NOT_SUPPORTED -> FEATURE_NOT_SUPPORTED
	PgSQL_Error_Helper::fill_error_info(info, "0A000", "feature not supported", "ERROR");
	ok(info.type == PGSQL_ERROR_CLASS::ERRCLASS_FEATURE_NOT_SUPPORTED,
	   "fill(0A000): type = ERRCLASS_FEATURE_NOT_SUPPORTED");
	ok(info.category == PGSQL_ERROR_CATEGORY::ERRCATEGORY_FEATURE_NOT_SUPPORTED,
	   "fill(0A000): category = ERRCATEGORY_FEATURE_NOT_SUPPORTED");

	// 0Bxxx -> INVALID_TRANSACTION_INITIATION -> TRANSACTION_ERROR
	PgSQL_Error_Helper::fill_error_info(info, "0B000", "invalid txn init", "ERROR");
	ok(info.type == PGSQL_ERROR_CLASS::ERRCLASS_INVALID_TRANSACTION_INITIATION,
	   "fill(0B000): type = ERRCLASS_INVALID_TRANSACTION_INITIATION");
	ok(info.category == PGSQL_ERROR_CATEGORY::ERRCATEGORY_TRANSACTION_ERROR,
	   "fill(0B000): category = ERRCATEGORY_TRANSACTION_ERROR");

	// 0Fxxx -> LOCATOR_EXCEPTION -> UNKNOWN (not explicitly mapped)
	PgSQL_Error_Helper::fill_error_info(info, "0F000", "locator", "ERROR");
	ok(info.type == PGSQL_ERROR_CLASS::ERRCLASS_LOCATOR_EXCEPTION,
	   "fill(0F000): type = ERRCLASS_LOCATOR_EXCEPTION");

	// 0Lxxx -> INVALID_GRANTOR -> AUTHORIZATION_ERROR
	PgSQL_Error_Helper::fill_error_info(info, "0L000", "invalid grantor", "ERROR");
	ok(info.type == PGSQL_ERROR_CLASS::ERRCLASS_INVALID_GRANTOR,
	   "fill(0L000): type = ERRCLASS_INVALID_GRANTOR");
	ok(info.category == PGSQL_ERROR_CATEGORY::ERRCATEGORY_AUTHORIZATION_ERROR,
	   "fill(0L000): category = ERRCATEGORY_AUTHORIZATION_ERROR");

	// 0Pxxx -> INVALID_ROLE_SPECIFICATION -> AUTHORIZATION_ERROR
	PgSQL_Error_Helper::fill_error_info(info, "0P000", "invalid role", "ERROR");
	ok(info.type == PGSQL_ERROR_CLASS::ERRCLASS_INVALID_ROLE_SPECIFICATION,
	   "fill(0P000): type = ERRCLASS_INVALID_ROLE_SPECIFICATION");
	ok(info.category == PGSQL_ERROR_CATEGORY::ERRCATEGORY_AUTHORIZATION_ERROR,
	   "fill(0P000): category = ERRCATEGORY_AUTHORIZATION_ERROR");

	// 0Zxxx -> DIAGNOSTICS_EXCEPTION -> default/UNKNOWN
	PgSQL_Error_Helper::fill_error_info(info, "0Z000", "diagnostics", "ERROR");
	ok(info.type == PGSQL_ERROR_CLASS::ERRCLASS_DIAGNOSTICS_EXCEPTION,
	   "fill(0Z000): type = ERRCLASS_DIAGNOSTICS_EXCEPTION");

	// 20xxx -> CASE_NOT_FOUND -> DATA_ERROR
	PgSQL_Error_Helper::fill_error_info(info, "20000", "case not found", "ERROR");
	ok(info.type == PGSQL_ERROR_CLASS::ERRCLASS_CASE_NOT_FOUND,
	   "fill(20000): type = ERRCLASS_CASE_NOT_FOUND");
	ok(info.category == PGSQL_ERROR_CATEGORY::ERRCATEGORY_DATA_ERROR,
	   "fill(20000): category = ERRCATEGORY_DATA_ERROR");

	// 21xxx -> CARDINALITY_VIOLATION -> DATA_ERROR
	PgSQL_Error_Helper::fill_error_info(info, "21000", "cardinality", "ERROR");
	ok(info.type == PGSQL_ERROR_CLASS::ERRCLASS_CARDINALITY_VIOLATION,
	   "fill(21000): type = ERRCLASS_CARDINALITY_VIOLATION");
	ok(info.category == PGSQL_ERROR_CATEGORY::ERRCATEGORY_DATA_ERROR,
	   "fill(21000): category = ERRCATEGORY_DATA_ERROR");

	// 22xxx -> DATA_EXCEPTION -> DATA_ERROR
	PgSQL_Error_Helper::fill_error_info(info, "22000", "data exception", "ERROR");
	ok(info.type == PGSQL_ERROR_CLASS::ERRCLASS_DATA_EXCEPTION,
	   "fill(22000): type = ERRCLASS_DATA_EXCEPTION");
	ok(info.category == PGSQL_ERROR_CATEGORY::ERRCATEGORY_DATA_ERROR,
	   "fill(22000): category = ERRCATEGORY_DATA_ERROR");

	// 24xxx -> INVALID_CURSOR_STATE -> CURSOR_ERROR
	PgSQL_Error_Helper::fill_error_info(info, "24000", "invalid cursor state", "ERROR");
	ok(info.type == PGSQL_ERROR_CLASS::ERRCLASS_INVALID_CURSOR_STATE,
	   "fill(24000): type = ERRCLASS_INVALID_CURSOR_STATE");
	ok(info.category == PGSQL_ERROR_CATEGORY::ERRCATEGORY_CURSOR_ERROR,
	   "fill(24000): category = ERRCATEGORY_CURSOR_ERROR");

	// 25xxx -> INVALID_TRANSACTION_STATE -> TRANSACTION_ERROR
	PgSQL_Error_Helper::fill_error_info(info, "25000", "invalid txn state", "ERROR");
	ok(info.type == PGSQL_ERROR_CLASS::ERRCLASS_INVALID_TRANSACTION_STATE,
	   "fill(25000): type = ERRCLASS_INVALID_TRANSACTION_STATE");
	ok(info.category == PGSQL_ERROR_CATEGORY::ERRCATEGORY_TRANSACTION_ERROR,
	   "fill(25000): category = ERRCATEGORY_TRANSACTION_ERROR");

	// 26xxx -> INVALID_SQL_STATEMENT_NAME -> default/UNKNOWN
	PgSQL_Error_Helper::fill_error_info(info, "26000", "invalid stmt name", "ERROR");
	ok(info.type == PGSQL_ERROR_CLASS::ERRCLASS_INVALID_SQL_STATEMENT_NAME,
	   "fill(26000): type = ERRCLASS_INVALID_SQL_STATEMENT_NAME");

	// 27xxx -> TRIGGERED_DATA_CHANGE_VIOLATION -> ROUTINE_ERROR
	PgSQL_Error_Helper::fill_error_info(info, "27000", "triggered data change", "ERROR");
	ok(info.type == PGSQL_ERROR_CLASS::ERRCLASS_TRIGGERED_DATA_CHANGE_VIOLATION,
	   "fill(27000): type = ERRCLASS_TRIGGERED_DATA_CHANGE_VIOLATION");
	ok(info.category == PGSQL_ERROR_CATEGORY::ERRCATEGORY_ROUTINE_ERROR,
	   "fill(27000): category = ERRCATEGORY_ROUTINE_ERROR");

	// 28xxx -> INVALID_AUTHORIZATION_SPECIFICATION -> AUTHORIZATION_ERROR
	PgSQL_Error_Helper::fill_error_info(info, "28000", "invalid auth", "ERROR");
	ok(info.type == PGSQL_ERROR_CLASS::ERRCLASS_INVALID_AUTHORIZATION_SPECIFICATION,
	   "fill(28000): type = ERRCLASS_INVALID_AUTHORIZATION_SPECIFICATION");
	ok(info.category == PGSQL_ERROR_CATEGORY::ERRCATEGORY_AUTHORIZATION_ERROR,
	   "fill(28000): category = ERRCATEGORY_AUTHORIZATION_ERROR");

	// 2Bxxx -> DEPENDENT_PRIVILEGE_DESCRIPTORS -> default/UNKNOWN
	PgSQL_Error_Helper::fill_error_info(info, "2B000", "dependent priv", "ERROR");
	ok(info.type == PGSQL_ERROR_CLASS::ERRCLASS_DEPENDENT_PRIVILEGE_DESCRIPTORS_STILL_EXIST,
	   "fill(2B000): type = ERRCLASS_DEPENDENT_PRIVILEGE_DESCRIPTORS_STILL_EXIST");

	// 2Dxxx -> INVALID_TRANSACTION_TERMINATION -> TRANSACTION_ERROR  (not in switch but would fall to default)
	PgSQL_Error_Helper::fill_error_info(info, "2D000", "invalid txn term", "ERROR");
	ok(info.type == PGSQL_ERROR_CLASS::ERRCLASS_INVALID_TRANSACTION_TERMINATION,
	   "fill(2D000): type = ERRCLASS_INVALID_TRANSACTION_TERMINATION");

	// 2Fxxx -> SQL_ROUTINE_EXCEPTION -> ROUTINE_ERROR
	PgSQL_Error_Helper::fill_error_info(info, "2F000", "sql routine", "ERROR");
	ok(info.type == PGSQL_ERROR_CLASS::ERRCLASS_SQL_ROUTINE_EXCEPTION,
	   "fill(2F000): type = ERRCLASS_SQL_ROUTINE_EXCEPTION");
	ok(info.category == PGSQL_ERROR_CATEGORY::ERRCATEGORY_ROUTINE_ERROR,
	   "fill(2F000): category = ERRCATEGORY_ROUTINE_ERROR");

	// 34xxx -> INVALID_CURSOR_NAME -> CURSOR_ERROR
	PgSQL_Error_Helper::fill_error_info(info, "34000", "invalid cursor name", "ERROR");
	ok(info.type == PGSQL_ERROR_CLASS::ERRCLASS_INVALID_CURSOR_NAME,
	   "fill(34000): type = ERRCLASS_INVALID_CURSOR_NAME");
	ok(info.category == PGSQL_ERROR_CATEGORY::ERRCATEGORY_CURSOR_ERROR,
	   "fill(34000): category = ERRCATEGORY_CURSOR_ERROR");

	// 38xxx -> EXTERNAL_ROUTINE_EXCEPTION -> EXTERNAL_ROUTINE_ERROR
	PgSQL_Error_Helper::fill_error_info(info, "38000", "external routine", "ERROR");
	ok(info.type == PGSQL_ERROR_CLASS::ERRCLASS_EXTERNAL_ROUTINE_EXCEPTION,
	   "fill(38000): type = ERRCLASS_EXTERNAL_ROUTINE_EXCEPTION");
	ok(info.category == PGSQL_ERROR_CATEGORY::ERRCATEGORY_EXTERNAL_ROUTINE_ERROR,
	   "fill(38000): category = ERRCATEGORY_EXTERNAL_ROUTINE_ERROR");

	// 39xxx -> EXTERNAL_ROUTINE_INVOCATION_EXCEPTION -> EXTERNAL_ROUTINE_ERROR
	PgSQL_Error_Helper::fill_error_info(info, "39000", "ext routine invocation", "ERROR");
	ok(info.type == PGSQL_ERROR_CLASS::ERRCLASS_EXTERNAL_ROUTINE_INVOCATION_EXCEPTION,
	   "fill(39000): type = ERRCLASS_EXTERNAL_ROUTINE_INVOCATION_EXCEPTION");
	ok(info.category == PGSQL_ERROR_CATEGORY::ERRCATEGORY_EXTERNAL_ROUTINE_ERROR,
	   "fill(39000): category = ERRCATEGORY_EXTERNAL_ROUTINE_ERROR");

	// 3Bxxx -> SAVEPOINT_EXCEPTION -> TRANSACTION_ERROR
	PgSQL_Error_Helper::fill_error_info(info, "3B000", "savepoint", "ERROR");
	ok(info.type == PGSQL_ERROR_CLASS::ERRCLASS_SAVEPOINT_EXCEPTION,
	   "fill(3B000): type = ERRCLASS_SAVEPOINT_EXCEPTION");
	ok(info.category == PGSQL_ERROR_CATEGORY::ERRCATEGORY_TRANSACTION_ERROR,
	   "fill(3B000): category = ERRCATEGORY_TRANSACTION_ERROR");

	// 3Dxxx -> INVALID_CATALOG_NAME -> default/UNKNOWN
	PgSQL_Error_Helper::fill_error_info(info, "3D000", "invalid catalog", "ERROR");
	ok(info.type == PGSQL_ERROR_CLASS::ERRCLASS_INVALID_CATALOG_NAME,
	   "fill(3D000): type = ERRCLASS_INVALID_CATALOG_NAME");

	// 3Fxxx -> INVALID_SCHEMA_NAME -> default/UNKNOWN
	PgSQL_Error_Helper::fill_error_info(info, "3F000", "invalid schema", "ERROR");
	ok(info.type == PGSQL_ERROR_CLASS::ERRCLASS_INVALID_SCHEMA_NAME,
	   "fill(3F000): type = ERRCLASS_INVALID_SCHEMA_NAME");

	// 40xxx -> TRANSACTION_ROLLBACK -> TRANSACTION_ERROR
	PgSQL_Error_Helper::fill_error_info(info, "40000", "txn rollback", "ERROR");
	ok(info.type == PGSQL_ERROR_CLASS::ERRCLASS_TRANSACTION_ROLLBACK,
	   "fill(40000): type = ERRCLASS_TRANSACTION_ROLLBACK");
	ok(info.category == PGSQL_ERROR_CATEGORY::ERRCATEGORY_TRANSACTION_ERROR,
	   "fill(40000): category = ERRCATEGORY_TRANSACTION_ERROR");

	// 44xxx -> WITH_CHECK_OPTION_VIOLATION -> DATA_ERROR
	PgSQL_Error_Helper::fill_error_info(info, "44000", "check option", "ERROR");
	ok(info.type == PGSQL_ERROR_CLASS::ERRCLASS_WITH_CHECK_OPTION_VIOLATION,
	   "fill(44000): type = ERRCLASS_WITH_CHECK_OPTION_VIOLATION");
	ok(info.category == PGSQL_ERROR_CATEGORY::ERRCATEGORY_DATA_ERROR,
	   "fill(44000): category = ERRCATEGORY_DATA_ERROR");

	// 53xxx -> INSUFFICIENT_RESOURCES -> RESOURCE_ERROR
	PgSQL_Error_Helper::fill_error_info(info, "53000", "insufficient resources", "ERROR");
	ok(info.type == PGSQL_ERROR_CLASS::ERRCLASS_INSUFFICIENT_RESOURCES,
	   "fill(53000): type = ERRCLASS_INSUFFICIENT_RESOURCES");
	ok(info.category == PGSQL_ERROR_CATEGORY::ERRCATEGORY_RESOURCE_ERROR,
	   "fill(53000): category = ERRCATEGORY_RESOURCE_ERROR");

	// 54xxx -> PROGRAM_LIMIT_EXCEEDED -> RESOURCE_LIMIT_ERROR
	PgSQL_Error_Helper::fill_error_info(info, "54000", "program limit", "ERROR");
	ok(info.type == PGSQL_ERROR_CLASS::ERRCLASS_PROGRAM_LIMIT_EXCEEDED,
	   "fill(54000): type = ERRCLASS_PROGRAM_LIMIT_EXCEEDED");
	ok(info.category == PGSQL_ERROR_CATEGORY::ERRCATEGORY_RESOURCE_LIMIT_ERROR,
	   "fill(54000): category = ERRCATEGORY_RESOURCE_LIMIT_ERROR");

	// 55xxx -> OBJECT_NOT_IN_PREREQUISITE_STATE -> OBJECT_STATE_ERROR
	PgSQL_Error_Helper::fill_error_info(info, "55000", "object state", "ERROR");
	ok(info.type == PGSQL_ERROR_CLASS::ERRCLASS_OBJECT_NOT_IN_PREREQUISITE_STATE,
	   "fill(55000): type = ERRCLASS_OBJECT_NOT_IN_PREREQUISITE_STATE");
	ok(info.category == PGSQL_ERROR_CATEGORY::ERRCATEGORY_OBJECT_STATE_ERROR,
	   "fill(55000): category = ERRCATEGORY_OBJECT_STATE_ERROR");

	// 57xxx -> OPERATOR_INTERVENTION -> OPERATOR_INTERVENTION_ERROR
	PgSQL_Error_Helper::fill_error_info(info, "57000", "operator intervention", "ERROR");
	ok(info.type == PGSQL_ERROR_CLASS::ERRCLASS_OPERATOR_INTERVENTION,
	   "fill(57000): type = ERRCLASS_OPERATOR_INTERVENTION");
	ok(info.category == PGSQL_ERROR_CATEGORY::ERRCATEGORY_OPERATOR_INTERVENTION_ERROR,
	   "fill(57000): category = ERRCATEGORY_OPERATOR_INTERVENTION_ERROR");

	// 58xxx -> SYSTEM_ERROR_UNSPECIFIED -> default/UNKNOWN
	PgSQL_Error_Helper::fill_error_info(info, "58000", "system error", "ERROR");
	ok(info.type == PGSQL_ERROR_CLASS::ERRCLASS_SYSTEM_ERROR_UNSPECIFIED,
	   "fill(58000): type = ERRCLASS_SYSTEM_ERROR_UNSPECIFIED");

	// 72xxx -> CRASH_SHUTDOWN
	PgSQL_Error_Helper::fill_error_info(info, "72000", "crash shutdown", "ERROR");
	ok(info.type == PGSQL_ERROR_CLASS::ERRCLASS_CRASH_SHUTDOWN,
	   "fill(72000): type = ERRCLASS_CRASH_SHUTDOWN");

	// F0xxx -> CONFIG_FILE_ERROR -> CONFIGURATION_ERROR
	PgSQL_Error_Helper::fill_error_info(info, "F0000", "config file error", "ERROR");
	ok(info.type == PGSQL_ERROR_CLASS::ERRCLASS_CONFIG_FILE_ERROR,
	   "fill(F0000): type = ERRCLASS_CONFIG_FILE_ERROR");
	ok(info.category == PGSQL_ERROR_CATEGORY::ERRCATEGORY_CONFIGURATION_ERROR,
	   "fill(F0000): category = ERRCATEGORY_CONFIGURATION_ERROR");

	// HVxxx -> FOREIGN_DATA_WRAPPER_ERROR -> FDW_ERROR
	PgSQL_Error_Helper::fill_error_info(info, "HV000", "fdw error", "ERROR");
	ok(info.type == PGSQL_ERROR_CLASS::ERRCLASS_FOREIGN_DATA_WRAPPER_ERROR,
	   "fill(HV000): type = ERRCLASS_FOREIGN_DATA_WRAPPER_ERROR");
	ok(info.category == PGSQL_ERROR_CATEGORY::ERRCATEGORY_FDW_ERROR,
	   "fill(HV000): category = ERRCATEGORY_FDW_ERROR");

	// P0xxx -> PLPGSQL_ERROR -> PLPGSQL_ERROR
	PgSQL_Error_Helper::fill_error_info(info, "P0000", "plpgsql error", "ERROR");
	ok(info.type == PGSQL_ERROR_CLASS::ERRCLASS_PLPGSQL_ERROR,
	   "fill(P0000): type = ERRCLASS_PLPGSQL_ERROR");
	ok(info.category == PGSQL_ERROR_CATEGORY::ERRCATEGORY_PLPGSQL_ERROR,
	   "fill(P0000): category = ERRCATEGORY_PLPGSQL_ERROR");
}

// ============================================================
// fill_error_info with severity variations
// ============================================================

static void test_fill_severity_variations() {
	PgSQL_ErrorInfo info;

	PgSQL_Error_Helper::fill_error_info(info, "00000", "ok", "FATAL");
	ok(info.severity == PGSQL_ERROR_SEVERITY::ERRSEVERITY_FATAL,
	   "fill severity: FATAL");

	PgSQL_Error_Helper::fill_error_info(info, "00000", "ok", "ERROR");
	ok(info.severity == PGSQL_ERROR_SEVERITY::ERRSEVERITY_ERROR,
	   "fill severity: ERROR");

	PgSQL_Error_Helper::fill_error_info(info, "00000", "ok", "WARNING");
	ok(info.severity == PGSQL_ERROR_SEVERITY::ERRSEVERITY_WARNING,
	   "fill severity: WARNING");

	PgSQL_Error_Helper::fill_error_info(info, "00000", "ok", "NOTICE");
	ok(info.severity == PGSQL_ERROR_SEVERITY::ERRSEVERITY_NOTICE,
	   "fill severity: NOTICE");

	PgSQL_Error_Helper::fill_error_info(info, "00000", "ok", "PANIC");
	ok(info.severity == PGSQL_ERROR_SEVERITY::ERRSEVERITY_PANIC,
	   "fill severity: PANIC");

	PgSQL_Error_Helper::fill_error_info(info, "00000", "ok", "DEBUG");
	ok(info.severity == PGSQL_ERROR_SEVERITY::ERRSEVERITY_DEBUG,
	   "fill severity: DEBUG");

	PgSQL_Error_Helper::fill_error_info(info, "00000", "ok", "LOG");
	ok(info.severity == PGSQL_ERROR_SEVERITY::ERRSEVERITY_LOG,
	   "fill severity: LOG");

	PgSQL_Error_Helper::fill_error_info(info, "00000", "ok", "INFO");
	ok(info.severity == PGSQL_ERROR_SEVERITY::ERRSEVERITY_INFO,
	   "fill severity: INFO");

	// Unknown severity string
	PgSQL_Error_Helper::fill_error_info(info, "00000", "ok", "GIBBERISH");
	ok(info.severity == PGSQL_ERROR_SEVERITY::ERRSEVERITY_UNKNOWN_SEVERITY,
	   "fill severity: unknown string = ERRSEVERITY_UNKNOWN_SEVERITY");
}

// ============================================================
// fill_error_info with PGSQL_ERROR_CODES enum overload
// ============================================================

static void test_fill_error_info_enum_overload() {
	PgSQL_ErrorInfo info;
	PgSQL_Error_Helper::fill_error_info(info, PGSQL_ERROR_CODES::ERRCODE_SYNTAX_ERROR,
	                                    "syntax error", PGSQL_ERROR_SEVERITY::ERRSEVERITY_ERROR);

	ok(info.code == PGSQL_ERROR_CODES::ERRCODE_SYNTAX_ERROR,
	   "fill(enum): code = ERRCODE_SYNTAX_ERROR");
	ok(info.severity == PGSQL_ERROR_SEVERITY::ERRSEVERITY_ERROR,
	   "fill(enum): severity = ERRSEVERITY_ERROR");
	ok(strcmp(info.sqlstate, "42601") == 0,
	   "fill(enum): sqlstate = '42601'");
	ok(info.type == PGSQL_ERROR_CLASS::ERRCLASS_SYNTAX_ERROR_OR_ACCESS_RULE_VIOLATION,
	   "fill(enum): type = ERRCLASS_SYNTAX_ERROR_OR_ACCESS_RULE_VIOLATION");
	ok(info.message == "syntax error",
	   "fill(enum): message stored correctly");
}

// ============================================================
// Unknown/invalid SQLSTATE edge cases
// ============================================================

static void test_fill_unknown_sqlstate() {
	PgSQL_ErrorInfo info;

	// Completely unknown SQLSTATE
	PgSQL_Error_Helper::fill_error_info(info, "99999", "unknown", "ERROR");
	ok(info.code == PGSQL_ERROR_CODES::ERRCODE_UNKNOWN,
	   "fill(99999): code = ERRCODE_UNKNOWN");
	ok(info.type == PGSQL_ERROR_CLASS::ERRCLASS_UNKNOWN_ERROR,
	   "fill(99999): type = ERRCLASS_UNKNOWN_ERROR");

	// Too short SQLSTATE (identify_error_code returns UNKNOWN for len != 5)
	PgSQL_Error_Helper::fill_error_info(info, "42", "short", "ERROR");
	ok(info.code == PGSQL_ERROR_CODES::ERRCODE_UNKNOWN,
	   "fill(42): too-short sqlstate -> ERRCODE_UNKNOWN");
	// But identify_error_class uses first 2 chars, so class should still resolve
	ok(info.type == PGSQL_ERROR_CLASS::ERRCLASS_SYNTAX_ERROR_OR_ACCESS_RULE_VIOLATION,
	   "fill(42): class still resolves from 2-char prefix");
}

// ============================================================
// reset_error_info() tests
// ============================================================

static void test_reset_error_info() {
	PgSQL_ErrorInfo info;
	PgSQL_Error_Helper::fill_error_info(info, "42601", "syntax error", "ERROR");

	// Verify fields are set
	ok(info.code != PGSQL_ERROR_CODES::ERRCODE_SUCCESSFUL_COMPLETION,
	   "reset: pre-condition - code is set");

	reset_error_info(info, true);

	ok(info.code == PGSQL_ERROR_CODES::ERRCODE_SUCCESSFUL_COMPLETION,
	   "reset: code = ERRCODE_SUCCESSFUL_COMPLETION");
	ok(info.severity == PGSQL_ERROR_SEVERITY::ERRSEVERITY_UNKNOWN_SEVERITY,
	   "reset: severity = ERRSEVERITY_UNKNOWN_SEVERITY");
	ok(info.type == PGSQL_ERROR_CLASS::ERRCLASS_UNKNOWN_ERROR,
	   "reset: type = ERRCLASS_UNKNOWN_ERROR");
	ok(info.category == PGSQL_ERROR_CATEGORY::ERRCATEGORY_UNKNOWN_CATEGORY,
	   "reset: category = ERRCATEGORY_UNKNOWN_CATEGORY");
	ok(info.message.empty(),
	   "reset: message cleared");
	ok(info.sqlstate[0] == '\0',
	   "reset: sqlstate cleared");
}

// ============================================================
// PgSQL_ErrorInfo_Ext::reset() test
// ============================================================

static void test_ext_info_reset() {
	PgSQL_ErrorInfo_Ext ext;
	ext.text = PGSQL_ERROR_SEVERITY::ERRSEVERITY_ERROR;
	ext.detail = "detail text";
	ext.hint = "hint text";
	ext.schema_name = "public";
	ext.table_name = "users";
	ext.column_name = "id";
	ext.source_file = "test.c";
	ext.source_line = "42";
	ext.source_function = "do_stuff";

	ext.reset();

	ok(ext.text == PGSQL_ERROR_SEVERITY::ERRSEVERITY_UNKNOWN_SEVERITY,
	   "ext reset: text = UNKNOWN");
	ok(ext.detail.empty(), "ext reset: detail cleared");
	ok(ext.hint.empty(), "ext reset: hint cleared");
	ok(ext.schema_name.empty(), "ext reset: schema_name cleared");
	ok(ext.table_name.empty(), "ext reset: table_name cleared");
	ok(ext.column_name.empty(), "ext reset: column_name cleared");
	ok(ext.source_file.empty(), "ext reset: source_file cleared");
	ok(ext.source_line.empty(), "ext reset: source_line cleared");
	ok(ext.source_function.empty(), "ext reset: source_function cleared");
}

int main() {
	plan(139);
	test_init_minimal();

	test_get_error_code();                  // 8
	test_get_severity();                    // 9
	test_fill_error_info_syntax_error();    // 6
	test_fill_error_info_connection_exception(); // 4
	test_fill_error_info_unique_violation();// 3
	test_fill_error_info_successful_completion(); // 4
	test_fill_error_info_internal_error();  // 4
	test_fill_error_class_branches();       // 54
	test_fill_severity_variations();        // 9
	test_fill_error_info_enum_overload();   // 5
	test_fill_unknown_sqlstate();           // 4
	test_reset_error_info();               // 7
	test_ext_info_reset();                 // 9

	test_cleanup_minimal();
	return exit_status();
}
