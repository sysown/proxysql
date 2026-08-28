/**
 * @file PgSQLErrorFields.h
 * @brief Parser for PostgreSQL ErrorResponse message fields.
 *
 * Extracted for unit testability. Scans ErrorResponse payload for
 * SQLSTATE ('C') and message ('M') fields.
 *
 * @see PostgreSQL Protocol: ErrorResponse message format
 */

#ifndef PGSQL_ERROR_FIELDS_H
#define PGSQL_ERROR_FIELDS_H

#include <cstdint>
#include <cstddef>

/**
 * @brief Result of parsing a PostgreSQL ErrorResponse payload.
 */
struct PgSQLErrorResult {
    bool parsed;              ///< True if payload was non-null and scanned.
    char sqlstate[6];         ///< 5-char SQLSTATE + null terminator (empty if not found).
    const char* message;      ///< Pointer into payload at 'M' field value (null if not found).
    size_t message_len;       ///< Length of message string.
};

/**
 * @brief Parse a PostgreSQL ErrorResponse payload to extract SQLSTATE and message.
 *
 * Scans the field-type/value pairs in the ErrorResponse payload.
 * Field format: type_byte + null_terminated_string, repeated, ending with '\0'.
 *
 * @param payload  ErrorResponse message payload (after the 5-byte header).
 * @param len      Length of the payload.
 * @return PgSQLErrorResult with parsed fields.
 */
PgSQLErrorResult pgsql_parse_error_response(const unsigned char* payload, size_t len);

#endif // PGSQL_ERROR_FIELDS_H
