#ifndef PGSQL_VARIABLES_VALIDATOR_H
#define PGSQL_VARIABLES_VALIDATOR_H
#include "proxysql.h"

typedef enum {
	VARIABLE_TYPE_NONE = 0, /**< No variable type. */
	VARIABLE_TYPE_INT, /**< Integer variable type. */
	VARIABLE_TYPE_FLOAT, /**< Float variable type. */
	VARIABLE_TYPE_BOOL, /**< Boolean variable type. */
	VARIABLE_TYPE_STRING, /**< String variable type. */
	VARIABLE_TYPE_DATESTYLE, /**< DateStyle variable type. */
	VARIABLE_TYPE_MAINTENANCE_WORK_MEM, /**< MaintenanceWorkMem variable type. */
	VARIABLE_TYPE_CLIENT_ENCODING /**< ClientEncoding variable type. */
} pgsql_variable_type_t;


template<typename T> 
struct range_t {
	T min; /**< Minimum value of the range. */
	T max; /**< Maximum value of the range. */
};

/**
 * @union params_t
 * @brief Union representing the parameters for variable validation.
 */
typedef union {
	range_t<int> int_range; /**< Integer range parameters. */
	range_t<unsigned int> uint_range; /**< Integer range parameters. */
	range_t<float> float_range; /**< Float range parameters. */
	const char** string_allowed; /**< Allowed string values. */
} params_t;

/**
 * @typedef pgsql_variable_validate_fn_t
 * @brief Function pointer type for variable value validation.
 * 
 * @param original_value The original value of the variable.
 * @param params The parameters for validation.
 * @param session The PostgreSQL session.
 * @param transformed_value The transformed value after validation.
 * @return True if validation is successful, false otherwise.
 */
typedef bool (*pgsql_variable_validate_fn_t)(const char* original_value, const params_t* params, PgSQL_Session* session, char** transformed_value);

/**
 * @struct pgsql_variable_validator
 * @brief Struct representing a PostgreSQL variable validator.
 */
struct pgsql_variable_validator {
	pgsql_variable_type_t type; /**< The type of the variable. */
	pgsql_variable_validate_fn_t validate; /**< The validation function. */
	params_t params; /**< The parameters for validation. */
};

extern const pgsql_variable_validator pgsql_variable_validator_bool;
extern const pgsql_variable_validator pgsql_variable_validator_intervalstyle;
extern const pgsql_variable_validator pgsql_variable_validator_synchronous_commit;
extern const pgsql_variable_validator pgsql_variable_validator_datestyle;
extern const pgsql_variable_validator pgsql_variable_validator_integer;
extern const pgsql_variable_validator pgsql_variable_validator_client_min_messages;
extern const pgsql_variable_validator pgsql_variable_validator_bytea_output;
extern const pgsql_variable_validator pgsql_variable_validator_extra_float_digits;
extern const pgsql_variable_validator pgsql_variable_validator_maintenance_work_mem;
extern const pgsql_variable_validator pgsql_variable_validator_client_encoding;
extern const pgsql_variable_validator pgsql_variable_validator_search_path;
#endif // PGSQL_VARIABLES_VALIDATOR_H
