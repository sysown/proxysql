#ifndef PGSQL_VARIABLES_H
#define PGSQL_VARIABLES_H

#include "proxysql.h"

#include <cstdint>
#include <vector>
#include <memory>

class PgSQL_Session;

extern void print_backtrace(void);

typedef bool (*pgsql_verify_var)(PgSQL_Session* session, int idx, uint32_t client_hash, uint32_t server_hash);
typedef bool (*pgsql_update_var)(PgSQL_Session* session, int idx, int &_rc);

bool update_server_variable(PgSQL_Session* session, int idx, int &_rc);
bool verify_server_variable(PgSQL_Session* session, int idx, uint32_t client_hash, uint32_t server_hash);

class PgSQL_Variables {
	static pgsql_verify_var verifiers[PGSQL_NAME_LAST_HIGH_WM];
	static pgsql_update_var updaters[PGSQL_NAME_LAST_HIGH_WM];

public:
	std::string variables_regexp;
	// ignore_vars is a list of all variables that proxysql will parse but ignore its value
	std::vector<std::string> ignore_vars;
public:
	PgSQL_Variables();
	~PgSQL_Variables();

	/**
	 * @brief Builds the pattern that routes a SET digest to the tracked-variable path.
	 *
	 * The variable name must be followed by the end of the digest, whitespace or '='.
	 * A plain prefix test would also send untracked names such as 'timezone_abbreviations'
	 * or the custom 'timezone.foo' down that path, where they are forwarded without
	 * locking the hostgroup. '\b' is not enough either: '.' is a non-word character.
	 *
	 * @param vars_regexp Alternation of the tracked and ignored names ('variables_regexp').
	 * @return The pattern, to be matched case-insensitively with RE2::PartialMatch().
	 */
	static std::string build_set_tracked_vars_regexp(const std::string& vars_regexp);

	/**
	 * @brief True when the statement `text` holds is 'SET [LOCAL|SESSION] TRANSACTION ...'.
	 *
	 * That form, including 'TRANSACTION SNAPSHOT', changes only the current transaction.
	 * PostgreSQL accepts it only inside a transaction block, where the session already
	 * holds its backend, and outside one it is a no-op that only raises a WARNING. Nothing
	 * survives the transaction, so there is nothing to track and no reason to lock the
	 * hostgroup. TRANSACTION must follow SET or its one scope word directly: the session-wide
	 * 'SET SESSION CHARACTERISTICS AS TRANSACTION ...' does not match.
	 *
	 * The words are read as PostgreSQL's lexer reads them: case-insensitive, and separated by
	 * whitespace, line comments or block comments, which nest. Leading whitespace and comments
	 * are skipped. After TRANSACTION comes a separator, ';' or the end of the text, and only
	 * whitespace and comments may follow any ';' (quotes are not read, so none can hide one).
	 *
	 * @param text A query text or a digest (query_digests_keep_comment keeps block comments).
	 */
	static bool is_set_transaction_stmt(const char* text);

	/**
	 * @brief True when a SET is 'SET [LOCAL|SESSION] TRANSACTION ...'.
	 *
	 * Both the digest and the query text must pass is_set_transaction_stmt(). The digest
	 * alone is not enough: ParserSQL 1.1.0 (pgsql-query_processor_parser=1) digests
	 * 'SET SESSION CHARACTERISTICS AS TRANSACTION READ ONLY' as 'SET TRANSACTION READ ONLY'.
	 *
	 * @param digest Digest text of the query.
	 * @param query  Query text exactly as the client sent it, comments included.
	 */
	static bool is_set_transaction(const char* digest, const char* query);

	bool client_set_value(PgSQL_Session* session, int idx, const std::string& value, bool reorder_dynamic_variables_idx);
	bool client_set_hash_and_value(PgSQL_Session* session, int idx, const std::string& value, uint32_t hash);
	void client_reset_value(PgSQL_Session* session, int idx, bool reorder_dynamic_variables_idx);
	const char* client_get_value(PgSQL_Session* session, int idx) const;
	uint32_t client_get_hash(PgSQL_Session* session, int idx) const;

	void server_set_value(PgSQL_Session* session, int idx, const char* value, bool reorder_dynamic_variables_idx);
	void server_set_hash_and_value(PgSQL_Session* session, int idx, const char* value, uint32_t hash);
	void server_reset_value(PgSQL_Session* session, int idx, bool reorder_dynamic_variables_idx);
	const char* server_get_value(PgSQL_Session* session, int idx) const;
	uint32_t server_get_hash(PgSQL_Session* session, int idx) const;

	bool verify_variable(PgSQL_Session* session, int idx) const;
	bool update_variable(PgSQL_Session* session, session_status status, int &_rc);
};

#endif // PGSQL_VARIABLES_H
