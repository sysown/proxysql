#ifndef PGSQL_EXPLICIT_TRANSACTION_STATE_MANAGER_H
#define PGSQL_EXPLICIT_TRANSACTION_STATE_MANAGER_H
#include <string>
#include <vector>
#include <algorithm>
#include "proxysql.h"
#include "cpp.h"
#include "PgSQL_Connection.h"

#ifndef PROXYJSON
#define PROXYJSON
#include "../deps/json/json_fwd.hpp"
#endif // PROXYJSON

/**
 * @struct PgSQL_Variable_Snapshot
 * @brief Represents a snapshot of PostgreSQL variables during a transaction.
 *
 * This structure is used to store the state of PostgreSQL variables, including
 * their values and hash representations, at a specific point in time during a transaction.
 */
struct PgSQL_Variable_Snapshot {
	char* var_value[PGSQL_NAME_LAST_HIGH_WM] = {}; // Not using smart pointers because we need fine-grained control over hashing when values change
	uint32_t var_hash[PGSQL_NAME_LAST_HIGH_WM] = {};
};

/**
 * @struct TxnCmd
 * @brief Represents a transaction command type begin executed and its associated metadata.
 *
 */
struct TxnCmd {
    /**
     * @enum Type
     * @brief Enumerates the types of transaction commands.
     */
    enum Type { 
        UNKNOWN = -1, 
        BEGIN, 
        COMMIT, 
        ROLLBACK, 
        SAVEPOINT, 
        RELEASE, 
        ROLLBACK_TO,
        ROLLBACK_AND_CHAIN
    } type = Type::UNKNOWN;
    std::string savepoint; //< The name of the savepoint, if applicable.
};

/**
 * @class PgSQL_TxnCmdParser
 * @brief Parses transaction-related commands for PostgreSQL.
 *
 * This class is responsible for tokenizing and interpreting transaction-related
 * commands such as BEGIN, COMMIT, ROLLBACK, SAVEPOINT, etc.
 */
class PgSQL_TxnCmdParser {
public:
    PgSQL_TxnCmdParser() noexcept { tokens.reserve(16); }
    ~PgSQL_TxnCmdParser() noexcept = default;

    TxnCmd parse(std::string_view input) noexcept;

private:
    std::vector<std::string_view> tokens;

    TxnCmd parse_rollback(size_t& pos) noexcept;
    TxnCmd parse_savepoint(size_t& pos) noexcept;
    TxnCmd parse_release(size_t& pos) noexcept;
    TxnCmd parse_start(size_t& pos) noexcept;

    // Helpers
    inline static bool iequals(std::string_view a, std::string_view b) noexcept {
        if (a.size() != b.size()) return false;
        for (size_t i = 0; i < a.size(); ++i) {
            char ca = a[i];
            char cb = b[i];
            if (ca >= 'A' && ca <= 'Z') ca += 32;
            if (cb >= 'A' && cb <= 'Z') cb += 32;
            if (ca != cb) return false;
        }
        return true;
    }

    inline static bool contains(std::vector<std::string_view>&& list, std::string_view value) noexcept {
        for (const auto& item : list) if (iequals(item, value)) return true;
        return false;
    }
};

/**
 * @class PgSQL_ExplicitTxnStateMgr
 * @brief Manages the state of explicit transactions in PostgreSQL.
 *
 * This class is responsible for handling explicit transaction commands such as
 * BEGIN, COMMIT, ROLLBACK, SAVEPOINT, and managing the associated state.
 */
class PgSQL_ExplicitTxnStateMgr {
public:
	PgSQL_ExplicitTxnStateMgr(PgSQL_Session* sess);
	~PgSQL_ExplicitTxnStateMgr();

    bool handle_transaction(std::string_view input);
	int get_savepoint_count() const { return savepoint.size(); }
    bool is_in_transaction() const { return !transaction_state.empty(); }
    void reset_state();
    // Make the tracker agree with the backend's own transaction status, read at a
    // cycle boundary: end the tracked transaction when it is idle, open one the keywords
    // never showed ('SELECT 1; BEGIN', COMMIT AND CHAIN) when it is in one.
    // 'ended_by' says how a tracked transaction the backend no longer has came to end:
    // 'R' rolled back (the tracked SET variables go back to their values at BEGIN, as
    // PostgreSQL put them back), 'C' committed (they are kept), 0 unknown (they are kept,
    // and the ones changed since BEGIN are re-sent to the backend before its next use,
    // since its own values cannot be known).
    void sync_with_backend(bool backend_in_txn, char ended_by = 0);
    // How the statements of `digest` last end a transaction: 'R' for ROLLBACK / ABORT,
    // 'C' for COMMIT / END, 0 for neither or when the digest cannot be followed to its
    // end. ROLLBACK TO SAVEPOINT and the PREPARED forms end no transaction block.
    static char txn_end_in_digest(const char* digest);
    // Whether running the statements of `digest` could have made a transaction's work durable:
    // a COMMIT (any form), END, or PREPARE TRANSACTION. A digest that cannot be followed to its
    // end counts as one, so a caller asking about a COMMIT that got no reply errs on the safe side.
    static bool commit_in_digest(const char* digest);
    /**
     * @brief Like commit_in_digest(), but safe when the digest is missing or cut short.
     *
     * The digest is whole only for a query up to query_digests_max_query_length, and absent when
     * both query_digests and commands_stats are off. In either case the query text is digested in
     * full here. If that cannot be done the answer is true: a COMMIT that may have taken effect
     * must not be reported as an aborted transaction.
     *
     * @param digest The statement's digest text, or NULL.
     * @param query The statement's own text (NUL-terminated), or NULL.
     */
    static bool commit_in_query(const char* digest, const char* query);
    void fill_internal_session(nlohmann::json& j);

private:
	PgSQL_Session* session;
	std::vector<PgSQL_Variable_Snapshot> transaction_state;
	std::vector<std::string> savepoint;
	PgSQL_TxnCmdParser tx_parser;

    void start_transaction();
    void commit();
    void rollback(bool rollback_and_chain);
    bool add_savepoint(std::string_view name);
    bool rollback_to_savepoint(std::string_view name);
    bool release_savepoint(std::string_view name);

	static void reset_variable_snapshot(PgSQL_Variable_Snapshot& var_snapshot) noexcept;
};

#endif // PGSQL_EXPLICIT_TRANSACTION_STATE_MANAGER_H
