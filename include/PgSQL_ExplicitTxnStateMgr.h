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

    TxnCmd parse(std::string_view input, bool in_transaction_mode) noexcept;

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
