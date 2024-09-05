template<typename S, typename DSi, typename B, typename T> class Base_Session;

//// avoid loading definition of MySQL_Session and PgSQL_Session
//#define __CLASS_MYSQL_SESSION_H
//#define __CLASS_PGSQL_SESSION_H

#include "proxysql.h"
#include "cpp.h"

#ifndef CLASS_BASE_SESSION_H
#define CLASS_BASE_SESSION_H

#ifndef PROXYJSON
#define PROXYJSON
#include "../deps/json/json_fwd.hpp"
#endif // PROXYJSON

class MySQL_STMTs_meta;
class StmtLongDataHandler;
class MySQL_Session;
class PgSQL_Session;

template<typename S, typename DS, typename B, typename T>
class Base_Session {
	public:
	Base_Session();
	virtual ~Base_Session();

	// uint64_t
	unsigned long long start_time;
	unsigned long long pause_until;

	unsigned long long idle_since;
	unsigned long long transaction_started_at;

	T * thread;
	B *mybe;
	PtrArray *mybes;
	DS * client_myds;
	/*
	 * @brief Store the hostgroups that hold connections that have been flagged as 'expired' by the
	 *  maintenance thread. These values will be used to release the retained connections in the specific
	 *  hostgroups in housekeeping operations, before client packet processing. Currently 'housekeeping_before_pkts'.
	 */
	std::vector<int32_t> hgs_expired_conns {};
	char * default_schema;
	char * user_attributes;

	//this pointer is always initialized inside handler().
	// it is an attempt to start simplifying the complexing of handler()
	uint32_t thread_session_id;
	unsigned long long last_insert_id;
	int last_HG_affected_rows;
	enum session_status status;
	int healthy;
	int user_max_connections;
	int current_hostgroup;
	int default_hostgroup;
	int previous_hostgroup;
	/**
	 * @brief Charset directly specified by the client. Supplied and updated via 'HandshakeResponse'
	 *   and 'COM_CHANGE_USER' packets.
	 * @details Used when session needs to be restored via 'COM_RESET_CONNECTION'.
	 */
	int default_charset;
	int locked_on_hostgroup;
	int next_query_flagIN;
	int mirror_hostgroup;
	int mirror_flagOUT;
	unsigned int active_transactions;
	int autocommit_on_hostgroup;
	int transaction_persistent_hostgroup;
	int to_process;
	int pending_connect;
	enum proxysql_session_type session_type;
	int warning_in_hg;

	// bool
	bool autocommit;
	bool autocommit_handled;
	bool sending_set_autocommit;
	bool killed;
	bool locked_on_hostgroup_and_all_variables_set;
	//bool admin;
	bool max_connections_reached;
	bool client_authenticated;
	bool connections_handler;
	bool mirror;
	//bool stats;
	bool schema_locked;
	bool transaction_persistent;
	bool session_fast_forward;
	bool started_sending_data_to_client; // this status variable tracks if some result set was sent to the client, or if proxysql is still buffering everything
	bool use_ssl;
	MySQL_STMTs_meta *sess_STMTs_meta;
	StmtLongDataHandler *SLDH;



	void init();
	//template<typename B> B * find_backend(int hostgroup_id);
	//template<typename B> B * create_backend(int, DS * _myds = NULL);
	//template<typename B> B * find_or_create_backend(int, DS * _myds = NULL);
	B * find_backend(int hostgroup_id);
	B * create_backend(int, DS * _myds = NULL);
	B * find_or_create_backend(int, DS * _myds = NULL);
	void writeout();
	void return_proxysql_internal(PtrSize_t* pkt);
	virtual void generate_proxysql_internal_session_json(nlohmann::json &) = 0;
	virtual void RequestEnd(DS *) = 0;
	virtual void SQLite3_to_MySQL(SQLite3_result*, char*, int, MySQL_Protocol*, bool in_transaction = false, bool deprecate_eof_active = false) = 0;
	bool has_any_backend();
	void reset_all_backends();
	bool handler_special_queries_STATUS(PtrSize_t*);
	/**
	 * @brief Performs the required housekeeping operations over the session and its connections before
	 *  performing any processing on received client packets.
	 */
	void housekeeping_before_pkts();
	virtual void create_new_session_and_reset_connection(DS *_myds) = 0;

	using TypeConn = typename std::conditional<
		std::is_same_v<S, MySQL_Session>, MySQL_Connection, PgSQL_Connection
	>::type;
	void update_expired_conns(const std::vector<std::function<bool(TypeConn*)>>&);

	void set_unhealthy();
	unsigned int NumActiveTransactions(bool check_savpoint=false);
	bool HasOfflineBackends();
	bool SetEventInOfflineBackends();
	/**
	 * @brief Finds one active transaction in the current backend connections.
	 * @details Since only one connection is returned, if the session holds multiple backend connections with
	 *  potential transactions, the priority is:
	 *   1. Connections flagged with 'SERVER_STATUS_IN_TRANS', or 'autocommit=0' in combination with
	 *      'autocommit_false_is_transaction'.
	 *   2. Connections with 'autocommit=0' holding a 'SAVEPOINT'.
	 *   3. Connections with 'unknown transaction status', e.g: connections with errors.
	 * @param check_savepoint Used to also check for connections holding savepoints. See MySQL bug
	 *  https://bugs.mysql.com/bug.php?id=107875.
	 * @returns The hostgroup in which the connection was found, -1 in case no connection is found.
	 */
	int FindOneActiveTransaction(bool check_savepoint=false);
};

#endif // CLASS_BASE_SESSION_H
