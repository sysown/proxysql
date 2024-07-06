class Base_Session;

//// avoid loading definition of MySQL_Session and PgSQL_Session
//#define __CLASS_MYSQL_SESSION_H
//#define __CLASS_PGSQL_SESSION_H


#include "Client_Session.h"
#include "proxysql.h"
#include "cpp.h"

#ifndef CLASS_BASE_SESSION_H
#define CLASS_BASE_SESSION_H

class MySQL_STMTs_meta;
class StmtLongDataHandler;
class MySQL_Session;
class PgSQL_Session;

class Base_Session {
	public:
	Base_Session();
	~Base_Session();

	// uint64_t
	unsigned long long start_time;
	unsigned long long pause_until;

	unsigned long long idle_since;
	unsigned long long transaction_started_at;

	PtrArray *mybes;
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



	template <typename T> void init();
	template<typename B, typename S> B * find_backend(int hostgroup_id);
	template<typename B, typename S, typename D> B * create_backend(int, D * _myds = NULL);
	template<typename B, typename S, typename D> B * find_or_create_backend(int, D * _myds = NULL);
};

#endif // CLASS_BASE_SESSION_H
