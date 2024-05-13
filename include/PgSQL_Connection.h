#ifndef __CLASS_POSTGRESQL_CONNECTION_H
#define __CLASS_POSTGRESQL_CONNECTION_H

#include "proxysql.h"
#include "cpp.h"

#ifndef PROXYJSON
#define PROXYJSON
namespace nlohmann { class json; }
#endif // PROXYJSON


class PgSQL_SrvC;

//#define STATUS_MYSQL_CONNECTION_TRANSACTION          0x00000001 // DEPRECATED
#define STATUS_MYSQL_CONNECTION_COMPRESSION          0x00000002
#define STATUS_MYSQL_CONNECTION_USER_VARIABLE        0x00000004
#define STATUS_MYSQL_CONNECTION_PREPARED_STATEMENT   0x00000008
#define STATUS_MYSQL_CONNECTION_LOCK_TABLES          0x00000010
#define STATUS_MYSQL_CONNECTION_TEMPORARY_TABLE      0x00000020
#define STATUS_MYSQL_CONNECTION_GET_LOCK             0x00000040
#define STATUS_MYSQL_CONNECTION_NO_MULTIPLEX         0x00000080
#define STATUS_MYSQL_CONNECTION_SQL_LOG_BIN0         0x00000100
#define STATUS_MYSQL_CONNECTION_FOUND_ROWS           0x00000200
#define STATUS_MYSQL_CONNECTION_NO_MULTIPLEX_HG      0x00000400
#define STATUS_MYSQL_CONNECTION_HAS_SAVEPOINT        0x00000800
#define STATUS_MYSQL_CONNECTION_HAS_WARNINGS         0x00001000


enum PgSQL_Param_Name {
	PG_HOST = 0,  // Name of host to connect to
	PG_HOSTADDR,  // Numeric IP address of host to connect to
	PG_PORT,  // Port number to connect to at the server host
	PG_DATABASE,  // The database name
	PG_USER,  // PgSQL user name to connect as
	PG_PASSWORD,  // Password to be used if the server demands password authentication
	PG_PASSFILE,  // Specifies the name of the file used to store passwords
	PG_REQUIRE_AUTH,  // Specifies the authentication method that the client requires from the server
	PG_CHANNEL_BINDING,  // Controls the client's use of channel binding
	PG_CONNECT_TIMEOUT,  // Maximum time to wait while connecting, in seconds
	PG_CLIENT_ENCODING,  // Sets the client_encoding configuration parameter for this connection
	PG_OPTIONS,  // Specifies command-line options to send to the server at connection start
	PG_APPLICATION_NAME,  // Specifies a value for the application_name configuration parameter
	PG_FALLBACK_APPLICATION_NAME,  // Specifies a fallback value for the application_name configuration parameter
	PG_KEEPALIVES,  // Controls whether client-side TCP keepalives are used
	PG_KEEPALIVES_IDLE,  // Controls the number of seconds of inactivity after which TCP should send a keepalive message to the server
	PG_KEEPALIVES_INTERVAL,  // Controls the number of seconds after which a TCP keepalive message that is not acknowledged by the server should be retransmitted
	PG_KEEPALIVES_COUNT,  // Controls the number of TCP keepalives that can be lost before the client's connection to the server is considered dead
	PG_TCP_USER_TIMEOUT,  // Controls the number of milliseconds that transmitted data may remain unacknowledged before a connection is forcibly closed
	PG_REPLICATION,  // Determines whether the connection should use the replication protocol instead of the normal protocol
	PG_GSSENCMODE,  // Determines whether a secure GSS TCP/IP connection will be negotiated with the server
	PG_SSLMODE,  // Determines whether a secure SSL TCP/IP connection will be negotiated with the server
	PG_REQUIRESSL,  // Requires an SSL connection to the server
	PG_SSLCOMPRESSION,  // If set, data sent over SSL connections will be compressed
	PG_SSLCERT,  // Specifies the file name of the client SSL certificate
	PG_SSLKEY,  // Specifies the location for the secret key used for the client certificate
	PG_SSLPASSWORD,  // Specifies the password for the secret key specified in sslkey
	PG_SSLCERTMODE,  // Determines whether a client certificate may be sent to the server
	PG_SSLROOTCERT,  // Specifies the name of a file containing SSL certificate authority (CA) certificate(s)
	PG_SSLCRL,  // Specifies the file name of the SSL server certificate revocation list (CRL)
	PG_SSLCRLDIR,  // Specifies the directory name of the SSL server certificate revocation list (CRL)
	PG_SSLSNI,  // Sets the TLS extension “Server Name Indication” (SNI) on SSL-enabled connections
	PG_REQUIREPEER,  // Specifies the operating-system user name of the server
	PG_SSL_MIN_PROTOCOL_VERSION,  // Specifies the minimum SSL/TLS protocol version to allow for the connection
	PG_SSL_MAX_PROTOCOL_VERSION,  // Specifies the maximum SSL/TLS protocol version to allow for the connection
	PG_KRBSRVNAME,  // Kerberos service name to use when authenticating with GSSAPI
	PG_GSSLIB,  // GSS library to use for GSSAPI authentication
	PG_GSSDELEGATION,  // Forward (delegate) GSS credentials to the server
	PG_SERVICE,  // Service name to use for additional parameters
	PG_TARGET_SESSION_ATTRS,  // Determines whether the session must have certain properties to be acceptable
	PG_LOAD_BALANCE_HOSTS,  // Controls the order in which the client tries to connect to the available hosts and addresses

	PG_PARAM_SIZE
};

static const char* PgSQL_Param_Name_Str[] = {
	"host",
	"hostaddr",
	"port",
	"database",
	"user",
	"password",
	"passfile",
	"require_auth",
	"channel_binding",
	"connect_timeout",
	"client_encoding",
	"options",
	"application_name",
	"fallback_application_name",
	"keepalives",
	"keepalives_idle",
	"keepalives_interval",
	"keepalives_count",
	"tcp_user_timeout",
	"replication",
	"gsseencmode",
	"sslmode",
	"requiressl",
	"sslcompression",
	"sslcert",
	"sslkey",
	"sslpassword",
	"sslcertmode",
	"sslrootcert",
	"sslcrl",
	"sslcrldir",
	"sslsni",
	"requirepeer",
	"ssl_min_protocol_version",
	"ssl_max_protocol_version",
	"krbsrvname",
	"gsslib",
	"gssdelegation",
	"service",
	"target_session_attrs",
	"load_balance_hosts"
};

struct Param_Name_Validation {
	const char** accepted_values;
	int default_value_idx;

};

static const Param_Name_Validation require_auth			{(const char*[]){"password","md5","gss","sspi","scram-sha-256","none",nullptr},-1};
static const Param_Name_Validation replication			{(const char*[]){"true","on","yes","1","database","false","off","no","0",nullptr},-1};
static const Param_Name_Validation gsseencmode			{(const char*[]){"disable","prefer","require",nullptr},1};
static const Param_Name_Validation sslmode				{(const char*[]){"disable","allow","prefer","require","verify-ca","verify-full",nullptr},2};
static const Param_Name_Validation sslcertmode			{(const char*[]){"disable","allow","require",nullptr},1};
static const Param_Name_Validation target_session_attrs {(const char*[]){"any","read-write","read-only","primary","standby","prefer-standby",nullptr},0 };
static const Param_Name_Validation load_balance_hosts	{(const char*[]){"disable","random",nullptr},-1};

static const Param_Name_Validation* PgSQL_Param_Name_Accepted_Values[PG_PARAM_SIZE] = {
	nullptr,
	nullptr,
	nullptr,
	nullptr,
	nullptr,
	nullptr,
	nullptr,
	&require_auth,
	nullptr,
	nullptr,
	nullptr,
	nullptr,
	nullptr,
	nullptr,
	nullptr,
	nullptr,
	nullptr,
	nullptr,
	nullptr,
	&replication,
	&gsseencmode,
	&sslmode,
	nullptr,
	nullptr,
	nullptr,
	nullptr,
	nullptr,
	&sslcertmode,
	nullptr,
	nullptr,
	nullptr,
	nullptr,
	nullptr,
	nullptr,
	nullptr,
	nullptr,
	nullptr,
	nullptr,
	nullptr,
	&target_session_attrs,
	&load_balance_hosts
};

class PgSQL_Conn_Param {
private:
	bool validate(PgSQL_Param_Name key, const char* val) {
		assert(val);
		const Param_Name_Validation* validation = PgSQL_Param_Name_Accepted_Values[key];

		if (validation != nullptr && validation->accepted_values) {
			const char** accepted_value = validation->accepted_values;
			while (accepted_value != nullptr) {
				if (strcmp(val, *accepted_value) == 0) {
					return true;
				}
			}
		} else {
			return true;
		}
		
		return false;
	}

public:
	PgSQL_Conn_Param() {}
	~PgSQL_Conn_Param() {
		for (int i = 0; i < PG_PARAM_SIZE; i++) {
			if (param_value[i])
				free(param_value[i]);
		}
	}

	bool set_value(PgSQL_Param_Name key, const char* val) {
		if (validate(key, val)) {
			if (param_value[key]) {
				free(param_value[key]);
			}
			param_value[key] = strdup(val);
			param_set.push_back(key);
			return true;
		}
		return false;
	}

	bool set_value(const char* key, const char* val) {
		return set_value((PgSQL_Param_Name)get_param_name(key), val);
	}

	void reset_value(PgSQL_Param_Name key) {
		if (param_value[key]) {
			free(param_value[key]);
		}
		param_value[key] = nullptr;

		// this has O(n) complexity. need to fix it....
		param_set.erase(param_set.begin() + static_cast<int>(key));
	}

	const char* get_value(PgSQL_Param_Name key) const {
		return param_value[key];
	}

	int get_param_name(const char* name) {
		int key = -1;

		for (int i = 0; i < PG_PARAM_SIZE; i++) {
			if (strcmp(name, PgSQL_Param_Name_Str[i]) == 0) {
				key = i;
				break;
			}
		}

		assert(key != -1);
		return key;
	}

	std::vector<PgSQL_Param_Name> param_set;
	char* param_value[PG_PARAM_SIZE]{};
};

class PgSQL_Variable {
public:
	char *value = (char*)"";
	void fill_server_internal_session(nlohmann::json &j, int conn_num, int idx);
	void fill_client_internal_session(nlohmann::json &j, int idx);
};

enum pgsql_charset_action {
	POSTGRESQL_CHARSET_ACTION_UNKNOWN,
	POSTGRESQL_CHARSET_ACTION_NAMES,
	POSTGRESQL_CHARSET_ACTION_CHARSET,
	POSTGRESQL_CHARSET_ACTION_CONNECT_START
};


class PgSQL_Connection_userinfo {
	private:
	uint64_t compute_hash();
  public:
	uint64_t hash;
	char *username;
	char *password;
	char *schemaname;
	char *sha1_pass;
	char *fe_username;
	// TODO POSGRESQL: add client and server scram keys
	PgSQL_Connection_userinfo();
	~PgSQL_Connection_userinfo();
	void set(char *, char *, char *, char *);
	void set(PgSQL_Connection_userinfo *);
	bool set_schemaname(char *, int);
};

class PgSQL_Connection {
	private:
	void update_warning_count_from_connection();
	void update_warning_count_from_statement();
	bool is_expired(unsigned long long timeout);
	unsigned long long inserted_into_pool;
	public:
	struct {
		char *server_version;
		uint32_t session_track_gtids_int;
		uint32_t max_allowed_pkt;
		uint32_t server_capabilities;
		uint32_t client_flag;
		unsigned int compression_min_length;
		char *init_connect;
		bool init_connect_sent;
		char * session_track_gtids;
		char *ldap_user_variable;
		char *ldap_user_variable_value;
		bool session_track_gtids_sent;
		bool ldap_user_variable_sent;
		uint8_t protocol_version;
		int8_t last_set_autocommit;
		bool autocommit;
		bool no_backslash_escapes;
	} options;

	PgSQL_Conn_Param conn_params;

	PgSQL_Variable variables[SQL_NAME_LAST_HIGH_WM];
	uint32_t var_hash[SQL_NAME_LAST_HIGH_WM];
	// for now we store possibly missing variables in the lower range
	// we may need to fix that, but this will cost performance
	bool var_absent[SQL_NAME_LAST_HIGH_WM] = {false};

	std::vector<uint32_t> dynamic_variables_idx;
	unsigned int reorder_dynamic_variables_idx();

	struct {
		unsigned long length;
		char *ptr;
		MYSQL_STMT *stmt;
		MYSQL_RES *stmt_result;
		stmt_execute_metadata_t *stmt_meta;
	} query;
	char scramble_buff[40];
	unsigned long long creation_time;
	unsigned long long last_time_used;
	unsigned long long timeout;
	int auto_increment_delay_token;
	int fd;
	MySQL_STMTs_local_v14 *local_stmts;	// local view of prepared statements
	MYSQL *pgsql;
	MYSQL *ret_mysql;
	MYSQL_RES *mysql_result;
	MYSQL_ROW mysql_row;
	MySQL_ResultSet *MyRS;
	MySQL_ResultSet *MyRS_reuse;
	PgSQL_SrvC *parent;
	PgSQL_Connection_userinfo *userinfo;
	PgSQL_Data_Stream *myds;

	struct {
		char* hostname;
		char* ip;
	} connected_host_details;
	/**
	 * @brief Keeps tracks of the 'server_status'. Do not confuse with the 'server_status' from the
	 *  'MYSQL' connection itself. This flag keeps track of the configured server status from the
	 *  parent 'MySrvC'.
	 */
	enum MySerStatus server_status; // this to solve a side effect of #774

	bytes_stats_t bytes_info; // bytes statistics
	struct {
		unsigned long long questions;
		unsigned long long myconnpoll_get;
		unsigned long long myconnpoll_put;
	} statuses;

	unsigned long largest_query_length;
	unsigned int warning_count;
	/**
	 * @brief This represents the internal knowledge of ProxySQL about the connection. It keeps track of those
	 *  states which *are not reflected* into 'server_status', but are relevant for connection handling.
	 */
	uint32_t status_flags;
	int async_exit_status; // exit status of MariaDB Client Library Non blocking API
	int interr;	// integer return
	MDB_ASYNC_ST async_state_machine;	// Async state machine
	short wait_events;
	uint8_t compression_pkt_id;
	my_bool ret_bool;
	bool async_fetch_row_start;
	bool send_quit;
	bool reusable;
	bool processing_multi_statement;
	bool multiplex_delayed;
	bool unknown_transaction_status;
	void compute_unknown_transaction_status();
	char gtid_uuid[128];
	PgSQL_Connection();
	~PgSQL_Connection();
	bool set_autocommit(bool);
	bool set_no_backslash_escapes(bool);
	unsigned int set_charset(unsigned int, enum pgsql_charset_action);

	void set_status(bool set, uint32_t status_flag);
	void set_status_sql_log_bin0(bool);
	bool get_status(uint32_t status_flag);
	bool get_status_sql_log_bin0();
	void connect_start();
	void connect_cont(short event);
	void change_user_start();
	void change_user_cont(short event);
	void ping_start();
	void ping_cont(short event);
	void set_autocommit_start();
	void set_autocommit_cont(short event);
	void set_names_start();
	void set_names_cont(short event);
	void real_query_start();
	void real_query_cont(short event);
#ifndef PROXYSQL_USE_RESULT
	void store_result_start();
	void store_result_cont(short event);
#endif // PROXYSQL_USE_RESULT
	void initdb_start();
	void initdb_cont(short event);
	void set_option_start();
	void set_option_cont(short event);
	void set_query(char *stmt, unsigned long length);
	MDB_ASYNC_ST handler(short event);
	void next_event(MDB_ASYNC_ST new_st);

	int async_connect(short event);
	int async_change_user(short event);
	int async_select_db(short event);
	int async_set_autocommit(short event, bool);
	int async_set_names(short event, unsigned int nr);
	int async_send_simple_command(short event, char *stmt, unsigned long length); // no result set expected
	int async_query(short event, char *stmt, unsigned long length, MYSQL_STMT **_stmt=NULL, stmt_execute_metadata_t *_stmt_meta=NULL);
	int async_ping(short event);
	int async_set_option(short event, bool mask);

	void stmt_prepare_start();
	void stmt_prepare_cont(short event);
	void stmt_execute_start();
	void stmt_execute_cont(short event);
	void stmt_execute_store_result_start();
	void stmt_execute_store_result_cont(short event);

	/**
	 * @brief Process the rows returned by 'async_stmt_execute_store_result'. Extracts all the received
	 *   rows from 'query.stmt->result.data' but the last one, adds them to 'MyRS', frees the buffer
	 *   used by 'query.stmt' and allocates a new one with the last row, leaving it ready for being filled
	 *   with the new rows to be received.
	 * @param processed_bytes Reference to the already processed bytes to be updated with the rows
	 *   that are being read and added to 'MyRS'.
	 */
	void process_rows_in_ASYNC_STMT_EXECUTE_STORE_RESULT_CONT(unsigned long long& processed_bytes);

	void async_free_result();
	/**
	 * @brief Returns if the connection is **for sure**, known to be in an active transaction.
	 * @details The function considers two things:
	 *   1. If 'server_status' is flagged with 'SERVER_STATUS_IN_TRANS'.
	 *   2. If the connection has 'autcommit=0' and 'autocommit_false_is_transaction' is set.
	 * @return True if the connection is known to be in a transaction, or equivalent state.
	 */
	bool IsKnownActiveTransaction();
	/**
	 * @brief Returns if the connection is in a **potential transaction**.
	 * @details This function is a more strict version of 'IsKnownActiveTransaction', which also considers
	 *  connections which holds 'unknown_transaction_status' as potentially active transactions.
	 * @return True if the connection is in potentially in an active transaction.
	 */
	bool IsActiveTransaction();
	bool IsServerOffline();
	bool IsAutoCommit();
	bool AutocommitFalse_AndSavepoint();
	bool MultiplexDisabled(bool check_delay_token = true);
	bool IsKeepMultiplexEnabledVariables(char *query_digest_text);
	void ProcessQueryAndSetStatusFlags(char *query_digest_text);
	void optimize();
	void close_mysql();

	void set_is_client(); // used for local_stmts

	void reset();

	bool get_gtid(char *buff, uint64_t *trx_id);
	void reduce_auto_increment_delay_token() { if (auto_increment_delay_token) auto_increment_delay_token--; };

	bool match_tracked_options(const PgSQL_Connection *c);
	bool requires_CHANGE_USER(const PgSQL_Connection *client_conn);
	unsigned int number_of_matching_session_variables(const PgSQL_Connection *client_conn, unsigned int& not_matching);
	unsigned long get_mysql_thread_id() { return pgsql ? pgsql->thread_id : 0; }
};
#endif /* __CLASS_POSTGRESQL_CONNECTION_H */
