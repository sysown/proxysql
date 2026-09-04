#ifndef PROXYSQL_PGSQL_CONNECTION_H
#define PROXYSQL_PGSQL_CONNECTION_H
#include "libpq-fe.h"
#include "proxysql.h"
#include "cpp.h"
#include "PgSQL_Error_Helper.h"
#include "PgSQL_Backend_Protocol.h"
#include <map>
#include <string>

#ifndef PROXYJSON
#define PROXYJSON
#include "../deps/json/json_fwd.hpp"
#endif // PROXYJSON

class PgSQL_SrvC;
class PgSQL_Query_Result;
class PgSQL_STMT_Local;
//class PgSQL_Describe_Prepared_Info;
class PgSQL_Bind_Info;
class PgSQL_Backend_Protocol;
//#define STATUS_PGSQL_CONNECTION_SEQUENCE			 0x00000001
#define STATUS_PGSQL_CONNECTION_COMPRESSION          0x00000002
#define STATUS_PGSQL_CONNECTION_USER_VARIABLE        0x00000004
#define STATUS_PGSQL_CONNECTION_PREPARED_STATEMENT   0x00000008
#define STATUS_PGSQL_CONNECTION_LOCK_TABLES          0x00000010
#define STATUS_PGSQL_CONNECTION_TEMPORARY_TABLE      0x00000020
#define STATUS_PGSQL_CONNECTION_ADVISORY_LOCK        0x00000040
#define STATUS_PGSQL_CONNECTION_NO_MULTIPLEX         0x00000080
#define STATUS_PGSQL_CONNECTION_HAS_SEQUENCES		 0x00000100
#define STATUS_PGSQL_CONNECTION_ADVISORY_XACT_LOCK   0x00000200
#define STATUS_PGSQL_CONNECTION_NO_MULTIPLEX_HG      0x00000400
#define STATUS_PGSQL_CONNECTION_HAS_SAVEPOINT        0x00000800
//#define STATUS_PGSQL_CONNECTION_HAS_WARNINGS         0x00001000


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
	PG_SSLSNI,  // Sets the TLS extension Server Name Indication (SNI) on SSL-enabled connections
	PG_REQUIREPEER,  // Specifies the operating-system user name of the server
	PG_SSL_MIN_PROTOCOL_VERSION,  // Specifies the minimum SSL/TLS protocol version to allow for the connection
	PG_SSL_MAX_PROTOCOL_VERSION,  // Specifies the maximum SSL/TLS protocol version to allow for the connection
	PG_KRBSRVNAME,  // Kerberos service name to use when authenticating with GSSAPI
	PG_GSSLIB,  // GSS library to use for GSSAPI authentication
	PG_GSSDELEGATION,  // Forward (delegate) GSS credentials to the server
	PG_SERVICE,  // Service name to use for additional parameters
	PG_TARGET_SESSION_ATTRS,  // Determines whether the session must have certain properties to be acceptable
	PG_LOAD_BALANCE_HOSTS,  // Controls the order in which the client tries to connect to the available hosts and addresses
	// Environment Options
	//PG_DATESTYLE,  // Sets the value of the DateStyle parameter
	//PG_TIMEZONE,  // Sets the value of the TimeZone parameter
	//PG_GEQO,  // Enables or disables the use of the GEQO query optimizer

	PG_PARAM_SIZE
};

struct Param_Name_Validation {
	const char** accepted_values;
	int default_value_idx;
};

static const Param_Name_Validation require_auth{ (const char* []) { "password","md5","gss","sspi","scram-sha-256","none",nullptr },-1 };
static const Param_Name_Validation replication{ (const char* []) { "true","on","yes","1","database","false","off","no","0",nullptr },-1 };
static const Param_Name_Validation gsseencmode{ (const char* []) { "disable","prefer","require",nullptr },1 };
static const Param_Name_Validation sslmode{ (const char* []) { "disable","allow","prefer","require","verify-ca","verify-full",nullptr },2 };
static const Param_Name_Validation sslcertmode{ (const char* []) { "disable","allow","require",nullptr },1 };
static const Param_Name_Validation target_session_attrs{ (const char* []) { "any","read-write","read-only","primary","standby","prefer-standby",nullptr },0 };
static const Param_Name_Validation load_balance_hosts{ (const char* []) { "disable","random",nullptr },-1 };

// Excluding client_encoding since it is managed as part of the session variables
#define PARAMETER_LIST \
    PARAM("host", nullptr) \
    PARAM("hostaddr", nullptr) \
    PARAM("port", nullptr) \
    PARAM("database", nullptr) \
    PARAM("user", nullptr) \
    PARAM("password", nullptr) \
    PARAM("passfile", nullptr) \
    PARAM("require_auth", &require_auth) \
    PARAM("channel_binding", nullptr) \
    PARAM("connect_timeout", nullptr) \
    PARAM("options", nullptr) \
    PARAM("application_name", nullptr) \
    PARAM("fallback_application_name", nullptr) \
    PARAM("keepalives", nullptr) \
    PARAM("keepalives_idle", nullptr) \
    PARAM("keepalives_interval", nullptr) \
    PARAM("keepalives_count", nullptr) \
    PARAM("tcp_user_timeout", nullptr) \
    PARAM("replication", &replication) \
    PARAM("gsseencmode", &gsseencmode) \
    PARAM("sslmode", &sslmode) \
    PARAM("requiressl", nullptr) \
    PARAM("sslcompression", nullptr) \
    PARAM("sslcert", nullptr) \
    PARAM("sslkey", nullptr) \
    PARAM("sslpassword", nullptr) \
    PARAM("sslcertmode", &sslcertmode) \
    PARAM("sslrootcert", nullptr) \
    PARAM("sslcrl", nullptr) \
    PARAM("sslcrldir", nullptr) \
    PARAM("sslsni", nullptr) \
    PARAM("requirepeer", nullptr) \
    PARAM("ssl_min_protocol_version", nullptr) \
    PARAM("ssl_max_protocol_version", nullptr) \
    PARAM("krbsrvname", nullptr) \
    PARAM("gsslib", nullptr) \
    PARAM("gssdelegation", nullptr) \
    PARAM("service", nullptr) \
    PARAM("target_session_attrs", &target_session_attrs) \
    PARAM("load_balance_hosts", &load_balance_hosts)

// Generate parameter array
constexpr const char* param_name[] = {
#define PARAM(name, val) name,
	PARAMETER_LIST
#undef PARAM
};

// make sure all the keys are in lower case
static const std::unordered_map<std::string_view, const Param_Name_Validation*> param_name_map = {
#define PARAM(name, val) {name, val},
	PARAMETER_LIST
#undef PARAM
};

#define PG_EVENT_NONE	 0x00
#define PG_EVENT_READ	 0x01
#define PG_EVENT_WRITE	 0x02
#define PG_EVENT_EXCEPT  0x04
#define PG_EVENT_TIMEOUT 0x08


/**
 * @class PgSQL_Conn_Param
 * @brief Stores PostgreSQL connection parameters sent by client.
 *
 * This class stores key-value pairs representing connection parameters 
 * for PostgreSQL connection. 
 *
 */
class PgSQL_Conn_Param {
public:
    PgSQL_Conn_Param() {}
    ~PgSQL_Conn_Param() {}

    bool set_value(const char* key, const char* val) {
        if (key == nullptr || val == nullptr) return false;
        connection_parameters[key] = val;
        return true;
    }

    inline
    const char* get_value(PgSQL_Param_Name key) const {
        return get_value(param_name[key]);
    }

    const char* get_value(const char* key) const {
        auto it = connection_parameters.find(key);
        if (it != connection_parameters.end()) {
            return it->second.c_str();
        }
        return nullptr;
    }

    bool remove_value(const char* key) {
        auto it = connection_parameters.find(key);
        if (it != connection_parameters.end()) {
            connection_parameters.erase(it);
            return true;
        }
        return false;
    }

    inline
    bool is_empty() const {
        return connection_parameters.empty();
    }

    inline
    void clear() {
        connection_parameters.clear();
    }

private:
    /**
     * @brief Stores the connection parameters as key-value pairs.
     */
    std::map<std::string, std::string> connection_parameters;

    friend class PgSQL_Session; 
    friend class PgSQL_Protocol;
};

class PgSQL_Variable {
public:
	char *value = nullptr;
	void fill_server_internal_session(nlohmann::json &j, int conn_num, int idx);
	void fill_client_internal_session(nlohmann::json &j, int idx);
};

// Length of a SCRAM-SHA-256 ClientKey/ServerKey (== SHA256_DIGEST_LENGTH).
#define PGSQL_SCRAM_KEY_LEN 32

class PgSQL_Connection_userinfo {
	private:
	uint64_t compute_hash();
  public:
	uint64_t hash;
	char *username;
	char *password;
	union {
		char* dbname;
		char* schemaname; // temporary fix. To avoid changes in Base_Session and Query_Processor
	};
	char *sha1_pass;
	char *fe_username;
	// ClientKey harvested from the client's frontend login + the stored verifier's ServerKey,
	// carried to the backend connection. Deliberately NOT part of compute_hash() so connection-pool
	// reuse semantics are unchanged.
	uint8_t scram_client_key[PGSQL_SCRAM_KEY_LEN];
	uint8_t scram_server_key[PGSQL_SCRAM_KEY_LEN];
	bool has_scram_keys;
	PgSQL_Connection_userinfo();
	~PgSQL_Connection_userinfo();
	void set(char *, char *, char *, char *);
	void set(PgSQL_Connection_userinfo *);
	bool set_dbname(const char *);
};

class PgSQL_Connection {
public:
	explicit PgSQL_Connection(bool is_client_conn);
	~PgSQL_Connection();

	PG_ASYNC_ST handler(short event);
	void connect_start();
	void connect_cont(short event);
	// Consults PgSQL_Monitor::dns_lookup; returns the cached IP on a hit,
	// empty std::string on a miss.  Used by connect_start() to set
	// `hostaddr=<ip>` in the libpq conninfo so PQconnectStart skips
	// getaddrinfo and doesn't block the worker thread on DNS.
	std::string connect_start_DNS_lookup();
	void query_start();
	void query_cont(short event);
	void fetch_result_start();
	void fetch_result_cont(short event);

    /**
     * @brief Initiates the asynchronous preparation of a SQL statement.
     *
     * This method starts the process of preparing a SQL statement on the PostgreSQL backend.
     *
     * The actual continuation and completion of the statement preparation is handled
     * by stmt_prepare_cont(short event).
     */
    void stmt_prepare_start();

    /**
     * @brief Continues the asynchronous preparation of a SQL statement.
     *
     * This method is called after stmt_prepare_start() to handle the next step in the
     * asynchronous state machine for preparing a SQL statement on the PostgreSQL backend.
     *
     * @param event The event flag indicating the current I/O event.
     */
    void stmt_prepare_cont(short event);

    /**
     * @brief Initiates the asynchronous description of a prepared SQL statement.
     *
     * This method starts the process of describing a previously prepared SQL statement
     * on the PostgreSQL backend.
	 * 
     */
    void stmt_describe_start();

    /**
     * @brief Continues the asynchronous description of a prepared SQL statement.
     *
     * This method is called after stmt_describe_start() to handle the next step in the
     * asynchronous state machine for describing a prepared SQL statement on the PostgreSQL backend.
     *
     * @param event The event flag indicating the current I/O event.
     */
    void stmt_describe_cont(short event);

    /**
     * @brief Initiates the asynchronous execution of a prepared SQL statement.
     *
     * This method starts the process of executing a previously prepared SQL statement
     * on the PostgreSQL backend. It sends Bind and Execute messages to the server
     * and transitions the connection's state machine to handle the subsequent response.
	 * 
     */
    void stmt_execute_start();

    /**
     * @brief Continues the asynchronous execution of a prepared SQL statement.
     *
     * This method is called after stmt_execute_start() to handle the next step in the
     * asynchronous state machine for executing a prepared SQL statement on the PostgreSQL backend.
     *
     * @param returned The event flag indicating the current I/O event.
     */
    void stmt_execute_cont(short event);

    /**
     * @brief Initiates the asynchronous reset of the PostgreSQL connection.
     *
     * Starts the internal state machine that resets connection to a clean,
     * reusable state so it can safely re-enter the multiplexing pool.
     *
     */
    void reset_session_start();

    /**
     * @brief Continues the asynchronous reset of the PostgreSQL session.
     *
     * This method advances the state machine initiated by reset_session_start()
     * to asynchronously reset the backend connection to a clean, reusable state.
     *
     * @param event The event flag indicating the current I/O event.
     */
    void reset_session_cont(short event);

    /**
     * @brief Start a resynchronization attempt for the current backend connection.
     *
     * Send protocol-level Sync (or otherwise trigger the backend to reach
     * ReadyForQuery) and transition the connection into the resynchronizing state.
     *
     */
    void resync_start();

    /**
	 * @brief Continue a previously started resynchronization in response to an event.
	 *
	 * @param event The event flag indicating the current I/O event.
	 */
    void resync_cont(short event);
	
	int async_connect(short event);
	int async_query(short event, const char* stmt, unsigned long length, const char* backend_stmt_name = nullptr, 
		PgSQL_Extended_Query_Type type = PGSQL_EXTENDED_QUERY_TYPE_NOT_SET, const PgSQL_Extended_Query_Info* extended_query_info = nullptr);
	int async_ping(short event);
	int async_reset_session(short event);
	int async_send_simple_command(short event, char* stmt, unsigned long length); // no result set expected
	int async_perform_resync(short event);

	void next_event(PG_ASYNC_ST new_st);
	bool is_connected() const;
	void compute_unknown_transaction_status();
	void async_free_result();
	void flush(bool is_resync = false);
	bool IsActiveTransaction();
	bool IsKnownActiveTransaction();
	bool IsServerOffline();
	void set_is_client(); // used for local_stmts
	bool is_connection_in_reusable_state() const;

	bool requires_RESETTING_CONNECTION(const PgSQL_Connection* client_conn);
	
	bool has_same_connection_options(const PgSQL_Connection* c);

	/**
	 * @brief Sets the error information for this connection from the current libpq error message.
	 *
	 * This method retrieves the latest error message from the underlying PostgreSQL connection (via PQerrorMessage),
	 * parses it into its component fields (such as severity, SQLSTATE, and message), and fills the internal error_info
	 * structure accordingly. If the error message is not available, it sets a generic "Unknown error" with fatal severity.
	 *
	 * The function distinguishes between server errors (with fields like "S", "C", "M") and library-generated errors
	 * (stored under the "LE" key). If a server error is present, it is preferred; otherwise, the library error message
	 * is used. The error fields are extracted using parse_pq_error_message().
	 *
	 * Example error string: "S:5:ERRORC:5:12345M:12:Some message"
	 *   - S: Severity
	 *   - C: SQLSTATE code
	 *   - M: Primary message
	 *   - LE: Library error (if present)
	 */
	void set_error_from_PQerrorMessage();

	int get_server_version() {
		return PQserverVersion(pgsql_conn);
	}

	int get_protocol_version() {
		return PQprotocolVersion(pgsql_conn);
	}

	inline
	bool is_error_present() const {
		if (error_info.severity == PGSQL_ERROR_SEVERITY::ERRSEVERITY_FATAL ||
			error_info.severity == PGSQL_ERROR_SEVERITY::ERRSEVERITY_ERROR ||
			error_info.severity == PGSQL_ERROR_SEVERITY::ERRSEVERITY_PANIC) {
			return true;
		}
		return false;
	}

	inline
	PGSQL_ERROR_SEVERITY get_error_severity() const {
		return error_info.severity;
	}

	inline
	PGSQL_ERROR_CATEGORY get_error_category() const {
		return error_info.category;
	}

	inline
	const std::string& get_error_message() const {
		return error_info.message;
	}

	inline
	const char* get_error_code_str() const {
		return error_info.sqlstate;
	}

	inline
	PGSQL_ERROR_CODES get_error_code() const {
		return error_info.code;
	}

	inline
	std::string get_error_code_with_message() const {
		return ("[" + std::string(error_info.sqlstate) + "] " + error_info.message);
	}

	void set_error(const char* code, const char* message, bool is_fatal) {
		PgSQL_Error_Helper::fill_error_info(error_info, code, message, is_fatal ? "FATAL" : "ERROR");
	}

	void set_error(PGSQL_ERROR_CODES code, const char* message, bool is_fatal) {
		PgSQL_Error_Helper::fill_error_info(error_info, code, message, is_fatal ? 
			PGSQL_ERROR_SEVERITY::ERRSEVERITY_FATAL : PGSQL_ERROR_SEVERITY::ERRSEVERITY_ERROR);
	}

	// safety check. Sometimes libpq return garbage result when connection is lost with the backend
	bool is_error_result_valid(const PGresult* result) const {
		if (result == nullptr)
			return false;
		return (PQresultErrorField(result, PG_DIAG_SQLSTATE) != nullptr);
	}

	void set_error_from_result(const PGresult* result, uint16_t ext_fields = 0) {
		if (is_error_result_valid(result)) { 
			PgSQL_Error_Helper::fill_error_info(error_info, result, ext_fields);
		} else {
			set_error_from_PQerrorMessage();
		}
	}

	void reset_error() { reset_error_info(error_info, false); }

	bool reset_session_in_txn = false;
	bool reset_session_in_pipeline = false;

	PGresult* get_result();
	void next_multi_statement_result(PGresult* result);
	bool set_single_row_mode();
	void update_bytes_recv(uint64_t bytes_recv);
	void update_bytes_sent(uint64_t bytes_sent);
	void ProcessQueryAndSetStatusFlags(const char* query_digest_text, int savepoint_count);

	inline const PGconn* get_pg_connection() const { return pgsql_conn; }
	inline int get_pg_server_version() {
		if (native_mode) {
			// native_params["server_version"] is e.g. "16.2" or "9.6.1"; libpq encodes
			// PQserverVersion as major*10000 + minor*100 + rev. Parse best-effort.
			auto it = native_params.find("server_version");
			if (it == native_params.end()) return 0;
			int maj = 0, min = 0, rev = 0;
			sscanf(it->second.c_str(), "%d.%d.%d", &maj, &min, &rev);
			return maj * 10000 + min * 100 + rev;
		}
		return PQserverVersion(pgsql_conn);
	}
	inline int get_pg_protocol_version() { return native_mode ? 3 : PQprotocolVersion(pgsql_conn); }
	inline const char* get_pg_host() { return native_mode ? native_host.c_str() : PQhost(pgsql_conn); }
	inline const char* get_pg_hostaddr() { return PQhostaddr(pgsql_conn); }
	inline const char* get_pg_port() { return PQport(pgsql_conn); }
	inline const char* get_pg_dbname() { return native_mode ? (userinfo ? userinfo->dbname : "") : PQdb(pgsql_conn); }
	inline const char* get_pg_user() { return native_mode ? (userinfo ? userinfo->username : "") : PQuser(pgsql_conn); }
	inline const char* get_pg_password() { return PQpass(pgsql_conn); }
	inline const char* get_pg_options() { return PQoptions(pgsql_conn); }
	inline int get_pg_socket_fd() { return native_mode ? fd : PQsocket(pgsql_conn); }
	inline int get_pg_backend_pid() { return native_mode ? native_backend_pid : PQbackendPID(pgsql_conn); }
	inline int get_pg_connection_needs_password() { return PQconnectionNeedsPassword(pgsql_conn); }
	inline int get_pg_connection_used_password() { return PQconnectionUsedPassword(pgsql_conn); }
	inline int get_pg_connection_used_gssapi() { return PQconnectionUsedGSSAPI(pgsql_conn); }
	inline int get_pg_client_encoding() { return PQclientEncoding(pgsql_conn); }
	// Native TLS (1.6b): SSL is in use once the handshake handed the SSL* to myds.
	// Out-of-line in PgSQL_Connection.cpp because PgSQL_Data_Stream is incomplete here.
	int get_pg_ssl_in_use();
	inline ConnStatusType get_pg_connection_status() {
		if (native_mode) return native_connected ? CONNECTION_OK : CONNECTION_BAD;
		return PQstatus(pgsql_conn);
	}
	inline PGTransactionStatusType get_pg_transaction_status() {
		if (native_mode) {
			switch (native_txn_status) {
				case 'I': return PQTRANS_IDLE;
				case 'T': return PQTRANS_INTRANS;
				case 'E': return PQTRANS_INERROR;
				default:  return PQTRANS_UNKNOWN;
			}
		}
		return PQtransactionStatus(pgsql_conn);
	}
	inline int get_pg_is_nonblocking() { return native_mode ? 1 : PQisnonblocking(pgsql_conn); }
	inline int get_pg_is_threadsafe() { return PQisthreadsafe(); }
	inline const char* get_pg_error_message() {
		return native_mode ? (error_info.message.empty() ? "" : error_info.message.c_str()) : PQerrorMessage(pgsql_conn);
	}
	// Out-of-line in PgSQL_Connection.cpp (PgSQL_Data_Stream incomplete here).
	SSL* get_pg_ssl_object();
	inline const char* get_pg_parameter_status(const char* param) {
		if (native_mode) {
			if (param == nullptr) return nullptr;
			auto it = native_params.find(param);
			return it == native_params.end() ? nullptr : it->second.c_str();
		}
		return PQparameterStatus(pgsql_conn, param);
	}
	const char* get_pg_server_version_str(char* buff, int buff_size);
	const char* get_pg_connection_status_str();
	const char* get_pg_transaction_status_str();
	unsigned int get_memory_usage() const;
	char get_transaction_status_char();
	inline int get_backend_pid() { return native_mode ? native_backend_pid : ((pgsql_conn) ? get_pg_backend_pid() : -1); }
	bool is_pipeline_active() { return (PQpipelineStatus(pgsql_conn) != PQ_PIPELINE_OFF); }
	const char* get_pg_backend_state() const;

	static int char_to_encoding(const char* name) {
		return pg_char_to_encoding(name);
	}

	static const char* encoding_to_char(int encoding) {
		return pg_encoding_to_char(encoding);
	}

	static int valid_server_encoding_id(int encoding) {
		return pg_valid_server_encoding_id(encoding);
	}

	inline
	void reduce_auto_increment_delay_token() { if (auto_increment_delay_token) auto_increment_delay_token--; };

	void set_status(bool set, uint32_t status_flag);
	bool get_status(uint32_t status_flag);
	bool MultiplexDisabled(bool check_delay_token = true);

	unsigned int reorder_dynamic_variables_idx();
	unsigned int number_of_matching_session_variables(const PgSQL_Connection* client_conn, unsigned int& not_matching);
	void set_query(const char* stmt, unsigned long length, const char* _backend_stmt_name = nullptr, const PgSQL_Extended_Query_Info* extended_query_info = nullptr);
	void reset();

	bool IsKeepMultiplexEnabledVariables(const char* query_digest_text);

	/**
	 * @brief Retrieves startup parameter and it's hash
	 *
	 * This function tries to retrieve value and hash of startup paramters if present (provided in connection parameters).
	 * If value is not found, it falls back to the thread-specific default variables.
	 *
	 * @param idx The index of startup parameter to retrieve.
	 * @return The value and hash of startup parameter.
	 *
	 */
	std::pair<const char*, uint32_t> get_startup_parameter_and_hash(enum pgsql_variable_name idx);
	
	/**
	 * @brief Copies tracked PgSQL session variables to startup parameters
	 *
	 * This function synchronizes the current tracked session variables (in `variables` and `var_hash`)
	 * to the startup parameters arrays (`startup_parameters` and `startup_parameters_hash`). If `copy_only_critical_param` 
	 * is true, only the critical parameters (indices 0 to PGSQL_NAME_LAST_LOW_WM-1) are copied. 
	 * Otherwise, all tracked variables up to PGSQL_NAME_LAST_HIGH_WM are copied.
	 *
	 * @param copy_only_critical_param If true, only critical parameters are copied; otherwise, all tracked variables.
	 */
	void copy_pgsql_variables_to_startup_parameters(bool copy_only_critical_param);

	/**
	 * @brief Copies startup parameters to tracked PgSQL session variables.
	 *
	 * This function synchronizes the startup parameters arrays (`startup_parameters` and `startup_parameters_hash`)
	 * to the tracked session variables (`variables` and `var_hash`). If `copy_only_critical_param` is true,
	 * only the critical parameters (indices 0 to PGSQL_NAME_LAST_LOW_WM-1) are copied. Otherwise, all tracked
	 * variables up to PGSQL_NAME_LAST_HIGH_WM are copied.
	 *
	 * @param copy_only_critical_param If true, only critical parameters are copied; otherwise, all tracked variables.
	 */
	void copy_startup_parameters_to_pgsql_variables(bool copy_only_critical_param);

	struct {
		unsigned long length;
		const char* ptr;
		const char* backend_stmt_name;
		const PgSQL_Extended_Query_Info* extended_query_info;
	} query;

	struct {
		char* init_connect;
		bool init_connect_sent;
	} options;

	struct {
		char* hostname;
		char* ip;
	} connected_host_details;

	bytes_stats_t bytes_info; // bytes statistics
	struct {
		unsigned long long questions;
		unsigned long long pgconnpoll_get;
		unsigned long long pgconnpoll_put;
	} statuses;

	std::array<PgSQL_Variable, PGSQL_NAME_LAST_HIGH_WM> variables = {};
	std::array<uint32_t, PGSQL_NAME_LAST_HIGH_WM> var_hash = {};
	// for now we store possibly missing variables in the lower range
	// we may need to fix that, but this will cost performance
	std::array<bool, PGSQL_NAME_LAST_HIGH_WM> var_absent = {};
	std::vector<uint32_t> dynamic_variables_idx;

	std::array<uint32_t, PGSQL_NAME_LAST_HIGH_WM> startup_parameters_hash = {};
	std::array<char*, PGSQL_NAME_LAST_HIGH_WM> startup_parameters = {};

	/**
	 * @brief Keeps tracks of the 'server_status'. Do not confuse with the 'server_status' from the
	 *  'MYSQL' connection itself. This flag keeps track of the configured server status from the
	 *  parent 'MySrvC'.
	 */
	enum MySerStatus server_status; // this to solve a side effect of #774

	PgSQL_Conn_Param conn_params;
	PgSQL_ErrorInfo error_info;
	PGconn* pgsql_conn;
	bool native_mode = false;          // true → native wire protocol, false → libpq
	class PgSQL_Backend_Protocol* bp = NULL;  // owned in native mode only; NULL in libpq mode

	// --- Native backend connect/auth handshake state (Task 1.6a, plaintext only) ---
	// All of the following members are only meaningful when native_mode == true.
	enum class PG_Native_Conn_St {
		TCP_CONNECTING,   // non-blocking connect() in flight, waiting for writable
		SSL_SEND_REQUEST, // socket connected, SSLRequest (8 bytes) to flush (TLS only)
		SSL_READ_REPLY,   // waiting for the single-byte 'S'/'N' SSLRequest reply
		SSL_HANDSHAKE,    // driving the OpenSSL client handshake over the raw fd
		SEND_STARTUP,     // socket connected, StartupMessage (and pending bytes) to flush
		AUTH,             // exchanging Authentication* / Password / SASL messages
		STARTUP_TAIL,     // consuming ParameterStatus/BackendKeyData until ReadyForQuery
		DONE,             // ReadyForQuery received; connection usable
		FAILED            // unrecoverable error during the native handshake
	};
	PG_Native_Conn_St native_st = PG_Native_Conn_St::TCP_CONNECTING;
	// When an outbound message is only partially sent, native_st is set to
	// SEND_STARTUP to flush the remainder; this records the state to resume in
	// once the buffer drains (AUTH after a password/SASL message, etc.).
	PG_Native_Conn_St native_st_after_send = PG_Native_Conn_St::AUTH;
	PgSQL_Backend_Msg_Framer native_framer;          // frames inbound backend bytes
	PgSQL_Scram_State* native_scram = nullptr;       // owned; freed in destructor / teardown
	std::string native_outbuf;                       // pending outbound bytes (partial send buffer)
	bool native_connected = false;                   // true once ReadyForQuery received
	bool handler_first_call = true;                  // one-shot first-call detector for handler() (both libpq and native paths)
	std::map<std::string, std::string> native_params; // ParameterStatus name->value
	std::string native_host;                         // backend host (parent->address, captured at connect)
	int native_backend_pid = 0;                      // BackendKeyData PID
	int native_backend_secret = 0;                   // BackendKeyData secret key
	char native_txn_status = 'I';                    // ReadyForQuery status byte ('I'/'T'/'E')

	// --- Native simple-query / simple-command execution (Task 1.6c / Phase 2 core) ---
	// Set true once a ReadyForQuery ('Z') has been consumed for the in-flight query,
	// signalling the result stream is complete. Reset at query_start().
	bool native_result_complete = false;
	// Set true once a CopyInResponse ('G') or CopyBothResponse ('W') has been
	// answered with a CopyFail by the native_fetch_result_cont() safety net
	// (see there). Reset at query_start() alongside native_result_complete.
	bool native_copy_intercepted = false;

	// --- Native extended-query (prepared-statement) drive (Task C) ---
	// Which extended-query wire step the native drive is currently executing. Set by
	// stmt_prepare_start / stmt_describe_start / stmt_execute_start, consumed by
	// native_fetch_result_cont() to apply the per-step terminator + ack-filtering
	// rules. Reset to NONE alongside native_result_complete at each stmt start.
	// APPEND-ONLY (values are compared by the drain/ack-filter; a mid-list insert
	// would silently reclassify steps in any translation unit not recompiled). CLOSE_P
	// (Task P2) drives a real backend Close('P', name) round-trip whose CloseComplete
	// '3' is forwarded to the client.
	enum class PG_Native_Stmt_Step { NONE, PARSE, DESCRIBE_S, DESCRIBE_P, EXECUTE, BIND, CLOSE_P };
	PG_Native_Stmt_Step native_stmt_step = PG_Native_Stmt_Step::NONE;
	// True when the current ASYNC_STMT_EXECUTE_* dispatch is actually a named-portal
	// Bind (PGSQL_EXTENDED_QUERY_TYPE_BIND), so stmt_execute_start() emits a Bind-only
	// frame (no Execute) and the drain forwards the real BindComplete. Set per-dispatch
	// in async_query(); read once at stmt_execute_start(). Task P1.
	bool native_bind_only = false;
	// True when the current ASYNC_STMT_EXECUTE_* dispatch is actually a named-portal
	// Close (PGSQL_EXTENDED_QUERY_TYPE_CLOSE), so stmt_execute_start() emits a
	// Close('P', portal)-only frame (no Bind/Execute) and the drain forwards the real
	// CloseComplete '3'. Set per-dispatch in async_query(); read once at
	// stmt_execute_start(). Task P2.
	bool native_close_only = false;
	// Set by the drain when a native EXECUTE step's terminator was 's' (PortalSuspended
	// — max_rows cut the result short); cleared when it was 'C'/'I' (the portal ran to
	// completion). Read once by the session epilogue to mark/clear a NAMED portal's
	// entry.suspended for resume. Reset at each native stmt start. Task P2.
	bool native_last_execute_suspended = false;
	// True when the step was terminated on the wire with Sync (so it completes on the
	// backend's ReadyForQuery 'Z'); false when terminated with Flush (completes on the
	// step's own terminator: '1' for PARSE, 'T'|'n' for DESCRIBE, 'C'|'I'|'s' for
	// EXECUTE — the backend sends no 'Z' until a later Sync).
	bool native_stmt_sync_terminated = false;
	// True for an implicit Parse (IMPLICIT_PREPARE detour): the client never issued a
	// Parse, so the backend's ParseComplete '1' must be suppressed (never forwarded).
	bool native_suppress_parse_complete = false;
	// Set true once native_fetch_result_cont() has injected a Sync to recover from an
	// ErrorResponse mid-frame on a Flush-terminated step. After 'E' the backend is in
	// the aborted-until-Sync state and emits no 'Z' on its own; the injected Sync
	// brings it back to ReadyForQuery so the drain can complete and the session's
	// error path can run. Guards against injecting a second Sync while draining to 'Z'.
	bool native_stmt_error_resync = false;
	// True once the injected-Sync recovery proxy_warning has been emitted on this
	// connection. Deliberately NOT reset in native_stmt_reset_step() — the warning
	// fires at most once per backend-connection lifetime, so a client habitually
	// sending Parse-time-invalid SQL (PQexecParams in a loop) cannot flood the
	// production log at WARNING level (the libpq oracle path logs nothing for the
	// same event). The recovery itself (native_stmt_error_resync) still runs on
	// every errored step; only the log line is deduplicated.
	bool native_stmt_resync_logged = false;
	// --- Statement-level Describe metadata capture (set-once, native mode) ---
	// During a DESCRIBE_S step the drain copies the ParameterDescription 't' body and
	// the RowDescription 'T' / NoData 'n' state here; on step completion (its 'T'|'n'
	// terminator for a Flush-terminated Describe, or the 'Z' for a Sync-terminated one)
	// native_publish_describe_cache() publishes them to the global statement's set-once
	// cache. Backend-origin bytes, byte-identical to the libpq-mode rebuild. Cleared at
	// each stmt start; a step that errors before 't' leaves param empty → no publish.
	std::string native_describe_param_payload;
	std::string native_describe_row_payload;
	bool native_describe_have_row = false;
	bool native_describe_no_data = false;
	// Publish the captured statement-level Describe metadata to the global statement's
	// set-once cache, iff a complete 't' + ('T'|'n') was captured on this DESCRIBE_S step.
	void native_publish_describe_cache();
	// Reset all per-step native stmt drive state. Called at each native stmt start.
	// (native_stmt_resync_logged is intentionally absent: per-connection, not per-step.)
	inline void native_stmt_reset_step() {
		native_result_complete = false;
		native_copy_intercepted = false;
		native_stmt_step = PG_Native_Stmt_Step::NONE;
		native_last_execute_suspended = false;
		native_stmt_sync_terminated = false;
		native_suppress_parse_complete = false;
		native_stmt_error_resync = false;
		native_describe_param_payload.clear();
		native_describe_row_payload.clear();
		native_describe_have_row = false;
		native_describe_no_data = false;
		native_framer.reset();
		native_outbuf.clear();
	}
	// Drive the native result fetch: recv backend bytes, frame them, and stream each
	// raw message into query_result via add_native_backend_message(). Non-blocking:
	// EAGAIN/incomplete frame → async_exit_status = PG_EVENT_READ and return; a fatal
	// recv/frame error sets error_info and marks the fetch done. Sets
	// native_result_complete when ReadyForQuery is reached.
	void native_fetch_result_cont(short event);
	// Flush the just-built extended-query step in native_outbuf and set
	// async_exit_status the way the stmt_*_start callers expect: PG_EVENT_WRITE while
	// bytes remain buffered (caller waits for POLLOUT), PG_EVENT_NONE once fully sent
	// (caller proceeds straight to the result fetch). Sets error_info on a fatal send.
	void native_stmt_send_or_wait();
	// Finish flushing a partially-sent extended-query step on a POLLOUT re-entry.
	void native_stmt_flush_cont();

	// --- Native backend TLS (Task 1.6b) ---
	// native_ssl_requested is set in native_connect_start() when SSL is wanted for
	// this backend (parent->use_ssl). When true the handshake takes the
	// SSL_SEND_REQUEST -> SSL_READ_REPLY -> SSL_HANDSHAKE path before SEND_STARTUP,
	// and all subsequent native I/O is funneled through SSL_read/SSL_write against
	// myds->ssl (BIO-mem model, pumped to/from `fd` by native_send_or_buffer /
	// native_recv_into_framer). When false the plaintext 1.6a path is used verbatim.
	bool native_ssl_requested = false;
	// SSL verification mode derived from the backend config. Mirrors the libpq
	// sslmode semantics so native TLS honors the same policy as the libpq path.
	enum class PG_Native_SSL_Mode {
		DISABLE,      // no SSL at all (native_ssl_requested == false)
		REQUIRE,      // encrypt, do NOT verify (matches libpq sslmode=require)
		VERIFY_CA,    // encrypt + verify chain to CA, no hostname check
		VERIFY_FULL   // encrypt + verify chain + hostname (X509 host check)
	};
	PG_Native_SSL_Mode native_ssl_mode = PG_Native_SSL_Mode::DISABLE;
	// Pending raw ciphertext awaiting send() to the fd (connect phase only). When
	// SSL_write/SSL_do_handshake produces bytes into wbio_ssl faster than the socket
	// drains, the remainder parks here so the next writable event flushes it. Kept
	// distinct from native_outbuf (which holds *plaintext* protocol bytes).
	std::string native_ssl_outbuf;
	// Owned per-connection client SSL_CTX (TLS_client_method()). Freed in
	// native_teardown() and the destructor. nullptr in plaintext mode.
	SSL_CTX* native_ssl_ctx = nullptr;

	// Native handshake helpers (implemented in PgSQL_Connection.cpp). They drive the
	// sub-state machine above and never block: every recv()/send() handles EAGAIN by
	// setting async_exit_status and returning to the event loop.
	void native_connect_start();
	void native_connect_cont(short event);
	void native_drive_auth(short event);             // AUTH sub-state: Authentication* exchange
	void native_drive_startup_tail(short event);     // post-auth: ParamStatus/KeyData/ReadyForQuery
	bool native_flush_outbuf();                      // returns false on fatal send error
	// Queue an outbound message and try to flush it. If it can't all go out now,
	// parks in SEND_STARTUP and resumes in `resume_st` once drained. Returns false
	// on fatal send error (caller should teardown + return).
	bool native_send_or_buffer(PG_Native_Conn_St resume_st);
	// Non-blocking recv() into the framer. Returns: 1 = got bytes (or already had
	// buffered), 0 = EAGAIN (caller should wait for READ), -1 = EOF/fatal.
	int native_recv_into_framer();
	void native_teardown();                          // close fd, free scram (capability gap / failure)
	void native_capability_gap(const char* mechanism); // tear down native, restart via libpq
	// Parse an ErrorResponse ('E') payload into error_info.
	void native_fill_error_from_E(const unsigned char* payload, uint32_t len);

	// --- Native backend TLS helpers (Task 1.6b). All non-blocking. ---
	// Drive the SSL_HANDSHAKE sub-state: pump bytes between the mem BIOs and the raw
	// fd, calling SSL_do_handshake(). Returns: 1 = handshake complete, 0 = need more
	// I/O (async_exit_status already set, caller returns), -1 = fatal (error_info set,
	// teardown done). On success the connection moves on to SEND_STARTUP over TLS.
	int native_drive_ssl_handshake();
	// Build/obtain a TLS_client_method() SSL_CTX configured from the backend SSL
	// params for this server (CA, client cert/key, CRL, min proto version, verify
	// mode). Returns a per-connection SSL_CTX the caller owns, or nullptr on error.
	SSL_CTX* native_create_client_ssl_ctx();
	// Pump any plaintext bytes SSL has buffered in wbio_ssl out to the raw fd.
	// Returns true on success (all flushed, or EAGAIN with bytes still buffered),
	// false on a fatal write error. Used by the encrypted native_flush_outbuf path.
	bool native_ssl_pump_wbio_to_fd(bool& would_block);
	// Build + queue the StartupMessage and advance toward AUTH. Works for both the
	// plaintext path and the post-handshake TLS path (native_send_or_buffer routes
	// through SSL_write when myds->encrypted). On a fatal error it sets error_info
	// and returns false (caller does the teardown). Returns true otherwise.
	bool native_send_startup();
	uint8_t result_type;
	PGresult* pgsql_result;
	PSresult  ps_result;
	PgSQL_Query_Result* query_result;
	PgSQL_Query_Result* query_result_reuse;
	unsigned long long creation_time;
	unsigned long long last_time_used;
	unsigned long long timeout;
	int auto_increment_delay_token;
	PG_ASYNC_ST async_state_machine;	// Async state machine
	short wait_events;
	bool new_result;
	bool is_copy_out;

	bool send_quit;
	bool reusable;
	bool healthy; // false: destroy the connection, never reset it; not restored by reset()
	bool processing_multi_statement;
	bool multiplex_delayed;
	bool is_client_connection; // true if this is a client connection, false if it is a server connection
	bool exit_pipeline_mode; // true if it is safe to exit pipeline mode
	bool resync_failed; // true if the last resync attempt failed

	PgSQL_STMT_Local* local_stmts;
	PgSQL_SrvC *parent;
	PgSQL_Connection_userinfo* userinfo;
	PgSQL_Data_Stream* myds;
	//unsigned int warning_count;
	int fd;
	/**
	 * @brief This represents the internal knowledge of ProxySQL about the connection. It keeps track of those
	 *  states which *are not reflected* into 'server_status', but are relevant for connection handling.
	 */
	uint32_t status_flags;
	unsigned long largest_query_length;
	int async_exit_status; // exit status of Non blocking API
	bool unknown_transaction_status;

private:
	// Set end state for the fetch result to indicate that it originates from a simple query or statement execution.
	ASYNC_ST fetch_result_end_st = ASYNC_QUERY_END;
	inline void set_fetch_result_end_state(ASYNC_ST st) {
		assert(st == ASYNC_QUERY_END || st == ASYNC_STMT_EXECUTE_END || 
			st == ASYNC_STMT_DESCRIBE_END || st == ASYNC_STMT_PREPARE_END ||
			st == ASYNC_RESYNC_END);
		fetch_result_end_st = st;
	}
	// Handles the COPY OUT response from the server.
	// Returns true if it consumes all buffer data, or false if the threshold for result size is reached
	bool handle_copy_out(const PGresult* result, uint64_t* processed_bytes);
	static void notice_handler_cb(void* arg, const PGresult* result);
	static void unhandled_notice_cb(void* arg, const PGresult* result);
	void init_query_result();

	/**
	 * @brief Checks if a substring at a given position in a string matches the format of a formatted PostgreSQL error header.
	 *
	 * The expected format is: <UPPERCASE_PREFIX>:<SIZE>:
	 * - <UPPERCASE_PREFIX>: One or more uppercase letters (A-Z).
	 * - <SIZE>: One or more digits representing the length of the following value.
	 * - The header must be followed by a colon ':'.
	 *
	 * Example of a valid header: "S:5:Error"
	 *
	 * @param s The string to check.
	 * @param pos The position in the string to start checking.
	 * @return true if a valid formatted error header is found at the given position, false otherwise.
	 */
	static bool is_valid_formatted_pq_error_header(const std::string& s, size_t pos);

	/**
	 * @brief Parses a PostgreSQL error message string into its component fields.
	 *
	 * This function scans the input error string, extracts all such formatted fields, and stores them
	 * in a map from prefix to a vector of values (to support repeated fields). Any unformatted text
	 * is stored under the "LE" (Library Error) key.
	 *
	 * Example input: "S:5:ERRORC:5:12345M:12:Some message"
	 * Output: { "S": ["ERROR"], "C": ["12345"], "M": ["Some message"] }
	 *
	 * @param error_str The error message string to parse.
	 * @return std::map<std::string, std::vector<std::string>> Map of error field prefixes to their values.
	 */
	static std::map<std::string, std::vector<std::string>> parse_pq_error_message(const std::string& error_str);
};

class PgSQL_Backend_Kill_Args {
public:
	enum class TYPE {
		CANCEL_QUERY = 0,
		TERMINATE_CONNECTION
	};
	PGcancel* cancel_conn;
	PgSQL_Thread* pgsql_thd;

	char* username;
	char* password;
	char* hostname;
	char* dbname;
	unsigned int port;

	// Copies of the credential material harvested for this user's frontend login. The kill/terminate
	// connection authenticates to the backend exactly like a pooled one, so it needs the same
	// pass-through keys: a verifier/md5 secret shipped as a plaintext 'password' is rejected.
	uint8_t scram_client_key[PGSQL_SCRAM_KEY_LEN];
	uint8_t scram_server_key[PGSQL_SCRAM_KEY_LEN];
	bool has_scram_keys;

	int backend_pid;
	unsigned int hostgroup_id;
	TYPE type;

	// Native-mode cancellation. When native_mode is true the backend connection
	// has no libpq handle (cancel_conn is NULL), so CANCEL_QUERY is served by
	// opening a fresh blocking TCP connection to hostname:port and sending a raw
	// 16-byte CancelRequest carrying (backend_pid, native_secret_key). For
	// TERMINATE_CONNECTION, backend_pid is set to the real backend PID captured
	// from BackendKeyData so the libpq pg_terminate_backend() path works too.
	bool native_mode = false;
	int native_secret_key = 0;

	// SSL options
	struct SSLConfig {
		bool use_ssl = false;
		char* sslkey;
		char* sslcert;
		char* sslrootcert;
		char* sslcrl;
		char* sslcrldir;
		char* ssl_min_protocol_version;
		char* ssl_max_protocol_version;
	} ssl_config;

	// 'ui' supplies the credentials (username/password/dbname AND any harvested SCRAM keys); it is
	// deep-copied, since the kill runs on a detached thread that outlives the source connection.
	PgSQL_Backend_Kill_Args(PGconn* conn, const PgSQL_Connection_userinfo* ui, const char* host,
		unsigned int port, unsigned int hid, bool ssl, TYPE typ, PgSQL_Thread* thd);
	~PgSQL_Backend_Kill_Args();
};

void* PgSQL_backend_kill_thread(void* arg);

#endif /* PROXYSQL_PGSQL_CONNECTION_H */
