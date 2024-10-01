#ifndef CLASS_BASE_THREAD_H
#define CLASS_BASE_THREAD_H

#include "proxysql.h"

typedef struct _thr_id_username_t {
	uint32_t id;
	char *username;
} thr_id_usr;

typedef struct _kill_queue_t {
	pthread_mutex_t m;
	std::vector<thr_id_usr *> conn_ids;
	std::vector<thr_id_usr *> query_ids;
} kill_queue_t;

/**
 * @class Session_Regex
 * @brief Encapsulates regex operations for session handling.
 *
 * This class is used for matching patterns in SQL queries, specifically for
 * settings like sql_log_bin, sql_mode, and time_zone.
 * See issues #509 , #815 and #816
 */
class Session_Regex {
private:
	void* opt;
	void* re;
	char* s;
public:
	Session_Regex(char* p);
	~Session_Regex();
	bool match(char* m);
};

class MySQL_Thread;
class PgSQL_Thread;

class Base_Thread {
	private:
	bool maintenance_loop;
	public:
	unsigned long long curtime;
	unsigned long long last_move_to_idle_thread_time;
	bool epoll_thread;
	int shutdown;
	PtrArray *mysql_sessions;
	Session_Regex **match_regexes;
	Base_Thread();
	~Base_Thread();
	template<typename T, typename S>
	S create_new_session_and_client_data_stream(int _fd);
	template<typename T, typename S>
	void register_session(T, S, bool up_start = true);
	template<typename T>
	void check_timing_out_session(unsigned int n);
	template<typename T>
	void check_for_invalid_fd(unsigned int n);
	template<typename S>
	void ProcessAllSessions_SortingSessions();
	template<typename T>
	void ProcessAllMyDS_AfterPoll();
	template<typename T>
	void read_one_byte_from_pipe(unsigned int n);
	template<typename T, typename DS>
	void tune_timeout_for_myds_needs_pause(DS * myds);
	template<typename T, typename DS>
	void tune_timeout_for_session_needs_pause(DS * myds);
	template<typename T, typename DS>
	void configure_pollout(DS * myds, unsigned int n);
	template<typename T, typename DS>
	bool set_backend_to_be_skipped_if_frontend_is_slow(DS * myds, unsigned int n);
#ifdef IDLE_THREADS
	template<typename T, typename DS> bool move_session_to_idle_mysql_sessions(DS * myds, unsigned int n);
#endif // IDLE_THREADS
	template<typename T, typename S> unsigned int find_session_idx_in_mysql_sessions(S * sess);
	template<typename T> void ProcessAllMyDS_BeforePoll();
	template<typename T, typename S> void run_SetAllSession_ToProcess0();


#if ENABLE_TIMER
	// for now this is not accessible via Admin/Prometheus , thus useful only with gdb
	struct {
		TimerCount Sessions_Handlers;
		TimerCount Connections_Handlers;
	} Timers;
#endif // ENABLE_TIMER

	friend class MySQL_Thread;
	friend class PgSQL_Thread;
};

std::string proxysql_session_type_str(enum proxysql_session_type session_type);

#endif // CLASS_BASE_THREAD_H
