#ifndef __CLASS_STANDARD_MYSQL_THREAD_H
#define __CLASS_STANDARD_MYSQL_THREAD_H


class Standard_MySQL_Thread: public MySQL_Thread
{
	private:
	MySQL_Connection **my_idle_conns;
	MySQL_Data_Stream **my_idle_myds;
	bool processing_idles;
	unsigned long long last_processing_idles;
	PtrArray *mysql_sessions_connections_handler;

	public:
	rwlock_t thread_mutex;
	Standard_MySQL_Thread();
	virtual ~Standard_MySQL_Thread();
	MySQL_Session * create_new_session_and_client_data_stream(int _fd);
	bool init();
	void run();
	void poll_listener_add(int sock);
	void poll_listener_del(int sock);
	void register_session(MySQL_Session*);
	void unregister_session(int);
	struct pollfd * get_pollfd(unsigned int i);
	void process_data_on_data_stream(MySQL_Data_Stream *myds, unsigned int n);
	void process_all_sessions();
	void refresh_variables();
	void process_all_sessions_connections_handler();
	void register_session_connection_handler(MySQL_Session *_sess);
	void unregister_session_connection_handler(int idx);
	void myds_backend_set_failed_connect(MySQL_Data_Stream *myds, unsigned int n);
	void myds_backend_pause_connect(MySQL_Data_Stream *myds);
	void myds_backend_first_packet_after_connect(MySQL_Data_Stream *myds, unsigned int n);
	void listener_handle_new_connection(MySQL_Data_Stream *myds, unsigned int n);
	SQLite3_result * SQL3_Thread_status(MySQL_Session *sess);
};
#endif /* __CLASS_STANDARD_MYSQL_THREAD_H */
