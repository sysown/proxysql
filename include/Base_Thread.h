#ifndef CLASS_BASE_THREAD_H
#define CLASS_BASE_THREAD_H

#include "proxysql.h"

class MySQL_Thread;
class PgSQL_Thread;

class Base_Thread {
	public:
	unsigned long long curtime;
	int shutdown;
	Base_Thread();
	~Base_Thread();
	template<typename T, typename S>
	S create_new_session_and_client_data_stream(int _fd);
};

#endif // CLASS_BASE_THREAD_H
