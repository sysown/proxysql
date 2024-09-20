#ifndef __CLASS_CLIENT_SESSION_H
#define __CLASS_CLIENT_SESSION_H

#include <functional>
#include <vector>

#include "proxysql.h"
#include "cpp.h"
#include "MySQL_Variables.h"

//#include "../deps/json/json.hpp"
//using json = nlohmann::json;

#ifndef PROXYJSON
#define PROXYJSON
#include "../deps/json/json_fwd.hpp"
#endif // PROXYJSON

class MySQL_Session;
class PgSQL_Session;

#if 0
// this code was moved into Base_Session.h
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
#endif // 0

template <class T>
class TypeSelector {
};

template<class T>
class TypeSelector<T*> {
public:
	TypeSelector(T* _ptr) : ptr(_ptr) { }
	~TypeSelector() {}
	TypeSelector<T*>& operator=(T* _ptr) {
		ptr = _ptr;
		return *this;
	}

	T* operator->() {
		return ptr;
	}
	bool operator==(T* _ptr) { return (ptr == _ptr); }
	T& operator*() const noexcept { return *ptr; }
	explicit operator bool() { return ptr != nullptr; }
	operator T* () {
		return ptr;
	}

private:
	T* ptr;
};

/* Issues with forward class declaration
template<class T>
using Client_Session = TypeSelector<T*>; 
*/
template <class T>
class Client_Session : public TypeSelector<T> {
public:
	//Client_Session(const Client_Session<T>&) = default;
	//Client_Session(Client_Session<T>&&) = default;
	//Client_Session& operator=(const Client_Session<T>&) = default;
	//Client_Session& operator=(Client_Session<T>&&) = default;
	//~Client_Session() = default;
	using TypeSelector<T>::TypeSelector;
};
#define TO_CLIENT_SESSION(sess) Client_Session<decltype(sess)>(sess)

/* Issues with forward class declaration
template<class T>
using Query_Info_T = TypeSelector<T*>;
*/
template <class T>
class Query_Info_T : public TypeSelector<T> {
public:
	using TypeSelector<T>::TypeSelector;
};
#define TO_QUERY_INFO(query_info) Query_Info_T<decltype(query_info)>(query_info)

/* Issues with forward class declaration
template<class T>
using Data_Stream_T = TypeSelector<T*>;
*/
template <class T>
class Data_Stream_T : public TypeSelector<T> {
public:
	using TypeSelector<T>::TypeSelector;
};
#define TO_DATA_STREAM(data_stream) Data_Stream_T<decltype(data_stream)>(data_stream)

/* Issues with forward class declaration
template<class T>
using Connection_Info_T = TypeSelector<T*>;
*/
template <class T>
class Connection_Info_T : public TypeSelector<T> {
public:
	using TypeSelector<T>::TypeSelector;
};
#define TO_CONNECTION_INFO(connection_info) Connection_Info_T<decltype(connection_info)>(connection_info)

std::string proxysql_session_type_str(enum proxysql_session_type session_type);

#endif /* __CLASS_CLIENT_SESSION_H */
