#ifndef CLASS_BASE_SESSION_H
#define CLASS_BASE_SESSION_H

#include "proxysql.h"
/*
#include "MySQL_Variables.h"

#include "../deps/json/json.hpp"
using json = nlohmann::json;
*/
class MySQL_Session;
class PgSQL_Session;

class Base_Session {
	public:
	Base_Session();
	~Base_Session();
};

#endif // CLASS_BASE_SESSION_H
