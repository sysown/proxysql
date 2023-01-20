#ifndef CLASS_MYSQL_LDAP_AUTHENTICATION_H
#define CLASS_MYSQL_LDAP_AUTHENTICATION_H

struct LDAP_USER_FIELD_IDX {
	enum index {
		USERNAME = 0,
		FRONTEND_CONNECTIONS = 1,
		FRONTED_MAX_CONNECTIONS = 2,
		__SIZE
	};
};

class MySQL_LDAP_Authentication {
public:
	virtual char * lookup(char *username, char *pass, 
			enum cred_username_type usertype, bool *use_ssl, int *default_hostgroup, 
			char **default_schema, bool *schema_locked, bool *transaction_persistent, 
			bool *fast_forward, int *max_connections, void **sha1_pass, char **attributes,
			char **backend_username) {return NULL;};

	virtual int increase_frontend_user_connections(char *username, int *max_connections = NULL) { return 0; };
	virtual void decrease_frontend_user_connections(char *username) {};
	virtual std::unique_ptr<SQLite3_result> dump_all_users() { return 0; };

	virtual void wrlock() {};
	virtual void wrunlock() {};

	virtual char **get_variables_list() {return NULL;}
	virtual bool has_variable(const char *name) {return false;};
	virtual char * get_variable(char *name) {return NULL;};
	virtual bool set_variable(char *name, char *value) {return false;};

	virtual void load_mysql_ldap_mapping(SQLite3_result *result) {};
	virtual SQLite3_result * dump_table_mysql_ldap_mapping() { return NULL; };
	virtual uint64_t get_ldap_mapping_runtime_checksum() { return 0; };
	virtual SQLite3_result * SQL3_getStats() { return NULL; }

	virtual void print_version() {};
};

typedef MySQL_LDAP_Authentication * create_MySQL_LDAP_Authentication_t();

#endif /* CLASS_MYSQL_LDAP_AUTHENTICATION_H */
