#ifndef CLASS_MYSQL_LDAP_AUTHENTICATION_H
#define CLASS_MYSQL_LDAP_AUTHENTICATION_H

class MySQL_LDAP_Authentication {
public:
	MySQL_LDAP_Authentication() {};
	virtual ~MySQL_LDAP_Authentication() {};
	//virtual bool add(char *username, char *backend_username, char *password, enum cred_username_type usertype, bool use_ssl, int default_hostgroup, char *default_schema, bool schema_locked, bool transaction_persistent, bool fast_forward, int max_connections) {return false;};
	// virtual bool del(char *username, enum cred_username_type usertype, bool set_lock=true) {return false;};
	virtual bool reset() {return false;};
	virtual void print_version() {};
	virtual char * lookup(char *username, char *pass, 
			enum cred_username_type usertype, bool *use_ssl, int *default_hostgroup, 
			char **default_schema, bool *schema_locked, bool *transaction_persistent, 
			bool *fast_forward, int *max_connections, void **sha1_pass, char **attributes,
			char **backend_username) {return NULL;};
	virtual int increase_frontend_user_connections(char *username, int *mc=NULL) {return 0;};
	virtual void decrease_frontend_user_connections(char *username) {};
	virtual void set_all_inactive(enum cred_username_type usertype) {};
	// virtual void remove_inactives(enum cred_username_type usertype) {};
	virtual bool set_SHA1(char *username, enum cred_username_type usertype, void *sha_pass) {return false;};
	virtual char **get_variables_list() {return NULL;}
	virtual bool has_variable(const char *name) {return false;};
	virtual void wrlock() {};
	virtual void wrunlock() {};
	virtual char * get_variable(char *name) {return NULL;};
	virtual bool set_variable(char *name, char *value) {return false;};
	virtual int password_matches(char *u, char *pass) {return 0;}; // 0 = not match , 1 = matches , 2 = not present
	virtual void load_mysql_ldap_mapping(SQLite3_result *result) {};
	virtual SQLite3_result * dump_table_mysql_ldap_mapping() { return NULL; };
	virtual uint64_t get_ldap_mapping_runtime_checksum() { return 0; };
	virtual SQLite3_result * SQL3_getStats() { return NULL; }
};

typedef MySQL_LDAP_Authentication * create_MySQL_LDAP_Authentication_t();

#endif /* CLASS_MYSQL_LDAP_AUTHENTICATION_H */
