#ifndef __CLASS_QUERY_PROCESSOR_H
#define __CLASS_QUERY_PROCESSOR_H
#include "proxysql.h"
#include "cpp.h"


typedef btree::btree_map<uint64_t, void *> BtMap_query_digest;

enum MYSQL_COM_QUERY_command {
	MYSQL_COM_QUERY_ALTER_TABLE,
	MYSQL_COM_QUERY_ANALYZE_TABLE,
	MYSQL_COM_QUERY_BEGIN,
	MYSQL_COM_QUERY_CHANGE_MASTER,
	MYSQL_COM_QUERY_COMMIT,
	MYSQL_COM_QUERY_CREATE_DATABASE,
	MYSQL_COM_QUERY_CREATE_INDEX,
	MYSQL_COM_QUERY_CREATE_TABLE,
	MYSQL_COM_QUERY_CREATE_TEMPORARY,
	MYSQL_COM_QUERY_CREATE_TRIGGER,
	MYSQL_COM_QUERY_CREATE_USER,
	MYSQL_COM_QUERY_DELETE,
	MYSQL_COM_QUERY_DESCRIBE,
	MYSQL_COM_QUERY_DROP_DATABASE,
	MYSQL_COM_QUERY_DROP_INDEX,
	MYSQL_COM_QUERY_DROP_TABLE,
	MYSQL_COM_QUERY_DROP_TRIGGER,
	MYSQL_COM_QUERY_DROP_USER,
	MYSQL_COM_QUERY_GRANT,
	MYSQL_COM_QUERY_EXPLAIN,
	MYSQL_COM_QUERY_FLUSH,
	MYSQL_COM_QUERY_INSERT,
	MYSQL_COM_QUERY_KILL,
	MYSQL_COM_QUERY_LOAD,
	MYSQL_COM_QUERY_LOCK_TABLE,
	MYSQL_COM_QUERY_OPTIMIZE,
	MYSQL_COM_QUERY_PREPARE,
	MYSQL_COM_QUERY_PURGE,
	MYSQL_COM_QUERY_RENAME_TABLE,
	MYSQL_COM_QUERY_RESET_MASTER,
	MYSQL_COM_QUERY_RESET_SLAVE,
	MYSQL_COM_QUERY_REPLACE,
	MYSQL_COM_QUERY_REVOKE,
	MYSQL_COM_QUERY_ROLLBACK,
	MYSQL_COM_QUERY_SAVEPOINT,
	MYSQL_COM_QUERY_SELECT,
	MYSQL_COM_QUERY_SELECT_FOR_UPDATE,
	MYSQL_COM_QUERY_SET,
	MYSQL_COM_QUERY_SHOW_TABLE_STATUS,
	MYSQL_COM_QUERY_START_TRANSACTION,
	MYSQL_COM_QUERY_UNLOCK_TABLES,
	MYSQL_COM_QUERY_UPDATE,
	MYSQL_COM_QUERY_USE,
	MYSQL_COM_QUERY_SHOW,
	MYSQL_COM_QUERY_UNKNOWN,
	MYSQL_COM_QUERY___NONE // Special marker.
};

struct _Query_Processor_rule_t {
	int rule_id;
	bool active;
	char *username;
	char *schemaname;
	int flagIN;
	char *match_digest;
	char *match_pattern;
	bool negate_match_pattern;
	int flagOUT;
	char *replace_pattern;
	int destination_hostgroup;
	int cache_ttl;
	int reconnect;
	int timeout;
	int delay;
	char *error_msg;
	bool apply;
	void *regex_engine1;
	void *regex_engine2;
	int hits;
	struct _Query_Processor_rule_t *parent; // pointer to parent, to speed up parent update
};


//struct _Query_Processor_output_t {
//	void *ptr;
//	unsigned int size;
//	int destination_hostgroup;
//	int cache_ttl;
//	int reconnect;
//	int timeout;
//	int delay;
//	std::string *new_query;
//};

typedef struct _Query_Processor_rule_t QP_rule_t;
//typedef struct _Query_Processor_output_t QP_out_t;

class Query_Processor_Output {
	public:
	void *ptr;
	unsigned int size;
	int destination_hostgroup;
	int cache_ttl;
	int reconnect;
	int timeout;
	int delay;
  char *error_msg;
	std::string *new_query;
	void * operator new(size_t size) {
		return l_alloc(size);
	}
	void operator delete(void *ptr) {
		l_free(sizeof(Query_Processor_Output),ptr);
	}
	Query_Processor_Output() {
		ptr=NULL;
		size=0;
		destination_hostgroup=-1;
		cache_ttl=-1;
		reconnect=-1;
		timeout=-1;
		delay=-1;
		new_query=NULL;
		error_msg=NULL;
	}
	~Query_Processor_Output() {
		if (error_msg) {
			free(error_msg);
		}
	}
};

static char *commands_counters_desc[MYSQL_COM_QUERY___NONE];

class Command_Counter {
	private:
	int cmd_idx;
	int _add_idx(unsigned long long t) {
		if (t<=100) return 0;
		if (t<=500) return 1;
		if (t<=1000) return 2;
		if (t<=5000) return 3;
		if (t<=10000) return 4;
		if (t<=50000) return 5;
		if (t<=100000) return 6;
		if (t<=500000) return 7;
		if (t<=1000000) return 8;
		if (t<=5000000) return 9;
		if (t<=10000000) return 10;
		return 11;
	}
	public:
	unsigned long long total_time;
	unsigned long long counters[13];
	Command_Counter(int a) {
		total_time=0;
		cmd_idx=a;
		total_time=0;
		for (int i=0; i<13; i++) {
			counters[i]=0;
		}
	}
	unsigned long long add_time(unsigned long long t) {
		total_time+=t;
		counters[0]++;
		int i=_add_idx(t);
		counters[i+1]++;
		return total_time;
	}
	char **get_row() {
		char **pta=(char **)malloc(sizeof(char *)*15);
		pta[0]=commands_counters_desc[cmd_idx];
		itostr(pta[1],total_time);
		for (int i=0;i<13;i++) itostr(pta[i+2], counters[i]);
		return pta;
	}
	void free_row(char **pta) {
		for (int i=1;i<15;i++) free(pta[i]);
		free(pta);
	}
};



class Query_Processor {


	private:
	enum MYSQL_COM_QUERY_command __query_parser_command_type(void *args);

	rwlock_t digest_rwlock;
	BtMap_query_digest digest_bt_map;

	protected:
	rwlock_t rwlock;
	std::vector<QP_rule_t *> rules;
	Command_Counter * commands_counters[MYSQL_COM_QUERY___NONE];
	volatile unsigned int version;
	public:
	Query_Processor();
	~Query_Processor();
	//const char *version();
	void print_version();
	void reset_all(bool lock=true);
	void wrlock();		// explicit write lock, to be used in multi-isert 
	void wrunlock();	// explicit write unlock
	bool insert(QP_rule_t *qr, bool lock=true);		// insert a new rule. Uses a generic void pointer to a structure that may vary depending from the Query Processor
//	virtual bool insert_locked(QP_rule_t *qr) {return false;};		// call this instead of insert() in case lock was already acquired via wrlock()
	QP_rule_t * new_query_rule(int rule_id, bool active, char *username, char *schemaname, int flagIN, char *match_digest, char *match_pattern, bool negate_match_pattern, int flagOUT, char *replace_pattern, int destination_hostgroup, int cache_ttl, int reconnect, int timeout, int delay, char *error_msg, bool apply);	// to use a generic query rule struct, this is generated by this function and returned as generic void pointer
	void delete_query_rule(QP_rule_t *qr);	// destructor
	//virtual bool remove(int rule_id, bool lock=true) {return false;}; // FIXME: not implemented yet, should be implemented at all ?
//	virtual bool remove_locked(int rule_id) {return false;};		// call this instead of remove() in case lock was already acquired via wrlock()
	Query_Processor_Output * process_mysql_query(MySQL_Session *sess, void *ptr, unsigned int size, Query_Info *qi);
	void delete_QP_out(Query_Processor_Output *o);

	void sort(bool lock=true);

	void init_thread();
	void end_thread();
	void commit();	// this applies all the changes in memory
	SQLite3_result * get_current_query_rules();
	SQLite3_result * get_stats_query_rules();	

	void update_query_processor_stats();

	void * query_parser_init(char *query, int query_length, int flags);
	enum MYSQL_COM_QUERY_command query_parser_command_type(void *args);
	bool query_parser_first_comment(Query_Processor_Output *qpo, char *fc);
	void query_parser_free(void *args);
	char * get_digest_text(void *args);

	void update_query_digest(void *p, MySQL_Connection_userinfo *ui, unsigned long long t, unsigned long long n);

	unsigned long long query_parser_update_counters(MySQL_Session *sess, enum MYSQL_COM_QUERY_command c, void *p, unsigned long long t);

	SQLite3_result * get_stats_commands_counters();
	SQLite3_result * get_query_digests();
	SQLite3_result * get_query_digests_reset();
};


typedef Query_Processor * create_Query_Processor_t();

#endif /* __CLASS_QUERY_PROCESSOR_H */
