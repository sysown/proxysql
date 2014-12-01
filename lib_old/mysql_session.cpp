#include "proxysql.h"
#include "cpp.h"
/*
class MySQL_Session
{
	public:
	int healthy;
	int admin;
	int client_fd;
	int server_fd;
	int status;
	char *username;
	char *password;
	char *schema_cur;
	char *schema_new;

	MySQL_Session();
	MySQL_Session(int);
	~MySQL_Session();
};
*/

MySQL_Session::MySQL_Session() {
	healthy=1;
	client_fd=0;
	server_fd=0;
	status=0;
	username=NULL;
	password=NULL;
	schema_cur=NULL;
	schema_new=NULL;
	client_myds=NULL;
	server_myds=NULL;
	sess_states=STATE_NOT_CONNECTED;
	mybes=g_ptr_array_new();
	//backend
}

MySQL_Session::MySQL_Session(int _fd) {
	MySQL_Session();
	client_fd=_fd;
}

MySQL_Session::~MySQL_Session() {
	if (username) { free(username); }
	if (password) { free(password); }
	if (schema_cur) { free(schema_cur); }
	if (schema_new) { free(schema_new); }
	g_ptr_array_free(mybes,TRUE);
	proxy_debug(PROXY_DEBUG_NET,1,"Shutdown Session %p\n" , this);
}


// scan the pointer array of mysql backends (mybes) looking for a backend for the specified hostgroup_id
int MySQL_Session::find_backend(int hostgroup_id) {
	MySQL_Backend *mybe;
	unsigned int i;
	for (i=0; i < mybes->len; i++) {
		mybe=(MySQL_Backend *)g_ptr_array_index(mybes,i);
		if (mybe->hostgroup_id==hostgroup_id) {
			return i;
		}
	}
	return -1; // -1 = backend not found
}


void MySQL_Session::reset_all_backends() {
	MySQL_Backend *mybe;
	while(mybes->len) {
		mybe=(MySQL_Backend *)g_ptr_array_remove_index_fast(mybes,0);
		mybe->reset();
		delete mybe;
	}
}

void MySQL_Session::writeout() {
	if (client_myds) client_myds->write_pkts();
	if (server_myds) server_myds->write_pkts();
	if (client_myds) client_myds->set_epollout();
	if (server_myds) server_myds->set_epollout();
}
//in MySQL_Session::
