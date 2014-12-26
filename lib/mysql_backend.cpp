#include "proxysql.h"
#include "cpp.h"

extern __thread MySQL_Connection_Pool * MyConnPool;


MySQL_Server * MySQL_HostGroups_Handler::server_add(MySQL_Server *srv) {
	proxy_debug(PROXY_DEBUG_MYSQL_CONNPOOL, 4, "Adding MySQL_Server %p in Global Handler\n", srv);
	Servers->add(srv);
	return srv;
}

void MySQL_HostGroups_Handler::reset() {
	proxy_debug(PROXY_DEBUG_MYSQL_CONNPOOL, 4, "Resetting all MSHGE from Global Handler\n");
//	if (MyHostGroups.empty()==false) MyHostGroups.clear();
	while (MyHostGroups->len) {
		MySQL_Hostgroup *myhg=(MySQL_Hostgroup *)MyHostGroups->remove_index_fast(0);
		delete myhg;
	}
	proxy_debug(PROXY_DEBUG_MYSQL_CONNPOOL, 4, "Resetting all MySQL Server from Global Handler\n");
	while (Servers->len) {
		MySQL_Server *srv=(MySQL_Server *)Servers->remove_index_fast(0);
		delete srv;
	}
}

MySQL_Server * MySQL_HostGroups_Handler::server_find(char *add, uint16_t p) {
	unsigned int i;
	for (i=0; i<Servers->len; i++) {
		MySQL_Server *srv=(MySQL_Server *)Servers->index(i);
		if (strcmp(srv->address,add)==0 && srv->port==p) {
			return srv;
		};
	}
	return NULL;
};

size_t MySQL_HostGroups_Handler::servers_in_hostgroup(int hid) {
	MySQL_Hostgroup *myhg=(MySQL_Hostgroup *)MyHostGroups->index(hid);
	return myhg->servers_in_hostgroup();
};


MySQL_Hostgroup_Entry * MySQL_HostGroups_Handler::set_HG_entry_status(unsigned int hid, MySQL_Server *msptr, enum proxysql_server_status _status) {
	MySQL_Hostgroup *myhg=(MySQL_Hostgroup *)MyHostGroups->index(hid);
	return myhg->set_HG_entry_status(msptr,_status);
};


MySQL_Hostgroup_Entry * MySQL_HostGroups_Handler::set_HG_entry_status(unsigned int hid, char *add, uint16_t p, enum proxysql_server_status _status) {
	MySQL_Server *msptr=server_find(add,p);
	if (msptr==NULL) return NULL; // server not found
	MySQL_Hostgroup *myhg=(MySQL_Hostgroup *)MyHostGroups->index(hid);
	MySQL_Hostgroup_Entry *myhge=myhg->set_HG_entry_status(msptr,_status);
	return myhge;
};



//MySQL_Hostgroup_Entry * MySQL_HostGroups_Handler::server_add_hg(unsigned int hid, char *add=NULL, uint16_t p=3306, unsigned int _weight=1) {
MySQL_Hostgroup_Entry * MySQL_HostGroups_Handler::server_add_hg(unsigned int hid, char *add, uint16_t p, unsigned int _weight) {
	proxy_debug(PROXY_DEBUG_MYSQL_CONNPOOL, 4, "Adding MySQL server %s:%d in Global Handler in hostgroup\n", add, p, hid);
	if (hid>=MyHostGroups->len) {
		create_hostgroup(hid);
	};
	MySQL_Server *srv=server_add(add,p);
	MySQL_Hostgroup *myhg=(MySQL_Hostgroup *)MyHostGroups->index(hid);
	return myhg->server_add(srv, _weight);
};
MySQL_Hostgroup_Entry * MySQL_HostGroups_Handler::MSHGE_find(unsigned int hid, MySQL_Server *srv) {
	proxy_debug(PROXY_DEBUG_MYSQL_CONNPOOL, 4, "Searching MSHGE for MySQL_Server %p into HID %d\n", srv, hid);
	MySQL_Hostgroup *myhg=(MySQL_Hostgroup *)MyHostGroups->index(hid);
	return myhg->MSHGE_find(srv);
}
MySQL_Hostgroup_Entry * MySQL_HostGroups_Handler::MSHGE_find(unsigned int hid, char *add, uint16_t p) {
	proxy_debug(PROXY_DEBUG_MYSQL_CONNPOOL, 4, "Searching MSHGE for MySQL server %s:%d into HID %d\n", add, p, hid);
	MySQL_Server *srv=server_find(add,p);
	if (srv==NULL) return NULL; // server not found
	return MSHGE_find(hid,srv);
}


void MySQL_HostGroups_Handler::insert_hostgroup(MySQL_Hostgroup *myhg) {
	unsigned int p=myhg->hostgroup_id;
	proxy_debug(PROXY_DEBUG_MYSQL_CONNPOOL, 4, "Inserting hostgroup %p with HID %d in Global Handler\n", myhg, p);
	while (MyHostGroups->len < (p+1) ) {
		MyHostGroups->add(NULL);
	}
	//MyHostGroups.insert(MyHostGroups.begin()+p,myhg);
	//MyHostGroups[p]=myhg;
	MyHostGroups->pdata[p]=myhg;
}



void * MySQL_Backend::operator new(size_t size) {
	return l_alloc(size);
}

void MySQL_Backend::operator delete(void *ptr) {
	l_free(sizeof(MySQL_Backend),ptr);
}

MySQL_Backend::MySQL_Backend() {
	hostgroup_id=-1;
	server_myds=NULL;
	myconn=NULL;
	server_bytes_at_cmd.bytes_recv=0;
	server_bytes_at_cmd.bytes_sent=0;
}

MySQL_Backend::~MySQL_Backend() {
}

void MySQL_Backend::reset() {
	if (server_myds) {
		//delete server_myds;
		server_myds=NULL;
	}
	if (myconn) {
		if (myconn->reusable==false) {
			//server_myds->myconn=NULL;
			delete myconn;
		} else {
//			MyConnArray *MCA=MyConnPool->MyConnArray_lookup(myconn->mshge->MSptr->address, myconn->myconn.user, myconn->mshge->MSptr->password, myconn->mshge->MSptr->db, myconn->mshge->MSptr->port);
		}
	};
	myconn=NULL;
}




void MySQL_Hostgroup::add(MySQL_Hostgroup_Entry *mshge) {
	proxy_debug(PROXY_DEBUG_MYSQL_CONNPOOL, 4, "Adding MySQL_Hostgroup_Entry %p to Hostgroup %p with HID %d\n", mshge, this, hostgroup_id);
	MSHGEs->add(mshge);
}

void MySQL_Hostgroup::add(MySQL_Server *msptr, unsigned int _weight) {
	MySQL_Hostgroup_Entry *mshge=new MySQL_Hostgroup_Entry(hostgroup_id, msptr, _weight);
	this->add(mshge);
}

bool MySQL_Hostgroup::del(MySQL_Hostgroup_Entry *mshge) {
	proxy_debug(PROXY_DEBUG_MYSQL_CONNPOOL, 4, "Deleting MySQL_Hostgroup_Entry %p from Hostgroup %p with HID %d\n", mshge, this, hostgroup_id);
	MySQL_Hostgroup_Entry *it=NULL;
	unsigned int i;
	for (i=0; i< MSHGEs->len; i++) {
		it=(MySQL_Hostgroup_Entry *)MSHGEs->index(i);
		if (it==mshge) {
			it=(MySQL_Hostgroup_Entry *)MSHGEs->remove_index_fast(i);
			delete it;
			return true;
		}
	}
	return false;
}

bool MySQL_Hostgroup::del(MySQL_Server *msptr) {
	proxy_debug(PROXY_DEBUG_MYSQL_CONNPOOL, 4, "Deleting MySQL_Hostgroup_Entry with MySQL_Server %p from Hostgroup %p with HID %d\n", msptr, this, hostgroup_id);
	MySQL_Hostgroup_Entry *it=NULL;
	unsigned int i;
	for (i=0; i< MSHGEs->len; i++) {
		it=(MySQL_Hostgroup_Entry *)MSHGEs->index(i);
		if (it->MSptr==msptr) {
			it=(MySQL_Hostgroup_Entry *)MSHGEs->remove_index_fast(i);
			delete it;
			return true;
		}
	}
	return false;
}

MySQL_Hostgroup_Entry * MySQL_Hostgroup::MSHGE_find(MySQL_Server *msptr) {
	proxy_debug(PROXY_DEBUG_MYSQL_CONNPOOL, 4, "Searching MySQL_Hostgroup_Entry for MySQL_Server %p from Hostgroup %p with HID %d\n", msptr, this, hostgroup_id);
	MySQL_Hostgroup_Entry *it=NULL;
	unsigned int i;
	for (i=0; i< MSHGEs->len; i++) {
		it=(MySQL_Hostgroup_Entry *)MSHGEs->index(i);
		if (it->MSptr==msptr) {
			return it; 
		}
	}
	proxy_debug(PROXY_DEBUG_MYSQL_CONNPOOL, 4, "MySQL_Hostgroup_Entry not found\n");
	return NULL;
}


size_t MySQL_Hostgroup::servers_in_hostgroup() {
	return MSHGEs->len;
}

