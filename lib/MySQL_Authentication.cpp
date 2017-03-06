#include "btree_map.h"
#include "proxysql.h"
#include "cpp.h"
#include "proxysql_atomic.h"
#include "SpookyV2.h"

/*
typedef struct _account_details_t {
	char *username;
	char *password;
	bool use_ssl;
	int default_hostgroup;
	char *default_schema;
	bool schema_locked;
	bool transaction_persistent;
	bool fast_forward;
} account_details_t;
*/

//#ifdef DEBUG
//#define DEB "_DEBUG"
//#else
//#define DEB ""
//#endif /* DEBUG */
//#define MYSQL_AUTHENTICATION_VERSION "0.1.0706" DEB

/*
typedef btree::btree_map<uint64_t, account_details_t *> BtMap;

typedef struct _creds_group_t {
	rwlock_t lock;
	BtMap bt_map;
	PtrArray cred_array;
} creds_group_t;
*/


MySQL_Authentication::MySQL_Authentication() {
#ifdef DEBUG
	if (glovars.has_debug==false) {
#else
	if (glovars.has_debug==true) {
#endif /* DEBUG */
		perror("Incompatible debagging version");
		exit(EXIT_FAILURE);
	}
	spinlock_rwlock_init(&creds_backends.lock);
	spinlock_rwlock_init(&creds_frontends.lock);
	creds_backends.cred_array = new PtrArray();
	creds_frontends.cred_array = new PtrArray();

//	spinlock_rwlock_init(&rwlock);
//	authdb=new SQLite3DB();
//	authdb->open((char *)"file:mem_authdb?mode=memory&cache=shared", SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE | SQLITE_OPEN_FULLMUTEX);
//	authdb->execute(AUTH_TABLE_MYSQL_USERS);
//	authdb->execute(AUTH_TABLE_MYSQL_USERS_INCOMING);

};

MySQL_Authentication::~MySQL_Authentication() {
	reset();
	delete creds_backends.cred_array;
	delete creds_frontends.cred_array;
//	delete authdb;
};

void MySQL_Authentication::print_version() {
		fprintf(stderr,"Standard MySQL Authentication rev. %s -- %s -- %s\n", MYSQL_AUTHENTICATION_VERSION, __FILE__, __TIMESTAMP__);
	};


//void MySQL_Authentication::rdlock() {
//	spin_wrlock(&rwlock);
//}
//
//void MySQL_Authentication::rdunlock() {
//	spin_wrunlock(&rwlock);
//}
//
//void MySQL_Authentication::wrlock() {
//	spin_wrlock(&rwlock);
//}
//
//void MySQL_Authentication::wrunlock() {
//	spin_wrunlock(&rwlock);
//}


//bool MySQL_Authentication::user_add(unsigned int hid, char *add, uint16_t p, unsigned int _weight, enum MySerStatus status, unsigned int _comp /*, uint8_t _charset */, unsigned int _max_connections) {
//  bool ret;
//  proxy_debug(PROXY_DEBUG_MYSQL_CONNPOOL, 7, "Adding in mysql_servers_incoming server %s:%d in hostgroup %u with weight %u , status %u, %s compression, max_connections %d\n", add,p,hid,_weight,status, (_comp ? "with" : "without") /*, _charset */ , _max_connections);
//  char *q=(char *)"INSERT INTO mysql_servers_incoming VALUES (%u, \"%s\", %u, %u, %u, %u, %u)";
//  char *query=(char *)malloc(strlen(q)+strlen(add)+100);
//  sprintf(query,q,hid,add,p,_weight,status,_comp /*,_charset */, _max_connections);
//  ret=mydb->execute(query);
//  free(query);
//  return ret;
//}

void MySQL_Authentication::set_all_inactive(enum cred_username_type usertype) {
	creds_group_t &cg=(usertype==USERNAME_BACKEND ? creds_backends : creds_frontends);
	spin_wrlock(&cg.lock);
	unsigned int i;
	for (i=0; i<cg.cred_array->len; i++) {
		account_details_t *ado=(account_details_t *)cg.cred_array->index(i);
		ado->__active=false;
	}
	spin_wrunlock(&cg.lock);
}

void MySQL_Authentication::remove_inactives(enum cred_username_type usertype) {
	creds_group_t &cg=(usertype==USERNAME_BACKEND ? creds_backends : creds_frontends);
	spin_wrlock(&cg.lock);
	unsigned int i;
__loop_remove_inactives:
	for (i=0; i<cg.cred_array->len; i++) {
		account_details_t *ado=(account_details_t *)cg.cred_array->index(i);
		if (ado->__active==false) {
			del(ado->username,usertype,false);
			goto __loop_remove_inactives; // we aren't sure how the underlying structure changes, so we jump back to 0
		}
	}
	spin_wrunlock(&cg.lock);
}

bool MySQL_Authentication::add(char * username, char * password, enum cred_username_type usertype, bool use_ssl, int default_hostgroup, char *default_schema, bool schema_locked, bool transaction_persistent, bool fast_forward, int max_connections) {
	uint64_t hash1, hash2;
	SpookyHash *myhash=new SpookyHash();
	myhash->Init(1,2);
	myhash->Update(username,strlen(username));
	myhash->Final(&hash1,&hash2);
	delete myhash;

	creds_group_t &cg=(usertype==USERNAME_BACKEND ? creds_backends : creds_frontends);
	
	void *sha1_pass=NULL;
	char *oldpass=NULL;
	spin_wrlock(&cg.lock);
	//btree::btree_map<uint64_t, account_details_t *>::iterator lookup;
	std::unordered_map<uint64_t, account_details_t *>::iterator lookup;
	lookup = cg.bt_map.find(hash1);
	if (lookup != cg.bt_map.end()) {
		account_details_t *ad=lookup->second;
		cg.cred_array->remove_fast(ad);
     cg.bt_map.erase(lookup);
		free(ad->username);
		if (ad->sha1_pass) {
			oldpass=strdup(ad->password);
			sha1_pass=malloc(SHA_DIGEST_LENGTH);
			memcpy(sha1_pass,ad->sha1_pass,SHA_DIGEST_LENGTH);
		}
		free(ad->password);
		if (ad->sha1_pass) {
			free(ad->sha1_pass);
			ad->sha1_pass=NULL;
		}
		free(ad->default_schema);
		free(ad);
   }
	account_details_t *ad=(account_details_t *)malloc(sizeof(account_details_t));
	ad->username=strdup(username);
	ad->password=strdup(password);
	ad->sha1_pass=NULL;
	if (strlen(password)) {
		if (password[0]=='*') { // password is sha1(sha1(real_password))
			if (oldpass) {
				if (strcmp(password,oldpass)==0) { // pass is unchanged
					ad->sha1_pass=malloc(SHA_DIGEST_LENGTH);
					memcpy(ad->sha1_pass,sha1_pass,SHA_DIGEST_LENGTH);
				}
			}
		}
	}
	ad->use_ssl=use_ssl;
	ad->default_hostgroup=default_hostgroup;
	ad->default_schema=strdup(default_schema);
	ad->schema_locked=schema_locked;
	ad->transaction_persistent=transaction_persistent;
	ad->fast_forward=fast_forward;
	ad->max_connections=max_connections;
	ad->num_connections_used=0;
	ad->__active=true;
	cg.bt_map.insert(std::make_pair(hash1,ad));
	cg.cred_array->add(ad);
	spin_wrunlock(&cg.lock);

	if (oldpass) {
		free(oldpass);
		oldpass=NULL;
	}
	if (sha1_pass) {
		free(sha1_pass);
		sha1_pass=NULL;
	}
	return true;
};

int MySQL_Authentication::dump_all_users(account_details_t ***ads) {
	spin_rdlock(&creds_frontends.lock);
	spin_rdlock(&creds_backends.lock);
	int total_size;
	int idx_=0;
	unsigned i=0;
	account_details_t **_ads;
	//total_size=creds_frontends.bt_map.size()+creds_backends.bt_map.size();
	total_size=creds_frontends.cred_array->len+creds_backends.cred_array->len;
	if (!total_size) goto __exit_dump_all_users;
	_ads=(account_details_t **)malloc(sizeof(account_details_t *)*total_size);
//	btree::btree_map<uint64_t, account_details_t *>::iterator it;
//	for (it=creds_frontends.bt_map.begin(); it!=creds_frontends.bt_map.end(); it++) {
//		account_details_t *ad=lookup->second;
//		ads[idx]=(account_details_t *)malloc(sizeof(account_details_t));	
//	}
	for (i=0; i<creds_frontends.cred_array->len; i++) {
		account_details_t *ad=(account_details_t *)malloc(sizeof(account_details_t));
		account_details_t *ado=(account_details_t *)creds_frontends.cred_array->index(i);
		ad->username=strdup(ado->username);
		ad->password=strdup(ado->password);
		ad->sha1_pass=NULL;
		ad->use_ssl=ado->use_ssl;
		ad->default_hostgroup=ado->default_hostgroup;
		ad->default_schema=strdup(ado->default_schema);
		ad->schema_locked=ado->schema_locked;
		ad->transaction_persistent=ado->transaction_persistent;
		ad->fast_forward=ado->fast_forward;
		ad->max_connections=ado->max_connections;
		ad->__frontend=1;
		ad->__backend=0;
		_ads[idx_]=ad;
		idx_++;
	}
	for (i=0; i<creds_backends.cred_array->len; i++) {
		account_details_t *ad=(account_details_t *)malloc(sizeof(account_details_t));
		account_details_t *ado=(account_details_t *)creds_backends.cred_array->index(i);
		ad->username=strdup(ado->username);
		ad->password=strdup(ado->password);
		ad->sha1_pass=NULL;
		ad->use_ssl=ado->use_ssl;
		ad->default_hostgroup=ado->default_hostgroup;
		ad->default_schema=strdup(ado->default_schema);
		ad->schema_locked=ado->schema_locked;
		ad->transaction_persistent=ado->transaction_persistent;
		ad->fast_forward=ado->fast_forward;
		ad->max_connections=ado->max_connections;
		ad->__frontend=0;
		ad->__backend=1;
		_ads[idx_]=ad;
		idx_++;
	}
	*ads=_ads;
__exit_dump_all_users:
	spin_rdunlock(&creds_frontends.lock);
	spin_rdunlock(&creds_backends.lock);
	return total_size;
}


int MySQL_Authentication::increase_frontend_user_connections(char *username, int *mc) {
	uint64_t hash1, hash2;
	SpookyHash *myhash=new SpookyHash();
	myhash->Init(1,2);
	myhash->Update(username,strlen(username));
	myhash->Final(&hash1,&hash2);
	delete myhash;
	creds_group_t &cg=creds_frontends;
	int ret=0;
	spin_wrlock(&cg.lock);
	//btree::btree_map<uint64_t, account_details_t *>::iterator it;
	std::unordered_map<uint64_t, account_details_t *>::iterator it;
	it = cg.bt_map.find(hash1);
	if (it != cg.bt_map.end()) {
		account_details_t *ad=it->second;
		if (ad->max_connections > ad->num_connections_used) {
			ret=ad->max_connections-ad->num_connections_used;
			ad->num_connections_used++;
		}
		if (mc) {
			*mc=ad->max_connections;
		}
	}
	spin_wrunlock(&cg.lock);
	return ret;
}

void MySQL_Authentication::decrease_frontend_user_connections(char *username) {
	uint64_t hash1, hash2;
	SpookyHash *myhash=new SpookyHash();
	myhash->Init(1,2);
	myhash->Update(username,strlen(username));
	myhash->Final(&hash1,&hash2);
	delete myhash;
	creds_group_t &cg=creds_frontends;
	spin_wrlock(&cg.lock);
	//btree::btree_map<uint64_t, account_details_t *>::iterator it;
	std::unordered_map<uint64_t, account_details_t *>::iterator it;
	it = cg.bt_map.find(hash1);
	if (it != cg.bt_map.end()) {
		account_details_t *ad=it->second;
		if (ad->num_connections_used > 0) {
			ad->num_connections_used--;
		}
	}
	spin_wrunlock(&cg.lock);
}

bool MySQL_Authentication::del(char * username, enum cred_username_type usertype, bool set_lock) {
	bool ret=false;
	uint64_t hash1, hash2;
	SpookyHash *myhash=new SpookyHash();
	myhash->Init(1,2);
	myhash->Update(username,strlen(username));
	myhash->Final(&hash1,&hash2);
	delete myhash;

	creds_group_t &cg=(usertype==USERNAME_BACKEND ? creds_backends : creds_frontends);

	if (set_lock)
		spin_wrlock(&cg.lock);
	//btree::btree_map<uint64_t, account_details_t *>::iterator lookup;
	std::unordered_map<uint64_t, account_details_t *>::iterator lookup;
	lookup = cg.bt_map.find(hash1);
	if (lookup != cg.bt_map.end()) {
		account_details_t *ad=lookup->second;
		cg.cred_array->remove_fast(ad);
		cg.bt_map.erase(lookup);
		free(ad->username);
		free(ad->password);
		if (ad->sha1_pass) { free(ad->sha1_pass); ad->sha1_pass=NULL; }
		free(ad->default_schema);
		free(ad);
		ret=true;
	}
	if (set_lock)
		spin_wrunlock(&cg.lock);

	return ret;
};

bool MySQL_Authentication::set_SHA1(char * username, enum cred_username_type usertype, void *sha_pass) {
	bool ret=false;
	uint64_t hash1, hash2;
	SpookyHash *myhash=new SpookyHash();
	myhash->Init(1,2);
	myhash->Update(username,strlen(username));
	myhash->Final(&hash1,&hash2);
	delete myhash;

	creds_group_t &cg=(usertype==USERNAME_BACKEND ? creds_backends : creds_frontends);

	spin_wrlock(&cg.lock);
	//btree::btree_map<uint64_t, account_details_t *>::iterator lookup;
	std::unordered_map<uint64_t, account_details_t *>::iterator lookup;
	lookup = cg.bt_map.find(hash1);
	if (lookup != cg.bt_map.end()) {
		account_details_t *ad=lookup->second;
		if (ad->sha1_pass) { free(ad->sha1_pass); ad->sha1_pass=NULL; }
		if (sha_pass) {
			ad->sha1_pass=malloc(SHA_DIGEST_LENGTH);
			memcpy(ad->sha1_pass,sha_pass,SHA_DIGEST_LENGTH);
		}
		ret=true;
	}
   spin_wrunlock(&cg.lock);

	return ret;
};



char * MySQL_Authentication::lookup(char * username, enum cred_username_type usertype, bool *use_ssl, int *default_hostgroup, char **default_schema, bool *schema_locked, bool *transaction_persistent, bool *fast_forward, int *max_connections, void **sha1_pass) {
	char *ret=NULL;
	uint64_t hash1, hash2;
	SpookyHash myhash;
	myhash.Init(1,2);
	myhash.Update(username,strlen(username));
	myhash.Final(&hash1,&hash2);

	creds_group_t &cg=(usertype==USERNAME_BACKEND ? creds_backends : creds_frontends);

	spin_rdlock(&cg.lock);
	//btree::btree_map<uint64_t, account_details_t *>::iterator lookup;
	std::unordered_map<uint64_t, account_details_t *>::iterator lookup;
	lookup = cg.bt_map.find(hash1);
	if (lookup != cg.bt_map.end()) {
		account_details_t *ad=lookup->second;
		ret=l_strdup(ad->password);
		if (use_ssl) *use_ssl=ad->use_ssl;
		if (default_hostgroup) *default_hostgroup=ad->default_hostgroup;
		if (default_schema) *default_schema=l_strdup(ad->default_schema);
		if (schema_locked) *schema_locked=ad->schema_locked;
		if (transaction_persistent) *transaction_persistent=ad->transaction_persistent;
		if (fast_forward) *fast_forward=ad->fast_forward;
		if (max_connections) *max_connections=ad->max_connections;
		if (sha1_pass) {
			if (ad->sha1_pass) {
				*sha1_pass=malloc(SHA_DIGEST_LENGTH);
				memcpy(*sha1_pass,ad->sha1_pass,SHA_DIGEST_LENGTH);
			}
		}
	}
	spin_rdunlock(&cg.lock);
	return ret;

}

bool MySQL_Authentication::_reset(enum cred_username_type usertype) {
	creds_group_t &cg=(usertype==USERNAME_BACKEND ? creds_backends : creds_frontends);

	spin_wrlock(&cg.lock);
	//btree::btree_map<uint64_t, account_details_t *>::iterator lookup;
	std::unordered_map<uint64_t, account_details_t *>::iterator lookup;

	while (cg.bt_map.size()) {
		lookup = cg.bt_map.begin();
		if ( lookup != cg.bt_map.end() ) {
			account_details_t *ad=lookup->second;
			cg.cred_array->remove_fast(ad);
     	cg.bt_map.erase(lookup);
			free(ad->username);
			free(ad->password);
			if (ad->sha1_pass) { free(ad->sha1_pass); ad->sha1_pass=NULL; }
			free(ad);
		}
	}
	spin_wrunlock(&cg.lock);

	return true;
};

bool MySQL_Authentication::reset() {
	_reset(USERNAME_BACKEND);
	_reset(USERNAME_FRONTEND);
	return true;
}
