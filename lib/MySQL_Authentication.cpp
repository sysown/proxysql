#include "MySQL_Authentication.hpp"

#include "gen_utils.h"
#include "proxysql_atomic.h"
#include "SpookyV2.h"

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
};

MySQL_Authentication::~MySQL_Authentication() {
	reset();
	delete creds_backends.cred_array;
	delete creds_frontends.cred_array;
};

void MySQL_Authentication::print_version() {
		fprintf(stderr,"Standard MySQL Authentication rev. %s -- %s -- %s\n", MYSQL_AUTHENTICATION_VERSION, __FILE__, __TIMESTAMP__);
	};

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
	SpookyHash myhash;
	myhash.Init(1,2);
	myhash.Update(username,strlen(username));
	myhash.Final(&hash1,&hash2);

	creds_group_t &cg=(usertype==USERNAME_BACKEND ? creds_backends : creds_frontends);
	
	spin_wrlock(&cg.lock);
	std::unordered_map<uint64_t, account_details_t *>::iterator lookup;
	lookup = cg.bt_map.find(hash1);
	// few changes will follow, due to issue #802
	account_details_t *ad=NULL;
	bool new_ad=false;
	if (lookup != cg.bt_map.end()) {
		ad=lookup->second;
		if (strcmp(ad->password,password)) {
			free(ad->password);
			ad->password=strdup(password);
			if (ad->sha1_pass) {
				free(ad->sha1_pass);
				ad->sha1_pass=NULL;
			}
		}
		if (strcmp(ad->default_schema,default_schema)) {
			free(ad->default_schema);
			ad->default_schema=strdup(default_schema);
		}
  } else {
		ad=(account_details_t *)malloc(sizeof(account_details_t));
		ad->username=strdup(username);
		ad->default_schema=strdup(default_schema);
		ad->password=strdup(password);
		new_ad=true;
		ad->sha1_pass=NULL;
	}

	ad->use_ssl=use_ssl;
	ad->default_hostgroup=default_hostgroup;
	ad->schema_locked=schema_locked;
	ad->transaction_persistent=transaction_persistent;
	ad->fast_forward=fast_forward;
	ad->max_connections=max_connections;
	ad->num_connections_used=0;
	ad->__active=true;
	if (new_ad) {
		cg.bt_map.insert(std::make_pair(hash1,ad));
		cg.cred_array->add(ad);
	}
	spin_wrunlock(&cg.lock);

	return true;
};

int MySQL_Authentication::dump_all_users(account_details_t ***ads) {
	spin_rdlock(&creds_frontends.lock);
	spin_rdlock(&creds_backends.lock);
	int total_size;
	int idx_=0;
	unsigned i=0;
	account_details_t **_ads;
	total_size=creds_frontends.cred_array->len+creds_backends.cred_array->len;
	if (!total_size) goto __exit_dump_all_users;
	_ads=(account_details_t **)malloc(sizeof(account_details_t *)*total_size);
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
	std::unordered_map<uint64_t, account_details_t *>::iterator it;
	it = cg.bt_map.find(hash1);
	if (it != cg.bt_map.end()) {
		account_details_t *ad=it->second;
		ad->num_connections_used++;
		ret=ad->max_connections-ad->num_connections_used;
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
	std::unordered_map<uint64_t, account_details_t *>::iterator lookup;

	while (cg.bt_map.size()) {
		lookup = cg.bt_map.begin();
		if ( lookup != cg.bt_map.end() ) {
			account_details_t *ad=lookup->second;
     	cg.bt_map.erase(lookup);
			free(ad->username);
			free(ad->password);
			if (ad->sha1_pass) { free(ad->sha1_pass); ad->sha1_pass=NULL; }
			free(ad->default_schema);
			free(ad);
		}
	}
	while (cg.cred_array->len) {
		cg.cred_array->remove_index_fast(0);
	}
	spin_wrunlock(&cg.lock);

	return true;
};

bool MySQL_Authentication::reset() {
	_reset(USERNAME_BACKEND);
	_reset(USERNAME_FRONTEND);
	return true;
}
