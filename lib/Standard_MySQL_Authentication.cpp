#include "btree_map.h"
#include "proxysql.h"
#include "cpp.h"
#include "proxysql_atomic.h"
#include "SpookyV2.h"


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

#ifdef DEBUG
#define DEB "_DEBUG"
#else
#define DEB ""
#endif /* DEBUG */
#define MYSQL_AUTHENTICATION_VERSION "0.1.0706" DEB

typedef btree::btree_map<uint64_t, account_details_t *> BtMap;

typedef struct _creds_group_t {
	rwlock_t lock;
	BtMap bt_map;
	PtrArray cred_array;
} creds_group_t;

class Standard_MySQL_Authentication: public MySQL_Authentication {
	private:
	creds_group_t creds_backends;
	creds_group_t creds_frontends;
	public:
	Standard_MySQL_Authentication() {
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
	};

	~Standard_MySQL_Authentication() {
		reset();
	};

	virtual void print_version() {
		fprintf(stderr,"Standard MySQL Authentication rev. %s -- %s -- %s\n", MYSQL_AUTHENTICATION_VERSION, __FILE__, __TIMESTAMP__);
	};

	virtual bool add(char * username, char * password, enum cred_username_type usertype, bool use_ssl, int default_hostgroup, char *default_schema, bool schema_locked, bool transaction_persistent, bool fast_forward) {
		uint64_t hash1, hash2;
		SpookyHash *myhash=new SpookyHash();
		myhash->Init(1,2);
		myhash->Update(username,strlen(username));
		myhash->Final(&hash1,&hash2);
		delete myhash;

		creds_group_t &cg=(usertype==USERNAME_BACKEND ? creds_backends : creds_frontends);
	
		spin_wrlock(&cg.lock);
		btree::btree_map<uint64_t, account_details_t *>::iterator lookup;
		lookup = cg.bt_map.find(hash1);
		if (lookup != cg.bt_map.end()) {
			account_details_t *ad=lookup->second;
			cg.cred_array.remove_fast(ad);
      cg.bt_map.erase(lookup);
			free(ad->username);
			free(ad->password);
			free(ad->default_schema);
			free(ad);
    }
		account_details_t *ad=(account_details_t *)malloc(sizeof(account_details_t));
		ad->username=strdup(username);
		ad->password=strdup(password);
		ad->use_ssl=use_ssl;
		ad->default_hostgroup=default_hostgroup;
		ad->default_schema=strdup(default_schema);
		ad->schema_locked=schema_locked;
		ad->transaction_persistent=transaction_persistent;
		ad->fast_forward=fast_forward;
    cg.bt_map.insert(std::make_pair(hash1,ad));
		cg.cred_array.add(ad);
    spin_wrunlock(&cg.lock);

		return true;
	};

	virtual bool del(char * username, enum cred_username_type usertype) {
		bool ret=false;
		uint64_t hash1, hash2;
		SpookyHash *myhash=new SpookyHash();
		myhash->Init(1,2);
		myhash->Update(username,strlen(username));
		myhash->Final(&hash1,&hash2);
		delete myhash;

		creds_group_t &cg=(usertype==USERNAME_BACKEND ? creds_backends : creds_frontends);

		spin_wrlock(&cg.lock);
		btree::btree_map<uint64_t, account_details_t *>::iterator lookup;
		lookup = cg.bt_map.find(hash1);
		if (lookup != cg.bt_map.end()) {
			account_details_t *ad=lookup->second;
			cg.cred_array.remove_fast(ad);
      cg.bt_map.erase(lookup);
			free(ad->username);
			free(ad->password);
			free(ad->default_schema);
			free(ad);
			ret=true;
		}
    spin_wrunlock(&cg.lock);

		return ret;
	};



	virtual char * lookup(char * username, enum cred_username_type usertype, bool *use_ssl, int *default_hostgroup, char **default_schema, bool *schema_locked, bool *transaction_persistent, bool *fast_forward) {
		char *ret=NULL;
		uint64_t hash1, hash2;
		SpookyHash myhash;
		myhash.Init(1,2);
		myhash.Update(username,strlen(username));
		myhash.Final(&hash1,&hash2);

		creds_group_t &cg=(usertype==USERNAME_BACKEND ? creds_backends : creds_frontends);

		spin_rdlock(&cg.lock);
		btree::btree_map<uint64_t, account_details_t *>::iterator lookup;
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
		}
		spin_rdunlock(&cg.lock);
		return ret;

	}

	bool _reset(enum cred_username_type usertype) {

		creds_group_t &cg=(usertype==USERNAME_BACKEND ? creds_backends : creds_frontends);

		spin_wrlock(&cg.lock);
		btree::btree_map<uint64_t, account_details_t *>::iterator lookup;

		while (cg.bt_map.size()) {
			lookup = cg.bt_map.begin();
			if ( lookup != cg.bt_map.end() ) {
				account_details_t *ad=lookup->second;
				cg.cred_array.remove_fast(ad);
      	cg.bt_map.erase(lookup);
				free(ad->username);
				free(ad->password);
				free(ad);
			}
		}
		spin_wrunlock(&cg.lock);

		return true;
	};

	virtual bool reset() {
		_reset(USERNAME_BACKEND);
		_reset(USERNAME_FRONTEND);
		return true;
	}
};


extern "C" MySQL_Authentication * create_MySQL_Authentication_func() {
    return new Standard_MySQL_Authentication();
}

extern "C" void destroy_MyAuth(MySQL_Authentication * myauth) {
    delete myauth;
}

