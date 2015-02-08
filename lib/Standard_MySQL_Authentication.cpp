#include "btree_map.h"
#include "proxysql.h"
#include "cpp.h"
#include "proxysql_atomic.h"
#include "SpookyV2.h"


typedef struct _account_details_t {
//	char *domain;
	char *username;
	char *password;
	bool use_ssl;
	int default_hostgroup;
	bool transaction_persistent;
} account_details_t;

#ifdef DEBUG
#define DEB "_DEBUG"
#else
#define DEB ""
#endif /* DEBUG */
#define MYSQL_AUTHENTICATION_VERSION "0.1.0706" DEB

//#define MY_SEPERATOR_HASH	"__uy1gf2doi3ujh4ge5__"

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
//	rwlock_t lock;
//	BtMap bt_map;
//	PtrArray cred_array;
	public:
	Standard_MySQL_Authentication() {
		spinlock_rwlock_init(&creds_backends.lock);
		spinlock_rwlock_init(&creds_frontends.lock);
	};

	~Standard_MySQL_Authentication() {
		reset();
	};

	virtual void print_version() {
		fprintf(stderr,"Standard MySQL Authentication rev. %s -- %s -- %s\n", MYSQL_AUTHENTICATION_VERSION, __FILE__, __TIMESTAMP__);
	};

	//virtual bool add(char * domain, char * username, char * password) {
//	virtual bool add(char * username, char * password, enum cred_username_type usertype, bool use_ssl) {
	virtual bool add(char * username, char * password, enum cred_username_type usertype, bool use_ssl, int default_hostgroup, bool transaction_persistent) {
		uint64_t hash1, hash2;
		SpookyHash *myhash=new SpookyHash();
		myhash->Init(1,2);
//		myhash->Update(domain,strlen(domain));
//		myhash->Update(MY_SEPERATOR_HASH,strlen(MY_SEPERATOR_HASH));
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
//			free(ad->domain);
			free(ad->username);
			free(ad->password);
			free(ad);
    }
		account_details_t *ad=(account_details_t *)malloc(sizeof(account_details_t));
//		ad->domain=strdup(domain);
		ad->username=strdup(username);
		ad->password=strdup(password);
		ad->use_ssl=use_ssl;
		ad->default_hostgroup=default_hostgroup;
		ad->transaction_persistent=transaction_persistent;
    cg.bt_map.insert(std::make_pair(hash1,ad));
		cg.cred_array.add(ad);
    spin_wrunlock(&cg.lock);

		return true;
	};

	//virtual bool del(char * domain, char * username) {
	virtual bool del(char * username, enum cred_username_type usertype) {
		bool ret=false;
		uint64_t hash1, hash2;
		SpookyHash *myhash=new SpookyHash();
		myhash->Init(1,2);
//		myhash->Update(domain,strlen(domain));
//		myhash->Update(MY_SEPERATOR_HASH,strlen(MY_SEPERATOR_HASH));
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
//			free(ad->domain);
			free(ad->username);
			free(ad->password);
			free(ad);
			ret=true;
		}
    spin_wrunlock(&cg.lock);

		return ret;
	};



	virtual char * lookup(char * username, enum cred_username_type usertype, bool *use_ssl, int *default_hostgroup, bool *transaction_persistent) {
		char *ret=NULL;
		uint64_t hash1, hash2;
		SpookyHash *myhash=new SpookyHash();
		myhash->Init(1,2);
		myhash->Update(username,strlen(username));
		myhash->Final(&hash1,&hash2);
		delete myhash;

		creds_group_t &cg=(usertype==USERNAME_BACKEND ? creds_backends : creds_frontends);

		spin_rdlock(&cg.lock);
		btree::btree_map<uint64_t, account_details_t *>::iterator lookup;
		lookup = cg.bt_map.find(hash1);
		if (lookup != cg.bt_map.end()) {
			account_details_t *ad=lookup->second;
			ret=l_strdup(ad->password);
			if (use_ssl) *use_ssl=ad->use_ssl;
			if (default_hostgroup) *default_hostgroup=ad->default_hostgroup;
			if (transaction_persistent) *transaction_persistent=ad->transaction_persistent;
		}
		spin_rdunlock(&cg.lock);
		return ret;

	}

/*
	//virtual char * lookup(char * domain, char * username) {
	virtual char * lookup(char * username, enum cred_username_type usertype, bool *use_ssl) {
		char *ret=NULL;
		uint64_t hash1, hash2;
		SpookyHash *myhash=new SpookyHash();
		myhash->Init(1,2);
//		myhash->Update(domain,strlen(domain));
//		myhash->Update(MY_SEPERATOR_HASH,strlen(MY_SEPERATOR_HASH));
		myhash->Update(username,strlen(username));
		myhash->Final(&hash1,&hash2);
		delete myhash;

		creds_group_t &cg=(usertype==USERNAME_BACKEND ? creds_backends : creds_frontends);

		spin_rdlock(&cg.lock);
		btree::btree_map<uint64_t, account_details_t *>::iterator lookup;
		lookup = cg.bt_map.find(hash1);
		if (lookup != cg.bt_map.end()) {
			account_details_t *ad=lookup->second;
			//ret=strdup(ad->password);
			ret=l_strdup(ad->password);
			if (use_ssl) *use_ssl=ad->use_ssl;
		}
		spin_rdunlock(&cg.lock);
		return ret;
	}
*/

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
//				free(ad->domain);
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

