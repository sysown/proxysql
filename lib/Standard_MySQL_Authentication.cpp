#include "btree_map.h"
#include "proxysql.h"
#include "cpp.h"
#include "proxysql_atomic.h"
#include "SpookyV2.h"


typedef struct _account_details_t {
	char *domain;
	char *username;
	char *password;
} account_details_t;

#define MYSQL_AUTHENTICATION_VERSION "0.1.0706"

#define MY_SEPERATOR_HASH	"__uy1gf2doi3ujh4ge5__"

typedef btree::btree_map<uint64_t, account_details_t *> BtMap;

class Standard_MySQL_Authentication: public MySQL_Authentication {
	private:
	rwlock_t lock;
	BtMap bt_map;
	PtrArray cred_array;
	public:
	Standard_MySQL_Authentication() {
		spinlock_rwlock_init(&lock);
	};

	~Standard_MySQL_Authentication() {
		reset();
	};

	virtual void print_version() {
		fprintf(stderr,"Standard MySQL Authentication rev. %s -- %s -- %s\n", MYSQL_AUTHENTICATION_VERSION, __FILE__, __TIMESTAMP__);
	};

	virtual bool add(char * domain, char * username, char * password) {
		uint64_t hash1, hash2;
		SpookyHash *myhash=new SpookyHash();
		myhash->Init(1,2);
		myhash->Update(domain,strlen(domain));
		myhash->Update(MY_SEPERATOR_HASH,strlen(MY_SEPERATOR_HASH));
		myhash->Update(username,strlen(username));
		myhash->Final(&hash1,&hash2);
		delete myhash;

		spin_wrlock(&lock);
		btree::btree_map<uint64_t, account_details_t *>::iterator lookup;
		lookup = bt_map.find(hash1);
		if (lookup != bt_map.end()) {
			account_details_t *ad=lookup->second;
			cred_array.remove_fast(ad);
      bt_map.erase(lookup);
			free(ad->domain);
			free(ad->username);
			free(ad->password);
			free(ad);
    }
		account_details_t *ad=(account_details_t *)malloc(sizeof(account_details_t));
		ad->domain=strdup(domain);
		ad->username=strdup(username);
		ad->password=strdup(password);
    bt_map.insert(std::make_pair(hash1,ad));
		cred_array.add(ad);
    spin_wrunlock(&lock);

		return true;
	};

	virtual bool del(char * domain, char * username) {
		bool ret=false;
		uint64_t hash1, hash2;
		SpookyHash *myhash=new SpookyHash();
		myhash->Init(1,2);
		myhash->Update(domain,strlen(domain));
		myhash->Update(MY_SEPERATOR_HASH,strlen(MY_SEPERATOR_HASH));
		myhash->Update(username,strlen(username));
		myhash->Final(&hash1,&hash2);
		delete myhash;

		spin_wrlock(&lock);
		btree::btree_map<uint64_t, account_details_t *>::iterator lookup;
		lookup = bt_map.find(hash1);
		if (lookup != bt_map.end()) {
			account_details_t *ad=lookup->second;
			cred_array.remove_fast(ad);
      bt_map.erase(lookup);
			free(ad->domain);
			free(ad->username);
			free(ad->password);
			free(ad);
			ret=true;
		}
    spin_wrunlock(&lock);

		return ret;
	};



	virtual char * lookup(char * domain, char * username) {
		char *ret=NULL;
		uint64_t hash1, hash2;
		SpookyHash *myhash=new SpookyHash();
		myhash->Init(1,2);
		myhash->Update(domain,strlen(domain));
		myhash->Update(MY_SEPERATOR_HASH,strlen(MY_SEPERATOR_HASH));
		myhash->Update(username,strlen(username));
		myhash->Final(&hash1,&hash2);
		delete myhash;

		spin_rdlock(&lock);
		btree::btree_map<uint64_t, account_details_t *>::iterator lookup;
		lookup = bt_map.find(hash1);
		if (lookup != bt_map.end()) {
			account_details_t *ad=lookup->second;
			//ret=strdup(ad->password);
			ret=l_strdup(ad->password);
		}
		spin_rdunlock(&lock);
		return ret;
	}


	virtual bool reset() {
		spin_wrlock(&lock);
		btree::btree_map<uint64_t, account_details_t *>::iterator lookup;

		while (bt_map.size()) {
			lookup = bt_map.begin();
			if ( lookup != bt_map.end() ) {
				account_details_t *ad=lookup->second;
				cred_array.remove_fast(ad);
      	bt_map.erase(lookup);
				free(ad->domain);
				free(ad->username);
				free(ad->password);
				free(ad);
			}
		}
		spin_wrunlock(&lock);

		return true;
	};


};


extern "C" MySQL_Authentication * create_MySQL_Authentication_func() {
    return new Standard_MySQL_Authentication();
}

extern "C" void destroy_MyAuth(MySQL_Authentication * myauth) {
    delete myauth;
}

