//#include "btree_map.h"
#include "proxysql.h"
#include "cpp.h"
#include "proxysql_atomic.h"

#include "MySQL_Authentication.hpp"

#ifndef SPOOKYV2
#include "SpookyV2.h"
#define SPOOKYV2
#endif

MySQL_Authentication::MySQL_Authentication() {
#ifdef DEBUG
	if (glovars.has_debug==false) {
#else
	if (glovars.has_debug==true) {
#endif /* DEBUG */
		perror("Incompatible debugging version");
		exit(EXIT_FAILURE);
	}
#ifdef PROXYSQL_AUTH_PTHREAD_MUTEX
	pthread_rwlock_init(&creds_backends.lock, NULL);
	pthread_rwlock_init(&creds_frontends.lock, NULL);
#else
	spinlock_rwlock_init(&creds_backends.lock);
	spinlock_rwlock_init(&creds_frontends.lock);
#endif
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
#ifdef PROXYSQL_AUTH_PTHREAD_MUTEX
	pthread_rwlock_wrlock(&cg.lock);
#else
	spin_wrlock(&cg.lock);
#endif
	unsigned int i;
	for (i=0; i<cg.cred_array->len; i++) {
		account_details_t *ado=(account_details_t *)cg.cred_array->index(i);
		ado->__active=false;
	}
#ifdef PROXYSQL_AUTH_PTHREAD_MUTEX
	pthread_rwlock_unlock(&cg.lock);
#else
	spin_wrunlock(&cg.lock);
#endif
}

void MySQL_Authentication::remove_inactives(enum cred_username_type usertype) {
	creds_group_t &cg=(usertype==USERNAME_BACKEND ? creds_backends : creds_frontends);
#ifdef PROXYSQL_AUTH_PTHREAD_MUTEX
	pthread_rwlock_wrlock(&cg.lock);
#else
	spin_wrlock(&cg.lock);
#endif
	unsigned int i;
__loop_remove_inactives:
	for (i=0; i<cg.cred_array->len; i++) {
		account_details_t *ado=(account_details_t *)cg.cred_array->index(i);
		if (ado->__active==false) {
			del(ado->username,usertype,false);
			goto __loop_remove_inactives; // we aren't sure how the underlying structure changes, so we jump back to 0
		}
	}
#ifdef PROXYSQL_AUTH_PTHREAD_MUTEX
	pthread_rwlock_unlock(&cg.lock);
#else
	spin_wrunlock(&cg.lock);
#endif
}

bool MySQL_Authentication::add(char * username, char * password, enum cred_username_type usertype, bool use_ssl, int default_hostgroup, char *default_schema, bool schema_locked, bool transaction_persistent, bool fast_forward, int max_connections, char* attributes, char *comment) {
	uint64_t hash1, hash2;
	SpookyHash myhash;
	myhash.Init(1,2);
	myhash.Update(username,strlen(username));
	myhash.Final(&hash1,&hash2);

	creds_group_t &cg=(usertype==USERNAME_BACKEND ? creds_backends : creds_frontends);
	
#ifdef PROXYSQL_AUTH_PTHREAD_MUTEX
	pthread_rwlock_wrlock(&cg.lock);
#else
	spin_wrlock(&cg.lock);
#endif
	std::map<uint64_t, account_details_t *>::iterator lookup;
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
		if (strcmp(ad->comment,comment)) {
			free(ad->comment);
			ad->comment=strdup(comment);
		}
		if (strcasecmp(ad->attributes, attributes)) {
			free(ad->attributes);
			if (strlen(attributes)) {
				// NOTE: add() is only place where we do input validation
				try {
					nlohmann::json valid=nlohmann::json::parse(attributes);
					// we do further input validation here, and possibly transforming the JSON itself
					bool json_rewritten = false;
					auto default_transaction_isolation = valid.find("default-transaction_isolation");
					if (default_transaction_isolation != valid.end()) {
						std::string dti = valid["default-transaction_isolation"].get<std::string>();
						for (unsigned int i = 0; i < dti.length(); ++i) {
							if (dti[i] == '-') {
								dti[i] = ' ';
								json_rewritten = true; // the json needs to be rewritten
							}
						}
						// input validation
						if (
							   (strcasecmp(dti.c_str(), "READ UNCOMMITTED")==0 )
							|| (strcasecmp(dti.c_str(), "READ COMMITTED")==0 )
							|| (strcasecmp(dti.c_str(), "REPEATABLE READ")==0 )
							|| (strcasecmp(dti.c_str(), "SERIALIZABLE")==0 )
						) {
							if (json_rewritten) {
								valid["default-transaction_isolation"]=dti;
							}
						} else {
							std::string dti_orig = valid["default-transaction_isolation"].get<std::string>();
							proxy_error("Invalid default-transaction_isolation for user %s : %s . Removing it from runtime\n", username, dti_orig.c_str());
							valid.erase("default-transaction_isolation");
							json_rewritten = true; // the json was rewritten
						}
					}
					if (json_rewritten) {
						std::string d = valid.dump();
						if (d.length()==2) { // empty json
							ad->attributes=strdup(""); // empty string
						} else {
							ad->attributes=strdup(d.c_str());
						}
					} else {
						// the JSON wasn't rewritten for the purpose of input validation, therefore we copy the original value
						ad->attributes=strdup(attributes);
					}
				}
				catch(nlohmann::json::exception& e) {
					ad->attributes=strdup("");
					proxy_error("Invalid attributes for user %s: %s\n", username, attributes);
				}
			} else {
				ad->attributes=strdup(attributes); // default, empty string
			}
		}
  } else {
		ad=(account_details_t *)malloc(sizeof(account_details_t));
		ad->username=strdup(username);
		ad->default_schema=strdup(default_schema);
		ad->comment=strdup(comment);
		ad->password=strdup(password);
		if (strlen(attributes)) {
			// NOTE: add() is only place where we do input validation
			try {
				nlohmann::json valid=nlohmann::json::parse(attributes);
				ad->attributes=strdup(attributes);
			}
			catch(nlohmann::json::exception& e) {
				ad->attributes=strdup("");
				proxy_error("Invalid attributes for user %s: %s\n", username, attributes);
			}
		} else {
			ad->attributes=strdup(attributes); // default, empty string
		}
		new_ad=true;
		ad->sha1_pass=NULL;
		ad->num_connections_used=0;
	}

	ad->use_ssl=use_ssl;
	ad->default_hostgroup=default_hostgroup;
	ad->schema_locked=schema_locked;
	ad->transaction_persistent=transaction_persistent;
	ad->fast_forward=fast_forward;
	ad->max_connections=max_connections;
	ad->__active=true;
	if (new_ad) {
		cg.bt_map.insert(std::make_pair(hash1,ad));
		cg.cred_array->add(ad);
	}
#ifdef PROXYSQL_AUTH_PTHREAD_MUTEX
	pthread_rwlock_unlock(&cg.lock);
#else
	spin_wrunlock(&cg.lock);
#endif
	return true;
};


unsigned int MySQL_Authentication::memory_usage() {
	unsigned int ret=0;
#ifdef PROXYSQL_AUTH_PTHREAD_MUTEX
	pthread_rwlock_rdlock(&creds_frontends.lock);
	pthread_rwlock_rdlock(&creds_backends.lock);
#else
	spin_rdlock(&creds_frontends.lock);
	spin_rdlock(&creds_backends.lock);
#endif
	unsigned i=0;
	for (i=0; i<creds_frontends.cred_array->len; i++) {
		account_details_t *ado=(account_details_t *)creds_frontends.cred_array->index(i);
		ret += sizeof(account_details_t);
		if (ado->username) ret += strlen(ado->username) + 1;
		if (ado->password) ret += strlen(ado->password) + 1;
		if (ado->sha1_pass) ret += SHA_DIGEST_LENGTH;
		if (ado->default_schema) ret += strlen(ado->default_schema) + 1;
		if (ado->comment) ret += strlen(ado->comment) + 1;
		if (ado->attributes) ret += strlen(ado->attributes) + 1;
	}
	ret += sizeof(creds_group_t);
	ret += sizeof(PtrArray);
	ret += (creds_frontends.cred_array->size * sizeof(void *));
	for (i=0; i<creds_backends.cred_array->len; i++) {
		account_details_t *ado=(account_details_t *)creds_backends.cred_array->index(i);
		ret += sizeof(account_details_t);
		if (ado->username) ret += strlen(ado->username) + 1;
		if (ado->password) ret += strlen(ado->password) + 1;
		if (ado->sha1_pass) ret += SHA_DIGEST_LENGTH;
		if (ado->default_schema) ret += strlen(ado->default_schema) + 1;
		if (ado->comment) ret += strlen(ado->comment) + 1;
		if (ado->attributes) ret += strlen(ado->attributes) + 1;
	}
	ret += sizeof(creds_group_t);
	ret += sizeof(PtrArray);
	ret += (creds_backends.cred_array->size * sizeof(void *));
#ifdef PROXYSQL_AUTH_PTHREAD_MUTEX
	pthread_rwlock_unlock(&creds_frontends.lock);
	pthread_rwlock_unlock(&creds_backends.lock);
#else
	spin_rdunlock(&creds_frontends.lock);
	spin_rdunlock(&creds_backends.lock);
#endif
	return ret;
}

int MySQL_Authentication::dump_all_users(account_details_t ***ads, bool _complete) {
#ifdef PROXYSQL_AUTH_PTHREAD_MUTEX
	pthread_rwlock_rdlock(&creds_frontends.lock);
	pthread_rwlock_rdlock(&creds_backends.lock);
#else
	spin_rdlock(&creds_frontends.lock);
	spin_rdlock(&creds_backends.lock);
#endif
	int total_size;
	int idx_=0;
	unsigned i=0;
	account_details_t **_ads;
	total_size=creds_frontends.cred_array->len;
	if (_complete) {
		total_size+=creds_backends.cred_array->len;
	}
	if (!total_size) goto __exit_dump_all_users;
	_ads=(account_details_t **)malloc(sizeof(account_details_t *)*total_size);
	for (i=0; i<creds_frontends.cred_array->len; i++) {
		account_details_t *ad=(account_details_t *)malloc(sizeof(account_details_t));
		account_details_t *ado=(account_details_t *)creds_frontends.cred_array->index(i);
		ad->username=strdup(ado->username);
		ad->max_connections=ado->max_connections;
		ad->default_hostgroup=ado->default_hostgroup;
		if (_complete==false) {
			ad->password=NULL;
			ad->default_schema=NULL;
			ad->attributes=NULL;
			ad->comment=NULL;
			ad->num_connections_used=ado->num_connections_used;
		} else {
			ad->num_connections_used=ado->num_connections_used;
			ad->password=strdup(ado->password);
			ad->sha1_pass=NULL;
			ad->use_ssl=ado->use_ssl;
			ad->default_schema=strdup(ado->default_schema);
			ad->attributes=strdup(ado->attributes);
			ad->comment=strdup(ado->comment);
			ad->schema_locked=ado->schema_locked;
			ad->transaction_persistent=ado->transaction_persistent;
			ad->fast_forward=ado->fast_forward;
			ad->__frontend=1;
			ad->__backend=0;
		}
		_ads[idx_]=ad;
		idx_++;
	}
	if (_complete==true) {
	for (i=0; i<creds_backends.cred_array->len; i++) {
		account_details_t *ad=(account_details_t *)malloc(sizeof(account_details_t));
		account_details_t *ado=(account_details_t *)creds_backends.cred_array->index(i);
		ad->num_connections_used=0;
		ad->username=strdup(ado->username);
		ad->password=strdup(ado->password);
		ad->sha1_pass=NULL;
		ad->use_ssl=ado->use_ssl;
		ad->default_hostgroup=ado->default_hostgroup;
		ad->default_schema=strdup(ado->default_schema);
		ad->attributes=strdup(ado->attributes);
		ad->comment=strdup(ado->comment);
		ad->schema_locked=ado->schema_locked;
		ad->transaction_persistent=ado->transaction_persistent;
		ad->fast_forward=ado->fast_forward;
		ad->max_connections=ado->max_connections;
		ad->__frontend=0;
		ad->__backend=1;
		_ads[idx_]=ad;
		idx_++;
	}
	}
	*ads=_ads;
__exit_dump_all_users:
#ifdef PROXYSQL_AUTH_PTHREAD_MUTEX
	pthread_rwlock_unlock(&creds_frontends.lock);
	pthread_rwlock_unlock(&creds_backends.lock);
#else
	spin_rdunlock(&creds_frontends.lock);
	spin_rdunlock(&creds_backends.lock);
#endif
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
#ifdef PROXYSQL_AUTH_PTHREAD_MUTEX
	pthread_rwlock_wrlock(&cg.lock);
#else
	spin_wrlock(&cg.lock);
#endif
	std::map<uint64_t, account_details_t *>::iterator it;
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
#ifdef PROXYSQL_AUTH_PTHREAD_MUTEX
	pthread_rwlock_unlock(&cg.lock);
#else
	spin_wrunlock(&cg.lock);
#endif
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
#ifdef PROXYSQL_AUTH_PTHREAD_MUTEX
	pthread_rwlock_wrlock(&cg.lock);
#else
	spin_wrlock(&cg.lock);
#endif
	std::map<uint64_t, account_details_t *>::iterator it;
	it = cg.bt_map.find(hash1);
	if (it != cg.bt_map.end()) {
		account_details_t *ad=it->second;
		if (ad->num_connections_used > 0) {
			ad->num_connections_used--;
		}
	}
#ifdef PROXYSQL_AUTH_PTHREAD_MUTEX
	pthread_rwlock_unlock(&cg.lock);
#else
	spin_wrunlock(&cg.lock);
#endif
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
#ifdef PROXYSQL_AUTH_PTHREAD_MUTEX
		pthread_rwlock_wrlock(&cg.lock);
#else
		spin_wrlock(&cg.lock);
#endif
	std::map<uint64_t, account_details_t *>::iterator lookup;
	lookup = cg.bt_map.find(hash1);
	if (lookup != cg.bt_map.end()) {
		account_details_t *ad=lookup->second;
		cg.cred_array->remove_fast(ad);
		cg.bt_map.erase(lookup);
		free(ad->username);
		free(ad->password);
		if (ad->sha1_pass) { free(ad->sha1_pass); ad->sha1_pass=NULL; }
		free(ad->default_schema);
		free(ad->attributes);
		free(ad->comment);
		free(ad);
		ret=true;
	}
	if (set_lock)
#ifdef PROXYSQL_AUTH_PTHREAD_MUTEX
		pthread_rwlock_unlock(&cg.lock);
#else
		spin_wrunlock(&cg.lock);
#endif
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

#ifdef PROXYSQL_AUTH_PTHREAD_MUTEX
	pthread_rwlock_wrlock(&cg.lock);
#else
	spin_wrlock(&cg.lock);
#endif
	std::map<uint64_t, account_details_t *>::iterator lookup;
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
#ifdef PROXYSQL_AUTH_PTHREAD_MUTEX
	pthread_rwlock_unlock(&cg.lock);
#else
   spin_wrunlock(&cg.lock);
#endif
	return ret;
};

bool MySQL_Authentication::exists(char * username) {
	bool ret = false;
	uint64_t hash1, hash2;
	SpookyHash myhash;
	myhash.Init(1,2);
	myhash.Update(username,strlen(username));
	myhash.Final(&hash1,&hash2);

	creds_group_t &cg = creds_frontends ;
	pthread_rwlock_rdlock(&cg.lock);
	std::map<uint64_t, account_details_t *>::iterator lookup;
	lookup = cg.bt_map.find(hash1);
	if (lookup != cg.bt_map.end()) {
		ret = true;
	}
	pthread_rwlock_unlock(&cg.lock);
	return ret;
}

char * MySQL_Authentication::lookup(char * username, enum cred_username_type usertype, bool *use_ssl, int *default_hostgroup, char **default_schema, bool *schema_locked, bool *transaction_persistent, bool *fast_forward, int *max_connections, void **sha1_pass, char **attributes) {
	char *ret=NULL;
	uint64_t hash1, hash2;
	SpookyHash myhash;
	myhash.Init(1,2);
	myhash.Update(username,strlen(username));
	myhash.Final(&hash1,&hash2);

	creds_group_t &cg=(usertype==USERNAME_BACKEND ? creds_backends : creds_frontends);

#ifdef PROXYSQL_AUTH_PTHREAD_MUTEX
	pthread_rwlock_rdlock(&cg.lock);
#else
	spin_rdlock(&cg.lock);
#endif
	std::map<uint64_t, account_details_t *>::iterator lookup;
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
		if (attributes) *attributes=l_strdup(ad->attributes);
	}
#ifdef PROXYSQL_AUTH_PTHREAD_MUTEX
	pthread_rwlock_unlock(&cg.lock);
#else
	spin_rdunlock(&cg.lock);
#endif
	return ret;

}

bool MySQL_Authentication::_reset(enum cred_username_type usertype) {
	creds_group_t &cg=(usertype==USERNAME_BACKEND ? creds_backends : creds_frontends);

#ifdef PROXYSQL_AUTH_PTHREAD_MUTEX
	pthread_rwlock_wrlock(&cg.lock);
#else
	spin_wrlock(&cg.lock);
#endif
	std::map<uint64_t, account_details_t *>::iterator lookup;

	while (cg.bt_map.size()) {
		lookup = cg.bt_map.begin();
		if ( lookup != cg.bt_map.end() ) {
			account_details_t *ad=lookup->second;
			cg.bt_map.erase(lookup);
			free(ad->username);
			free(ad->password);
			if (ad->sha1_pass) { free(ad->sha1_pass); ad->sha1_pass=NULL; }
			free(ad->default_schema);
			free(ad->comment);
			free(ad->attributes);
			free(ad);
		}
	}
	while (cg.cred_array->len) {
		cg.cred_array->remove_index_fast(0);
	}
#ifdef PROXYSQL_AUTH_PTHREAD_MUTEX
	pthread_rwlock_unlock(&cg.lock);
#else
	spin_wrunlock(&cg.lock);
#endif
	return true;
};

bool MySQL_Authentication::reset() {
	_reset(USERNAME_BACKEND);
	_reset(USERNAME_FRONTEND);
	return true;
}

using std::map;

uint64_t compute_accounts_hash(const umap_auth& accs_map) {
	if (accs_map.size() == 0) {
		return 0;
	}
	bool foundany = false;
	SpookyHash acc_map_hash;
	acc_map_hash.Init(13,4);

	for (const pair<const uint64_t, account_details_t*>& map_entry : accs_map) {
		const account_details_t* ad = map_entry.second;

		if (ad->default_hostgroup >= 0) {
			foundany = true;
			acc_map_hash.Update(&ad->use_ssl,sizeof(ad->use_ssl));
			acc_map_hash.Update(&ad->default_hostgroup,sizeof(ad->default_hostgroup));
			acc_map_hash.Update(&ad->schema_locked,sizeof(ad->schema_locked));
			acc_map_hash.Update(&ad->transaction_persistent,sizeof(ad->transaction_persistent));
			acc_map_hash.Update(&ad->fast_forward,sizeof(ad->fast_forward));
			acc_map_hash.Update(&ad->max_connections,sizeof(ad->max_connections));
			acc_map_hash.Update(ad->username,strlen(ad->username));
			acc_map_hash.Update(ad->password,strlen(ad->password));
			if (ad->default_schema)
				acc_map_hash.Update(ad->default_schema,strlen(ad->default_schema));
			if (ad->comment)
				acc_map_hash.Update(ad->comment,strlen(ad->comment));
			if (ad->attributes) {
				acc_map_hash.Update(ad->attributes,strlen(ad->attributes));
			}
		}
	}

	if (foundany == false) {
		return 0;
	} else {
		uint64_t hash1 = 0, hash2 = 0;
		acc_map_hash.Final(&hash1, &hash2);

		return hash1;
	}
}

uint64_t MySQL_Authentication::_get_runtime_checksum(enum cred_username_type usertype) {
	creds_group_t &cg=(usertype==USERNAME_BACKEND ? creds_backends : creds_frontends);
	uint64_t accs_hash = compute_accounts_hash(cg.bt_map);

	return accs_hash;
}

uint64_t MySQL_Authentication::get_runtime_checksum() {
	uint64_t hashB = _get_runtime_checksum(USERNAME_BACKEND);
	uint64_t hashF = _get_runtime_checksum(USERNAME_FRONTEND);
	return hashB+hashF;
}

pair<umap_auth, umap_auth> extract_accounts_details(MYSQL_RES* resultset, unique_ptr<SQLite3_result>& all_users) {
	if (resultset == nullptr) { return { umap_auth {}, umap_auth {} }; }

	// The following order is assumed for the resulset received fields:
	//  - username, password, active, use_ssl, default_hostgroup, default_schema, schema_locked, 
	// 	  transaction_persistent, fast_forward, backend, frontend, max_connections, attributes, comment.
	umap_auth f_accs_map {};
	umap_auth b_accs_map {};

	// Create the SQLite3 resultsets for 'frontend' and 'backend' users
	uint32_t num_fields = mysql_num_fields(resultset);
	MYSQL_FIELD* fields = mysql_fetch_fields(resultset);

	SQLite3_result* _all_users { new SQLite3_result(num_fields) };

	for (uint32_t i = 0; i < num_fields; i++) {
		_all_users->add_column_definition(SQLITE_TEXT, fields[i].name);
	}

	const auto create_account_details = [] (MYSQL_ROW row) -> account_details_t* {
		account_details_t* acc_details { new account_details_t {} };

		acc_details->username = row[0];
		acc_details->password = row[1] ? row[1] : const_cast<char*>("");
		acc_details->__active = true;
		acc_details->use_ssl = strcmp(row[2], "1") == 0 ? true : false;
		acc_details->default_hostgroup = atoi(row[3]);
		acc_details->default_schema = row[4] ? row[4] : const_cast<char*>("");
		acc_details->schema_locked = strcmp(row[5], "1") == 0 ? true : false;
		acc_details->transaction_persistent = strcmp(row[6], "1") == 0 ? true : false;
		acc_details->fast_forward = strcmp(row[7], "1") == 0 ? true : false;
		acc_details->__backend = strcmp(row[8], "1") == 0 ? true : false;
		acc_details->__frontend = strcmp(row[9], "1") == 0 ? true : false;
		acc_details->max_connections = atoi(row[10]);
		acc_details->attributes = row[11] ? row[11] : const_cast<char*>("");
		acc_details->comment = row[12] ? row[12] : const_cast<char*>("");

		return acc_details;
	};

	vector<char*> pta(static_cast<size_t>(num_fields));
	while (MYSQL_ROW row = mysql_fetch_row(resultset)) {
		// compute the 'username' hash for the map
		uint64_t u_hash = 0, _u_hash2 = 0;
		SpookyHash myhash {};
		myhash.Init(1,2);
		myhash.Update(row[0], strlen(row[0]));
		myhash.Final(&u_hash, &_u_hash2);

		// is backend
		if (strcmp(row[8], "1") == 0) {
			account_details_t* acc_details = create_account_details(row);
			b_accs_map.insert({u_hash, acc_details});
		}
		// is frontend
		if (strcmp(row[9], "1") == 0) {
			account_details_t* acc_details = create_account_details(row);
			f_accs_map.insert({u_hash, acc_details});
		}

		// Update the contents of the row for the SQLite3 resultset
		for (uint32_t i = 0; i < num_fields; i++) {
			pta[i] = row[i];
		}
		_all_users->add_row(&pta[0]);
	}

	mysql_data_seek(resultset, 0);

	// Update the supplied 'unique_ptr' with the target resultsets
	all_users.reset(_all_users);

	return { b_accs_map, f_accs_map };
}

uint64_t MySQL_Authentication::get_runtime_checksum(MYSQL_RES* resultset, unique_ptr<SQLite3_result>& all_users) {
	if (resultset == NULL) { return 0; }

	pair<umap_auth, umap_auth> acc_maps { extract_accounts_details(resultset, all_users) };

	uint64_t b_acc_hash = compute_accounts_hash(acc_maps.first);
	uint64_t f_acc_hash = compute_accounts_hash(acc_maps.second);

	for (pair<const uint64_t, account_details_t*>& map_entry : acc_maps.first) {
		delete map_entry.second;
	}
	for (pair<const uint64_t, account_details_t*>& map_entry : acc_maps.second) {
		delete map_entry.second;
	}

	return b_acc_hash + f_acc_hash;
}

void MySQL_Authentication::save_mysql_users(unique_ptr<SQLite3_result>&& users) {
	this->mysql_users_resultset = std::move(users);
}

SQLite3_result* MySQL_Authentication::get_current_mysql_users() {
	return this->mysql_users_resultset.get();
}
