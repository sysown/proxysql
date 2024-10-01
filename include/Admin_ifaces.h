#ifndef ADMIN_IFACES_H
#define ADMIN_IFACES_H

#define MAX_IFACES	8
#define MAX_ADMIN_LISTENERS 16

typedef struct _main_args {
	int nfds;
	struct pollfd *fds;
	int *callback_func;
	volatile int *shutdown;
} main_args;

typedef struct _ifaces_desc_t {
		char **mysql_ifaces;
		char **pgsql_ifaces;
		char **telnet_admin_ifaces;
		char **telnet_stats_ifaces;
} ifaces_desc_t;

class ifaces_desc {
	public:
	PtrArray *ifaces;
	ifaces_desc() {
		ifaces=new PtrArray();
	}
	bool add(const char *iface) {
		for (unsigned int i=0; i<ifaces->len; i++) {
			if (strcmp((const char *)ifaces->index(i),iface)==0) {
				return false;
			}
		}
		ifaces->add(strdup(iface));
		return true;
	}
	~ifaces_desc() {
		while(ifaces->len) {
			char *d=(char *)ifaces->remove_index_fast(0);
			free(d);
		}
		delete ifaces;
	}
};

class admin_main_loop_listeners {
	private:
	int version;
#ifdef PA_PTHREAD_MUTEX
	pthread_rwlock_t rwlock;
#else
	rwlock_t rwlock;
#endif

	char ** reset_ifaces(char **ifaces) {
		int i;
		if (ifaces) {
			for (i=0; i<MAX_IFACES; i++) {
				if (ifaces[i]) free(ifaces[i]);
			}
		} else {
			ifaces=(char **)malloc(sizeof(char *)*MAX_IFACES);
		}
		for (i=0; i<MAX_IFACES; i++) {
			ifaces[i]=NULL;
		}
		return ifaces;
	}


	public:
	int nfds;
	struct pollfd *fds;
	int *callback_func;
	int get_version() { return version; }
	void wrlock() {
#ifdef PA_PTHREAD_MUTEX
		pthread_rwlock_wrlock(&rwlock);
#else
		spin_wrlock(&rwlock);
#endif
	}
	void wrunlock() {
#ifdef PA_PTHREAD_MUTEX
		pthread_rwlock_unlock(&rwlock);
#else
		spin_wrunlock(&rwlock);
#endif
	}
	ifaces_desc *ifaces_mysql;
	ifaces_desc *ifaces_pgsql;
	ifaces_desc *ifaces_telnet_admin;
	ifaces_desc *ifaces_telnet_stats;
	ifaces_desc_t descriptor_new;
	admin_main_loop_listeners() {
#ifdef PA_PTHREAD_MUTEX
		pthread_rwlock_init(&rwlock, NULL);
#else
		spinlock_rwlock_init(&rwlock);
#endif
		ifaces_mysql=new ifaces_desc();
		ifaces_pgsql=new ifaces_desc();
		ifaces_telnet_admin=new ifaces_desc();
		ifaces_telnet_stats=new ifaces_desc();
		version=0;
		descriptor_new.mysql_ifaces=NULL;
		descriptor_new.pgsql_ifaces=NULL;
		descriptor_new.telnet_admin_ifaces=NULL;
		descriptor_new.telnet_stats_ifaces=NULL;
	}


	void update_ifaces(char *list, ifaces_desc **ifd) {
		wrlock();
		delete *ifd;
		*ifd=new ifaces_desc();
		int i=0;
		tokenizer_t tok;
		tokenizer( &tok, list, ";", TOKENIZER_NO_EMPTIES );
		const char* token;
		for ( token = tokenize( &tok ) ; token && i < MAX_IFACES ; token = tokenize( &tok ) ) {
			(*ifd)->add(token);
			i++;
		}
		free_tokenizer( &tok );
		version++;
		wrunlock();
	}


	bool update_ifaces(char *list, char ***_ifaces) {
		wrlock();
		int i;
		char **ifaces=*_ifaces;
		tokenizer_t tok;
		tokenizer( &tok, list, ";", TOKENIZER_NO_EMPTIES );
		const char* token;
		ifaces=reset_ifaces(ifaces);
		i=0;
		for ( token = tokenize( &tok ) ; token && i < MAX_IFACES ; token = tokenize( &tok ) ) {
			ifaces[i]=(char *)malloc(strlen(token)+1);
			strcpy(ifaces[i],token);
			i++;
		}
		free_tokenizer( &tok );
		version++;
		wrunlock();
		return true;
	}
};
#endif // ADMIN_IFACES_H
