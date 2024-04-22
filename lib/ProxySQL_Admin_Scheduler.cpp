#include <iostream>     // std::cout
#include <sstream>      // std::stringstream
#include <fstream>
#include <algorithm>    // std::sort
#include <memory>
#include <vector>       // std::vector
#include <unordered_set>
#include "MySQL_HostGroups_Manager.h"
#include "proxysql_admin.h"

Scheduler_Row::Scheduler_Row(unsigned int _id, bool _is_active, unsigned int _in, char *_f, char *a1, char *a2, char *a3, char *a4, char *a5, char *_comment) {
	int i;
	id=_id;
	is_active=_is_active;
	interval_ms=_in;
	filename=strdup(_f);
	args=(char **)malloc(6*sizeof(char *));
	for (i=0;i<6;i++) {
		args[i]=NULL;
	}
	// only copy fields if the previous one is not null
	if (a1) {
		args[0]=strdup(a1);
		if (a2) {
			args[1]=strdup(a2);
			if (a3) {
				args[2]=strdup(a3);
				if (a4) {
					args[3]=strdup(a4);
					if (a5) {
						args[4]=strdup(a5);
					}
				}
			}
		}
	}
	comment=strdup(_comment);
}

Scheduler_Row::~Scheduler_Row() {
	int i;
	for (i=0;i<6;i++) {
		if (args[i]) {
			free(args[i]);
		}
		args[i]=NULL;
	}
	if (filename) {
		free(filename);
	}
	free(args);
	free(comment);
	args=NULL;
}

ProxySQL_External_Scheduler::ProxySQL_External_Scheduler() {
#ifdef PA_PTHREAD_MUTEX
	pthread_rwlock_init(&rwlock,NULL);
#else
	spinlock_rwlock_init(&rwlock);
#endif
	last_version=0;
	version=0;
	next_run=0;
}

ProxySQL_External_Scheduler::~ProxySQL_External_Scheduler() {
}

void ProxySQL_External_Scheduler::update_table(SQLite3_result *resultset) {
#ifdef PA_PTHREAD_MUTEX
	pthread_rwlock_wrlock(&rwlock);
#else
	spin_wrlock(&rwlock);
#endif
	// delete all current rows
	Scheduler_Row *sr;
	for (std::vector<Scheduler_Row *>::iterator it=Scheduler_Rows.begin(); it!=Scheduler_Rows.end(); ++it) {
		sr=*it;
		delete sr;
  }
  Scheduler_Rows.clear();

	for (std::vector<SQLite3_row *>::iterator it = resultset->rows.begin() ; it != resultset->rows.end(); ++it) {
		SQLite3_row *r=*it;
		unsigned int id=strtoul(r->fields[0], NULL, 10);
		bool is_active=false;
		if (atoi(r->fields[1])) {
			is_active=true;
		}
		unsigned int interval_ms=strtoul(r->fields[2], NULL, 10);
		Scheduler_Row *sr=new Scheduler_Row(id, is_active, interval_ms,
			r->fields[3],
			r->fields[4], r->fields[5],
			r->fields[6], r->fields[7],
			r->fields[8],
			r->fields[9] // comment, issue #643
		);
		Scheduler_Rows.push_back(sr);
	}
	// increase version
	__sync_fetch_and_add(&version,1);
	// unlock
#ifdef PA_PTHREAD_MUTEX
	pthread_rwlock_unlock(&rwlock);
#else
	spin_wrunlock(&rwlock);
#endif
}

// this fuction will be called as a deatached thread
static void * waitpid_thread(void *arg) {
	pid_t *cpid_ptr=(pid_t *)arg;
	int status;
	waitpid(*cpid_ptr, &status, 0);
	free(cpid_ptr);
	return NULL;
}

unsigned long long ProxySQL_External_Scheduler::run_once() {
	Scheduler_Row *sr=NULL;
	unsigned long long curtime=monotonic_time();
	curtime=curtime/1000;
#ifdef PA_PTHREAD_MUTEX
	pthread_rwlock_rdlock(&rwlock);
#else
	spin_rdlock(&rwlock);
#endif
	if (__sync_add_and_fetch(&version,0) > last_version) {	// version was changed
		next_run=0;
		last_version=version;
		for (std::vector<Scheduler_Row *>::iterator it=Scheduler_Rows.begin(); it!=Scheduler_Rows.end(); ++it) {
			sr=*it;
			if (sr->is_active==false) {
				continue;
			}
			sr->next=curtime+sr->interval_ms;
			if (next_run==0) {
				next_run=sr->next;
			} else {
				if (sr->next < next_run) {	// we try to find the first event that needs to be executed
					next_run=sr->next;
				}
			}
		}
	}
	if (curtime >= next_run) {
		next_run=0;
		for (std::vector<Scheduler_Row *>::iterator it=Scheduler_Rows.begin(); it!=Scheduler_Rows.end(); ++it) {
			sr=*it;
			if (sr->is_active==false) {
				continue;
			}
			if (curtime >= sr->next) {
				// the event is scheduled for execution
				sr->next=curtime+sr->interval_ms;
				char **newargs=(char **)malloc(7*sizeof(char *));
				for (int i=1;i<7;i++) {
					newargs[i]=sr->args[i-1];
				}
				newargs[0]=sr->filename;
				proxy_info("Scheduler starting id: %u , filename: %s\n", sr->id, sr->filename);
				pid_t cpid;
				cpid = fork();
				if (cpid == -1) {
					perror("fork");
					exit(EXIT_FAILURE);
				}
				if (cpid == 0) {
					close_all_non_term_fd({});
					char *newenviron[] = { NULL };
					int rc;
					rc=execve(sr->filename, newargs, newenviron);
					if (rc) {
						proxy_error("Scheduler: Failed to run %s\n", sr->filename);
						perror("execve()");
						exit(EXIT_FAILURE);
					}
				} else {
					pthread_attr_t attr;
					pthread_attr_init(&attr);
					pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
					pthread_attr_setstacksize (&attr, 64*1024);
					pid_t *cpid_ptr=(pid_t *)malloc(sizeof(pid_t));
					*cpid_ptr=cpid;
					pthread_t thr;
					if (pthread_create(&thr, &attr, waitpid_thread, (void *)cpid_ptr) !=0 ) {
						perror("Thread creation");
						exit(EXIT_FAILURE);
					}
				}
				free(newargs);
			}
			if (next_run==0) {
				next_run=sr->next;
			} else {
				if (sr->next < next_run) {	// we try to find the first event that needs to be executed
					next_run=sr->next;
				}
			}
		}
	}
	// find the smaller next_run
	for (std::vector<Scheduler_Row *>::iterator it=Scheduler_Rows.begin(); it!=Scheduler_Rows.end(); ++it) {
		sr=*it;
		if (next_run==0) {
		}
	}
#ifdef PA_PTHREAD_MUTEX
	pthread_rwlock_unlock(&rwlock);
#else
	spin_rdunlock(&rwlock);
#endif
	return next_run;
}
