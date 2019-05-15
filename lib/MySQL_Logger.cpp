#include <fstream>
#include "proxysql.h"
#include "cpp.h"
#include <dirent.h>
#include <libgen.h>

#include "../deps/json/json.hpp"
using json = nlohmann::json;

static uint8_t mysql_encode_length(uint64_t len, unsigned char *hd) {
	if (len < 251) return 1;
	if (len < 65536) { if (hd) { *hd=0xfc; }; return 3; }
	if (len < 16777216) { if (hd) { *hd=0xfd; }; return 4; }
	if (hd) { *hd=0xfe; }
	return 9;
}

static inline int write_encoded_length(unsigned char *p, uint64_t val, uint8_t len, char prefix) {
	if (len==1) {
		*p=(char)val;
		return 1;
	}
	*p=prefix;
	p++;
	memcpy(p,&val,len-1);
	return len;
}

MySQL_Event::MySQL_Event (log_event_type _et, uint32_t _thread_id, char * _username, char * _schemaname , uint64_t _start_time , uint64_t _end_time , uint64_t _query_digest, char *_client, size_t _client_len) {
	thread_id=_thread_id;
	username=_username;
	schemaname=_schemaname;
	start_time=_start_time;
	end_time=_end_time;
	query_digest=_query_digest;
	client=_client;
	client_len=_client_len;
	et=_et;
	hid=UINT64_MAX;
	server=NULL;
	err = NULL;
}

void MySQL_Event::set_error(char *_err) {
	err = _err;
}

void MySQL_Event::set_query(const char *ptr, int len) {
	query_ptr=(char *)ptr;
	query_len=len;
}

void MySQL_Event::set_server(int _hid, const char *ptr, int len) {
	server=(char *)ptr;
	server_len=len;
	hid=_hid;
}

uint64_t MySQL_Event::write(std::fstream *f, MySQL_Session *sess) {
	uint64_t total_bytes=0;
	switch (et) {
		case PROXYSQL_QUERY:
			total_bytes=write_query(f);
			break;
		case PROXYSQL_MYSQL_AUTH_OK:
		case PROXYSQL_MYSQL_AUTH_ERR:
		case PROXYSQL_MYSQL_AUTH_CLOSE:
		case PROXYSQL_MYSQL_AUTH_QUIT:
		case PROXYSQL_ADMIN_AUTH_OK:
		case PROXYSQL_ADMIN_AUTH_ERR:
		case PROXYSQL_ADMIN_AUTH_CLOSE:
		case PROXYSQL_ADMIN_AUTH_QUIT:
		case PROXYSQL_SQLITE_AUTH_OK:
		case PROXYSQL_SQLITE_AUTH_ERR:
		case PROXYSQL_SQLITE_AUTH_CLOSE:
		case PROXYSQL_SQLITE_AUTH_QUIT:
			write_auth(f, sess);
			break;
		default:
			break;
	}
	return total_bytes;
}

void MySQL_Event::write_auth(std::fstream *f, MySQL_Session *sess) {
	json j;	
	j["timestamp"] = start_time/1000;
	time_t timer=start_time/1000/1000;
	struct tm* tm_info;
	tm_info = localtime(&timer);
	char buffer1[64];
	char buffer2[64];
	strftime(buffer1, 32, "%Y-%m-%d %H:%M:%S", tm_info);
	sprintf(buffer2,"%s.%03u", buffer1, (unsigned)(start_time%1000000)/1000);
	j["time"] = buffer2;
	j["thread_id"] = thread_id;
	if (username) {
		j["username"] = username;
	} else {
		j["username"] = "";
	}
	if (schemaname) {
		j["schemaname"] = schemaname;
	} else {
		j["schemaname"] = "";
	}
	if (client) {
		j["client_addr"] = client;
	} else {
		j["client_addr"] = "";
	}
	if (server) {
		j["server_addr"] = server;
	}
	if (err) {
		j["error"] = err;
	}
	switch (et) {
		case PROXYSQL_MYSQL_AUTH_OK:
			j["event"]="MySQL_Client_Connect_OK";
			break;
		case PROXYSQL_MYSQL_AUTH_ERR:
			j["event"]="MySQL_Client_Connect_ERR";
			break;
		case PROXYSQL_MYSQL_AUTH_CLOSE:
			j["event"]="MySQL_Client_Close";
			break;
		case PROXYSQL_MYSQL_AUTH_QUIT:
			j["event"]="MySQL_Client_Quit";
			break;
		case PROXYSQL_ADMIN_AUTH_OK:
			j["event"]="Admin_Connect_OK";
			break;
		case PROXYSQL_ADMIN_AUTH_ERR:
			j["event"]="Admin_Connect_ERR";
			break;
		case PROXYSQL_ADMIN_AUTH_CLOSE:
			j["event"]="Admin_Close";
			break;
		case PROXYSQL_ADMIN_AUTH_QUIT:
			j["event"]="Admin_Quit";
			break;
		case PROXYSQL_SQLITE_AUTH_OK:
			j["event"]="SQLite3_Connect_OK";
			break;
		case PROXYSQL_SQLITE_AUTH_ERR:
			j["event"]="SQLite3_Connect_ERR";
			break;
		case PROXYSQL_SQLITE_AUTH_CLOSE:
			j["event"]="SQLite3_Close";
			break;
		case PROXYSQL_SQLITE_AUTH_QUIT:
			j["event"]="SQLite3_Quit";
			break;
		default:
			break;
	}
	if (sess->client_myds) {
		if (sess->client_myds->proxy_addr.addr) {
			std::string s = sess->client_myds->proxy_addr.addr;
			s += ":" + std::to_string(sess->client_myds->proxy_addr.port);
			j["proxy_addr"] = s;
		}
		j["ssl"] = sess->client_myds->encrypted;
	}
	*f << j.dump() << std::endl;
}

uint64_t MySQL_Event::write_query(std::fstream *f) {
	uint64_t total_bytes=0;
	total_bytes+=1; // et
	total_bytes+=mysql_encode_length(thread_id, NULL);
	username_len=strlen(username);
	total_bytes+=mysql_encode_length(username_len,NULL)+username_len;
	schemaname_len=strlen(schemaname);
	total_bytes+=mysql_encode_length(schemaname_len,NULL)+schemaname_len;

	total_bytes+=mysql_encode_length(client_len,NULL)+client_len;

	total_bytes+=mysql_encode_length(hid, NULL);
	if (hid!=UINT64_MAX) {
		total_bytes+=mysql_encode_length(server_len,NULL)+server_len;
	}

	total_bytes+=mysql_encode_length(start_time,NULL);
	total_bytes+=mysql_encode_length(end_time,NULL);
	total_bytes+=mysql_encode_length(query_digest,NULL);

	total_bytes+=mysql_encode_length(query_len,NULL)+query_len;

	// write total length , fixed size
	f->write((const char *)&total_bytes,sizeof(uint64_t));
	//char prefix;
	uint8_t len;

	f->write((char *)&et,1);

	len=mysql_encode_length(thread_id,buf);
	write_encoded_length(buf,thread_id,len,buf[0]);
	f->write((char *)buf,len);

	len=mysql_encode_length(username_len,buf);
	write_encoded_length(buf,username_len,len,buf[0]);
	f->write((char *)buf,len);
	f->write(username,username_len);

	len=mysql_encode_length(schemaname_len,buf);
	write_encoded_length(buf,schemaname_len,len,buf[0]);
	f->write((char *)buf,len);
	f->write(schemaname,schemaname_len);

	len=mysql_encode_length(client_len,buf);
	write_encoded_length(buf,client_len,len,buf[0]);
	f->write((char *)buf,len);
	f->write(client,client_len);

	len=mysql_encode_length(hid,buf);
	write_encoded_length(buf,hid,len,buf[0]);
	f->write((char *)buf,len);

	if (hid!=UINT64_MAX) {
		len=mysql_encode_length(server_len,buf);
		write_encoded_length(buf,server_len,len,buf[0]);
		f->write((char *)buf,len);
		f->write(server,server_len);
	}

	len=mysql_encode_length(start_time,buf);
	write_encoded_length(buf,start_time,len,buf[0]);
	f->write((char *)buf,len);

	len=mysql_encode_length(end_time,buf);
	write_encoded_length(buf,end_time,len,buf[0]);
	f->write((char *)buf,len);

	len=mysql_encode_length(query_digest,buf);
	write_encoded_length(buf,query_digest,len,buf[0]);
	f->write((char *)buf,len);

	len=mysql_encode_length(query_len,buf);
	write_encoded_length(buf,query_len,len,buf[0]);
	f->write((char *)buf,len);
	if (query_len) {
		f->write(query_ptr,query_len);
	}

	return total_bytes;
}

extern Query_Processor *GloQPro;

MySQL_Logger::MySQL_Logger() {
	events.enabled=false;
	events.base_filename=NULL;
	events.datadir=NULL;
	events.base_filename=strdup((char *)"");
	audit.enabled=false;
	audit.base_filename=NULL;
	audit.datadir=NULL;
	audit.base_filename=strdup((char *)"");
#ifdef PROXYSQL_LOGGER_PTHREAD_MUTEX
	pthread_mutex_init(&wmutex,NULL);
#else
	spinlock_rwlock_init(&rwlock);
#endif
	events.logfile=NULL;
	events.log_file_id=0;
	events.max_log_file_size=100*1024*1024;
	audit.log_file_id=0;
	audit.max_log_file_size=100*1024*1024;
};

MySQL_Logger::~MySQL_Logger() {
	if (events.datadir) {
		free(events.datadir);
	}
	free(events.base_filename);
	if (audit.datadir) {
		free(audit.datadir);
	}
	free(audit.base_filename);
};

void MySQL_Logger::wrlock() {
#ifdef PROXYSQL_LOGGER_PTHREAD_MUTEX
	pthread_mutex_lock(&wmutex);
#else
  spin_wrlock(&rwlock);
#endif
};

void MySQL_Logger::wrunlock() {
#ifdef PROXYSQL_LOGGER_PTHREAD_MUTEX
	pthread_mutex_unlock(&wmutex);
#else
  spin_wrunlock(&rwlock);
#endif
};

void MySQL_Logger::flush_log() {
	if (audit.enabled==false && events.enabled==false) return;
	wrlock();
	events_flush_log_unlocked();
	audit_flush_log_unlocked();
	wrunlock();
}


void MySQL_Logger::events_close_log_unlocked() {
	if (events.logfile) {
		events.logfile->flush();
		events.logfile->close();
		delete events.logfile;
		events.logfile=NULL;
	}
}

void MySQL_Logger::audit_close_log_unlocked() {
	if (audit.logfile) {
		audit.logfile->flush();
		audit.logfile->close();
		delete audit.logfile;
		audit.logfile=NULL;
	}
}

void MySQL_Logger::events_flush_log_unlocked() {
	if (events.enabled==false) return;
	events_close_log_unlocked();
	events_open_log_unlocked();
}

void MySQL_Logger::audit_flush_log_unlocked() {
	if (audit.enabled==false) return;
	audit_close_log_unlocked();
	audit_open_log_unlocked();
}

void MySQL_Logger::events_open_log_unlocked() {
	events.log_file_id=events_find_next_id();
	if (events.log_file_id!=0) {
		events.log_file_id=events_find_next_id()+1;
	} else {
		events.log_file_id++;
	}
	char *filen=NULL;
	if (events.base_filename[0]=='/') { // absolute path
		filen=(char *)malloc(strlen(events.base_filename)+10);
		sprintf(filen,"%s.%08d",events.base_filename,events.log_file_id);
	} else { // relative path
		filen=(char *)malloc(strlen(events.datadir)+strlen(events.base_filename)+10);
		sprintf(filen,"%s/%s.%08d",events.datadir,events.base_filename,events.log_file_id);
	}
	events.logfile=new std::fstream();
	events.logfile->exceptions ( std::ofstream::failbit | std::ofstream::badbit );
	try {
		events.logfile->open(filen , std::ios::out | std::ios::binary);
		proxy_info("Starting new mysql event log file %s\n", filen);
	}
	catch (std::ofstream::failure e) {
		proxy_error("Error creating new mysql event log file %s\n", filen);
		delete events.logfile;
		events.logfile=NULL;
	}
	free(filen);
};

void MySQL_Logger::audit_open_log_unlocked() {
	audit.log_file_id=audit_find_next_id();
	if (audit.log_file_id!=0) {
		audit.log_file_id=audit_find_next_id()+1;
	} else {
		audit.log_file_id++;
	}
	char *filen=NULL;
	if (audit.base_filename[0]=='/') { // absolute path
		filen=(char *)malloc(strlen(audit.base_filename)+10);
		sprintf(filen,"%s.%08d",audit.base_filename,audit.log_file_id);
	} else { // relative path
		filen=(char *)malloc(strlen(audit.datadir)+strlen(audit.base_filename)+10);
		sprintf(filen,"%s/%s.%08d",audit.datadir,audit.base_filename,audit.log_file_id);
	}
	audit.logfile=new std::fstream();
	audit.logfile->exceptions ( std::ofstream::failbit | std::ofstream::badbit );
	try {
		audit.logfile->open(filen , std::ios::out | std::ios::binary);
		proxy_info("Starting new audit log file %s\n", filen);
	}
	catch (std::ofstream::failure e) {
		proxy_error("Error creating new audit log file %s\n", filen);
		delete audit.logfile;
		audit.logfile=NULL;
	}
	free(filen);
};

void MySQL_Logger::events_set_base_filename() {
	// if filename is the same, return
	wrlock();
	events.max_log_file_size=mysql_thread___eventslog_filesize;
	if (strcmp(events.base_filename,mysql_thread___eventslog_filename)==0) {
		wrunlock();
		return;
	}
	// close current log
	events_close_log_unlocked();
	// set file id to 0 , so that find_next_id() will be called
	events.log_file_id=0;
	free(events.base_filename);
	events.base_filename=strdup(mysql_thread___eventslog_filename);
	if (strlen(events.base_filename)) {
		events.enabled=true;
		events_open_log_unlocked();
	} else {
		events.enabled=false;
	}
	wrunlock();
}

void MySQL_Logger::events_set_datadir(char *s) {
	events.datadir=strdup(s);
	flush_log();
};

void MySQL_Logger::audit_set_base_filename() {
	// if filename is the same, return
	wrlock();
	audit.max_log_file_size=mysql_thread___auditlog_filesize;
	if (strcmp(audit.base_filename,mysql_thread___auditlog_filename)==0) {
		wrunlock();
		return;
	}
	// close current log
	audit_close_log_unlocked();
	// set file id to 0 , so that find_next_id() will be called
	audit.log_file_id=0;
	free(audit.base_filename);
	audit.base_filename=strdup(mysql_thread___auditlog_filename);
	if (strlen(audit.base_filename)) {
		audit.enabled=true;
		audit_open_log_unlocked();
	} else {
		audit.enabled=false;
	}
	wrunlock();
}

void MySQL_Logger::audit_set_datadir(char *s) {
	audit.datadir=strdup(s);
	flush_log();
};

void MySQL_Logger::log_request(MySQL_Session *sess, MySQL_Data_Stream *myds) {
	if (events.enabled==false) return;
	if (events.logfile==NULL) return;

	MySQL_Connection_userinfo *ui=sess->client_myds->myconn->userinfo;

	uint64_t curtime_real=realtime_time();
	uint64_t curtime_mono=sess->thread->curtime;
	int cl=0;
	char *ca=(char *)""; // default
	if (sess->client_myds->addr.addr) {
		ca=sess->client_myds->addr.addr;
	}
	cl+=strlen(ca);
	if (cl && sess->client_myds->addr.port) {
		ca=(char *)malloc(cl+8);
		sprintf(ca,"%s:%d",sess->client_myds->addr.addr,sess->client_myds->addr.port);
	}
	cl=strlen(ca);
	MySQL_Event me(PROXYSQL_QUERY,
		sess->thread_session_id,ui->username,ui->schemaname,
		sess->CurrentQuery.start_time + curtime_real - curtime_mono,
		sess->CurrentQuery.end_time + curtime_real - curtime_mono,
		GloQPro->get_digest(&sess->CurrentQuery.QueryParserArgs),
		ca, cl
	);
	char *c=(char *)sess->CurrentQuery.QueryPointer;
	if (c) {
		me.set_query(c,sess->CurrentQuery.QueryLength);
	} else {
		me.set_query("",0);
	}

	int sl=0;
	char *sa=(char *)""; // default
	if (myds) {
		if (myds->myconn) {
			sa=myds->myconn->parent->address;
		}
	}
	sl+=strlen(sa);
	if (sl && myds->myconn->parent->port) {
		sa=(char *)malloc(sl+8);
		sprintf(sa,"%s:%d", myds->myconn->parent->address, myds->myconn->parent->port);
	}
	sl=strlen(sa);
	if (sl) {
		int hid=-1;
		hid=myds->myconn->parent->myhgc->hid;
		me.set_server(hid,sa,sl);
	}

	wrlock();

	me.write(events.logfile, sess);


	unsigned long curpos=events.logfile->tellp();
	if (curpos > events.max_log_file_size) {
		events_flush_log_unlocked();
	}
	wrunlock();

	if (cl && sess->client_myds->addr.port) {
		free(ca);
	}
	if (sl && myds->myconn->parent->port) {
		free(sa);
	}
}

void MySQL_Logger::log_audit_entry(log_event_type _et, MySQL_Session *sess, MySQL_Data_Stream *myds, char *err) {
	if (audit.enabled==false) return;
	if (audit.logfile==NULL) return;

	MySQL_Connection_userinfo *ui=sess->client_myds->myconn->userinfo;

	if (sess) {
		// to reduce complexing in the calling function, we do some changes here
		if (_et == PROXYSQL_MYSQL_AUTH_OK) {
			switch (sess->session_type) {
				case PROXYSQL_SESSION_ADMIN:
				case PROXYSQL_SESSION_STATS:
					_et = PROXYSQL_ADMIN_AUTH_OK;
					break;
				case PROXYSQL_SESSION_SQLITE:
					_et = PROXYSQL_SQLITE_AUTH_OK;
				default:
					break;
			}
		}
		if (_et == PROXYSQL_MYSQL_AUTH_ERR) {
			switch (sess->session_type) {
				case PROXYSQL_SESSION_ADMIN:
				case PROXYSQL_SESSION_STATS:
					_et = PROXYSQL_ADMIN_AUTH_ERR;
					break;
				case PROXYSQL_SESSION_SQLITE:
					_et = PROXYSQL_SQLITE_AUTH_ERR;
				default:
					break;
			}
		}
	}

	uint64_t curtime_real=realtime_time();
	uint64_t curtime_mono=sess->thread->curtime;
	int cl=0;
	char *ca=(char *)""; // default
	if (sess->client_myds->addr.addr) {
		ca=sess->client_myds->addr.addr;
	}
	cl+=strlen(ca);
	if (cl && sess->client_myds->addr.port) {
		ca=(char *)malloc(cl+8);
		sprintf(ca,"%s:%d",sess->client_myds->addr.addr,sess->client_myds->addr.port);
	}
	cl=strlen(ca);

	char *un = "";
	char *sn = "";
	if (ui) {
		if (ui->username) {
			un = ui->username;
		}
		if (ui->schemaname) {
			sn = ui->schemaname;
		}
	}
	MySQL_Event me(_et, sess->thread_session_id,
		un, sn, 
		curtime_real, 0, 0,
		ca, cl
	);
/*
	char *c=(char *)sess->CurrentQuery.QueryPointer;
	if (c) {
		me.set_query(c,sess->CurrentQuery.QueryLength);
	} else {
		me.set_query("",0);
	}
*/
	int sl=0;
	char *sa=(char *)""; // default
	if (myds) {
		if (myds->myconn) {
			sa=myds->myconn->parent->address;
		}
	}
	sl+=strlen(sa);
	if (sl && myds->myconn->parent->port) {
		sa=(char *)malloc(sl+8);
		sprintf(sa,"%s:%d", myds->myconn->parent->address, myds->myconn->parent->port);
	}
	sl=strlen(sa);
	if (sl) {
		int hid=-1;
		hid=myds->myconn->parent->myhgc->hid;
//		me.set_server(hid,sa,sl);
	}

	wrlock();

	me.write(audit.logfile, sess);


	unsigned long curpos=audit.logfile->tellp();
	if (curpos > audit.max_log_file_size) {
		audit_flush_log_unlocked();
	}
	wrunlock();

	if (cl && sess->client_myds->addr.port) {
		free(ca);
	}
	if (sl && myds->myconn->parent->port) {
		free(sa);
	}
}

void MySQL_Logger::flush() {
	wrlock();
	if (events.logfile) {
		events.logfile->flush();
	}
	if (audit.logfile) {
		audit.logfile->flush();
	}
	wrunlock();
}

unsigned int MySQL_Logger::events_find_next_id() {
	int maxidx=0;
	DIR *dir;
	struct dirent *ent;
	char *eval_filename = NULL;
	char *eval_dirname = NULL;
	char *eval_pathname = NULL;
	assert(events.base_filename);
	if (events.base_filename[0] == '/') {
		eval_pathname = strdup(events.base_filename);
		eval_filename = basename(eval_pathname);
		eval_dirname = dirname(eval_pathname);
	} else {
		assert(events.datadir);
		eval_filename = strdup(events.base_filename);
		eval_dirname = strdup(events.datadir);
	}
	size_t efl=strlen(eval_filename);
	if ((dir = opendir(eval_dirname)) != NULL) {
		while ((ent = readdir (dir)) != NULL) {
			if (strlen(ent->d_name)==efl+9) {
				if (strncmp(ent->d_name,eval_filename,efl)==0) {
					if (ent->d_name[efl]=='.') {
						int idx=atoi(ent->d_name+efl+1);
						if (idx>maxidx) maxidx=idx;
					}
				}
			}
		}
		closedir (dir);
		if (events.base_filename[0] != '/') {
			free(eval_dirname);
			free(eval_filename);
		}
                if (eval_pathname) {
                        free(eval_pathname);
                }
		return maxidx;
	} else {
        /* could not open directory */
		proxy_error("Unable to open datadir: %s\n", eval_dirname);
		exit(EXIT_FAILURE);
	}        
	return 0;
}

unsigned int MySQL_Logger::audit_find_next_id() {
	int maxidx=0;
	DIR *dir;
	struct dirent *ent;
	char *eval_filename = NULL;
	char *eval_dirname = NULL;
	char *eval_pathname = NULL;
	assert(audit.base_filename);
	if (audit.base_filename[0] == '/') {
		eval_pathname = strdup(audit.base_filename);
		eval_filename = basename(eval_pathname);
		eval_dirname = dirname(eval_pathname);
	} else {
		assert(audit.datadir);
		eval_filename = strdup(audit.base_filename);
		eval_dirname = strdup(audit.datadir);
	}
	size_t efl=strlen(eval_filename);
	if ((dir = opendir(eval_dirname)) != NULL) {
		while ((ent = readdir (dir)) != NULL) {
			if (strlen(ent->d_name)==efl+9) {
				if (strncmp(ent->d_name,eval_filename,efl)==0) {
					if (ent->d_name[efl]=='.') {
						int idx=atoi(ent->d_name+efl+1);
						if (idx>maxidx) maxidx=idx;
					}
				}
			}
		}
		closedir (dir);
		if (audit.base_filename[0] != '/') {
			free(eval_dirname);
			free(eval_filename);
		}
                if (eval_pathname) {
                        free(eval_pathname);
                }
		return maxidx;
	} else {
        /* could not open directory */
		proxy_error("Unable to open datadir: %s\n", eval_dirname);
		exit(EXIT_FAILURE);
	}        
	return 0;
}
