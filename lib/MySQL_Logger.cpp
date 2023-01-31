#include <fstream>
#include "proxysql.h"
#include "cpp.h"

#include "MySQL_Data_Stream.h"
#include "query_processor.h"
#include "MySQL_PreparedStatement.h"
#include "MySQL_Logger.hpp"

#include <dirent.h>
#include <libgen.h>

#include "../deps/json/json.hpp"
using json = nlohmann::json;

#ifdef DEBUG
#define DEB "_DEBUG"
#else
#define DEB ""
#endif /* DEBUG */
#define PROXYSQL_MYSQL_LOGGER_VERSION "2.0.0714" DEB

extern MySQL_Logger *GloMyLogger;

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
	extra_info = NULL;
	have_affected_rows=false;
	affected_rows=0;
	have_rows_sent=false;
	rows_sent=0;
	client_stmt_id=0;
}

void MySQL_Event::set_client_stmt_id(uint32_t client_stmt_id) {
	this->client_stmt_id = client_stmt_id;
}

void MySQL_Event::set_affected_rows(uint64_t ar) {
	have_affected_rows=true;
	affected_rows=ar;
}

void MySQL_Event::set_rows_sent(uint64_t rs) {
	have_rows_sent=true;
	rows_sent=rs;
}

void MySQL_Event::set_extra_info(char *_err) {
	extra_info = _err;
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
		case PROXYSQL_COM_QUERY:
		case PROXYSQL_COM_STMT_EXECUTE:
		case PROXYSQL_COM_STMT_PREPARE:
			if (mysql_thread___eventslog_format==1) { // format 1 , binary
				total_bytes=write_query_format_1(f);
			} else { // format 2 , json
				total_bytes=write_query_format_2_json(f);
			}
			break;
		case PROXYSQL_MYSQL_AUTH_OK:
		case PROXYSQL_MYSQL_AUTH_ERR:
		case PROXYSQL_MYSQL_AUTH_CLOSE:
		case PROXYSQL_MYSQL_AUTH_QUIT:
		case PROXYSQL_MYSQL_INITDB:
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
	json j = {};
	j["timestamp"] = start_time/1000;
	{
		time_t timer=start_time/1000/1000;
		struct tm* tm_info;
		tm_info = localtime(&timer);
		char buffer1[36];
		char buffer2[64];
		strftime(buffer1, 32, "%Y-%m-%d %H:%M:%S", tm_info);
		sprintf(buffer2,"%s.%03u", buffer1, (unsigned)(start_time%1000000)/1000);
		j["time"] = buffer2;
	}
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
	if (extra_info) {
		j["extra_info"] = extra_info;
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
		case PROXYSQL_MYSQL_INITDB:
			j["event"]="MySQL_Client_Init_DB";
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
	switch (et) {
		case PROXYSQL_MYSQL_AUTH_CLOSE:
		case PROXYSQL_ADMIN_AUTH_CLOSE:
		case PROXYSQL_SQLITE_AUTH_CLOSE:
			{
				uint64_t curtime_real=realtime_time();
				uint64_t curtime_mono=sess->thread->curtime;
				uint64_t timediff = curtime_mono - sess->start_time;
				uint64_t orig_time = curtime_real - timediff;
				time_t timer= (orig_time)/1000/1000;
				struct tm* tm_info;
				tm_info = localtime(&timer);
				char buffer1[36];
				char buffer2[64];
				strftime(buffer1, 32, "%Y-%m-%d %H:%M:%S", tm_info);
				sprintf(buffer2,"%s.%03u", buffer1, (unsigned)(orig_time%1000000)/1000);
				j["creation_time"] = buffer2;
				//unsigned long long life = sess->thread->curtime - sess->start_time;
				//life/=1000;
				float f = timediff;
				f /= 1000;
				sprintf(buffer1, "%.3fms", f);
				j["duration"] = buffer1;
			}
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
	// for performance reason, we are moving the write lock
	// right before the write to disk
	//GloMyLogger->wrlock();
	//move wrlock() function to log_audit_entry() function, avoid to get a null pointer in a multithreaded environment
	*f << j.dump(-1, ' ', false, json::error_handler_t::replace) << std::endl;
}

uint64_t MySQL_Event::write_query_format_1(std::fstream *f) {
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
	total_bytes+=mysql_encode_length(client_stmt_id,NULL);
	total_bytes+=mysql_encode_length(affected_rows,NULL);
	total_bytes+=mysql_encode_length(rows_sent,NULL);

	total_bytes+=mysql_encode_length(query_digest,NULL);

	total_bytes+=mysql_encode_length(query_len,NULL)+query_len;

	// for performance reason, we are moving the write lock
	// right before the write to disk
	//GloMyLogger->wrlock();
        //move wrlock() function to log_request() function, avoid to get a null pointer in a multithreaded environment

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

	if (et == PROXYSQL_COM_STMT_PREPARE || et == PROXYSQL_COM_STMT_EXECUTE) {
		len=mysql_encode_length(client_stmt_id,buf);
		write_encoded_length(buf,client_stmt_id,len,buf[0]);
		f->write((char *)buf,len);
	}

	len=mysql_encode_length(affected_rows,buf);
	write_encoded_length(buf,affected_rows,len,buf[0]);
	f->write((char *)buf,len);

	len=mysql_encode_length(rows_sent,buf);
	write_encoded_length(buf,rows_sent,len,buf[0]);
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

uint64_t MySQL_Event::write_query_format_2_json(std::fstream *f) {
	json j = {};
	uint64_t total_bytes=0;
	if (hid!=UINT64_MAX) {
		j["hostgroup_id"] = hid;
	} else {
		j["hostgroup_id"] = -1;
	}
	j["thread_id"] = thread_id;
	switch (et) {
		case PROXYSQL_COM_STMT_EXECUTE:
			j["event"]="COM_STMT_EXECUTE";
			break;
		case PROXYSQL_COM_STMT_PREPARE:
			j["event"]="COM_STMT_PREPARE";
			break;
		default:
			j["event"]="COM_QUERY";
			break;
	}
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
		j["client"] = client;
	} else {
		j["client"] = "";
	}
	if (hid!=UINT64_MAX) {
		if (server) {
			j["server"] = server;
		}
	}
	j["rows_affected"] = affected_rows;
	j["rows_sent"] = rows_sent;
	j["query"] = string(query_ptr,query_len);
	j["starttime_timestamp_us"] = start_time;
	{
		time_t timer=start_time/1000/1000;
		struct tm* tm_info;
		tm_info = localtime(&timer);
		char buffer1[36];
		char buffer2[64];
		strftime(buffer1, 32, "%Y-%m-%d %H:%M:%S", tm_info);
		sprintf(buffer2,"%s.%06u", buffer1, (unsigned)(start_time%1000000));
		j["starttime"] = buffer2;
	}
	j["endtime_timestamp_us"] = end_time;
	{
		time_t timer=end_time/1000/1000;
		struct tm* tm_info;
		tm_info = localtime(&timer);
		char buffer1[36];
		char buffer2[64];
		strftime(buffer1, 32, "%Y-%m-%d %H:%M:%S", tm_info);
		sprintf(buffer2,"%s.%06u", buffer1, (unsigned)(end_time%1000000));
		j["endtime"] = buffer2;
	}
	j["duration_us"] = end_time-start_time;
	char digest_hex[20];
	sprintf(digest_hex,"0x%016llX", (long long unsigned int)query_digest);
	j["digest"] = digest_hex;

	if (et == PROXYSQL_COM_STMT_PREPARE || et == PROXYSQL_COM_STMT_EXECUTE) {
		j["client_stmt_id"] = client_stmt_id;
	}

	// for performance reason, we are moving the write lock
	// right before the write to disk
	//GloMyLogger->wrlock();
        //move wrlock() function to log_request() function, avoid to get a null pointer in a multithreaded environment

	*f << j.dump(-1, ' ', false, json::error_handler_t::replace) << std::endl;
	return total_bytes; // always 0
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
	audit.logfile=NULL;
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
		filen=(char *)malloc(strlen(events.base_filename)+11);
		sprintf(filen,"%s.%08d",events.base_filename,events.log_file_id);
	} else { // relative path
		filen=(char *)malloc(strlen(events.datadir)+strlen(events.base_filename)+11);
		sprintf(filen,"%s/%s.%08d",events.datadir,events.base_filename,events.log_file_id);
	}
	events.logfile=new std::fstream();
	events.logfile->exceptions ( std::ofstream::failbit | std::ofstream::badbit );
	try {
		events.logfile->open(filen , std::ios::out | std::ios::binary);
		proxy_info("Starting new mysql event log file %s\n", filen);
	}
	catch (const std::ofstream::failure&) {
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
		filen=(char *)malloc(strlen(audit.base_filename)+11);
		sprintf(filen,"%s.%08d",audit.base_filename,audit.log_file_id);
	} else { // relative path
		filen=(char *)malloc(strlen(audit.datadir)+strlen(audit.base_filename)+11);
		sprintf(filen,"%s/%s.%08d",audit.datadir,audit.base_filename,audit.log_file_id);
	}
	audit.logfile=new std::fstream();
	audit.logfile->exceptions ( std::ofstream::failbit | std::ofstream::badbit );
	try {
		audit.logfile->open(filen , std::ios::out | std::ios::binary);
		proxy_info("Starting new audit log file %s\n", filen);
	}
	catch (const std::ofstream::failure&) {
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
	if (events.datadir)
		free(events.datadir);
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
	if (audit.datadir)
		free(audit.datadir);
	audit.datadir=strdup(s);
	flush_log();
};

void MySQL_Logger::log_request(MySQL_Session *sess, MySQL_Data_Stream *myds) {
	if (events.enabled==false) return;
	if (events.logfile==NULL) return;
	// 'MySQL_Session::client_myds' could be NULL in case of 'RequestEnd' being called over a freshly created session
	// due to a failed 'CONNECTION_RESET'. Because this scenario isn't a client request, we just return.
	if (sess->client_myds==NULL || sess->client_myds->myconn== NULL) return;

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
		ca=(char *)malloc(cl+9);
		sprintf(ca,"%s:%d",sess->client_myds->addr.addr,sess->client_myds->addr.port);
	}
	cl=strlen(ca);
	enum log_event_type let = PROXYSQL_COM_QUERY; // default
	switch (sess->status) {
		case PROCESSING_STMT_EXECUTE:
			let = PROXYSQL_COM_STMT_EXECUTE;
			break;
		case PROCESSING_STMT_PREPARE:
			let = PROXYSQL_COM_STMT_PREPARE;
			break;
		case WAITING_CLIENT_DATA:
			{
				unsigned char c=*((unsigned char *)sess->pktH->ptr+sizeof(mysql_hdr));
				switch ((enum_mysql_command)c) {
					case _MYSQL_COM_STMT_PREPARE:
						// proxysql is responding to COM_STMT_PREPARE without
						// preparing on any backend
						let = PROXYSQL_COM_STMT_PREPARE;
						break;
					default:
						break;
				}
			}
			break;
		default:
			break;
	}

	uint64_t query_digest = 0;

	if (sess->status != PROCESSING_STMT_EXECUTE) {
		query_digest = GloQPro->get_digest(&sess->CurrentQuery.QueryParserArgs);
	} else {
		query_digest = sess->CurrentQuery.stmt_info->digest;
	}

	MySQL_Event me(let,
		sess->thread_session_id,ui->username,ui->schemaname,
		sess->CurrentQuery.start_time + curtime_real - curtime_mono,
		sess->CurrentQuery.end_time + curtime_real - curtime_mono,
		query_digest,
		ca, cl
	);
	char *c = NULL;
	int ql = 0;
	switch (sess->status) {
		case PROCESSING_STMT_EXECUTE:
			c = (char *)sess->CurrentQuery.stmt_info->query;
			ql = sess->CurrentQuery.stmt_info->query_length;
			me.set_client_stmt_id(sess->CurrentQuery.stmt_client_id);
			break;
		case PROCESSING_STMT_PREPARE:
		default:
			c = (char *)sess->CurrentQuery.QueryPointer;
			ql = sess->CurrentQuery.QueryLength;
			// NOTE: This needs to be located in the 'default' case because otherwise will miss state
			// 'WAITING_CLIENT_DATA'. This state is possible when the prepared statement is found in the
			// global cache and due to that we immediately reply to the client and session doesn't reach
			// 'PROCESSING_STMT_PREPARE' state. 'stmt_client_id' is expected to be '0' for anything that isn't
			// a prepared statement, still, logging should rely 'log_event_type' instead of this value.
			me.set_client_stmt_id(sess->CurrentQuery.stmt_client_id);
			break;
	}
	if (c) {
		me.set_query(c,ql);
	} else {
		me.set_query("",0);
	}

	if (sess->CurrentQuery.have_affected_rows) {
		me.set_affected_rows(sess->CurrentQuery.affected_rows);
	}
	me.set_rows_sent(sess->CurrentQuery.rows_sent);

	int sl=0;
	char *sa=(char *)""; // default
	if (myds) {
		if (myds->myconn) {
			sa=myds->myconn->parent->address;
		}
	}
	sl+=strlen(sa);
	if (sl && myds->myconn->parent->port) {
		sa=(char *)malloc(sl+9);
		sprintf(sa,"%s:%d", myds->myconn->parent->address, myds->myconn->parent->port);
	}
	sl=strlen(sa);
	if (sl) {
		int hid=-1;
		hid=myds->myconn->parent->myhgc->hid;
		me.set_server(hid,sa,sl);
	}

	// for performance reason, we are moving the write lock
	// right before the write to disk
	//wrlock();
	
	//add a mutex lock in a multithreaded environment, avoid to get a null pointer of events.logfile that leads to the program coredump
        GloMyLogger->wrlock();

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

void MySQL_Logger::log_audit_entry(log_event_type _et, MySQL_Session *sess, MySQL_Data_Stream *myds, char *xi) {
	if (audit.enabled==false) return;
	if (audit.logfile==NULL) return;

	if (sess == NULL) return;
	if (sess->client_myds == NULL)  return; 

	MySQL_Connection_userinfo *ui= NULL;
	if (sess) {
		if (sess->client_myds) {
			if (sess->client_myds->myconn) {
				ui = sess->client_myds->myconn->userinfo;
			}
		}
	}
	if (sess) {
		// to reduce complexing in the calling function, we do some changes here
		switch (_et) {
			case PROXYSQL_MYSQL_AUTH_OK:
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
				break;
			case PROXYSQL_MYSQL_AUTH_ERR:
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
				break;
			case PROXYSQL_MYSQL_AUTH_QUIT:
				switch (sess->session_type) {
					case PROXYSQL_SESSION_ADMIN:
					case PROXYSQL_SESSION_STATS:
						_et = PROXYSQL_ADMIN_AUTH_QUIT;
						break;
					case PROXYSQL_SESSION_SQLITE:
						_et = PROXYSQL_SQLITE_AUTH_QUIT;
					default:
						break;
				}
				break;
			case PROXYSQL_MYSQL_AUTH_CLOSE:
				switch (sess->session_type) {
					case PROXYSQL_SESSION_ADMIN:
					case PROXYSQL_SESSION_STATS:
						_et = PROXYSQL_ADMIN_AUTH_CLOSE;
						break;
					case PROXYSQL_SESSION_SQLITE:
						_et = PROXYSQL_SQLITE_AUTH_CLOSE;
					default:
						break;
				}
				break;
			default:
				break;
		}
	}

	uint64_t curtime_real=realtime_time();
	int cl=0;
	char *ca=(char *)""; // default
	if (sess->client_myds->addr.addr) {
		ca=sess->client_myds->addr.addr;
	}
	cl+=strlen(ca);
	if (cl && sess->client_myds->addr.port) {
		ca=(char *)malloc(cl+9);
		sprintf(ca,"%s:%d",sess->client_myds->addr.addr,sess->client_myds->addr.port);
	}
	cl=strlen(ca);

	char *un = (char *)"";
	char *sn = (char *)"";
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
		sa=(char *)malloc(sl+9);
		sprintf(sa,"%s:%d", myds->myconn->parent->address, myds->myconn->parent->port);
	}
	sl=strlen(sa);

	if (xi) {
		me.set_extra_info(xi);
	}

	// for performance reason, we are moving the write lock
	// right before the write to disk
	//wrlock();

	//add a mutex lock in a multithreaded environment, avoid to get a null pointer of events.logfile that leads to the program coredump
        GloMyLogger->wrlock();
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

void MySQL_Logger::print_version() {
  fprintf(stderr,"Standard ProxySQL MySQL Logger rev. %s -- %s -- %s\n", PROXYSQL_MYSQL_LOGGER_VERSION, __FILE__, __TIMESTAMP__);
};

