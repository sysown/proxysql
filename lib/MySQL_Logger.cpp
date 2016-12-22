#include "MySQL_Logger.hpp"

#include <fstream>
#include <dirent.h>

#include "MySQL_Session.h"
#include "MySQL_Thread.h"
#include "proxysql_debug.h"


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

MySQL_Event::MySQL_Event (uint32_t _thread_id, char * _username, char * _schemaname , uint64_t _start_time , uint64_t _end_time , uint64_t _query_digest, char *_client, size_t _client_len) {
	thread_id=_thread_id;
	username=_username;
	schemaname=_schemaname;
	start_time=_start_time;
	end_time=_end_time;
	query_digest=_query_digest;
	client=_client;
	client_len=_client_len;
	et=PROXYSQL_QUERY;
	hid=UINT64_MAX;
	server=NULL;
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

uint64_t MySQL_Event::write(std::fstream *f) {
	uint64_t total_bytes=0;
	switch (et) {
		case PROXYSQL_QUERY:
			total_bytes=write_query(f);
			break;
		default:
			break;
	}
	return total_bytes;
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
	enabled=false;
	base_filename=NULL;
	datadir=NULL;
	base_filename=strdup((char *)"");
	spinlock_rwlock_init(&rwlock);
	logfile=NULL;
	log_file_id=0;
	max_log_file_size=100*1024*1024;
};

MySQL_Logger::~MySQL_Logger() {
	if (datadir) {
		free(datadir);
	}
	free(base_filename);
};

void MySQL_Logger::wrlock() {
  spin_wrlock(&rwlock);
};

void MySQL_Logger::wrunlock() {
  spin_wrunlock(&rwlock);
};

void MySQL_Logger::flush_log() {
	if (enabled==false) return;
	wrlock();
	flush_log_unlocked();
	wrunlock();
}


void MySQL_Logger::close_log_unlocked() {
	if (logfile) {
		logfile->flush();
		logfile->close();
		delete logfile;
		logfile=NULL;
	}
}

void MySQL_Logger::flush_log_unlocked() {
	if (enabled==false) return;
	close_log_unlocked();
	open_log_unlocked();
}


void MySQL_Logger::open_log_unlocked() {
	if (log_file_id==0) {
		log_file_id=find_next_id()+1;
	} else {
		log_file_id++;
	}
	char *filen=NULL;
	if (base_filename[0]=='/') { // absolute path
		filen=(char *)malloc(strlen(base_filename)+10);
		sprintf(filen,"/%s.%08d",base_filename,log_file_id);
	} else { // relative path
		filen=(char *)malloc(strlen(datadir)+strlen(base_filename)+10);
		sprintf(filen,"%s/%s.%08d",datadir,base_filename,log_file_id);
	}
	logfile=new std::fstream();
	logfile->exceptions ( std::ofstream::failbit | std::ofstream::badbit );
	try {
		logfile->open(filen , std::ios::out | std::ios::binary);
		proxy_info("Starting new mysql log file %s\n", filen);
	}
	catch (std::ofstream::failure e) {
		proxy_error("Error creating new mysql log file %s\n", filen);
		delete logfile;
		logfile=NULL;
	}
	free(filen);
};

void MySQL_Logger::set_base_filename() {
	// if filename is the same, return
	wrlock();
	max_log_file_size=mysql_thread___eventslog_filesize;
	if (strcmp(base_filename,mysql_thread___eventslog_filename)==0) {
		wrunlock();
		return;
	}
	// close current log
	close_log_unlocked();
	// set file id to 0 , so that find_next_id() will be called
	log_file_id=0;
	free(base_filename);
	base_filename=strdup(mysql_thread___eventslog_filename);
	if (strlen(base_filename)) {
		enabled=true;
		open_log_unlocked();
	} else {
		enabled=false;
	}
	wrunlock();
}

void MySQL_Logger::set_datadir(char *s) {
	datadir=strdup(s);
	flush_log();
};

void MySQL_Logger::log_request(MySQL_Session *sess, MySQL_Data_Stream *myds) {
	if (enabled==false) return;
	if (logfile==NULL) return;

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
	MySQL_Event me(sess->thread_session_id,ui->username,ui->schemaname,
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

	me.write(logfile);


	unsigned long curpos=logfile->tellp();
	if (curpos > max_log_file_size) {
		flush_log_unlocked();
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
	if (logfile) {
		logfile->flush();
	}
	wrunlock();
}

unsigned int MySQL_Logger::find_next_id() {
	int maxidx=0;
	DIR *dir;
	struct dirent *ent;
	assert(base_filename);
	assert(datadir);
	size_t bfl=strlen(base_filename);
	if ((dir = opendir(datadir)) != NULL) {
	  while ((ent = readdir (dir)) != NULL) {
			if (strlen(ent->d_name)==bfl+9) {
				if (strncmp(ent->d_name,base_filename,bfl)==0) {
					if (ent->d_name[bfl]=='.') {
						int idx=atoi(ent->d_name+bfl+1);
						if (idx>maxidx) maxidx=idx;
					}
				}
			}
		}
  closedir (dir);
	return maxidx;
	} else {
  /* could not open directory */
		fprintf(stderr,"Unable to open datadir: %s\n", datadir);
		exit(EXIT_FAILURE);
	}
	return 0;
}
