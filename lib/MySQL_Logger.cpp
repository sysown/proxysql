#include <fstream>
#include "mysql_logger.pb.h"
#include "proxysql.h"
#include "cpp.h"
#include <dirent.h>


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

MySQL_Event::MySQL_Event (uint32_t _thread_id, char * _username, char * _schemaname , uint64_t _start_time , uint64_t _end_time , uint64_t _query_digest) {
	thread_id=_thread_id;
	username=_username;
	schemaname=_schemaname;
	start_time=_start_time;
	end_time=_end_time;
	query_digest=_query_digest;
}

void MySQL_Event::set_query(const char *ptr, int len) {
	query_ptr=(char *)ptr;
	query_len=len;
}

uint64_t MySQL_Event::write(std::fstream *f) {
	uint64_t total_bytes=0;
	total_bytes+=mysql_encode_length(thread_id, NULL);
	username_len=strlen(username);
	total_bytes+=mysql_encode_length(username_len,NULL)+username_len;
	schemaname_len=strlen(schemaname);
	total_bytes+=mysql_encode_length(schemaname_len,NULL)+schemaname_len;

	total_bytes+=mysql_encode_length(start_time,NULL);
	total_bytes+=mysql_encode_length(end_time,NULL);
	total_bytes+=mysql_encode_length(query_digest,NULL);

	total_bytes+=mysql_encode_length(query_len,NULL)+query_len;

	// write total length , fixed size
	f->write((const char *)&total_bytes,sizeof(uint64_t));
	//char prefix;
	uint8_t len;

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
	//int fd=open(filen, O_WRONLY | O_APPEND | O_CREAT , S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP);
	free(filen);
	//close(fd);
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

void MySQL_Logger::log_request(MySQL_Session *sess) {
	if (enabled==false) return;
	if (logfile==NULL) return;

	MySQL_Connection_userinfo *ui=sess->client_myds->myconn->userinfo;

	MySQL_Event me(sess->thread_session_id,ui->username,ui->schemaname,sess->CurrentQuery.start_time,sess->CurrentQuery.end_time,GloQPro->get_digest(sess->CurrentQuery.QueryParserArgs));
	char *c=(char *)sess->CurrentQuery.QueryPointer;
	if (c) {
		me.set_query(c,sess->CurrentQuery.QueryLength);
	} else {
		me.set_query("",0);
	}

/*
	ev.set_server("");
	ev.set_client("");
*/

	wrlock();

	me.write(logfile);

	unsigned long curpos=logfile->tellp();
	if (curpos > max_log_file_size) {
		flush_log_unlocked();
	}
	wrunlock();
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
