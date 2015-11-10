#include <fstream>
#include "proxysql.h"
#include "cpp.h"
#include <dirent.h>

MySQL_Logger::MySQL_Logger() {
	base_filename=NULL;
	datadir=NULL;
	// FIXME, temp
	base_filename=(char *)"mysql-log";
	spinlock_rwlock_init(&rwlock);
	logfile=NULL;
};

MySQL_Logger::~MySQL_Logger() {
	if (datadir) {
		free(datadir);
	}
};

void MySQL_Logger::wrlock() {
  spin_wrlock(&rwlock);
};

void MySQL_Logger::wrunlock() {
  spin_wrunlock(&rwlock);
};

void MySQL_Logger::flush_log() {
	wrlock();
	if (logfile) {
		logfile->flush();
		logfile->close();
		delete logfile;
		logfile=NULL;
	}
	log_file_id=find_next_id()+1;
	char *filen=(char *)malloc(strlen(datadir)+strlen(base_filename)+10);
	sprintf(filen,"%s/%s.%06d",datadir,base_filename,log_file_id);
	logfile=new std::ofstream();
	logfile->exceptions ( std::ofstream::failbit | std::ofstream::badbit );
	try {
		logfile->open(filen);
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
	wrunlock();
};

void MySQL_Logger::set_datadir(char *s) {
	datadir=strdup(s);
	flush_log();
};

void MySQL_Logger::log_request(unsigned long long t, int id) {
	wrlock();
	*logfile << t << std::endl << id << std::endl << std::endl ;
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
			if (strlen(ent->d_name)==bfl+7) {
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
