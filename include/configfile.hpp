#ifndef __CLASS_PROXYSQL_CONFIGFILE_H
#define __CLASS_PROXYSQL_CONFIGFILE_H

#include <sys/stat.h>

#include "libconfig.h++"

using namespace libconfig;


class ProxySQL_ConfigFile {
  private:
  struct stat statbuf;
  char *filename;
  public:
  Config *cfg;
  ProxySQL_ConfigFile();
  bool OpenFile(const char *);
	void CloseFile();
	bool ReadGlobals();
	bool configVariable(const char *, const char *, int &, int, int, int, int);
	bool configVariable(const char *, const char *, int64_t &, int64_t, int64_t, int64_t, int64_t);
	bool configVariable(const char *, const char *, bool &, bool);
	bool configVariable(const char *, const char *, char **, const char *);
  ~ProxySQL_ConfigFile();
};


#endif /* __CLASS_PROXYSQL_CONFIGFILE_H */
