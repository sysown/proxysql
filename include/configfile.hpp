#ifndef __CLASS_PROXYSQL_CONFIGFILE_H
#define __CLASS_PROXYSQL_CONFIGFILE_H

#include "libconfig.h++"

using namespace libconfig;


class ProxySQL_ConfigFile {
  private:
  //struct stat statbuf;
  std::string filename;
  public:
  Config cfg;
  bool OpenFile(const char *);
  void CloseFile();
  bool ReadGlobals();
  bool configVariable(const char *, const char *, int &, int, int, int, int);
  bool configVariable(const char *, const char *, int64_t &, int64_t, int64_t, int64_t, int64_t);
  bool configVariable(const char *, const char *, bool &, bool);
  bool configVariable(const char *, const char *, char **, const char *);
};


#endif /* __CLASS_PROXYSQL_CONFIGFILE_H */
