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
};


#endif /* __CLASS_PROXYSQL_CONFIGFILE_H */
