#include "proxysql.h"
//#include "cpp.h"
#undef swap
#undef min
#undef max

#include "fileutils.hpp"

#include <iostream>

#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>


#include <libconfig.h++>

using namespace std;
using namespace libconfig;

typedef struct _global_configfile_entry_t global_configfile_entry_t;

// this struct define global variable entries, and how these are configured during startup
struct _global_configfile_entry_t {
  const char *key_name; // key name
  int dynamic;  // if dynamic > 0 , reconfigurable
  Setting::Type type; // type of variable
  void *arg_data; // pointer to variable
  const char *description;
  long long value_min;
  long long value_max;
  long long value_round;  // > 0 if value needs to be rounded
  int value_multiplier;   // if the value needs to be multiplied
  long long int_default;  // numeric default if applies
  const char *char_default; // string default if applies
  void (*func_pre)(global_configfile_entry_t *);  // function called before initializing variable
  void (*func_post)(global_configfile_entry_t *); // function called after initializing variable
};

bool ProxySQL_ConfigFile::OpenFile(const char *__filename) {
	if (__filename) filename = __filename;
	if (FileUtils::isReadable(filename.c_str())==false) return false;
	try
	{
		cfg.readFile(filename.c_str());
	}
	catch(const FileIOException &fioex)
	{
		std::cerr << "I/O error while reading file." << std::endl;
		return false;
	}
	catch(const ParseException &pex)
	{
		std::cerr << "Parse error at " << pex.getFile() << ":" << pex.getLine()
              << " - " << pex.getError() << std::endl;
			if (__filename) {
				// exit with failure only if it is the first time it is opened
				exit(EXIT_FAILURE);
			}
		return false;
	}
	return true;
};


void ProxySQL_ConfigFile::CloseFile() {
	// this function is now empty
	// perhaps we can remove it
	// see e85c34b2952f5a05d3f02a8afca30c0de334d898 for reference
}

bool ProxySQL_ConfigFile::ReadGlobals() {
	return true;
};
