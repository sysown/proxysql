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
	assert(__filename);
	filename = __filename;
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
}

bool ProxySQL_ConfigFile::ReadGlobals() {
	return true;
};

bool ProxySQL_ConfigFile::configVariable(const char *group, const char *key, int &variable, int defValue, int minValue, int maxValue, int multiplier) {
	const Setting& root = cfg.getRoot();
	if (root.exists(group)==true) {
		const Setting& mygroup=root[group];
		if (mygroup.isGroup()==true) {
			// group exists
			if (mygroup.exists(key)==true) {
				const Setting& myvar=mygroup[key];
				if ((myvar.getType()==Setting::Type::TypeInt) || (myvar.getType()==Setting::Type::TypeInt64)) {
					int var=myvar;
					if ( var < minValue ) {
						cerr << "[ERROR] Out of range value for " << group << "." << key << " in config file\n";
						var=minValue;
					}
					if ( var > maxValue ) {
						cerr << "[ERROR] Out of range value for " << group << "." << key << " in config file\n";
						var=maxValue;
					}
					variable=var*(multiplier > 0 ? multiplier : 1);
				} else {
					cerr << "[ERROR] Incorrect datatype for " << group << "." << key << " in config file. Setting default\n";
					variable=defValue*(multiplier > 0 ? multiplier : 1);
					return false;
				}
			} else {
				variable=defValue*(multiplier > 0 ? multiplier : 1);
				return false;
			}
		} else {
			variable=defValue*(multiplier > 0 ? multiplier : 1);
			return false;
		}
	} else {
		variable=defValue*(multiplier > 0 ? multiplier : 1);
		return false;	
	}
	return true;
}

bool ProxySQL_ConfigFile::configVariable(const char *group, const char *key, int64_t &variable, int64_t defValue, int64_t minValue, int64_t maxValue, int64_t multiplier) {
	const Setting& root = cfg.getRoot();
	if (root.exists(group)==true) {
		const Setting& mygroup=root[group];
		if (mygroup.isGroup()==true) {
			// group exists
			if (mygroup.exists(key)==true) {
				const Setting& myvar=mygroup[key];
				if ((myvar.getType()==Setting::Type::TypeInt) || (myvar.getType()==Setting::Type::TypeInt64)) {
					int64_t var=myvar;
					if ( var < minValue ) {
						cerr << "[ERROR] Out of range value for " << group << "." << key << " in config file\n";
						var=minValue;
					}
					if ( var > maxValue ) {
						cerr << "[ERROR] Out of range value for " << group << "." << key << " in config file\n";
						var=maxValue;
					}
					variable=var*(multiplier > 0 ? multiplier : 1);
				} else {
					cerr << "[ERROR] Incorrect datatype for " << group << "." << key << " in config file. Setting default\n";
					variable=defValue*multiplier;
					return false;
				}
			} else {
				variable=defValue*(multiplier > 0 ? multiplier : 1);
				return false;
			}
		} else {
			variable=defValue*(multiplier > 0 ? multiplier : 1);
			return false;
		}
	} else {
		variable=defValue*(multiplier > 0 ? multiplier : 1);
		return false;	
	}
	return true;
}

bool ProxySQL_ConfigFile::configVariable(const char *group, const char *key, bool & variable, bool defValue) {
	const Setting& root = cfg.getRoot();
	if (root.exists(group)==true) {
		const Setting& mygroup=root[group];
		if (mygroup.isGroup()==true) {
			// group exists
			if (mygroup.exists(key)==true) {
				const Setting& myvar=mygroup[key];
				if (myvar.getType()==Setting::Type::TypeBoolean) {
				} else {
					cerr << "[ERROR] Incorrect datatype for " << group << "." << key << " in config file. Setting default\n";
					variable=defValue;
					return false;
				}
			} else {
				variable=defValue;
				return false;
			}
		} else {
			variable=defValue;
			return false;
		}
	} else {
		variable=defValue;
		return false;	
	}
	return true;
}

bool ProxySQL_ConfigFile::configVariable(const char *group, const char *key, char **variable, const char *defValue) {
	const Setting& root = cfg.getRoot();
	if (root.exists(group)==true) {
		const Setting& mygroup=root[group];
		if (mygroup.isGroup()==true) {
			// group exists
			if (mygroup.exists(key)==true) {
				const Setting& myvar=mygroup[key];
				if (myvar.getType()==Setting::Type::TypeString) {
				} else {
					cerr << "[ERROR] Incorrect datatype for " << group << "." << key << " in config file. Setting default\n";
					*variable=strdup(defValue);
					return false;
				}
			} else {
				*variable=strdup(defValue);
				return false;
			}
		} else {
			*variable=strdup(defValue);
			return false;
		}
	} else {
		*variable=strdup(defValue);
		return false;	
	}
	return true;
}
