#include "proxysql.h"

#include "cpp.h"

#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>


#include <libconfig.h++>

using namespace std;
using namespace libconfig;

typedef struct _global_configfile_entry_t global_configfile_entry_t;

// this struct define global variable entries, and how these are configured during startup
struct _global_configfile_entry_t {
//  const char *group_name; // [group name] in proxysql.cnf 
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
/*
static global_configfile_entry_t glo_entries[]= {
#ifdef DEBUG
  {"debug", 1, Setting::Type::TypeInt, &GloVars.global.gdbg, "debugging messages", 0, 1, 0, 0, 0, NULL, NULL, NULL},
#endif
};
*/




ProxySQL_ConfigFile::ProxySQL_ConfigFile() {
	filename=NULL;
};


bool ProxySQL_ConfigFile::OpenFile(const char *__filename) {
	filename=strdup(__filename);
	if (FileUtils::isReadable(filename)==false) return false;
	try
	{
		cfg.readFile(filename);
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
		return false;
	}
	return true;
	};


bool ProxySQL_ConfigFile::ReadGlobals() {
/*
	const Setting& root = cfg.getRoot();
	unsigned int i;
	for (i=0;i<sizeof(glo_entries)/sizeof(global_configfile_entry_t);i++) {
		global_configfile_entry_t *gve=glo_entries+i;
		std::cerr << "Setting " << gve->description << endl;
		if (root.exists(gve->key_name)==true) {
			const Setting& key = root[gve->key_name];
			if (key.getType() == gve->type) {
				switch (gve->type) {
					case Setting::Type::TypeInt :
						int aint;
						root.lookupValue(gve->key_name, aint);
						aint=aint*(gve->value_multiplier > 0 ? gve->value_multiplier :  1 );
						*(int *)gve->arg_data=aint;
						cerr << "Setting " << gve->key_name << " value " << aint << endl;
						break;
					case Setting::Type::TypeInt64 :
						int64_t aint64;
						root.lookupValue(gve->key_name, aint64);
						aint64=aint64*(gve->value_multiplier > 0 ? gve->value_multiplier :  1 );
						*(int64_t *)gve->arg_data=aint64;
						cerr << "Setting " << gve->key_name << " value " << aint64 << endl;
						break;
					case Setting::Type::TypeString :
						const char *achar;
						root.lookupValue(gve->key_name, achar);
						*(char **)gve->arg_data=strdup(achar);
						cerr << "Setting " << gve->key_name << " value " << achar << endl;
						break;
					default:
						break;
				}
			} else {
				cerr << "Wrong data type" << endl;
			}
		} else {
			cerr << "key " << gve->key_name << " not found, setting default\n" ;
			switch (gve->type) {
				case Setting::Type::TypeInt :
					*(int *)gve->arg_data=(int)gve->int_default*(gve->value_multiplier > 0 ? gve->value_multiplier :  1 );
					break;
				case Setting::Type::TypeInt64 :
					*(int64_t *)gve->arg_data=(int64_t)gve->int_default*(gve->value_multiplier > 0 ? gve->value_multiplier :  1 );
					break;
				case Setting::Type::TypeString :
					*(char **)gve->arg_data=strdup(gve->char_default);
					break;
				default:
					break;
			}
			
		}
	}
*/
	return true;
};


//void ProxySQL_ConfigFile::setDefault(int &variable, const char *defValue, int multiplier) {
//	variable=defValue*multiplier;
//}



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

ProxySQL_ConfigFile::~ProxySQL_ConfigFile() {
//	cfg.~Config();
	if (filename) free(filename);
};
