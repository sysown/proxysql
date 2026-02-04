#ifndef MYSQL_VARIABLES_UTILS_H
#define MYSQL_VARIABLES_UTILS_H

#include <string>
#include <vector>

/**
 * @brief Gets all the variables for ProxySQL to recognize but ignore.
 */
const std::vector<std::string>& get_mysql_ignore_vars();
/**
 * @brief Gets a regex with all the variables ProxySQL should recognize for SET statements.
 */
const std::string& get_mysql_variables_regexp();

#endif
