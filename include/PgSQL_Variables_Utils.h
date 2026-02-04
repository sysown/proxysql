#ifndef PGSQL_VARIABLES_UTILS_H
#define PGSQL_VARIABLES_UTILS_H

#include <string>
#include <vector>

/**
 * @brief Gets all the variables for ProxySQL to recognize but ignore.
 */
const std::vector<std::string>& get_pgsql_ignore_vars();
/**
 * @brief Gets a regex with all the variables ProxySQL should recognize for SET statements.
 */
const std::string& get_pgsql_variables_regexp();

#endif
