#pragma once
#include "Embedded_Execution.h"

namespace embedded {
// Derive a trusted refresh request from ParserSQL relation nodes only. The
// emitted query is never executed. Literals, aliases and comments cannot select
// refresh actions. Reset projections and CTE scope are unsupported in this slice.
Status admin_sqlite_statistics_refresh_query(const std::string&, std::string&, std::vector<std::string>* relations = nullptr);
bool admin_sqlite_statistics_reset_table(const std::string&);
bool admin_sqlite_statistics_dynamic_table(const std::string&);
}
