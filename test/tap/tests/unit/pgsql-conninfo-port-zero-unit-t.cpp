#include "tap.h"
#include "test_globals.h"
#include "test_init.h"
#include "PgSQL_Conninfo_Helper.h"

#include <sstream>
#include <string>

int main(int argc, char** argv) {
    plan(2);

    // Skip if test harness requests environment-only actions
    if (cl.getEnv()) return exit_status();

    {
        std::ostringstream ss;
        append_pg_conninfo_port(ss, 0);
        std::string s = ss.str();
        ok(s.find("port=") == std::string::npos, "append_pg_conninfo_port omits port when port == 0");
    }

    {
        std::ostringstream ss;
        append_pg_conninfo_port(ss, 5432);
        std::string s = ss.str();
        ok(s.find("port=5432") != std::string::npos, "append_pg_conninfo_port includes port when non-zero");
    }

    return exit_status();
}
