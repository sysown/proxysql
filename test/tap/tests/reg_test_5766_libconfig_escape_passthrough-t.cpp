/**
 * @file reg_test_5766_libconfig_escape_passthrough-t.cpp
 * @brief Regression test for https://github.com/sysown/proxysql/issues/5766
 *
 * libconfig 1.8.1 introduced new escape rules (\a, \b, \v) that did not
 * exist in 1.7.3.  When a proxysql.cnf string contains the literal
 * two-character sequence `\v` (backslash + v), 1.8.1 silently collapses
 * it to the single byte 0x0B (vertical tab), corrupting passwords and
 * other config values.  The bundled libconfig is patched (see
 * deps/libconfig/restore_unknown_escape_passthrough.patch) to restore
 * 1.7.3 passthrough behaviour for these three escape sequences.
 *
 * This test creates a config file containing values with literal `\a`,
 * `\b` and `\v` sequences, loads it via `LOAD ... VARIABLES FROM CONFIG`,
 * and asserts that each value is read back byte-for-byte unchanged.
 *
 * It also verifies that `\n` and `\xHH` (hex escapes) -- which were
 * already interpreted by libconfig 1.7.3 -- still work as expected.
 */
#include <cstdio>
#include <cstdlib>
#include <fstream>
#include <string>
#include <string_view>
#include <unistd.h>
#include "mysql.h"

#include "tap.h"
#include "utils.h"
#include "command_line.h"

using std::string;
using std::string_view;

/* Probe values exercised below.  Every literal `\` in C++ source maps to
 * a single backslash byte in the rendered config; libconfig should then
 * leave it untouched (for \a \b \v) or interpret it (for \n \x).
 * `expected_value` is a string_view so the comparison length is the
 * compile-time literal size and we do not call strlen at runtime. */
struct Probe {
    const char* var_name;
    string_view config_literal; /* what we write between the quotes in the .cnf */
    string_view expected_value; /* bytes we expect to read back via admin */
    const char* description;
};

static const Probe probes[] = {
    /* The three regressions introduced by libconfig 1.8.1. */
    { "mysql-server_version",     "pass\\vword",        "pass\\vword",      "\\v preserved as two bytes (was 0x0B in 1.8.1)" },
    { "mysql-default_schema",     "ho\\ame",            "ho\\ame",          "\\a preserved as two bytes (was 0x07 in 1.8.1)" },
    { "mysql-init_connect",       "se\\bt names utf8",  "se\\bt names utf8","\\b preserved as two bytes (was 0x08 in 1.8.1)" },
    /* Already-interpreted escapes -- must keep their 1.7.3 behaviour. */
    { "mysql-ldap_user_variable", "line1\\nline2",      "line1\nline2",     "\\n still collapsed to 0x0A (unchanged from 1.7.3)" },
    { "mysql-add_ldap_user_comment","tab\\x09sep",      "tab\tsep",         "\\xHH still interpreted as hex (unchanged from 1.7.3)" },
};
static const size_t n_probes = sizeof(probes) / sizeof(probes[0]);

static void write_config(const string& path, const string& datadir) {
    std::ofstream cfg(path);
    cfg << "datadir=\"" << datadir << "\"\n";
    cfg << "errorlog=\"" << datadir << "/proxysql.log\"\n";
    cfg << "mysql_variables=\n{\n";
    for (size_t i = 0; i < n_probes; ++i) {
        /* Strip the "mysql-" prefix when writing into the mysql_variables
         * group; libconfig stores it as `mysql-<name>` after loading. */
        string_view var{probes[i].var_name};
        if (var.substr(0, 6) == "mysql-") var.remove_prefix(6);
        cfg << "    " << var << "=\"" << probes[i].config_literal << "\"\n";
    }
    cfg << "}\n";
    cfg.close();
}

int main(int argc, char** argv) {
    CommandLine cl;

    if (cl.getEnv()) {
        diag("Failed to get the required environmental variables.");
        return EXIT_FAILURE;
    }

    plan(n_probes);

    MYSQL* admin = mysql_init(NULL);
    if (!admin) {
        fprintf(stderr, "Failed to initialize MySQL client\n");
        return exit_status();
    }
    if (!mysql_real_connect(admin, cl.host, cl.admin_username, cl.admin_password,
                            NULL, cl.admin_port, NULL, 0)) {
        fprintf(stderr, "Failed to connect to admin: %s\n", mysql_error(admin));
        return exit_status();
    }

    /* Prefer the TAP-managed workdir (TAP_WORKDIR / cl.workdir, defaults
     * to "./"). REGULAR_INFRA_DATADIR is honoured first when set by the
     * infra so the cnf lands in the same private datadir the proxysql
     * instance uses, matching test_load_from_config_*-t. No hardcoded
     * /tmp path. */
    string cfg_dir;
    if (const char* datadir = getenv("REGULAR_INFRA_DATADIR")) {
        cfg_dir = datadir;
    } else if (cl.workdir && *cl.workdir) {
        cfg_dir = cl.workdir;
    } else {
        cfg_dir = ".";
    }
    while (cfg_dir.size() > 1 && cfg_dir.back() == '/') cfg_dir.pop_back();
    string cfg_path = cfg_dir + "/reg_test_5766.cfg";
    write_config(cfg_path, cfg_dir);

    string set_cfg = "PROXYSQL SET CONFIG FILE '" + cfg_path + "'";
    MYSQL_QUERY_T(admin, set_cfg.c_str());

    /* Wipe any prior value so a stale row can't mask a regression. */
    for (size_t i = 0; i < n_probes; ++i) {
        string del = string("DELETE FROM global_variables WHERE variable_name='") + probes[i].var_name + "'";
        MYSQL_QUERY_T(admin, del.c_str());
    }

    MYSQL_QUERY_T(admin, "LOAD MYSQL VARIABLES FROM CONFIG");

    for (size_t i = 0; i < n_probes; ++i) {
        string sel = string("SELECT variable_value FROM global_variables WHERE variable_name='") + probes[i].var_name + "'";
        MYSQL_QUERY_T(admin, sel.c_str());
        MYSQL_RES* res = mysql_store_result(admin);
        MYSQL_ROW row = res ? mysql_fetch_row(res) : NULL;
        unsigned long* lens = res ? mysql_fetch_lengths(res) : NULL;

        bool match = false;
        const string_view& exp = probes[i].expected_value;
        if (row && row[0] && lens) {
            if (lens[0] == exp.size() && string_view(row[0], lens[0]) == exp) {
                match = true;
            } else {
                diag("Mismatch for %s: expected %zu bytes, got %lu bytes",
                     probes[i].var_name, exp.size(), lens[0]);
                /* Hex-dump both for easier triage. */
                fprintf(stderr, "  expected hex: ");
                for (size_t k = 0; k < exp.size(); ++k) fprintf(stderr, "%02x ", (unsigned char)exp[k]);
                fprintf(stderr, "\n  actual hex:   ");
                for (size_t k = 0; k < lens[0]; ++k) fprintf(stderr, "%02x ", (unsigned char)row[0][k]);
                fprintf(stderr, "\n");
            }
        } else {
            diag("Variable %s not found after LOAD MYSQL VARIABLES FROM CONFIG", probes[i].var_name);
        }
        ok(match, "%s", probes[i].description);
        if (res) mysql_free_result(res);
    }

    unlink(cfg_path.c_str());
    mysql_close(admin);
    return exit_status();
}
