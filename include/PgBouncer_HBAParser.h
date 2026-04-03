#ifndef PGBOUNCER_HBA_PARSER_H
#define PGBOUNCER_HBA_PARSER_H

#include "PgBouncer_Config.h"
#include <string>
#include <vector>

namespace PgBouncer {

class HBAParser {
public:
    // Parse a pg_hba.conf file as understood by PgBouncer.
    // PgBouncer supports a subset of PostgreSQL's HBA format:
    //   Record types: local, host, hostssl, hostnossl
    //   Database: all, sameuser, specific name, @file
    //   User: all, specific name, @file
    //   Address: IPv4/CIDR, IPv6/CIDR, "all" (for host/hostssl/hostnossl)
    //   Methods: trust, reject, md5, scram-sha-256, password, cert, peer, ldap, pam
    //   Options: key=value pairs after the method (e.g., map=mymap)
    bool parse(const std::string& filepath,
               std::vector<HBARule>& rules,
               std::vector<ParseMessage>& errors);

private:
    // Tokenize a line respecting double-quoted strings
    static std::vector<std::string> tokenize(const std::string& line);

    // Parse a single HBA record from tokens
    bool parse_record(const std::vector<std::string>& tokens,
                      HBARule& rule,
                      const std::string& file, int line,
                      std::vector<ParseMessage>& errors);
};

} // namespace PgBouncer

#endif
