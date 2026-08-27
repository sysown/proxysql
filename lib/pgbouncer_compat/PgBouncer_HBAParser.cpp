#include "PgBouncer_HBAParser.h"
#include <fstream>
#include <sstream>
#include <algorithm>
#include <cctype>

namespace PgBouncer {

// ---------------------------------------------------------------------------
// Valid connection types and authentication methods recognised by PgBouncer
// ---------------------------------------------------------------------------

static bool is_valid_conn_type(const std::string& t) {
    return t == "local" || t == "host" || t == "hostssl" || t == "hostnossl";
}

static bool is_valid_method(const std::string& m) {
    return m == "trust"  || m == "reject"  || m == "md5"  ||
           m == "scram-sha-256" || m == "password" || m == "cert" ||
           m == "peer"  || m == "ldap"    || m == "pam";
}

// Return true when the token looks like an IP/CIDR (contains '/' with digits
// after it) or a bare IP address (contains '.' or ':').  Used to distinguish
// an address token from a method token when there is no CIDR suffix and the
// address is followed by a separate netmask.
static bool looks_like_address(const std::string& tok) {
    if (tok == "all" || tok == "samehost" || tok == "samenet")
        return true;
    // Contains '/' -> CIDR notation
    if (tok.find('/') != std::string::npos)
        return true;
    // IPv4 dotted-decimal or IPv6 colon-hex
    if (tok.find('.') != std::string::npos || tok.find(':') != std::string::npos)
        return true;
    return false;
}

// ---------------------------------------------------------------------------
// Tokenizer -- splits a line on whitespace, keeping double-quoted substrings
// as single tokens (quotes are stripped from the result).
// ---------------------------------------------------------------------------

bool HBAParser::tokenize(const std::string& line,
                         std::vector<std::string>& tokens) {
    tokens.clear();
    std::string token;
    bool in_quotes = false;
    // A token that came from a quoted run is emitted even when empty, so that
    // `""` is a real (empty) field rather than silently disappearing.
    bool quoted_token = false;

    for (size_t i = 0; i < line.size(); ++i) {
        char c = line[i];

        if (in_quotes) {
            if (c == '"') {
                // PostgreSQL/PgBouncer escape a quote inside a quoted string by
                // doubling it ("").
                if (i + 1 < line.size() && line[i + 1] == '"') {
                    token += '"';
                    ++i;
                } else {
                    in_quotes = false;
                }
            } else {
                token += c;
            }
        } else {
            if (c == '#') {
                // Rest of line is a comment
                break;
            } else if (c == '"') {
                in_quotes = true;
                quoted_token = true;
            } else if (std::isspace(static_cast<unsigned char>(c))) {
                if (!token.empty() || quoted_token) {
                    tokens.push_back(token);
                    token.clear();
                    quoted_token = false;
                }
            } else {
                token += c;
            }
        }
    }
    if (!token.empty() || quoted_token) {
        tokens.push_back(token);
    }
    // An unterminated quote means the line is malformed; the caller must not
    // treat the partial tokens as a valid record.
    return !in_quotes;
}

// ---------------------------------------------------------------------------
// parse_record -- interpret one tokenized line as an HBA rule
// ---------------------------------------------------------------------------

bool HBAParser::parse_record(const std::vector<std::string>& tokens,
                             HBARule& rule,
                             const std::string& file, int lineno,
                             std::vector<ParseMessage>& errors) {
    if (tokens.empty())
        return false;

    size_t idx = 0;

    // -- connection type --
    rule.conn_type = tokens[idx++];
    if (!is_valid_conn_type(rule.conn_type)) {
        errors.push_back({file, lineno,
            "invalid connection type '" + rule.conn_type + "'"});
        return false;
    }

    // -- database --
    if (idx >= tokens.size()) {
        errors.push_back({file, lineno, "missing database field"});
        return false;
    }
    rule.database = tokens[idx++];

    // -- user --
    if (idx >= tokens.size()) {
        errors.push_back({file, lineno, "missing user field"});
        return false;
    }
    rule.user = tokens[idx++];

    // -- address (only for host/hostssl/hostnossl) --
    if (rule.conn_type != "local") {
        if (idx >= tokens.size()) {
            errors.push_back({file, lineno, "missing address field"});
            return false;
        }
        rule.address = tokens[idx++];

        // If the address has no CIDR suffix and is not a keyword ("all" etc.),
        // the next token might be a separate netmask rather than the method.
        if (rule.address.find('/') == std::string::npos &&
            rule.address != "all" &&
            rule.address != "samehost" &&
            rule.address != "samenet")
        {
            // Peek at next token: if it looks like an IP it is a netmask
            if (idx < tokens.size() && looks_like_address(tokens[idx]) &&
                !is_valid_method(tokens[idx]))
            {
                rule.mask = tokens[idx++];
            }
        }
    }

    // -- method --
    if (idx >= tokens.size()) {
        errors.push_back({file, lineno, "missing authentication method"});
        return false;
    }
    rule.method = tokens[idx++];
    if (!is_valid_method(rule.method)) {
        errors.push_back({file, lineno,
            "invalid authentication method '" + rule.method + "'"});
        return false;
    }

    // -- options (key=value pairs) --
    while (idx < tokens.size()) {
        const std::string& opt = tokens[idx++];
        size_t eq = opt.find('=');
        if (eq == std::string::npos) {
            errors.push_back({file, lineno,
                "invalid option '" + opt + "' (expected key=value)"});
            return false;
        }
        std::string key = opt.substr(0, eq);
        std::string val = opt.substr(eq + 1);
        rule.options[key] = val;
    }

    return true;
}

// ---------------------------------------------------------------------------
// parse -- read and parse an entire pg_hba.conf file
// ---------------------------------------------------------------------------

bool HBAParser::parse(const std::string& filepath,
                      std::vector<HBARule>& rules,
                      std::vector<ParseMessage>& errors) {
    // parse() is a full load, not an append: reusing the vector across calls
    // must not accumulate duplicate rules. `errors` is deliberately left alone,
    // since callers thread one diagnostic list through several parsers.
    rules.clear();
    std::ifstream in(filepath);
    if (!in.is_open()) {
        errors.push_back({filepath, 0,
            "cannot open file '" + filepath + "'"});
        return false;
    }

    std::string line;
    int lineno = 0;
    bool ok = true;

    while (std::getline(in, line)) {
        ++lineno;

        std::vector<std::string> tokens;
        if (!tokenize(line, tokens)) {
            errors.push_back({filepath, lineno,
                "unterminated double quote"});
            ok = false;
            continue;
        }
        if (tokens.empty())
            continue;

        HBARule rule;
        if (parse_record(tokens, rule, filepath, lineno, errors)) {
            rules.push_back(std::move(rule));
        } else {
            ok = false;
        }
    }

    return ok;
}

// ---------------------------------------------------------------------------
// Free function declared in PgBouncer_Config.h -- delegates to HBAParser
// ---------------------------------------------------------------------------

bool parse_hba_file(const std::string& filepath,
                    std::vector<HBARule>& rules,
                    std::vector<ParseMessage>& errors) {
    HBAParser parser;
    return parser.parse(filepath, rules, errors);
}

} // namespace PgBouncer
