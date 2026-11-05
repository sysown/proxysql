#include "duckdb_mysql_compat.h"
#include <algorithm>
#include <cctype>
#include <stdexcept>
#include <string>
#include <vector>

namespace {
enum class Kind { word, number, string, identifier, symbol };
struct Token {
	Kind kind;
	std::string text;
	std::string value;
};
std::string upper(std::string s) {
	for (char &c : s)
		c = std::toupper(static_cast<unsigned char>(c));
	return s;
}
std::string quoted(const std::string &s, char quote) {
	std::string out(1, quote);
	for (char c : s) {
		out += c;
		if (c == quote)
			out += c;
	}
	return out + quote;
}
bool word_char(unsigned char c) {
	return std::isalnum(c) || c == '_' || c == '$' || c >= 128;
}
std::vector<Token> lex(const std::string &sql, bool first_only = false) {
	std::vector<Token> out;
	for (size_t i = 0; i < sql.size();) {
		unsigned char c = sql[i];
		if (std::isspace(c)) {
			++i;
			continue;
		}
		if (c == 0)
			throw std::runtime_error("NUL in SQL is unsupported");
		if (c == '#' ||
			(c == '-' && i + 1 < sql.size() && sql[i + 1] == '-' &&
			 (i + 2 == sql.size() || std::isspace(static_cast<unsigned char>(sql[i + 2]))))) {
			while (i < sql.size() && sql[i] != '\n')
				++i;
			continue;
		}
		if (c == '/' && i + 1 < sql.size() && sql[i + 1] == '*') {
			if (i + 2 < sql.size() && (sql[i + 2] == '!' || sql[i + 2] == '+'))
				throw std::runtime_error("executable comments and optimizer hints are unsupported");
			const size_t end = sql.find("*/", i + 2);
			if (end == std::string::npos)
				throw std::runtime_error("unterminated comment");
			i = end + 2;
			continue;
		}
		if (c == '\'' || c == '"' || c == '`') {
			const char quote = c;
			std::string value;
			bool closed = false;
			++i;
			while (i < sql.size()) {
				char next = sql[i++];
				if (next == 0)
					throw std::runtime_error("NUL in quoted value is unsupported");
				if (next == quote) {
					if (i < sql.size() && sql[i] == quote) {
						value += quote;
						++i;
						continue;
					}
					closed = true;
					break;
				}
				if (next == '\\' && quote != '`') {
					if (i == sql.size())
						break;
					next = sql[i++];
					switch (next) {
					case '0':
						throw std::runtime_error("NUL string escapes are unsupported");
					case 'b':
						next = '\b';
						break;
					case 'n':
						next = '\n';
						break;
					case 'r':
						next = '\r';
						break;
					case 't':
						next = '\t';
						break;
					case 'Z':
						next = 26;
						break;
					case '%':
					case '_':
						value += '\\';
						break;
					default:
						break;
					}
				}
				value += next;
			}
			if (!closed)
				throw std::runtime_error("unterminated quoted value");
			if (quote != '`' && !out.empty() && out.back().kind == Kind::string) {
				out.back().value += value;
				out.back().text = quoted(out.back().value, '\'');
			} else {
				out.push_back({quote == '`' ? Kind::identifier : Kind::string,
							   quoted(value, quote == '`' ? '"' : '\''), value});
			}
		} else if (std::isdigit(c)) {
			size_t begin = i++;
			if (c == '0' && i < sql.size() &&
				(sql[i] == 'x' || sql[i] == 'X' || sql[i] == 'b' || sql[i] == 'B'))
				throw std::runtime_error("hexadecimal and bit literals are unsupported");
			while (i < sql.size() && std::isdigit(static_cast<unsigned char>(sql[i])))
				++i;
			if (i < sql.size() && sql[i] == '.') {
				++i;
				while (i < sql.size() && std::isdigit(static_cast<unsigned char>(sql[i])))
					++i;
			}
			if (i < sql.size() && (sql[i] == 'e' || sql[i] == 'E')) {
				++i;
				if (i < sql.size() && (sql[i] == '+' || sql[i] == '-'))
					++i;
				while (i < sql.size() && std::isdigit(static_cast<unsigned char>(sql[i])))
					++i;
			}
			out.push_back({Kind::number, sql.substr(begin, i - begin), {}});
		} else if (word_char(c)) {
			size_t begin = i++;
			while (i < sql.size() && word_char(sql[i]))
				++i;
			out.push_back({Kind::word, sql.substr(begin, i - begin), {}});
		} else {
			std::string op;
			for (const char *candidate :
				 {"<=>", "<=", ">=", "<>", "!=", "&&", "||", "::", "<<", ">>"}) {
				if (sql.compare(i, std::char_traits<char>::length(candidate), candidate) == 0) {
					op = candidate;
					break;
				}
			}
			if (op.empty())
				op.assign(1, c);
			if (op == "@" || op == "?" || op == "!")
				throw std::runtime_error("user variables, parameters and unary ! are unsupported");
			out.push_back({Kind::symbol, op, {}});
			i += op.size();
		}
		if (out.size() > 100000)
			throw std::runtime_error("query token limit exceeded");
		if (first_only)
			break;
	}
	return out;
}

class Renderer {
	const std::vector<Token> &t;
	std::vector<size_t> close;
	bool is(size_t i, const char *text) const {
		return i < t.size() && t[i].kind == Kind::word && upper(t[i].text) == text;
	}
	static void add(std::string &out, const std::string &part) {
		if (!out.empty())
			out += ' ';
		out += part;
	}
	std::vector<std::pair<size_t, size_t>> split(size_t a, size_t b) const {
		std::vector<std::pair<size_t, size_t>> args;
		size_t begin = a;
		for (size_t i = a; i < b; ++i) {
			if (t[i].text == "(")
				i = close[i];
			else if (t[i].text == ",") {
				args.push_back({begin, i});
				begin = i + 1;
			}
		}
		args.push_back({begin, b});
		return args;
	}
	std::string date_format(const std::string &format) const {
		std::string out;
		for (size_t i = 0; i < format.size(); ++i) {
			if (format[i] != '%') {
				out += format[i];
				continue;
			}
			if (++i == format.size())
				throw std::runtime_error("trailing % in DATE_FORMAT");
			switch (format[i]) {
			case '%':
				out += "%%";
				break;
			case 'Y':
				out += "%Y";
				break;
			case 'y':
				out += "%y";
				break;
			case 'm':
				out += "%m";
				break;
			case 'c':
				out += "%-m";
				break;
			case 'd':
				out += "%d";
				break;
			case 'e':
				out += "%-d";
				break;
			case 'H':
				out += "%H";
				break;
			case 'k':
				out += "%-H";
				break;
			case 'h':
			case 'I':
				out += "%I";
				break;
			case 'l':
				out += "%-I";
				break;
			case 'i':
				out += "%M";
				break;
			case 's':
			case 'S':
				out += "%S";
				break;
			case 'f':
				out += "%f";
				break;
			case 'p':
				out += "%p";
				break;
			case 'a':
				out += "%a";
				break;
			case 'W':
				out += "%A";
				break;
			case 'b':
				out += "%b";
				break;
			case 'M':
				out += "%B";
				break;
			case 'j':
				out += "%j";
				break;
			case 'w':
				out += "%w";
				break;
			case 'r':
				out += "%I:%M:%S %p";
				break;
			case 'T':
				out += "%H:%M:%S";
				break;
			default:
				throw std::runtime_error("unsupported DATE_FORMAT directive");
			}
		}
		return quoted(out, '\'');
	}
	std::string parenthesized(size_t i, size_t end, unsigned depth) {
		const size_t right = close[i];
		(void)end;
		return "(" + render(i + 1, right, depth + 1) + ")";
	}
	std::string function(size_t name, size_t left, size_t right, unsigned depth) {
		const auto args = split(left + 1, right);
		if (is(name, "DATE_FORMAT")) {
			if (args.size() != 2 || args[1].second != args[1].first + 1 ||
				t[args[1].first].kind != Kind::string)
				throw std::runtime_error("DATE_FORMAT requires a literal format");
			return "strftime(CAST(" + render(args[0].first, args[0].second, depth + 1) +
				   " AS TIMESTAMP)," + date_format(t[args[1].first].value) + ")";
		}
		if (is(name, "DATEDIFF")) {
			if (args.size() != 2)
				throw std::runtime_error("DATEDIFF requires two arguments");
			return "date_diff('day',CAST(" + render(args[1].first, args[1].second, depth + 1) +
				   " AS DATE),CAST(" + render(args[0].first, args[0].second, depth + 1) +
				   " AS DATE))";
		}
		if (is(name, "CAST")) {
			for (size_t i = left + 1; i < right; ++i) {
				if (t[i].text == "(") {
					i = close[i];
					continue;
				}
				if (is(i, "AS") && i + 1 < right &&
					(is(i + 1, "SIGNED") || is(i + 1, "UNSIGNED"))) {
					if (i + 2 != right && !(i + 3 == right && is(i + 2, "INTEGER")))
						throw std::runtime_error("unsupported integer CAST target");
					// Bind the expression once, including aggregate/correlated values.
					// Explicit MySQL integer casts reinterpret the signed 64th bit.
					const bool signed_target = is(i + 1, "SIGNED");
					const std::string value = "__proxysql_integer";
					const std::string converted =
						signed_target ? "CASE WHEN " + value + " > 9223372036854775807 THEN " +
											value + " - 18446744073709551616 ELSE " + value + " END"
									  : "CASE WHEN " + value + " < 0 THEN " + value +
											" + 18446744073709551616 ELSE " + value + " END";
					return "list_transform([CAST(" + render(left + 1, i, depth + 1) +
						   " AS HUGEINT)], " + value + " -> CASE WHEN " + value +
						   " < -9223372036854775808 OR " + value +
						   " > 18446744073709551615 THEN error('MySQL integer CAST out of "
						   "supported range') ELSE CAST((" +
						   converted + ") AS " + (signed_target ? "BIGINT" : "UBIGINT") +
						   ") END)[1]";
				}
			}
		}
		return t[name].text + parenthesized(left, right, depth);
	}
	std::string order(size_t a, size_t b, unsigned depth) {
		std::string out;
		for (auto arg : split(a, b)) {
			if (!out.empty())
				out += ", ";
			if (arg.first == arg.second)
				throw std::runtime_error("empty ORDER BY expression");
			out += render(arg.first, arg.second, depth + 1);
			if (arg.second >= arg.first + 2 && is(arg.second - 2, "NULLS") &&
				(is(arg.second - 1, "FIRST") || is(arg.second - 1, "LAST")))
				continue;
			out += is(arg.second - 1, "DESC") ? " NULLS LAST" : " NULLS FIRST";
		}
		return out;
	}
	void validate_comparisons(size_t a, size_t b, unsigned depth) const {
		if (depth > 64)
			throw std::runtime_error("CASE nesting limit exceeded");
		// IS NOT DISTINCT FROM binds differently from MySQL's <=> in
		// comparison chains. Require explicit grouping instead of changing
		// a chain's meaning without a complete MySQL expression AST.
		unsigned comparisons = 0;
		bool null_safe = false;
		for (size_t i = a; i < b; ++i) {
			if (t[i].text == "(") {
				i = close[i];
				continue;
			}
			if (is(i, "CASE")) {
				size_t arm = i + 1, end = b;
				unsigned cases = 1;
				for (size_t j = i + 1; j < b; ++j) {
					if (t[j].text == "(") {
						j = close[j];
						continue;
					}
					if (is(j, "CASE"))
						++cases;
					else if (is(j, "END")) {
						if (--cases == 0) {
							validate_comparisons(arm, j, depth + 1);
							end = j;
							break;
						}
					} else if (cases == 1 && (is(j, "WHEN") || is(j, "THEN") || is(j, "ELSE"))) {
						validate_comparisons(arm, j, depth + 1);
						arm = j + 1;
					}
				}
				if (end == b)
					throw std::runtime_error("unterminated CASE expression");
				i = end;
				continue;
			}
			if (t[i].text == "," || t[i].text == "&&" || t[i].text == "||" || is(i, "AND") ||
				is(i, "OR") || is(i, "SELECT") || is(i, "FROM") || is(i, "WHERE") || is(i, "ON") ||
				is(i, "HAVING") || is(i, "WHEN") || is(i, "THEN") || is(i, "ELSE") || is(i, "AS") ||
				is(i, "ORDER") || is(i, "GROUP")) {
				comparisons = 0;
				null_safe = false;
				continue;
			}
			if ((t[i].kind == Kind::symbol &&
				 (t[i].text == "<=>" || t[i].text == "=" || t[i].text == "!=" ||
				  t[i].text == "<>" || t[i].text == "<" || t[i].text == ">" || t[i].text == "<=" ||
				  t[i].text == ">=")) ||
				is(i, "IS") || is(i, "LIKE") || is(i, "IN") || is(i, "BETWEEN")) {
				++comparisons;
				null_safe = null_safe || t[i].text == "<=>";
				if (null_safe && comparisons > 1)
					throw std::runtime_error(
						"comparison chains containing <=> require parentheses");
			}
		}
	}

  public:
	explicit Renderer(const std::vector<Token> &tokens) : t(tokens), close(t.size(), t.size()) {
		std::vector<size_t> stack;
		for (size_t i = 0; i < t.size(); ++i) {
			if (t[i].text == "(" && t[i].kind == Kind::symbol) {
				stack.push_back(i);
				if (stack.size() > 64)
					throw std::runtime_error("query nesting limit exceeded");
			} else if (t[i].text == ")" && t[i].kind == Kind::symbol) {
				if (stack.empty())
					throw std::runtime_error("unmatched closing parenthesis");
				close[stack.back()] = i;
				stack.pop_back();
			}
		}
		if (!stack.empty())
			throw std::runtime_error("unclosed parenthesis");
	}
	std::string render(size_t a, size_t b, unsigned depth = 0) {
		if (depth > 128)
			throw std::runtime_error("query nesting limit exceeded");
		validate_comparisons(a, b, 0);
		std::string out;
		for (size_t i = a; i < b; ++i) {
			if (is(i, "LIKE")) {
				const size_t pattern = i + 1;
				if (pattern >= b)
					throw std::runtime_error("LIKE requires a pattern");
				size_t end = pattern + 1;
				if (t[pattern].text == "(")
					end = close[pattern] + 1;
				else if (t[pattern].kind == Kind::word && pattern + 1 < b &&
						 t[pattern + 1].text == "(")
					end = close[pattern + 1] + 1;
				else
					while (end + 1 < b && t[end].text == ".")
						end += 2;
				add(out, "LIKE " + render(pattern, end, depth + 1));
				if (!is(end, "ESCAPE"))
					out += " ESCAPE '\\'";
				i = end - 1;
				continue;
			}
			if (is(i, "GROUP_CONCAT") || is(i, "SQL_CALC_FOUND_ROWS") || is(i, "STRAIGHT_JOIN") ||
				is(i, "COLLATE") || (is(i, "FOR") && (is(i + 1, "UPDATE") || is(i + 1, "SHARE"))) ||
				(is(i, "LOCK") && is(i + 1, "IN")) ||
				(is(i, "INTO") && (is(i + 1, "OUTFILE") || is(i + 1, "DUMPFILE"))))
				throw std::runtime_error("unsupported MySQL SELECT feature: " + t[i].text);
			if (is(i, "ORDER") && i + 1 < b && is(i + 1, "BY")) {
				size_t end = i + 2;
				for (; end < b; ++end) {
					if (t[end].text == "(") {
						end = close[end];
						continue;
					}
					if (is(end, "LIMIT") || is(end, "OFFSET") || is(end, "FETCH") ||
						is(end, "UNION") || is(end, "EXCEPT") || is(end, "INTERSECT") ||
						is(end, "ROWS") || is(end, "RANGE") || is(end, "GROUPS"))
						break;
				}
				add(out, "ORDER BY " + order(i + 2, end, depth + 1));
				i = end - 1;
				continue;
			}
			if (is(i, "LIMIT") && i + 3 < b && t[i + 2].text == ",") {
				auto integer = [&](size_t k) {
					return t[k].kind == Kind::number && !t[k].text.empty() &&
						   t[k].text.find_first_not_of("0123456789") == std::string::npos;
				};
				if (!integer(i + 1) || !integer(i + 3))
					throw std::runtime_error("LIMIT requires integer literals");
				add(out, "LIMIT " + t[i + 3].text + " OFFSET " + t[i + 1].text);
				i += 3;
				continue;
			}
			if (t[i].kind == Kind::word && i + 1 < b && t[i + 1].text == "(") {
				const size_t right = close[i + 1];
				add(out, function(i, i + 1, right, depth + 1));
				i = right;
				continue;
			}
			if (t[i].kind == Kind::symbol && t[i].text == "(") {
				add(out, parenthesized(i, b, depth));
				i = close[i];
				continue;
			}
			if (t[i].kind == Kind::symbol && t[i].text == "<=>")
				add(out, "IS NOT DISTINCT FROM");
			else if (t[i].kind == Kind::symbol && t[i].text == "&&")
				add(out, "AND");
			else if (t[i].kind == Kind::symbol && t[i].text == "||")
				add(out, "OR");
			else
				add(out, t[i].text);
		}
		return out;
	}
};
} // namespace

bool duckdb_translate_mysql_select(const std::string &sql, std::string &translated,
								   std::string &error) {
	translated.clear();
	error.clear();
	try {
		const auto first = lex(sql, true);
		if (first.empty() || first[0].kind != Kind::word ||
			(upper(first[0].text) != "SELECT" && upper(first[0].text) != "WITH")) {
			translated = sql;
			return true;
		}
		auto tokens = lex(sql);
		if (!tokens.empty() && tokens.back().text == ";" && tokens.back().kind == Kind::symbol)
			tokens.pop_back();
		for (const auto &token : tokens)
			if (token.kind == Kind::symbol && token.text == ";")
				throw std::runtime_error("multiple statements are unsupported");
		Renderer renderer(tokens);
		translated = renderer.render(0, tokens.size());
		return true;
	} catch (const std::exception &ex) {
		error = std::string("MySQL compatibility: ") + ex.what();
		return false;
	}
}
