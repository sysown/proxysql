#include <vector>
#include <memory>
#include <sstream>
#include "gen_utils.h"


using std::vector;
using std::unique_ptr;

char *escape_string_single_quotes(char *input, bool free_it) {
	int i,j,l;
	char *o=NULL;	// output string, if any
	l=strlen(input);
	j=0;
	for (i=0;i<l;i++) {
		if (input[i]=='\'') {
			j++;
		}
	}
	if (j==0) {	// no double quotes found, exit now
		return input;
	}
	// double quotes found
	o=(char *)malloc(l+j+1);
	o[l+j]='\0';
	j=0;
	for (i=0;i<l;i++) {
		if (input[i]=='\'') {
			o[j]='\'';
			j++;
		}
		o[j]=input[i];
		j++;
	}
	if (free_it) {
		free(input);
	}
	return o;
}

int remove_spaces(const char *s) {
	char *inp = (char *)s, *outp = (char *)s;
	bool prev_space = false;
	bool fns = false;
	while (*inp) {
		if (isspace(*inp)) {
			if (fns) {
				if (!prev_space) {
					*outp++ = ' ';
					prev_space = true;
				}
			}
		} else {
			*outp++ = *inp;
			prev_space = false;
			if (!fns) fns=true;
		}
		++inp;
	}
	if (outp>s) {
		if (prev_space) {
			outp--;
		}
	}
	*outp = '\0';
	return strlen(s);
}

// This function returns a pointer to a substring of the original string. It also
// modifies the original string by setting a null terminator to mark the end
// of the substring.
//
// If the given string was allocated dynamically, the caller must not overwrite
// that pointer with the returned value, since the original pointer must be
// deallocated using the same allocator with which it was allocated.  The return
// value must NOT be deallocated using free() etc.
//
// Source: http://stackoverflow.com/a/122721
char *trim_spaces_in_place(char *str)
{
	char *end;

	// Trim leading space
	while(isspace(*str)) str++;

	if(*str == 0)  // All spaces?
		return str;

	// Trim trailing space
	end = str + strlen(str) - 1;
	while(end > str && isspace(*end)) end--;

	// Write new null terminator
	*(end+1) = 0;

	return str;
}


char *trim_spaces_and_quotes_in_place(char *str) {
	char *end;
	// Trim leading space
	while(isspace(*str) || *str=='\"' || *str=='\'')
		str++;
	if(*str == 0)  // All spaces?
		return str;
	// Trim trailing space
	end = str + strlen(str) - 1;
	while(end > str && (isspace(*end) || *end=='\"' || *end=='\'' || *end==';')) end--;
	// Write new null terminator
	*(end+1) = 0;
	return str;
}

bool mywildcmp(const char *p, const char *str) {
	if (*p == '\0') {
		if (*str == '\0') {
			return true;
		} else {
			return false;
		}
	}

	if (*p == '_' || *p == *str) {
		if (*str == '\0') {
			return false;
		} else {
			return mywildcmp(p + 1, str + 1);
		}
	}

	if (*p == '%') {
		if (mywildcmp(p + 1, str)) {
			return true;
		} else {
			if (*str == '\0') {
				return false;
			} else {
				return mywildcmp(p, str + 1);
			}
		}
	}
	return false;
}

std::string trim(const std::string& s)
{
	if (s.length() == 0)
		return s;

	std::string::size_type b = s.find_first_not_of(" \t\n");
	std::string::size_type e = s.find_last_not_of(" \t\n");
	if (b == std::string::npos)
		return "";

	return std::string(s, b, e - b + 1);
}

void * PtrSizeArray::operator new(size_t size) {
	return l_alloc(size);
}

void PtrSizeArray::operator delete(void *ptr) {
	l_free(sizeof(PtrSizeArray), ptr);
}

PtrSizeArray::PtrSizeArray(unsigned int __size) {
	len=0;
	pdata=NULL;
	size=0;
	if (__size) {
		expand(__size);
	}
	size=__size;
}

PtrSizeArray::~PtrSizeArray() {
	//if (pdata) free(pdata);
	if (pdata) l_free(size*sizeof(PtrSize_t),pdata);
	pdata=NULL;
}

void PtrSizeArray::shrink() {
	unsigned int new_size=l_near_pow_2(len+1);
	//pdata=(PtrSize_t *)realloc(pdata,new_size*sizeof(PtrSize_t));
	pdata=(PtrSize_t *)realloc(pdata,new_size*sizeof(PtrSize_t));
	size=new_size;
}

void PtrSizeArray::expand(unsigned int more) {
    if ( (len+more) > size ) {
        unsigned int new_size=l_near_pow_2(len+more);
        //void *new_pdata=malloc(new_size*sizeof(PtrSize_t));
        void *new_pdata=l_alloc(new_size*sizeof(PtrSize_t));
        if (pdata) {
            memcpy(new_pdata,pdata,size*sizeof(PtrSize_t));
            //free(pdata);
            l_free(size*sizeof(PtrSize_t),pdata);
        }
        size=new_size;
        pdata=(PtrSize_t *)new_pdata;
    }
}

void PtrSizeArray::remove_index_fast(unsigned int i, PtrSize_t *ps) {
	if (ps) {
		ps->ptr=pdata[i].ptr;
	    ps->size=pdata[i].size;
	}
    if (i != (len-1)) {
    	pdata[i].ptr=pdata[len-1].ptr;
    	pdata[i].size=pdata[len-1].size;
	}
    len--;
}

void PtrSizeArray::copy_add(PtrSizeArray *psa, unsigned int from, unsigned int cnt) {
	unsigned int i;
	PtrSize_t *psp;
	for (i=from;i<from+cnt;i++) {
		psp=psa->index(i);
		add(psp->ptr,psp->size);
	}
}

bool Proxy_file_exists(const char *path) {
	struct stat sb;
	int rc=stat(path, &sb);
	if (rc==0) return true;
	return false;
}

bool Proxy_file_regular(const char *path) {
	struct stat sb;
	int rc=stat(path, &sb);
	if (rc==0)
		if (sb.st_mode & S_IFREG) return true;
	return false;
}

std::unique_ptr<SQLite3_result> get_SQLite3_resulset(MYSQL_RES* resultset) {
	if (resultset == nullptr) {
		return std::unique_ptr<SQLite3_result>(nullptr);
	}

	uint32_t num_fields = mysql_num_fields(resultset);
	MYSQL_FIELD* fields = mysql_fetch_fields(resultset);

	std::unique_ptr<SQLite3_result> sqlite_result { new SQLite3_result(num_fields) };

	for (uint32_t i = 0; i < num_fields; i++) {
		sqlite_result->add_column_definition(SQLITE_TEXT, fields[i].name);
	}

	vector<char*> pta(static_cast<size_t>(num_fields));
	while (MYSQL_ROW row = mysql_fetch_row(resultset)) {
		for (uint32_t i = 0; i < num_fields; i++) {
			pta[i] = row[i];
		}
		sqlite_result->add_row(&pta[0]);
	}

	// restore the initial resulset index
	mysql_data_seek(resultset, 0);

	return sqlite_result;
} 

std::vector<std::string> split_string(const std::string& str, char delimiter) {
	std::vector<std::string> tokens {};
	std::string token {};
	std::istringstream tokenStream(str);

	while (std::getline(tokenStream, token, delimiter)) {
		tokens.push_back(token);
	}

	return tokens;
}

char* escape_string_single_quotes_and_backslashes(char* input, bool free_it) {
	const char* c;
	int input_len = 0;
	int escape_count = 0;

	for (c = input; *c != '\0'; c++) {
		if ((*c == '\'') || (*c == '\\')) {
			escape_count += 2;
		}
		input_len++;
	}

	if (escape_count == 0)
		return input;

	char* output = (char*)malloc(input_len + escape_count + 1);
	char* p = output;

	for (c = input; *c != '\0'; c++) {
		if ((*c == '\'') || (*c == '\\')) {
			*(p++) = '\\';
		}
		*(p++) = *c;
	}
	*(p++) = '\0';
	if (free_it) {
		free(input);
	}
	return output;
}

/**
 * Escapes spaces in the input string by prepending "\\".
 * If no spaces are present, the original input is returned.
 * If spaces are escaped, a new string is returned, and the caller
 * is responsible for freeing it.
 *
 * @param input The input string to process.
 * @return A new string with spaces escaped, or the original input string if no escaping is needed.
 */
const char* escape_string_backslash_spaces(const char* input) {
	const char* c;
	int input_len = 0;
	int escape_count = 0;

	for (c = input; *c != '\0'; c++) {
		if ((*c == ' ')) {
			escape_count += 3;
		} else if ((*c == '\\')) {
			escape_count += 2;
		}
		input_len++;
	}

	if (escape_count == 0)
		return input;

	char* output = (char*)malloc(input_len + escape_count + 1);
	char* p = output;

	for (c = input; *c != '\0'; c++) {
		if ((*c == ' ')) {
			memcpy(p, "\\\\", 2);
			p += 2;
		} else if (*c == '\\') {
			*(p++) = '\\';
		}
		*(p++) = *c;
	}
	*(p++) = '\0';
	return output;
}

/**
 * Strip schema prefix from the query
 *
 * @param query The input query
 * @param schema The schema name to strip (e.g., "stats")
 * @param tables List of table names to process (empty = process all tables)
 * @param ansi_quotes If true, double quotes are identifiers (ANSI SQL mode)
 *						   If false, double quotes are string literals (default MySQL mode)
 * @return Result string with prefix stripped
 */
std::string strip_schema_from_query(const char* query, const char* schema,
                                    const std::vector<std::string>& tables, bool ansi_quotes) {
	if (!query || strlen(query) == 0) {
		return "";
	}

	int query_len = strlen(query);

	int schema_len = strlen(schema);
	if (schema_len == 0) {
		return std::string(query, query_len);
	}

	if (!strcasestr(query, schema)) {
		return std::string(query, query_len);
	}

	// find string literal positions

	std::vector<bool> is_string_char(query_len, false);
	bool in_string = false;
	char string_delimiter = '\0';

	for (int i = 0; i < query_len; i++) {
		if (!in_string) {
			if (query[i] == '\'' || (!ansi_quotes && query[i] == '"')) {
				in_string = true;
				string_delimiter = query[i];
				is_string_char[i] = true;
			}
		} else {
			is_string_char[i] = true;
			if (query[i] == string_delimiter) {
				if (i + 1 < query_len && query[i + 1] == string_delimiter) {
					i++; // Skip escaped quote
					is_string_char[i] = true;
				} else {
					in_string = false;
				}
			}
		}
	}

	// scan query string and look for the pattern <schema>.<table>

	struct SchemaTablePos {
		int schema_start;
		int schema_end;
		int table_start;
		int table_end;
	};
	std::vector<SchemaTablePos> matches;

	const char* search = query;
	const char* found = nullptr;

	while ((found = strcasestr(search, schema)) != nullptr) {
		int schema_pos = found - query;

		if (is_string_char[schema_pos]) {
			// schema name is part of string literal; skip this match
			search = found + schema_len;
			continue;
		}

		if (schema_pos > 0) {
			char prev = query[schema_pos - 1];
			if (std::isalnum(prev) || prev == '_') {
				// schema name is a substring; skip this match
				search = found + schema_len;
				continue;
			}
		}

		int start = schema_pos;
		int pos = schema_pos + schema_len;
		char schema_quote = '\0';

		// check if schema is quoted
		if (schema_pos > 0 && (query[schema_pos - 1] == '`' ||
								(ansi_quotes && query[schema_pos - 1] == '"'))) {
			schema_quote = query[schema_pos - 1];
			start--;

			// check for closing quote
			if (pos < query_len && query[pos] == schema_quote) {
				pos++;
			} else {
				// no closing quote; skip this match
				search = query + pos;
				continue;
			}
		}

		// match dot character

		// skip the whitespaces before dot character
		while (pos < query_len && std::isspace(query[pos])) {
			pos++;
		}
		if (pos >= query_len || query[pos] != '.') {
			// dot character not found followed by schema name; skip this match
			search = query + pos;
			continue;
		}

		pos++;

		// skip the whitespaces after dot character
		while (pos < query_len && std::isspace(query[pos])) {
			pos++;
		}
		if (pos >= query_len) {
			// table name not found followed by dot character; skip this match
			search = query + pos;
			continue;
		}

		// extract table name

		int table_start = pos;
		char table_quote = '\0';
		bool table_quoted = false;

		if (query[pos] == '`' || (ansi_quotes && query[pos] == '"')) {
			table_quoted = true;
			table_quote = query[pos];
			pos++;
			table_start = pos;
		}

		int table_end = pos;
		if (table_quoted) {
			while (table_end < query_len && query[table_end] != table_quote) {
				table_end++;
			}
			if (table_end >= query_len) {
				// no closing quote for table name; skip this match
				search = query + pos;
				continue;
			}
			pos = table_end + 1;
		} else {
			while (table_end < query_len &&
					(std::isalnum(query[table_end]) || query[table_end] == '_')) {
				table_end++;
			}
			pos = table_end;
		}

		// try matching table name if table_list not empty
		if (!tables.empty()) {
			int table_name_len = table_end - table_start;
			bool table_found = false;
			for (auto& target_table : tables) {
				if (target_table.length() == (size_t) table_name_len &&
					strncasecmp(query + table_start, target_table.c_str(), table_name_len) == 0) {
					table_found = true;
					break;
				}
			}

			if (!table_found) {
				search = query + pos;
				continue;
			}
		}

		// add start/end pos to match set
		table_start = table_quoted ? table_start - 1 : table_start;
		table_end = table_quoted ? table_end + 1 : table_end;
		matches.push_back({start, pos, table_start, table_end});

		search = query + table_end;
	}

	if (matches.empty()) {
		return std::string(query, query_len);
	}

	// strip matched schema name and build final result

	std::string result;
	result.reserve(query_len);
	int last_pos = 0;

	for (const auto& m : matches) {
		// append text before this match
		result.append(query + last_pos, m.schema_start - last_pos);
		// append just the table name, skip schema name and dot character
		result.append(query + m.table_start, m.table_end - m.table_start);
		last_pos = m.schema_end;
	}
	// append remaining query
	if (last_pos < query_len) {
		result.append(query + last_pos, query_len - last_pos);
	}

	return result;
}
