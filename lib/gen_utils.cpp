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
