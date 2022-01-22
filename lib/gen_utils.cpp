#include "gen_utils.h"
#include "proxysql_utils.h"
#include <sstream>

using std::vector;
using std::string;

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

std::vector<std::string> str_split(const std::string& s, char delimiter) {
	std::vector<std::string> tokens {};
	std::string token {};
	std::istringstream tokenStream(s);

	while (std::getline(tokenStream, token, delimiter)) {
		tokens.push_back(token);
	}

	return tokens;
}

int string_to_tls_version(const std::string& tls_version) {
	if (!strcasecmp(tls_version.c_str(), "TLSv1")) {
		return TLS1_VERSION;
	} else if (!strcasecmp(tls_version.c_str(), "TLSv1.1")) {
		return TLS1_1_VERSION;
	} else if (!strcasecmp(tls_version.c_str(), "TLSv1.2")) {
		return TLS1_2_VERSION;
	} else if (!strcasecmp(tls_version.c_str(), "TLSv1.3")) {
		return TLS1_3_VERSION;
	} else {
		proxy_error(
			"Invalid 'TLS' version: '%s' present in 'mysql-tls_version'. Please report a bug.\n",
			tls_version.c_str()
		);
		return -1;
	}
}

vector<string> sort_tls_versions(const string& tls_versions) {
	// sort the supported 'tls_versions' allowed
	vector<string> v_tls_versions { str_split(tls_versions, ',') };

	// perform a case insensitive sorting of the allowed versions
	std::sort(
		v_tls_versions.begin(), v_tls_versions.end(),
		[](const string& v1, const string& v2) {
			const auto result =
				mismatch_(
					v1.cbegin(), v1.cend(), v2.cbegin(), v2.cend(),
					[](const unsigned char lhs, const unsigned char rhs) {
						return tolower(lhs) == tolower(rhs);
					}
				);

			const bool not_equal = result.second != v2.cend();
			const bool fst_shorter = result.first == v1.cend();
			const bool fst_lesser = std::tolower(*result.first) < std::tolower(*result.second);

			return not_equal && (fst_shorter || fst_lesser);
		}
	);

	return v_tls_versions;
}
