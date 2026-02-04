#include "Base_Session_Utils.h"

#include "re2/re2.h"

#include <stdlib.h>
#include <string.h>

Session_Regex::Session_Regex(const char* p) {
	s = strdup(p);
	re2::RE2::Options* opt2 = new re2::RE2::Options(RE2::Quiet);
	opt2->set_case_sensitive(false);
	opt = (void*)opt2;
	re = (RE2*)new RE2(s, *opt2);
}

Session_Regex::~Session_Regex() {
	free(s);
	delete (RE2*)re;
	delete (re2::RE2::Options*)opt;
}

bool Session_Regex::match(const char* m) {
	bool rc = false;
	rc = RE2::PartialMatch(m, *(RE2*)re);
	return rc;
}
