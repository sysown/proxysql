
__thread bool mysql_thread___query_digests_lowercase = false;
__thread bool mysql_thread___query_digests_replace_null = false;
__thread bool mysql_thread___query_digests_no_digits = false;
__thread int mysql_thread___query_digests_max_query_length = 2048;
__thread int mysql_thread___query_digests_grouping_limit = 3;
__thread unsigned long long cnt = 0;
#include "c_tokenizer.h"
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <string>
#include <iostream>
#include <vector>

#define MUQ 100000 // we need a lot of queries to not fit in CPU cache
#define NQ 2000000

#define QUERY_DIGEST_BUF 1024

inline unsigned long long monotonic_time() {
  struct timespec ts;
  clock_gettime(CLOCK_MONOTONIC, &ts);
  return (((unsigned long long) ts.tv_sec) * 1000000) + (ts.tv_nsec / 1000);
}


struct cpu_timer
{
    cpu_timer() {
        begin = monotonic_time();
    }
    ~cpu_timer()
    {   
        unsigned long long end = monotonic_time();
        std::cerr << double( end - begin ) / 1000000 << " secs.\n" ;
        begin=end-begin; // here only to make compiler happy
    };
    unsigned long long begin;
};


int main(int argc, char **argv) {
	if (argc < 2) {
		exit(EXIT_FAILURE);
	}
	{ // this code is to avoid some code optimization
	mysql_thread___query_digests_max_query_length = atoi(argv[1]);
	if (mysql_thread___query_digests_max_query_length < 10) {
		mysql_thread___query_digests_grouping_limit = mysql_thread___query_digests_max_query_length;
	}
	if (mysql_thread___query_digests_grouping_limit > 8) {
		mysql_thread___query_digests_lowercase = true;
		mysql_thread___query_digests_replace_null = true;
		mysql_thread___query_digests_no_digits = true;
	}
	}

	std::vector<std::string> queries;
	std::string line;
	while (std::getline(std::cin, line))
	{
		queries.push_back(line);
	}

	// here we multiplies the queries
	while(queries.size() < MUQ) {
		unsigned int cqs = queries.size();
		for (int i = 0; i<cqs; i++) {
			queries.push_back(queries[i]);
		}
	}
	unsigned int long long qlt1 = 0;
	unsigned int long long qlt2 = 0;
	for (std::vector<std::string>::iterator it = queries.begin() ; it != queries.end(); it++) {
		std::string s = *it;
    	qlt1 += s.length();
	}

	int qids[NQ];
	srand(queries.size());
	for (int i = 0; i<NQ; i++) {
		qids[i] = rand()%queries.size();
	}

	{
		cpu_timer t;
		char localbuf[QUERY_DIGEST_BUF];
		for (unsigned int i=0 ; i<NQ; i++) {
		//for (unsigned int i=0 ; i<1; i++) {
			const char *query = queries[qids[i]].c_str();
			int query_length = queries[qids[i]].length();
			qlt2 += query_length;
			char *first_comment = NULL;
			char *digest_text = mysql_query_digest_and_first_comment((char *)query, query_length, &first_comment,  (query_length < QUERY_DIGEST_BUF ? localbuf : NULL));
			if (digest_text) {
				if (digest_text != localbuf) {
					free(digest_text);
				}
			}
		}
		std::cout << "Queries table size is " << qlt1 << " bytes. Make sure it is larger than CPU cache." << std::endl;
		std::cout << "Processed " << qlt2 << " bytes in " << NQ << " queries." << std::endl;
		std::cout << "isspace called " << cnt << " times." << std::endl;
	}
	return 0;
}
