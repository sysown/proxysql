#include "re2/re2.h"
#include "re2/regexp.h"
#include "proxysql.h"
#include "cpp.h"

#include <ctime>
#include <thread>

struct __RE2_objects_t {
	re2::RE2::Options *opt;
	RE2 *re;
};

typedef struct __RE2_objects_t re2_t;

int main() {
	re2_t *r=(re2_t *)malloc(sizeof(re2_t));
	r->opt=new re2::RE2::Options(RE2::Quiet);
	r->opt->set_case_sensitive(false);
	//char *myq=(char *)" sEt   NAmEs    'utf8' ";
	char *myq=(char *)"sEt   NAmEs    'utf8' ";
	r->re=new RE2(" *SET  *NAMES *.* *", *r->opt);
	bool rc;
	for (int i=0;i<1000000;i++) {
		rc=RE2::PartialMatch(myq,*r->re);
	}
	printf("%d\n",rc);
	return 0;
}
