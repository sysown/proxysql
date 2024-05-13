#include "MySQL_HostGroups_Manager.h"

class MySrvConnList;
class MySrvC;
class MySrvList;
class MyHGC;

MySrvList::MySrvList(MyHGC *_myhgc) {
	myhgc=_myhgc;
	servers=new PtrArray();
}

void MySrvList::add(MySrvC *s) {
	if (s->myhgc==NULL) {
		s->myhgc=myhgc;
	}
	servers->add(s);
}


int MySrvList::find_idx(MySrvC *s) {
  for (unsigned int i=0; i<servers->len; i++) {
    MySrvC *mysrv=(MySrvC *)servers->index(i);
    if (mysrv==s) {
      return (unsigned int)i;
    }
  }
  return -1;
}

void MySrvList::remove(MySrvC *s) {
	int i=find_idx(s);
	assert(i>=0);
	servers->remove_index_fast((unsigned int)i);
}

MySrvList::~MySrvList() {
	myhgc=NULL;
	while (servers->len) {
		MySrvC *mysrvc=(MySrvC *)servers->remove_index_fast(0);
		delete mysrvc;
	}
	delete servers;
}
