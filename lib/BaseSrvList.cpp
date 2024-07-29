#include "Base_HostGroups_Manager.h"

template<typename HGC>
using TypeSrvC = typename std::conditional<
	std::is_same_v<HGC, MyHGC>, MySrvC, PgSQL_SrvC
>::type;

template BaseSrvList<MyHGC>::BaseSrvList(MyHGC*);
template BaseSrvList<MyHGC>::~BaseSrvList();
template void BaseSrvList<MyHGC>::add(MySrvC*);

template BaseSrvList<PgSQL_HGC>::BaseSrvList(PgSQL_HGC*);
template BaseSrvList<PgSQL_HGC>::~BaseSrvList();
template void BaseSrvList<PgSQL_HGC>::add(PgSQL_SrvC*);


template<typename HGC>
BaseSrvList<HGC>::BaseSrvList(HGC *_myhgc) {
	myhgc=_myhgc;
	servers=new PtrArray();
}

template<typename HGC>
void BaseSrvList<HGC>::add(TypeSrvC *s) {
	if (s->myhgc==NULL) {
		s->myhgc=myhgc;
	}
	servers->add(s);
	if constexpr (std::is_same_v<HGC, MyHGC>) {
		myhgc->refresh_online_server_count();
	} else if constexpr (std::is_same_v<HGC, PgSQL_HGC>) {
		//myhgc->refresh_online_server_count(); FIXME: not implemented
	} else {
		assert(0);
	}
}


template<typename HGC>
int BaseSrvList<HGC>::find_idx(TypeSrvC *s) {
  for (unsigned int i=0; i<servers->len; i++) {
    TypeSrvC *mysrv=(TypeSrvC *)servers->index(i);
    if (mysrv==s) {
      return (unsigned int)i;
    }
  }
  return -1;
}

template<typename HGC>
void BaseSrvList<HGC>::remove(TypeSrvC *s) {
	int i=find_idx(s);
	assert(i>=0);
	servers->remove_index_fast((unsigned int)i);
	if constexpr (std::is_same_v<HGC, MyHGC>) {
		myhgc->refresh_online_server_count();
	} else if constexpr (std::is_same_v<HGC, PgSQL_HGC>) {
		//myhgc->refresh_online_server_count(); FIXME: not implemented
	} else {
		assert(0);
	}
}

template<typename HGC>
BaseSrvList<HGC>::~BaseSrvList() {
	myhgc=NULL;
	while (servers->len) {
		TypeSrvC *mysrvc=(TypeSrvC *)servers->remove_index_fast(0);
		delete mysrvc;
	}
	delete servers;
}
