#ifndef __CLASS_STAT_COUNTERS_H
#define __CLASS_STAT_COUNTERS_H

#include "proxysql_atomic.h"

class StatCounters {
	private:
	bool with_lock;
	rwlock_t _lock;
	int last;
	int keep;
	void cleanup() {
		int i;
		int l=last%len;
		if (l<keep) {
			for (i=l+1; i <= len+l-keep; i++) {
				val[i]=0;
			}
		} else {
			for (i=l+1 ; i<len; i++) {
				val[i]=0;
			}
			for (i=0; i <= l-keep ; i++) {
				val[i]=0;
			}
		}
	}
	public:
	int len;
	int *val;
	StatCounters(int _l, int _k, bool _wl=false) {
		with_lock=_wl;
		if (with_lock)
			spinlock_rwlock_init(&_lock);
		last=0;
		keep=_k;
		len=_l;
		val=(int *)malloc(sizeof(int)*len);
		int i;
		for (i=0;i<len;i++) {
			val[i]=0;
		}
	}
	~StatCounters() {
		free(val);
	}
	void set(int _i, int _v) {
		if (with_lock)
			spin_wrlock(&_lock);
		if ( _i > last ) {
			last=_i; cleanup();
		}
		val[_i%len]=_v;
		if (with_lock)
			spin_wrunlock(&_lock);
	}
	void incr(int _i) {
		if (with_lock)
			spin_wrlock(&_lock);
		if ( _i > last ) {
			if ( _i > last + keep ) val[_i%len]=0;
			last=_i; cleanup();
		}
		val[_i%len]++;
		if (with_lock)
			spin_wrunlock(&_lock);
	}
	void decr(int _i) {
		if (with_lock)
			spin_wrlock(&_lock);
		if ( _i > last ) {
			if ( _i > last + keep ) val[_i%len]=0;
			last=_i; cleanup();
		}
		val[_i%len]--;
		if (with_lock)
			spin_wrunlock(&_lock);
	}
	int sum(int _i, int _k) {
		if (with_lock)
			spin_wrlock(&_lock);
		if ( _i > last ) {
			if ( _i > last + keep ) val[_i%len]=0;
			last=_i; cleanup();
		}
		int i;
		int ret=0;
		for (i=0; i<_k; i++) {
			ret+=val[(_i-i)%len];
		}
		if (with_lock)
			spin_wrunlock(&_lock);	
		return ret;
	}
};
#endif /* __CLASS_STAT_COUNTERS_H */

