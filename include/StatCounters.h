#ifndef __CLASS_STAT_COUNTERS_H
#define __CLASS_STAT_COUNTERS_H
#include "proxysql_atomic.h"

class StatCounters {
	private:
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
	StatCounters(int _l, int _k) {
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
		if ( _i > last ) {
			last=_i; cleanup();
		}
		val[_i%len]=_v;
	}
	void incr(int _i) {
		if ( _i > last ) {
			if ( _i > last + keep ) val[_i%len]=0;
			last=_i; cleanup();
		}
		val[_i%len]++;
	}
	void decr(int _i) {
		if ( _i > last ) {
			if ( _i > last + keep ) val[_i%len]=0;
			last=_i; cleanup();
		}
		val[_i%len]--;
	}
	int sum(int _i, int _k) {
		if ( _i > last ) {
			if ( _i > last + keep ) val[_i%len]=0;
			last=_i; cleanup();
		}
		int i;
		int ret=0;
		for (i=0; i<_k; i++) {
			ret+=val[(_i-i)%len];
		}
		return ret;
	}
};
#endif /* __CLASS_STAT_COUNTERS_H */

