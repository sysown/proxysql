#ifndef __CLASS_PTR_ARRAY_H
#define __CLASS_PTR_ARRAY_H

#include <memory>

#include "proxysql.h"
#include "sqlite3db.h"

#define MIN_ARRAY_LEN 8
#define MIN_ARRAY_DELETE_RATIO  8

static unsigned int l_near_pow_2 (unsigned int n) {
	unsigned int i = 1;
	while (i < n) i <<= 1;
	return i ? i : n;
}


#ifndef def_fastrand
inline int fastrand() {
	g_seed = (214013*g_seed+2531011);
	return (g_seed>>16)&0x7FFF;
}
#define def_fastrand
#endif

class PtrArray {
	private:
	void expand(unsigned int more) {
		if ( (len+more) > size ) {
			unsigned int new_size=l_near_pow_2(len+more);
			void *new_pdata=malloc(new_size*sizeof(void *));
			memset(new_pdata,0,new_size*sizeof(void *));
			if (pdata) {
				memcpy(new_pdata,pdata,size*sizeof(void *));
				free(pdata);
			}
			size=new_size;
			pdata=(void **)new_pdata;
		}
	}
	void shrink() {
		unsigned int new_size=l_near_pow_2(len+1);
		pdata=(void **)realloc(pdata,new_size*sizeof(void *));
		size=new_size;
	}
	public:
	unsigned int len;
	unsigned int size;
	void **pdata;
	PtrArray(unsigned int __size=0) {
		len=0;
		pdata=NULL;
		size=0;
		if (__size) {
			expand(__size);
		}
		size=__size;
	}
	~PtrArray() {
		if (pdata) ( free(pdata) );
		pdata=NULL;
	}

	void reset() {
		len=0;
		if (pdata) ( free(pdata) );
		pdata=NULL;
		size=0;
	}

	void *index(unsigned int i) { return pdata[i];}

	void add(void *p) {
		if (len==size) {
			expand(1);
		}
		pdata[len++]=p;
	}

	bool remove(void *p) {
		unsigned int i;
		for (i=0; i<len; i++) {
			if (pdata[i]==p) {
				remove_index(i);
				return true;
			}
		}
		return false;
	}

	void * remove_index(unsigned int i) {
		void *r=pdata[i];
		if (i != (len-1)) {
			memmove((void **)pdata+i,(void **)pdata+i+1,(len-i-1)*sizeof(void *));
		}
		len--;
		if ( ( len>MIN_ARRAY_LEN ) && ( size > len*MIN_ARRAY_DELETE_RATIO ) ) {
			shrink();
		}
		return r;
	}

	bool remove_fast(void *p) {
		unsigned int i;
		for (i=0; i<len; i++) {
			if (pdata[i]==p) {
				remove_index_fast(i);
				return true;
			}
		}
		return false;
	}

	void * remove_index_fast(unsigned int i) {
		void *r=pdata[i];
		if (i != (len-1))
			pdata[i]=pdata[len-1];
		len--;
		if ( ( len>MIN_ARRAY_LEN ) && ( size > len*MIN_ARRAY_DELETE_RATIO ) ) {
			//shrink(); // FIXME: when shrink is called, is r invalid ??
		}
		return r;
	}
};


class PtrSizeArray {
	private:
	void expand(unsigned int);
	void shrink();
	public:
	void * operator new(size_t);
	void operator delete(void *);
	unsigned int len;
	unsigned int size;
	PtrSize_t *pdata;
	PtrSizeArray(unsigned int __size=0);
	~PtrSizeArray();

	void add(void *p, unsigned int s) {
		if (len==size) {
			expand(1);
		}
		pdata[len].ptr=p;
		pdata[len].size=s;
		len++;
//#ifdef DEBUG
//		mysql_hdr *m=(mysql_hdr *)p;
//		fprintf(stderr,"%u %u\n", m->pkt_id, m->pkt_length);
//#endif /* DEBUG */
	};

	void remove_index(unsigned int i, PtrSize_t *ps) {
		if (ps) {
			ps->ptr=pdata[i].ptr;
			ps->size=pdata[i].size;
		}
		if (i != (len-1)) {
			memmove(pdata+i,pdata+i+1,(len-i-1)*sizeof(PtrSize_t));
		}
		len--;
	};

	void remove_index_range(unsigned int i, unsigned int s) {
		if (i != (len-s)) {
			memmove(pdata+i,pdata+i+s,(len-i-s)*sizeof(PtrSize_t));	
		}
		len-=s;
	};

	void remove_index_fast(unsigned int, PtrSize_t *);
	void copy_add(PtrSizeArray *, unsigned int, unsigned int);

	PtrSize_t * index(unsigned int i) {
		return &pdata[i];
	}
	unsigned int total_size(unsigned int _min_size=0) {
		unsigned int intsize=0;
		unsigned int i=0;
		for (i = 0 ; i < len ; i++) {
			PtrSize_t *pts = index(i);
			if (pts->size > _min_size) {
				intsize += pts->size;
			} else {
				intsize += _min_size;
			}
		}
		return intsize;
	}
};
#endif /* __CLASS_PTR_ARRAY_H */



#ifndef __GEN_FUNCTIONS
#define __GEN_FUNCTIONS

#ifdef __APPLE__
#include <sys/types.h>
#include <sys/_types/_timespec.h>
#include <mach/mach.h>
#include <mach/clock.h>
#include <mach/mach_time.h>

#ifndef mach_time_h
#define mach_time_h 
#ifndef CLOCK_MONOTONIC
#define CLOCK_MONOTONIC SYSTEM_CLOCK
#endif // CLOCK_MONOTONIC

static void clock_gettime(int clk_id, struct timespec *tp) {
	clock_serv_t cclock;
	mach_timespec_t mts;
	host_get_clock_service(mach_host_self(), SYSTEM_CLOCK, &cclock);
	//retval = clock_get_time(cclock, &mts);
	mach_port_deallocate(mach_task_self(), cclock);
	tp->tv_sec = mts.tv_sec;
	tp->tv_nsec = mts.tv_nsec;
}
#endif /* mach_time_t */
#endif /* __APPLE__ */


inline unsigned long long monotonic_time() {
  struct timespec ts;
  clock_gettime(CLOCK_MONOTONIC, &ts);
  return (((unsigned long long) ts.tv_sec) * 1000000) + (ts.tv_nsec / 1000);
}

inline unsigned long long realtime_time() {
  struct timespec ts;
  clock_gettime(CLOCK_REALTIME, &ts);
  return (((unsigned long long) ts.tv_sec) * 1000000) + (ts.tv_nsec / 1000);
}

#endif /* __GEN_FUNCTIONS */

bool Proxy_file_exists(const char *);
bool Proxy_file_regular(const char *);

char *escape_string_single_quotes(char *input, bool free_it);
int remove_spaces(const char *);
char *trim_spaces_in_place(char *str);
char *trim_spaces_and_quotes_in_place(char *str);
bool mywildcmp(const char *p, const char *str);
std::string trim(const std::string& s);

/**
 * @brief Helper function that converts a MYSQL_RES into a 'SQLite3_result'.
 * @param resultset The resultset to be converted into a 'SQLite3_result'.
 * @return An 'unique_ptr' holding the resulting 'SQLite3_result'.
 */
std::unique_ptr<SQLite3_result> get_SQLite3_resulset(MYSQL_RES* resultset);
