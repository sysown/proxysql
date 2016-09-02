#ifndef __CLASS_PTR_ARRAY_H
#define __CLASS_PTR_ARRAY_H
#include "proxysql.h"
#include "cpp.h"

/*
#ifdef __cplusplus
extern "C" {
#endif
void fast_srand( int seed );
char * gen_random_string(const int len);
#ifdef __cplusplus
}
#endif
*/

/*
typedef struct _PtrSize_t PtrSize_t;
struct _PtrSize_t {
	void *ptr;
	unsigned int size;
}; 
*/

class PtrArray {
	private:
	void expand(unsigned int);
	void shrink();
//	bool use_l_alloc;
	public:
//	void * operator new(size_t);
//	void operator delete(void *);
//	void * operator new(size_t, bool);
//	void operator delete(void *, bool);
	void **pdata;
	unsigned int len;
	unsigned int size;
	//PtrArray(unsigned int __size=0, bool _use_l_alloc=false);
	PtrArray(unsigned int __size=0);
	~PtrArray();

	void *index(unsigned int i) { return pdata[i];} ;

	void add(void *p) {
		if (len==size) {
			expand(1);
		}
		pdata[len++]=p;
	};

	bool remove(void *);
	void * remove_index(unsigned int);
	bool remove_fast(void *);
	void * remove_index_fast(unsigned int);
};


class PtrSizeArray {
	private:
	void expand(unsigned int);
	void shrink();
	public:
	void * operator new(size_t);
	void operator delete(void *);
	PtrSize_t *pdata;
	unsigned int len;
	unsigned int size;
	PtrSizeArray(unsigned int __size=0);
	~PtrSizeArray();
	//PtrSize_t *index(unsigned int);

//	void add(void *, unsigned int);
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


//	void remove_index(unsigned int, PtrSize_t *);
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
#define CLOCK_MONOTONIC SYSTEM_CLOCK

void clock_gettime(int clk_id, struct timespec *tp) {
	clock_serv_t cclock;
	mach_timespec_t mts;
	host_get_clock_service(mach_host_self(), SYSTEM_CLOCK, &cclock);
	retval = clock_get_time(cclock, &mts);
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
