#include "proxysql.h"
#include "cpp.h"


/*
static unsigned int g_seed;


inline void fast_srand( int seed ) {
g_seed = seed;
}
inline int fastrand() {
	g_seed = (214013*g_seed+2531011);
	return (g_seed>>16)&0x7FFF;
}


char * gen_random_string(const int len) {
	char *s=(char *)malloc(len+1);
    static const char alphanum[] =
        "0123456789"
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        "abcdefghijklmnopqrstuvwxyz";

    for (int i = 0; i < len; ++i) {
        s[i] = alphanum[fastrand() % (sizeof(alphanum) - 1)];
    }

    s[len] = 0;
	return s;
}
*/

#define MIN_ARRAY_LEN	8
#define MIN_ARRAY_DELETE_RATIO	8

static unsigned int l_near_pow_2 (unsigned int n) {
	unsigned int i = 1;
	while (i < n) i <<= 1;
	return i ? i : n;
}


// PtrArray is used also for shared struct, needs to fork the class in two)

void * PtrArray::operator new(size_t size) {
	return malloc(size);
}

void PtrArray::operator delete(void *ptr) {
	(((PtrArray *)ptr)->use_l_alloc ? l_free(sizeof(PtrArray), ptr) : free(ptr));
	//free(ptr);
}

void * PtrArray::operator new(size_t size, bool b) {
	return l_alloc(size);
}

void PtrArray::operator delete(void *ptr, bool b) {
	l_free(sizeof(PtrArray), ptr);
}


PtrArray::PtrArray(unsigned int __size, bool _use_l_alloc) {
	use_l_alloc=false;
	use_l_alloc=_use_l_alloc;
	len=0;
	pdata=NULL;
	size=0;
	if (__size) {
		expand(__size);
	}
	size=__size;
}

PtrArray::~PtrArray() {
	if (pdata) (use_l_alloc ? l_free(size*sizeof(void *),pdata) :  free(pdata) );
	//if (pdata) l_free(size*sizeof(void *),pdata);
	pdata=NULL;
}


void PtrArray::shrink() {
	unsigned int new_size=l_near_pow_2(len+1);
	pdata=(use_l_alloc ? (void **)l_realloc(pdata,new_size*sizeof(void *),size*sizeof(void *)) : (void **)realloc(pdata,new_size*sizeof(void *)) );
	//pdata=(void **)realloc(pdata,new_size*sizeof(void *));
	//pdata=(void **)l_realloc(pdata,new_size*sizeof(void *),size*sizeof(void *));
	size=new_size;
}

void PtrArray::expand(unsigned int more) {
    if ( (len+more) > size ) {
        unsigned int new_size=l_near_pow_2(len+more);
				void *new_pdata=( use_l_alloc ? l_alloc(new_size*sizeof(void *)) : malloc(new_size*sizeof(void *)) );
				memset(new_pdata,0,new_size*sizeof(void *));
        //void *new_pdata=malloc(new_size*sizeof(void *));
        //void *new_pdata=l_alloc(new_size*sizeof(void *));
        if (pdata) {
            memcpy(new_pdata,pdata,size*sizeof(void *));
						( use_l_alloc ? l_free(size*sizeof(void *),pdata) : free(pdata) );
            //free(pdata);
						//l_free(size*sizeof(void *),pdata);
        }
        size=new_size;
        pdata=(void **)new_pdata;
    }
}

/*
void * PtrArray::index(unsigned int i) {
	return pdata[i];
}

void PtrArray::add(void *p) {
    if (len==size) {
        expand(1);
    }
    pdata[len++]=p;
}
*/

bool PtrArray::remove(void *p) {
	unsigned int i;
    for (i=0; i<len; i++) {
        if (pdata[i]==p) {
            remove_index(i);
            return true;
        }
    }
    return false;
	
}

void * PtrArray::remove_index(unsigned int i) {
    void *r=pdata[i];
    if (i != (len-1)) {
		memmove(pdata+(i)*sizeof(void *),pdata+(i+1)*sizeof(void *),(len-i-1)*sizeof(void *));
    }
    len--;
	if ( ( len>MIN_ARRAY_LEN ) && ( size > len*MIN_ARRAY_DELETE_RATIO ) ) {
		shrink();
	}
    return r;
}


bool PtrArray::remove_fast(void *p) {
    unsigned int i;
    //unsigned l=len;
    for (i=0; i<len; i++) {
        if (pdata[i]==p) {
            remove_index_fast(i);
            return true;
        }
    }
    return false;
}


void * PtrArray::remove_index_fast(unsigned int i) {
    void *r=pdata[i];
    if (i != (len-1))
    	pdata[i]=pdata[len-1];
    len--;
	if ( ( len>MIN_ARRAY_LEN ) && ( size > len*MIN_ARRAY_DELETE_RATIO ) ) {
		//shrink(); // FIXME: when shrink is called, is r invalid ??
	}
    return r;
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
	pdata=(PtrSize_t *)l_realloc(pdata,new_size*sizeof(PtrSize_t),size*sizeof(PtrSize_t));
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


/*
void PtrSizeArray::add(void *p, unsigned int s) {
    if (len==size) {
        expand(1);
    }
	//fprintf(stderr,"Adding on %p of len %d : ptr %p size %d\n", pdata, len, p, s);
    pdata[len].ptr=p;
    pdata[len].size=s;
	len++;
}

void PtrSizeArray::remove_index(unsigned int i, PtrSize_t *ps) {
	if (ps) {
		ps->ptr=pdata[i].ptr;
		ps->size=pdata[i].size;
		//fprintf(stderr,"removing from %p of len %d : ptr %p size %d\n", pdata, len, ps->ptr, ps->size);
	}
    if (i != (len-1)) {
		//memmove(pdata+(i)*sizeof(PtrSize_t),pdata+(i+1)*sizeof(PtrSize_t),(len-i-1)*sizeof(PtrSize_t));
		memmove(pdata+i,pdata+i+1,(len-i-1)*sizeof(PtrSize_t));
    }
    len--;
}
*/

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


//PtrSize_t * PtrSizeArray::index(unsigned int i) {
//	return &pdata[i];
//}

void PtrSizeArray::copy_add(PtrSizeArray *psa, unsigned int from, unsigned int cnt) {
	unsigned int i;
	PtrSize_t *psp;
	for (i=from;i<from+cnt;i++) {
		psp=psa->index(i);
		add(psp->ptr,psp->size);
	}
}
