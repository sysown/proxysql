#include <iostream>
#include <vector>
#include <stdlib.h>
#include <string.h>

#define l_alloc(s) malloc(s)
#define l_free(s,p) free(p)


static unsigned int l_near_pow_2 (unsigned int n) {
  unsigned int i = 1;
  while (i < n) i <<= 1;
  return i ? i : n;
}


typedef struct _PtrSize_t PtrSize_t;

struct _PtrSize_t {
  void *ptr;
  unsigned int size;
};


class PtrSizeArray {
  private:
  unsigned int size;
  void expand(unsigned int);
  void shrink();
  public:
  PtrSize_t *pdata;
  unsigned int len;
  PtrSizeArray(unsigned int __size=0);
  ~PtrSizeArray();
  PtrSize_t *index(unsigned int);
  void add(void *, unsigned int);
  void remove_index(unsigned int, PtrSize_t *);
  void remove_index_fast(unsigned int, PtrSize_t *);
};


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



void PtrSizeArray::add(void *p, unsigned int s) {
    if (len==size) {
        expand(1);
    }
  //fprintf(stderr,"Adding on %p of len %d : ptr %p size %d\n", pdata, len, p, s);
    pdata[len].ptr=p;
    pdata[len].size=s;
  len++;
}

PtrSize_t * PtrSizeArray::index(unsigned int i) {
  return &pdata[i];
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


#define ARRSIZE	16
#define RESSIZE	50
int main() {
	int i, j;

	
	PtrSize_t myarr[ARRSIZE];
	for (i=0;i<ARRSIZE;i++) {
		myarr[i].ptr=NULL;
		myarr[i].size=i;
	}

	PtrSizeArray *psa=new PtrSizeArray();
//	std::vector<PtrSize_t> *vec = new std::vector<PtrSize_t>();	
	

	for (i=0; i<RESSIZE; i++) {
		psa->add(myarr[i%ARRSIZE].ptr,myarr[i%ARRSIZE].size);
//		vec->push_back(myarr[i%ARRSIZE]);
	}	
	PtrSize_t *psp;
	PtrSize_t ps;


	for (j=0;j<2000000;j++) {
	for (i=0; i<RESSIZE; i++) psa->add(myarr[i%ARRSIZE].ptr,myarr[i%ARRSIZE].size);
	
//	for (i=0; i<RESSIZE; i++) psa->remove_index(0,&ps);

	for (i=0; i<RESSIZE; i++) psp=psa->index(i);
	while (psa->len) psa->remove_index(psa->len-1,NULL);
/*
	for (i=0; i<RESSIZE; i++) {
	//	psp=&((*vec)[i]);
//		std::cout<<psp->size<<std::endl;
			//psp=&(vec[i]);
			//std::cout << vec[i] ;

		psp=psa->index(i);
	}
*/
	
	}
}
