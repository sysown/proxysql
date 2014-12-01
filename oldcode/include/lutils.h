#include <stdint.h>
#include <unistd.h>
//#define mypkt_alloc() l_alloc(thrLD->sfp,sizeof(pkt))
//#define mypkt_free1(p) { l_free(thrLD->sfp, p->length, p->data); l_free(thrLD->sfp, sizeof(pkt), p); }
//#define mypkt_free0(p) { l_free(thrLD->sfp, sizeof(pkt), p); }
#define mypkt_alloc() l_alloc(sizeof(pkt))
#define mypkt_free1(p) { l_free(p->length, p->data); l_free(sizeof(pkt), p); }
#define mypkt_free0(p) { l_free(sizeof(pkt), p); }


#define l_ptr_array_index(array,l_index_) ((array)->pdata)[l_index_]

#define l_ptr_array_free0(array) { l_free(sizeof(LPtrArray),array); }
#define l_ptr_array_free1(array) { if (array->pdata) l_free(sizeof(void *)*array->size,array->pdata); l_free(sizeof(LPtrArray),array); }


#define L_SFC_MIN_ELEM_SIZE	8
#define L_SFC_MID_ELEM_SIZE 32
#define L_SFC_MAX_ELEM_SIZE	256
#define L_SFP_ARRAY_MID 3
#define L_SFP_ARRAY_LEN	6
//#define L_SFC_MAX_ELEM_SIZE	32
//#define L_SFP_ARRAY_LEN	3
#define L_SFC_MEM_BLOCK_SIZE 262144
typedef struct _l_stack_t l_stack;
typedef struct _l_super_free_chunk_t l_sfc;
#ifndef L_SFP
#define L_SFP
typedef struct _l_super_free_pool_t l_sfp;
typedef struct _LPtrArray LPtrArray;
#endif
extern __thread l_sfp *__thr_sfp;

struct _LPtrArray {
  void **pdata;
  unsigned int len;
  unsigned int size;
};


struct _l_stack_t {
	l_stack *n;
};

struct _l_super_free_chunk_t {
	l_stack *stack;
	void **mem_blocks;
	size_t elem_size;
	size_t blocks_cnt;
	size_t alloc_cnt;
	size_t free_cnt;
	size_t __mem_l_free_count;

};

struct _l_super_free_pool_t {
	l_sfc sfc[L_SFP_ARRAY_LEN];
};

static inline void l_stack_push (l_stack **s, void *p) {
	l_stack *d=(l_stack *)p;
	d->n=*s;
	*s=d;
}

static inline void * l_stack_pop (l_stack **s) {
	l_stack *d;
	d=*s;
	if (d) { *s=d->n; d->n=NULL; }
	return d;
}

l_sfp * l_mem_init();
void l_mem_destroy(l_sfp *);
//void * l_alloc(l_sfp *, size_t);
//void * l_alloc0(l_sfp *, size_t);
//void l_free(l_sfp *, size_t, void *);
void * l_alloc(size_t);
void * l_alloc0(size_t);
void l_free(size_t, void *);

void * __l_alloc(l_sfp *, size_t);
void __l_free(l_sfp *, size_t, void *);

LPtrArray *l_ptr_array_sized_new(unsigned int);
LPtrArray *l_ptr_array_new();
void l_ptr_array_add(LPtrArray *, void *);
void * l_ptr_array_remove_index(LPtrArray *, unsigned int);
void * l_ptr_array_remove_index_fast (LPtrArray *, unsigned int);
int l_ptr_array_remove_fast(LPtrArray *, void *);
