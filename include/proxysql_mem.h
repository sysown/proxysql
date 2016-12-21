#define L_SFC_MIN_ELEM_SIZE 8
#define L_SFC_MID_ELEM_SIZE 128
#define L_SFC_MAX_ELEM_SIZE 2048
#define L_SFP_ARRAY_MID 5
#define L_SFP_ARRAY_LEN 9
#define L_SFC_MEM_BLOCK_SIZE 262144
typedef struct _l_stack_t l_stack;
typedef struct _l_super_free_chunk_t l_sfc;
#ifndef L_SFP
#define L_SFP
typedef struct _l_super_free_pool_t l_sfp;
typedef struct _LPtrArray LPtrArray;

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

#endif
//extern __thread l_sfp *__thr_sfp;

l_sfp * l_mem_init();
void l_mem_destroy(l_sfp *);
//void * l_alloc(size_t);
void * l_alloc0(size_t);
void * l_realloc(void *, size_t, size_t);
//void l_free(size_t, void *);
void * __l_alloc(l_sfp *, size_t);
void __l_free(l_sfp *, size_t, void *);

#ifndef L_STACK
#define L_STACK

//#define l_alloc(s) __l_alloc(__thr_sfp,s)
//#define l_free(s,p) __l_free(__thr_sfp,s,p)
#define l_alloc(s) malloc(s)
#define l_free(s,p) free(p)

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

inline int mystrcasecmp(const char *a, const char *b) {
	char ca;
	char cb;
	do {
		cb = *b++;
		ca = *a++;

		if (cb >= 'a' && cb <= 'z') {
			cb -= 0x20;
		}
		if (ca != cb)
			return 1;
	} while (cb);

	return 0;
}

static inline char * l_strdup(const char *s) {
	size_t len=strlen(s)+1;
	char *r=(char *)l_alloc(len);
	memcpy(r,s,len);
	return r;
}


#endif /* L_STACK */
