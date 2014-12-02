#include "proxysql.h"


static void *__x_malloc(size_t size) {
  void *m=malloc(size);
  assert(m);
  return m;
}


static void * __x_memalign(size_t size) {
  int rc;
  void *m;
  rc=posix_memalign(&m, L_SFC_MEM_BLOCK_SIZE, size);
  assert(rc==0);
  return m;
}

static void __add_mem_block(l_sfc *sfc, void *m) {
  void *nmp=__x_malloc(sizeof(void *)*(sfc->blocks_cnt+1));
  if (sfc->mem_blocks) {
    memcpy(nmp,sfc->mem_blocks,sizeof(void *)*(sfc->blocks_cnt));
    free(sfc->mem_blocks);
  }
  sfc->mem_blocks=(void **)nmp;
  sfc->mem_blocks[sfc->blocks_cnt++]=m;
}

static inline void __push_mem_block(l_sfc *sfc, void *m) {
  size_t j;
  void *n;
  for (j=0; j<L_SFC_MEM_BLOCK_SIZE/sfc->elem_size; j++) {
    n=(char *)m+j*sfc->elem_size;
    l_stack_push(&sfc->stack,n);
  }
}



l_sfp * l_mem_init() {
  l_sfp *s=(l_sfp *)__x_malloc(sizeof(l_sfp));
  int i;
  for (i=0; i<L_SFP_ARRAY_LEN; i++) {
    s->sfc[i].stack=NULL;
    s->sfc[i].mem_blocks=NULL;
    s->sfc[i].elem_size=L_SFC_MIN_ELEM_SIZE * (1 << i) ;
    s->sfc[i].alloc_cnt=0;
    s->sfc[i].free_cnt=0;
    s->sfc[i].blocks_cnt=0;
    s->sfc[i].__mem_l_free_count=0;
  }
  return s;
}


void l_mem_destroy(l_sfp *s) {
  size_t i,j;
  for (i=0; i<L_SFP_ARRAY_LEN; i++) {
    for (j=0;j<s->sfc[i].blocks_cnt;j++) {
      free(s->sfc[i].mem_blocks[j]);
    }
    if (s->sfc[i].mem_blocks) {
      free(s->sfc[i].mem_blocks);
    }
  }
	free(s);
}

void * __l_alloc(l_sfp *sfp, size_t size) {
  if (size>L_SFC_MAX_ELEM_SIZE) {
    return __x_malloc(size);
  }
  void *p;
  int i;
#ifdef __GNUC__
	unsigned int x=size;
	int j=__builtin_clz(x);
	int k=__builtin_ffs(x);
	i=(k+j==(sizeof(unsigned int)*8) ? k : sizeof(unsigned int)*8+1-j);
	i=(i >= 4 ? i-4 : 0);
#else
	i= ( size<=L_SFC_MID_ELEM_SIZE ? L_SFP_ARRAY_MID-1 : L_SFP_ARRAY_LEN-1 );
  for ( ; i>=0 ; i-- ) {
    if ((size<<1)>sfp->sfc[i].elem_size || i==0) {
#endif /* __GNUC__ */
      p=l_stack_pop(&sfp->sfc[i].stack);
      if (p) {
				//assert((uintptr_t)p%(sfp->sfc[i].elem_size)==0);
        return p;
      }
      void *m=__x_memalign(L_SFC_MEM_BLOCK_SIZE);
      __add_mem_block(&sfp->sfc[i],m);
      __push_mem_block(&sfp->sfc[i],m);
      sfp->sfc[i].alloc_cnt+=L_SFC_MEM_BLOCK_SIZE/sfp->sfc[i].elem_size;
      sfp->sfc[i].free_cnt+=L_SFC_MEM_BLOCK_SIZE/sfp->sfc[i].elem_size;
      p=l_stack_pop(&sfp->sfc[i].stack);
			//assert((uintptr_t)p%(sfp->sfc[i].elem_size)==0);
      return p;
#ifdef __GNUC__
#else
    }
  }
#endif /* __GNUC__ */
  return NULL;
}


/*
void * l_alloc(size_t size) {
  return __l_alloc(__thr_sfp,size);
}
*/

void * l_alloc0(size_t size) {
    void *p=l_alloc(size);
    memset(p,0,size);
    return p;
}


void __l_free(l_sfp *sfp, size_t size, void *p) {
  if (size>L_SFC_MAX_ELEM_SIZE) {
    free(p);
    return;
  }
  int i;
#ifdef __GNUC__
	unsigned int x=size;
	int j=__builtin_clz(x);
	int k=__builtin_ffs(x);
	i=(k+j==(sizeof(unsigned int)*8) ? k : sizeof(unsigned int)*8+1-j);
	i=(i >= 4 ? i-4 : 0);
#else
	i= ( size<=L_SFC_MID_ELEM_SIZE ? L_SFP_ARRAY_MID-1 : L_SFP_ARRAY_LEN-1 );	
  for ( ; i>=0 ; i-- ) {
    if ((size<<1)>sfp->sfc[i].elem_size || i==0) {
#endif /* __GNUC__ */
			//assert((uintptr_t)p%(sfp->sfc[i].elem_size)==0);
      l_stack_push(&sfp->sfc[i].stack,p);
//      sfp->sfc[i].free_cnt++;
//      sfp->sfc[i].__mem_l_free_count++;

//      if ((sfp->sfc[i].__mem_l_free_count%(L_SFC_MEM_BLOCK_SIZE)==0) && (sfp->sfc[i].blocks_cnt>16) && (sfp->sfc[i].free_cnt > sfp->sfc[i].alloc_cnt * 990/1000)) {
//        compact_mem(&sfp->sfc[i]);
//        fprintf(stderr,"%d\n",(int)sfp->sfc[i].__mem_l_free_count);
//        sfp->sfc[i].__mem_l_free_count=0;
//      }

      return;
#ifdef __GNUC__
#else
    }
  }
#endif /* __GNUC__ */
}

/*
void l_free(size_t size, void *p) {
//  free(p);
  __l_free(__thr_sfp,size,p);
}
*/

void *l_realloc(void *p, size_t old_size, size_t new_size) {
	void *new_ptr=__l_alloc(__thr_sfp,new_size);
	memcpy(new_ptr,p,old_size);
	__l_free(__thr_sfp,old_size,p);
	return new_ptr;
}
