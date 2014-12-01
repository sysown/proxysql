#include <stdlib.h>
#include <assert.h>
#include <string.h>
#include "lutils.h"
#include <stdio.h>

#ifdef PROXYMEMTRACK
extern long long __mem_l_alloc_size;
extern long long __mem_l_alloc_count;
extern long long __mem_l_free_size;
extern long long __mem_l_free_count;
extern long long __mem_l_memalign_size;
extern long long __mem_l_memalign_count;
#endif

extern __thread l_sfp *__thr_sfp;

static unsigned int l_near_pow_2 (int n) {
	unsigned int i = 1;
	while (i < n) i <<= 1;
	return i ? i : n;
}


static inline void __sort_stack(l_sfc *sfc, void **sort_buff) {
	int i;
	sfc->stack=NULL;
	for (i=0;i<sfc->free_cnt;i++) {
		void *n=sort_buff[i];
		if (n) {
			l_stack_push(&sfc->stack,n);
		}
	}
}


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
#ifdef PROXYMEMTRACK
	__sync_fetch_and_add(&__mem_l_memalign_size,size);
	__sync_fetch_and_add(&__mem_l_memalign_count,1);
#endif
	return m;
}


static void l_ptr_array_expand(LPtrArray *array, unsigned int more) {
	if ( (array->len+more) > array->size ) {
		unsigned int new_size=l_near_pow_2(array->len+more);
		void *new_pdata=l_alloc(new_size*sizeof(void *));
		if (array->pdata) {
			memcpy(new_pdata,array->pdata,array->size*sizeof(void *));
			l_free(array->size*sizeof(void *),array->pdata);
		}
		array->size=new_size;
		array->pdata=new_pdata;
	}
}


LPtrArray *l_ptr_array_sized_new(unsigned int size) {
	LPtrArray *array=l_alloc(sizeof(LPtrArray));
	array->pdata=NULL;
	array->len=0;
	array->size=0;
	if (size) {
		l_ptr_array_expand(array, size);
	}
	return array;
}

LPtrArray *l_ptr_array_new() {
	return l_ptr_array_sized_new(0);
}

void l_ptr_array_add(LPtrArray *array, void *p) {
	if (array->len==array->size) {
		l_ptr_array_expand(array,1);
	}
	array->pdata[array->len++]=p;
}

void * l_ptr_array_remove_index(LPtrArray *array, unsigned int i) {
	void *r=array->pdata[i];
	if (i != (array->len-1)) {
		int j;
		for (j=i; j<array->len-1; j++) {
			array->pdata[j]=array->pdata[j+1];
		}
	}
	array->len--;
	return r;
}

void * l_ptr_array_remove_index_fast (LPtrArray *array, unsigned int i) {
	void *r=array->pdata[i];
	if (i != (array->len-1))
    array->pdata[i]=array->pdata[array->len-1];
	array->len--;
	return r;
}

int l_ptr_array_remove_fast(LPtrArray *array, void *p) {
	unsigned int i;
	unsigned len=array->len;
	for (i=0; i<len; i++) {
		if (array->pdata[i]==p) {
			l_ptr_array_remove_index_fast(array, i);
			return 1;
		}
	}
	return 0;
}


static void __add_mem_block(l_sfc *sfc, void *m) {
	void *nmp=__x_malloc(sizeof(void *)*(sfc->blocks_cnt+1));
	if (sfc->mem_blocks) {
		memcpy(nmp,sfc->mem_blocks,sizeof(void *)*(sfc->blocks_cnt));
		free(sfc->mem_blocks);
	}
	sfc->mem_blocks=nmp;
	sfc->mem_blocks[sfc->blocks_cnt++]=m;
}


l_sfp * l_mem_init() {
	l_sfp *s=__x_malloc(sizeof(l_sfp));
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
	int i,j;
	for (i=0; i<L_SFP_ARRAY_LEN; i++) {
		for (j=0;j<s->sfc[i].blocks_cnt;j++) {
			free(s->sfc[i].mem_blocks[j]);
		}
		if (s->sfc[i].mem_blocks) {
			free(s->sfc[i].mem_blocks);
		}
	}
}
static inline void __push_mem_block(l_sfc *sfc, void *m) {
	int j;
	void *n;
	for (j=0; j<L_SFC_MEM_BLOCK_SIZE/sfc->elem_size; j++) {
		n=m+j*sfc->elem_size;
		l_stack_push(&sfc->stack,n);
	}
}


void * __l_alloc(l_sfp *sfp, size_t size) {
	if (size>L_SFC_MAX_ELEM_SIZE) {
		return __x_malloc(size);
	}
#ifdef PROXYMEMTRACK
	__sync_fetch_and_add(&__mem_l_alloc_size,size);
	__sync_fetch_and_add(&__mem_l_alloc_count,1);
#endif
	void *p;
	int i;
	i=L_SFP_ARRAY_LEN-1;
	if (size<=L_SFC_MID_ELEM_SIZE)
		i=L_SFP_ARRAY_MID-1;
	for ( ; i>=0 ; i-- ) {
		if (size*2>sfp->sfc[i].elem_size || i==0) {
			p=l_stack_pop(&sfp->sfc[i].stack);
			if (p) {
				return p;
			}
			void *m=__x_memalign(L_SFC_MEM_BLOCK_SIZE);
			__add_mem_block(&sfp->sfc[i],m);
			__push_mem_block(&sfp->sfc[i],m);
			sfp->sfc[i].alloc_cnt+=L_SFC_MEM_BLOCK_SIZE/sfp->sfc[i].elem_size;
			sfp->sfc[i].free_cnt+=L_SFC_MEM_BLOCK_SIZE/sfp->sfc[i].elem_size;
			p=l_stack_pop(&sfp->sfc[i].stack);
			return p;
		}
	}
	return NULL;
}

void * l_alloc(size_t size) {
//	return malloc(size);
	return __l_alloc(__thr_sfp,size);
}


void * l_alloc0(size_t size) {
		void *p=l_alloc(size);
		memset(p,0,size);
		return p;
}


int cmpptr(const void *a, const void *b) {
	int d= *(intptr_t *)a - *(intptr_t *)b;
	return d;
}


static void inline __compact_mem_copy_to_sort_buff(l_sfc *sfc, int elems, void **sort_buff) {
	int i;
	l_stack *p=sfc->stack;
	for (i=0;i<elems;i++) {
		sort_buff[i]=(void *)p;
		if (p) p=p->n;
	}
}

void compact_mem(l_sfc *sfc) {
	int elems=sfc->free_cnt;
	int i;
	int fbi=0;
	void **sort_buff=__x_malloc(elems*sizeof(void *));
	void **free_block=__x_malloc(sfc->blocks_cnt*sizeof(void *));
	__compact_mem_copy_to_sort_buff(sfc,elems,sort_buff);

	qsort(sort_buff,elems,sizeof(void *),cmpptr);
	for (i=0;i<elems-L_SFC_MEM_BLOCK_SIZE/(long)sfc->elem_size;i++) {
		intptr_t v1=(intptr_t)sort_buff[i];
		if (v1%L_SFC_MEM_BLOCK_SIZE) {
			continue;
		}
		//unsigned long v2=*(unsigned long *)sort_buff[i+L_SFC_MEM_BLOCK_SIZE/sfc->elem_size-1];
		intptr_t v2=(intptr_t)sort_buff[i+L_SFC_MEM_BLOCK_SIZE/sfc->elem_size-1];
		//if (v2!=v1+sizeof(void *)*(L_SFC_MEM_BLOCK_SIZE/sfc->elem_size-1)) {
		if (v2!=v1+L_SFC_MEM_BLOCK_SIZE-sfc->elem_size) {
			continue;
		}
		free_block[fbi]=sort_buff[i];
		memset(sort_buff+i,0,sizeof(void *)*L_SFC_MEM_BLOCK_SIZE/sfc->elem_size);
		fbi++;
		i+=L_SFC_MEM_BLOCK_SIZE/sfc->elem_size-1;
	}
	fprintf(stderr, "block_size: %d, blocks_cnt: %d, free_blocks: %d\n", (int)sfc->elem_size, (int)sfc->blocks_cnt, fbi);
	if (fbi) {
		int k=0;
		int j=0;
		void **new_mem_blocks=__x_malloc((sfc->blocks_cnt-fbi)*sizeof(void *));
		for (i=0;i<sfc->blocks_cnt;i++) {
			for (j=0;j<fbi;j++) {
				if (free_block[j]==sfc->mem_blocks[i]) {
					// found
					free(sfc->mem_blocks[i]);
					sfc->mem_blocks[i]=NULL;
					j=fbi;
				}
			}
			if (sfc->mem_blocks[i]) {
				new_mem_blocks[k]=sfc->mem_blocks[i];
				k++;
			}
		}
		free(sfc->mem_blocks);
		sfc->mem_blocks=new_mem_blocks;
		sfc->blocks_cnt-=fbi;
		__sort_stack(sfc, sort_buff);

		fprintf(stderr, "block_size: %d, blocks_cnt: %d\n", (int)sfc->elem_size, (int)sfc->blocks_cnt);
		sfc->alloc_cnt-=fbi*L_SFC_MEM_BLOCK_SIZE/sfc->elem_size;
		sfc->free_cnt-=fbi*L_SFC_MEM_BLOCK_SIZE/sfc->elem_size;
	}
	__sort_stack(sfc, sort_buff);
	free(free_block);
	free(sort_buff);
}


void __l_free(l_sfp *sfp, size_t size, void *p) {
	if (size>L_SFC_MAX_ELEM_SIZE) {
		free(p);
		return;
	}
#ifdef PROXYMEMTRACK
	__sync_fetch_and_add(&__mem_l_free_size,size);
	__sync_fetch_and_add(&__mem_l_free_count,1);
#endif
	int i;
	i=L_SFP_ARRAY_LEN-1;
	if (size<=L_SFC_MID_ELEM_SIZE)
		i=L_SFP_ARRAY_MID-1;
	for ( ; i>=0 ; i-- ) {
		if (size*2>sfp->sfc[i].elem_size || i==0) {
			l_stack_push(&sfp->sfc[i].stack,p);
			sfp->sfc[i].free_cnt++;
			sfp->sfc[i].__mem_l_free_count++;

			if ((sfp->sfc[i].__mem_l_free_count%(L_SFC_MEM_BLOCK_SIZE)==0) && (sfp->sfc[i].blocks_cnt>16) && (sfp->sfc[i].free_cnt > sfp->sfc[i].alloc_cnt * 990/1000)) {
				compact_mem(&sfp->sfc[i]);
				fprintf(stderr,"%d\n",(int)sfp->sfc[i].__mem_l_free_count);
				sfp->sfc[i].__mem_l_free_count=0;
			}

			return;
		}
	}
}

void l_free(size_t size, void *p) {
//	free(p);
	__l_free(__thr_sfp,size,p);
}
