#ifndef PROXYSQL_ATOMIC
#define PROXYSQL_ATOMIC 
/*
typedef unsigned spinlock;
typedef struct _rwlock_t rwlock_t;
struct _rwlock_t {
    spinlock lock;
    unsigned readers;
};
*/
#define atomic_inc(P) __sync_add_and_fetch((P), 1)
#define atomic_dec(P) __sync_add_and_fetch((P), -1)

/* Compile read-write barrier */
#define barrier() asm volatile("": : :"memory")

/* Pause instruction to prevent excess processor bus usage */
#define cpu_relax_pa() asm volatile("pause\n": : :"memory")
#define cpu_relax_us() usleep(10)

#define RELAX_TRIES	1

static inline unsigned xchg_32(void *ptr, unsigned x) {
    __asm__ __volatile__("xchgl %0,%1"
                :"=r" ((unsigned) x)
                :"m" (*(volatile unsigned *)ptr), "0" (x)
                :"memory");
    return x;
}

static inline void spinlock_rwlock_init(rwlock_t *l) {
	memset(l,0,sizeof(rwlock_t));
}

static inline void spinlock_init(spinlock *l) {
	memset(l,0,sizeof(spinlock));
}

static inline void spin_lock(spinlock *lock) {
		int i=RELAX_TRIES;
    while (1) {
        if (!xchg_32(lock, 1)) return;
        while (*lock) { if (i) { i--; cpu_relax_pa(); } else { i=RELAX_TRIES; cpu_relax_us(); } }
    }
}

static inline void spin_unlock(spinlock *lock) {
    barrier();
    *lock = 0;
}

static inline void spin_wrlock(rwlock_t *l) {
    spin_lock(&l->lock);
		int i=RELAX_TRIES;
    while (l->readers) { if (i) { i--; cpu_relax_pa(); } else { i=RELAX_TRIES; cpu_relax_us(); } }
}

static inline void spin_wrunlock(rwlock_t *l) {
    spin_unlock(&l->lock);
}

static inline void spin_rdlock(rwlock_t *l) {
		int i=RELAX_TRIES;
    while (1) {
        atomic_inc(&l->readers);
        if (!l->lock) return;
        atomic_dec(&l->readers); 
        while (l->lock) { if (i) { i--; cpu_relax_pa(); } else { i=RELAX_TRIES; cpu_relax_us(); } }
    }
}

static inline void spin_rdunlock(rwlock_t *l) {
    atomic_dec(&l->readers);
}


#endif /* PROXYSQL_ATOMIC */
