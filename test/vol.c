#include <stdlib.h>
#include <stdio.h>
#include <pthread.h>


#define THRS 8
#define LOOPS 1000000

static volatile int aa=0;

void *func() {
	int i=0;
	for (i=0;i<LOOPS;i++) aa++;
	return NULL;
}

int main() {
	int i, j;
	pthread_t thr[THRS];
	for (i=0;i<THRS;i++) {
		pthread_create(&thr[i], NULL, func, NULL);
	}
	for (i=0;i<THRS;i++) {
		pthread_join(thr[i],NULL);
	}
	fprintf(stdout,"%d\n",aa);
	return 0;
}
