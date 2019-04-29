// cc -O2 issue522.c -o issue522 -L../../deps/jemalloc/jemalloc/lib -Wl,-Bstatic -ljemalloc -Wl,-Bdynamic -lpthread -lm -ldl
#include <stdlib.h>
int main() {
	int i;
	char *c=NULL;
	for (i=0;i<500000000;i++) {
		c=(char *)malloc(100);
		if (__builtin_expect(c==NULL, 0)) return -1;
		free(c);
	}
	return 0;
}
