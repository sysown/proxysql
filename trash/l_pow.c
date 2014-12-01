#include <stdio.h>
#include <pthread.h>


static unsigned int g_seed;


inline void fast_srand( int seed ) {
g_seed = seed;
}
inline int fastrand() {
  g_seed = (214013*g_seed+2531011);
  return (g_seed>>16)&0x7FFF;
}


static unsigned int l_near_pow_2 (unsigned int n) {
  unsigned int i = 8;
  while (i < n) i <<= 1;
  //return i ? i : n;
  return i;
}


#define LOOPS	100*1000*1000



int main() {

	int i,j, k;
	int sizes[9] = { 8, 16, 32, 64, 128, 256 , 512, 1024, 2048};
	unsigned long long t=0;

	fast_srand(pthread_self());
	for (i=0; i<LOOPS;i++) {


		j=l_near_pow_2(fastrand()%2048);
		switch (j) {
//			case 0:
//				t+=1024;
//				break;
			case 8:
				t+=8;
				break;
			case 16:
				t+=16;
				break;
			case 32:
				t+=32;
				break;
			case 64:
				t+=64;
				break;
			case 128:
				t+=128;
				break;
			case 256:
				t+=256;
				break;
			case 512:
				t+=512;
				break;
			case 1024:
				t+=1024;
				break;
			case 2048:
				t+=2048;
				break;
			default:
				break;
		}

/*
		j=fastrand()%2048;
		k=8;
		for( ; k >= 0 ; k-- ) {
			if ((j<<1)>sizes[k] || k==0) {
				t+=sizes[k];
				k=-1;
			}
		}
*/

	}
	printf("%llu\n", t);
	return 0;
}
