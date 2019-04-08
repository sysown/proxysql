#include <cstdio>
#include <cstdlib>
#include <iostream>

__thread unsigned int g_seed;

inline int fastrand() {
    g_seed = (214013*g_seed+2531011);
    return (g_seed>>16)&0x7FFF;
}

inline unsigned long long monotonic_time() {
	struct timespec ts;
	clock_gettime(CLOCK_MONOTONIC, &ts);
	return (((unsigned long long) ts.tv_sec) * 1000000) + (ts.tv_nsec / 1000);
}


#define NSRV	24
#define NLOOP	10000000

struct cpu_timer
{
	cpu_timer() {
		begin = monotonic_time();
	}
	~cpu_timer()
	{   
		unsigned long long end = monotonic_time();
		std::cerr << double( end - begin ) / 1000000 << " secs.\n" ;
		begin=end-begin; // here only to make compiler happy
	};
	unsigned long long begin;
};


int main(int argc, char** argv) {
	unsigned int * usedConns = NULL;
	unsigned int * weights = NULL;
	unsigned int sum = 0;
	unsigned int TotalUsedConn = 0;

	srand(monotonic_time());
	usedConns = (unsigned int *)malloc(NSRV*sizeof(unsigned int));
	weights = (unsigned int *)malloc(NSRV*sizeof(unsigned int));
	for (int i=0 ; i < NSRV ; i++ ) {
		usedConns[i] = 20+rand()%1000;
		weights[i] = 20+rand()%10000;
	}
	for (int N=4; N<=NSRV; N+=4) {
	std::cerr << "Test with " << N << " servers:" << std::endl;
	{
		cpu_timer c;
		for (int i=0; i<NLOOP; i++) {
			sum = 0;
			TotalUsedConn = 0;
			for (int j=0; j<N; j++) {
				sum += weights[j];
				TotalUsedConn += usedConns[j];
			}
			unsigned int New_sum=0;
			unsigned int New_TotalUsedConn=0;
			for (int j=0; j<N; j++) {
				unsigned int len = usedConns[j];
				unsigned int weight = weights[j];
				if ((len * sum) <= (TotalUsedConn * weight * 1.5 + 1)) {
					New_sum += weight;
					New_TotalUsedConn += len;
				}
			}
			unsigned int k;
			if (New_sum > 32768) {
				k = rand() % New_sum;
			} else {
				k = fastrand() % New_sum;
			}
			New_sum = 0;
			for (int j=0; j<N; j++) {
				unsigned int len = usedConns[j];
				unsigned int weight = weights[j];
				if ((len * sum) <= (TotalUsedConn * weight * 1.5 + 1)) {
					New_sum += weight;
					if (k <= New_sum) {
						break;
					}
				}
			}
		}
		std::cerr << "INT test ran in \t";
	}
	{
		cpu_timer c;
		for (int i=0; i<NLOOP; i++) {
			double sum = 0;
			TotalUsedConn = 0;
			for (int j=0; j<N; j++) {
				sum += weights[j];
				TotalUsedConn += usedConns[j];
			}
			double New_sum=0;
			unsigned int New_TotalUsedConn=0;
			for (int j=0; j<N; j++) {
				unsigned int len = usedConns[j];
				unsigned int weight = weights[j];
				if ((len * sum) <= (TotalUsedConn * weight * 1.5 + 1)) {
					New_sum += weight;
					New_TotalUsedConn += len;
				}
			}
			double k;
			if (New_sum > 32768) {
				k = drand48() * New_sum;
			} else {
				k = fastrand() % (unsigned int)New_sum;
			}
			New_sum = 0;
			for (int j=0; j<N; j++) {
				unsigned int len = usedConns[j];
				unsigned int weight = weights[j];
				if ((len * sum) <= (TotalUsedConn * weight * 1.5 + 1)) {
					New_sum += weight;
					if (k <= New_sum) {
						break;
					}
				}
			}
		}
		std::cerr << "DOUBLE test ran in \t";
	}
	}
}
