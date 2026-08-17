#include <cstdio>
#include <cstdlib>
#include <iostream>
#include <vector>

__thread unsigned int g_seed;

inline int fastrand() {
    g_seed = (214013*g_seed+2531011);
    return (g_seed>>16)&0x7FFF;
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
	std::vector<unsigned int> usedConns(NSRV);
	std::vector<unsigned int> weights(NSRV);
	unsigned int sum = 0;
	unsigned int TotalUsedConn = 0;

	g_seed = static_cast<unsigned int>(monotonic_time());
	for (int i=0 ; i < NSRV ; i++ ) {
		usedConns[i] = 20+fastrand()%1000;
		weights[i] = 20+fastrand()%10000;
	}
	auto random_u30 = []() -> unsigned int {
		return (static_cast<unsigned int>(fastrand()) << 15) | static_cast<unsigned int>(fastrand());
	};

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
			if (New_sum == 0) {
				continue;
			}
			if (New_sum > 32768) {
				k = random_u30() % New_sum;
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
			if (New_sum == 0) {
				continue;
			}
			if (New_sum > 32768) {
				k = static_cast<double>(random_u30() % New_sum);
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
