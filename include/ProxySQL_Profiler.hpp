#ifndef PROXYSQL_PROFILER
#define PROXYSQL_PROFILER

#include <string>
#include <unordered_map>
#include <mutex>



// _BLOK0 passes 0 as first argument. This means that the object WON'T measure time BUT it will generate a path
#define PROFILER1_BLOCK0(a)     Profiler1 a(0,__FILE__,__LINE__,__func__)
// when _2 suffix is added, a user defined C string can be passed as argument instead of function name
#define PROFILER1_BLOCK0_2(a,b) Profiler1 a(0,__FILE__,__LINE__,b)
// _BLOK0 passes 0 as first argument. This means that the object WILL measure time AND it will generate a path
#define PROFILER1_BLOCK1(a)     Profiler1 a(1,__FILE__,__LINE__,__func__)
// when _2 suffix is added, a user defined C string can be passed as argument instead of function name
#define PROFILER1_BLOCK1_2(a,b) Profiler1 a(1,__FILE__,__LINE__,b)

class CounterProfiling1 {
	public:
	unsigned long long cnt = 0;
	unsigned long long tottime = 0;
	CounterProfiling1(unsigned long long t) {
		tottime = t;
		cnt = 1;
	}
	void add(unsigned long long t) {
		tottime += t;
		cnt++;
	}
};

class Profiler1 {
	private:
	int log = 0;
	timespec begint;
	timespec endt;
	std::string prev_bt = "";
	public:
	Profiler1(int l, const char *__file, int __line, const char *__func);
	~Profiler1();
};
#endif // PROXYSQL_PROFILER
