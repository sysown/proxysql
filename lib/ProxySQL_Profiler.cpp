#include "ProxySQL_Profiler.hpp"
#include <vector>
#include <assert.h>

using namespace std;

extern thread_local std::string thread_bt;
extern std::mutex GlobalProfiling1_mutex;
extern std::unordered_map<std::string,CounterProfiling1> GlobalProfiling1;


class Counter2 {
	public:
	unsigned long long cnt = 0;
	unsigned long long tottime = 0;
	unsigned long long tottime1 = 0; // used by print_values
	unsigned long long tottime2 = 0;
	unsigned long long tottime3 = 0;
	string name = "";
	string last_word = "";
	unordered_map<string, Counter2 *> map = {};
	~Counter2() {
		for (auto it = map.begin(); it != map.end(); it++) {
			Counter2* c = it->second;
			delete c;
		}
	}
};

int MMID = 1;
static unsigned long long total_leaf_times1 = 0;
static unsigned long long total_leaf_times2 = 0;
static unsigned long long total_leaf_times3 = 0;
static unordered_map<string, Counter2 *> MyMap = {};


void getWords(vector<string>& words, string str) {
	words = {};
	int n = str.length();
	string word = "";
	for (int i = 0; i < n; i++) {
		if (str[i] == ' ' || i == (n - 1)) {
			words.push_back(word);
			word = "";
		} else {
			word += str[i];
		}
	}
}


void insert_element(unordered_map<string, Counter2 *>& MyMap, vector<string>& words, unsigned int idx, CounterProfiling1& c) {
		Counter2 * c2 = NULL;
		auto it = MyMap.find(words[idx]);
		if (it != MyMap.end()) {
			c2 = it->second;
		} else {
			c2 = new Counter2();
			c2->name = "P" + to_string(MMID);
			MMID++;
			c2->last_word = words[idx];
			MyMap.emplace(c2->last_word,c2);
		}
		if (idx != words.size() - 1) {
			idx++;
			insert_element(c2->map, words, idx, c);
		} else {
			c2->cnt = c.cnt;
			c2->tottime = c.tottime;
		}
}

void retrieve_total_leaf_times(unordered_map<string, Counter2 *>& MyMap) {
	total_leaf_times1 = 0;
	total_leaf_times2 = 0;
	total_leaf_times3 = 0;
	for (auto it = MyMap.begin() ; it != MyMap.end() ; it++) {
		Counter2 *c2 = it->second;
		c2->tottime1 = c2->tottime;
		c2->tottime2 = 0;
		c2->tottime3 = c2->tottime;;
		if (c2->map.size()) {
			retrieve_total_leaf_times(c2->map);
			for (auto it2 = c2->map.begin() ; it2 != c2->map.end(); it2++) {
				c2->tottime2 += it2->second->tottime2; // time of all the leaves from this branch
				c2->tottime3 -= it2->second->tottime; // its own time only
			}
		} else {
			c2->tottime2 = c2->tottime; // time of only leaves
			total_leaf_times2 += c2->tottime2;
		}
		total_leaf_times1 += c2->tottime;
		total_leaf_times3 += c2->tottime3;
	}
}

/*
void retrieve_total_leaf_times(unordered_map<string, Counter2 *>& MyMap, int algo) {
	for (auto it = MyMap.begin() ; it != MyMap.end() ; it++) {
		Counter2 *c2 = it->second;
		c2->tottime2 = 0;
		if (algo == 1) {
			if (c2->map.size()) {
				retrieve_total_leaf_times(c2->map, algo);
			}
			c2->tottime2 = c2->tottime;
			total_leaf_times += c2->tottime2;
		} else if (algo == 2) {
			if (c2->map.size()) {
				retrieve_total_leaf_times(c2->map, algo);
			}
			for (auto it2 = c2->map.begin() ; it2 != c2->map.end(); it2++) {
				c2->tottime -= it2->second->tottime;
			}
		} else if (algo == 3) {
		} 
	}
}
*/
void print_values(string& output, unordered_map<string, Counter2 *>& MyMap, string parent, int algo) {
	for (auto it = MyMap.begin() ; it != MyMap.end() ; it++) {
		Counter2 *c2 = it->second;
		string last_word = c2->last_word;
		string path = parent + last_word + " ";
		if (c2->map.size() == 0) {
			if (last_word != "") {
				auto it = GlobalProfiling1.find(path);
				assert(it != GlobalProfiling1.end());
				CounterProfiling1& c = it->second;
				assert(c.cnt == c2->cnt);
				assert(c.tottime == c2->tottime);
			}
		} else {
			print_values(output, c2->map, path, algo);
			output += c2->name + "[" + last_word + "]\n";
			char buf[10];
			for (auto it2 = c2->map.begin() ; it2 != c2->map.end() ; it2++) {
				Counter2 *c3 = it2->second;
				double pct = 0;
				unsigned long long tt = 0;
				switch (algo) {
					case 1:
						tt = c3->tottime1;
						pct = (double)tt * 100 / total_leaf_times1;
						break;
					case 2:
						tt = c3->tottime2;
						pct = (double)tt * 100 / total_leaf_times2;
						break;
					case 3:
						tt = c3->tottime3;
						pct = (double)tt * 100 / total_leaf_times3;
						break;
					default:
						assert(0);
						break;
				}
				sprintf(buf, "%.2f", pct);
				output += c3->name + "[\"" + c3->last_word + "\n" + to_string(tt) + " (" + string(buf) + "%)\"]\n";
				output += c2->name + " -- " + to_string(c3->cnt) + " --> " + c3->name + "\n";
			}
		}
	}
}

void GenerateMermaid1(string& output) {
	MyMap = {};
	MMID = 1;
	output = "```mermaid\nflowchart LR\n";
	const std::lock_guard<std::mutex> lock(GlobalProfiling1_mutex);
	for (auto it = GlobalProfiling1.begin() ; it != GlobalProfiling1.end() ; it++) {
		vector<string> words = {};
		getWords(words, it->first);
		CounterProfiling1& c = it->second;
		insert_element(MyMap, words, 0, c);
	}
	retrieve_total_leaf_times(MyMap);
	print_values(output, MyMap,"",1);
	output += "```\n";
	output += "```mermaid\nflowchart LR\n";
	print_values(output, MyMap,"",2);
	output += "```\n";
	output += "```mermaid\nflowchart LR\n";
	print_values(output, MyMap,"",3);
	output += "```";
}

Profiler1::Profiler1(int l, const char *__file, int __line, const char *__func) {
	log = l;
	if (log) {
		clock_gettime(CLOCK_MONOTONIC,&begint);
		//clock_gettime(CLOCK_THREAD_CPUTIME_ID,&begint);
	}
	prev_bt = thread_bt;
	thread_bt += std::string(__file) + ":" + std::to_string(__line) + ":" + std::string(__func) + " ";
}

Profiler1::~Profiler1() {
	if (log) {
		clock_gettime(CLOCK_MONOTONIC,&endt);
		//clock_gettime(CLOCK_THREAD_CPUTIME_ID,&endt);
		unsigned long long delta = (endt.tv_sec*1000000000+endt.tv_nsec) - (begint.tv_sec*1000000000+begint.tv_nsec);
		const std::lock_guard<std::mutex> lock(GlobalProfiling1_mutex);
		auto it = GlobalProfiling1.find(thread_bt);
		if (it != GlobalProfiling1.end()) {
			CounterProfiling1& c = it->second;
			c.add(delta);
		} else {
			CounterProfiling1 c(delta);
			GlobalProfiling1.emplace(thread_bt,c);
		}
	}
	thread_bt = prev_bt;
}
