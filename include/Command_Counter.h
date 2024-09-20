#ifndef __CLASS_COMMAND_COUNTER_H
#define __CLASS_COMMAND_COUNTER_H

class Command_Counter {
public:
	Command_Counter(int cmd_idx, int col_count, char** cmd_desc) : _counters{}, _total_time(0), _cmd_idx(cmd_idx), 
		_col_count(col_count), _cmd_desc(cmd_desc) {

		//memset(_counters, 0, sizeof(_counters));
	}
	void add_and_reset(Command_Counter* cc) {
		for (int j = 0; j < static_cast<int>(sizeof(_counters)/sizeof(_counters[0])); j++) {
			if (cc->_counters[j]) {
				__sync_fetch_and_add(&_counters[j], cc->_counters[j]);
				cc->_counters[j] = 0;
			}
		}
		if (cc->_total_time)
			__sync_fetch_and_add(&_total_time, cc->_total_time);
		cc->_total_time = 0;
	}
	unsigned long long add_time(unsigned long long t) {
		_total_time += t;
		_counters[0]++;
		int i = _add_idx(t);
		_counters[i + 1]++;
		return _total_time;
	}
	char** get_row() {
		char** pta = (char**)malloc(sizeof(char*) * _col_count);
		pta[0] = _cmd_desc[_cmd_idx];
		itostr(pta[1], _total_time);
		for (int i = 0; i < static_cast<int>(sizeof(_counters)/sizeof(_counters[0])); i++) itostr(pta[i + 2], _counters[i]);
		return pta;
	}
	void free_row(char** pta) {
		for (int i = 1; i < _col_count; i++) free(pta[i]);
		free(pta);
	}

private:
	unsigned long long _counters[13];
	unsigned long long _total_time;
	const int _cmd_idx;
	const int _col_count;
	char** _cmd_desc;

	int _add_idx(unsigned long long t) {
		if (t <= 100) return 0;
		if (t <= 500) return 1;
		if (t <= 1000) return 2;
		if (t <= 5000) return 3;
		if (t <= 10000) return 4;
		if (t <= 50000) return 5;
		if (t <= 100000) return 6;
		if (t <= 500000) return 7;
		if (t <= 1000000) return 8;
		if (t <= 5000000) return 9;
		if (t <= 10000000) return 10;
		return 11;
	}
};

#endif /* __CLASS_COMMAND_COUNTER_H */
