#ifndef __CLASS_SET_PARSER_H
#define __CLASS_SET_PARSER_H
#include <string>
#include <map>
#include <vector>

class SetParser {
	private:
	std::string query;
#ifdef PARSERDEBUG
	int verbosity;
	public:
	SetParser(std::string q, int verb = 0);
#else
	public:
	SetParser(std::string q);
#endif
	std::map<std::string, std::vector<std::string>> parse1();
	std::map<std::string, std::vector<std::string>> parse1v2();
	std::map<std::string, std::vector<std::string>> parse2();
	std::string parse_character_set();
};


#endif /* __CLASS_SET_PARSER_H */
