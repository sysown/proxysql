#ifndef __CLASS_SET_PARSER_H
#define __CLASS_SET_PARSER_H
#include <string>
#include <map>
#include <vector>

class SetParser {
	private:
  std::string query;
	public:
	SetParser(std::string q);
	std::map<std::string, std::vector<std::string>> parse();
};


#endif /* __CLASS_SET_PARSER_H */
