#include <iostream>
#include <regex>
#include <string>

using namespace std;

int main()
{
	const char *input="Select";
	//regex reg1("SELECT (?:.*)(?!FOR UPDATE)$" , regex_constants::icase);
	regex reg1("SELECT" , regex::icase);
//	while (true) {
//		cout<<"Write a query: "<<endl;
//		getline (std::cin, input);
//		cout<<input<<endl;
		if(regex_match(input,reg1)) {
			cout<<"Match"<<endl;
		}
	//}
	return 0;
}
