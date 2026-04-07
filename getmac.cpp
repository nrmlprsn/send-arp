#include <regex>
#include <fstream>
#include <streambuf>
using namespace std;

bool get_mac(const string& if_name, uint8_t* mac_buf){
	string mac;
	ifstream iface("/sys/class/net/" + if_name + "/address");
	string str((istreambuf_iterator<char>(iface)), istreambuf_iterator<char>());
	if(str.length() > 0){
		string hex = regex_replace(str, regex(":"), "");
		uint64_t result = stoull(hex, 0, 16);
		for(int i=0;i<MAC_LEN;i++)
			mac_buf[i] = (uint8_t)((result & ((uint64_t)0xFF << (i*8))) >> (i*8));
		return true;
	}
	return false;
}
