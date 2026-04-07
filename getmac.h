#pragma once

#include <string>

#define MAC_LEN 6

bool get_mac(const std::string& if_name, uint8_t* mac_buf);
