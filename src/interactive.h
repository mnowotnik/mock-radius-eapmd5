#pragma once
#include <string>
/**
Safely get string from standard input ('*' instead of input when
show_asterix=true)
 */
std::string getPassword(const string &prompt);
