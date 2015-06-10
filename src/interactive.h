#pragma once
#include <string>
/**
Safely get string from standard input ('*' instead of input when
show_asterix=true)
 */
 namespace radius{
std::string getPassword(const std::string &prompt);
std::string getUsername();
 }
