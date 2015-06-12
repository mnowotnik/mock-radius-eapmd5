
#pragma once
#include <string>
#include <map>
#include <iostream>
#include <fstream>
#include <sstream>

namespace radius{
std::map<std::string,std::string> readCsvFile(const std::string &fileName);
}