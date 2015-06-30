#ifndef CSV_READER_H_STA6WQ2C
#define CSV_READER_H_STA6WQ2C

#include <string>
#include <map>
#include <iostream>
#include <fstream>
#include <sstream>
#include "exception.h"

namespace radius {
std::map<std::string, std::string> readCsvFile(const std::string &fileName);
}


#endif /* end of include guard: CSV_READER_H_STA6WQ2C */
