#include "csv_reader.h"
#include "catch.hpp"
#include <map>
#include <string>
namespace radius{
namespace{
	
std::map<std::string,std::string> csvData = {{"Micha³","5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8"},
{"Basia","5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8"}
,{"Ryœ","5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8"}};
}
TEST_CASE("Simple read file test", "[csvRead]") { 
std::map<std::string,std::string> csvRead = readCsvFile("src/test/csv.csv");
REQUIRE(csvRead.find("Basia") != csvRead.end());
REQUIRE(csvData["Basia"] == csvRead["Basia"]);
 }
}//namespace
