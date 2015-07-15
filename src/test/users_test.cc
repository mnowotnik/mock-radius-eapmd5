#include "users.h"
#include "catch.hpp"
#include <map>
#include <string>
namespace radius {
namespace {

std::map<std::string, std::string> csvData = {
    {"Mike",
     "5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8"},
    {"Kate",
     "5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8"}};
}

TEST_CASE("Simple read file test", "[readUsersDb]") {
    std::map<std::string, std::string> csvRead =
        readUsersDb("src/test/users.txt");
    REQUIRE(csvRead.find("Mike") != csvRead.end());
    REQUIRE(csvData["Kate"] == csvRead["Kate"]);
}

TEST_CASE("File doesn't exists", "[readCsvFile]") {
    REQUIRE_THROWS(readUsersDb("k.csv"));
}

} // namespace
