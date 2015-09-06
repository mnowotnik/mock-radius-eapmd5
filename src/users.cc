#include "users.h"

namespace radius {

std::map<std::string, std::string> readUsersDb(const std::string &fileName) {

    std::string user, password, line;
    std::ifstream fileStream;
    fileStream.open(fileName);

    std::map<std::string, std::string> map;
    std::map<std::string, std::string>::iterator it = map.begin();
    if (fileStream.is_open()) {

        while (std::getline(fileStream, line)) {
            std::stringstream lineStream(line);
            std::string cell;
            while (std::getline(lineStream, cell, ',')) {
                user = cell;
                std::getline(lineStream, cell, ',');
                password = cell;
            }
            map[user] = password;
        }

    } else {
        throw FileNotFound("Cannot open the file at: " + fileName);
    }
    fileStream.close();
    return map;
}
} // namespace
