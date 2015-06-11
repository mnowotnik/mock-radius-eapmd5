#include <iostream>
#include <thread>
#include <string>
#include <map>
#include "server.h"
#include "radius_server.h"
#include "packets/packet.h"
#include "packets/common.h"
namespace radius {
namespace packets {
// md5 of char '0'
const std::array<byte, 16> MD5_0 = {0xcf, 0xcd, 0x20, 0x84, 0x95, 0xd5,
                                    0x65, 0xef, 0x66, 0xe7, 0xdf, 0xf9,
                                    0xf9, 0x87, 0x64, 0xda};

const std::string TXT = "000";
const std::array<byte, 3> TXT_BYTES = {0x30, 0x30, 0x30};

const std::array<byte, 16> RADIUS_BASE_AUTH = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f};

const std::vector<byte> RADIUS_BASE_BUF = {0x01,       // code
                                           0x01,       // identifier
                                           0x00, 0x14, // length
                                           0x00, 0x01, 0x02, 0x03, 0x04, 0x05,
                                           0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b,
                                           0x0c, 0x0d, 0x0e, 0x0f};
const sockaddr_in DEST_ADDR = {
    AF_INET, inet_addr("192.168.1.1"),

};
const std::map<string, string> USER_MAP = {
    {"user",
     "5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8"},
    {"Tom Servo",
     "e96c3c31143412620d3d7595d71dffc3f7d35929a791adb9ac1eee72397a933e"}};
const std::string SECRET = "radius";

TEST_CASE("Create basic Packet", "[Packet]") {
    Packet pack(RADIUS_BASE_BUF, DEST_ADDR);
}

}
}
