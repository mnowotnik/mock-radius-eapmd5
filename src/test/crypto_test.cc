#include "crypto.h"
#include "catch.hpp"
#include "typedefs.h"
#include <vector>
#include <string>
#include <array>
namespace radius {

namespace {
const std::string secret = "secret";
const std::vector<byte> msg = {0x66, 0x6f, 0x6f}; // string 'foo'
const std::array<byte, 16> msgMd5 = {0xac, 0xbd, 0x18, 0xdb, 0x4c, 0xc2,
                                     0xf8, 0x5c, 0xed, 0xef, 0x65, 0x4f,
                                     0xcc, 0xc4, 0xa4, 0xd8};
const std::array<byte, 16> msgHmacMd5 = {0xba, 0x19, 0xfb, 0xc6, 0x06, 0xa9,
                                         0x60, 0x05, 0x1b, 0x60, 0x24, 0x4e,
                                         0x9a, 0x5e, 0xd3, 0xd2};
}

TEST_CASE("md5 correctness test", "[md5Bin]") {
    std::array<byte, 16> md5 = md5Bin(msg);
    REQUIRE(md5 == msgMd5);
}

TEST_CASE("hmac-md5 correctness test", "[hmacMd5Bin]") {
    std::array<byte, 16> hmacMd5 = md5HmacBin(msg, secret);
    REQUIRE(hmacMd5 == msgHmacMd5);
}
}
