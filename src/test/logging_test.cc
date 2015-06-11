#include "packets/radius_packet.h"
#include "packets/eap_packet.h"
#include "logging.h"
#include <sstream>
#include <string>
#include <iostream>
#include "typedefs.h"
#include "catch.hpp"

namespace radius {
namespace packets {

namespace {
const std::vector<radius::byte> RADIUS_BASE_BUF = {
    0x01,       // code
    0x01,       // identifier
    0x00, 0x14, // length
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f};
}



TEST_CASE("Print bytes of RadiusPacket", "[packet2LogBytes]") {
    RadiusPacket packet(RADIUS_BASE_BUF);
    std::string logStr = packet2LogBytes(packet);

    REQUIRE(logStr == "01 01 00 14 00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F ");
}

TEST_CASE("Print RadiusPacket"){
    RadiusPacket packet(RADIUS_BASE_BUF);
    std::ostringstream stream;
    stream << packet;
    REQUIRE(stream.str() == 
            "1 Code = 1(Access-Request)\n"
            "1 ID = 1\n"
            "2 Length = 20\n"
            "16 Authenticator\n"
            "Attributes:\n"
            "    None\n");
}
TEST_CASE("Print RadiusPacket with AVPs"){
    RadiusPacket packet(RADIUS_BASE_BUF);
    MessageAuthenticator ma;
    EapMessage em;
    packet.addAVP(static_cast<const RadiusAVP&>(ma));
    packet.addAVP(static_cast<const RadiusAVP&>(em));
    std::ostringstream stream;
    stream << packet;
    REQUIRE(stream.str() == 
            "1 Code = 1(Access-Request)\n"
            "1 ID = 1\n"
            "2 Length = 42\n"
            "16 Authenticator\n"
            "Attributes:\n"
            "    18 Message Authenticator\n"
            "    4 Eap-Message\n");
}

TEST_CASE("Print EapPacket"){
    EapPacket packet;




}

}
}
