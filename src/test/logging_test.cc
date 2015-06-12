#include "packets/radius_packet.h"
#include "packets/eap_packet.h"
#include "logging.h"
#include <sstream>
#include <string>
#include <iostream>
#include "typedefs.h"
#include "catch.hpp"
#include "constants.h"

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
    REQUIRE(packet2LogBytes(RADIUS_BASE_BUF) ==
            "01 01 00 14 00 01 02 03 04 05 " + NL +
                "06 07 08 09 0A 0B 0C 0D 0E 0F ");
}

TEST_CASE("Print RadiusPacket") {
    RadiusPacket packet(RADIUS_BASE_BUF);
    std::ostringstream stream;
    stream << packet;
    // clang-format off
    REQUIRE(stream.str() ==
            "1 Code = 1(Access-Request)" + NL + 
            "1 ID = 1" + NL +
            "2 Length = 20" + NL + 
            "16 Authenticator" + NL + 
            "Attributes:" + NL + 
            "    None" + NL);
    // clang-format on
}
TEST_CASE("Print RadiusPacket with AVPs") {
    RadiusPacket packet(RADIUS_BASE_BUF);
    packet.setCode(RadiusPacket::ACCESS_ACCEPT);
    MessageAuthenticator ma;
    EapMessage em;
    packet.addAVP(static_cast<const RadiusAVP &>(ma));
    packet.addAVP(static_cast<const RadiusAVP &>(em));
    std::ostringstream stream;
    stream << packet;
    // clang-format off
    REQUIRE(stream.str() ==
            "1 Code = 2(Access-Accept)" + NL + 
            "1 ID = 1" + NL +
            "2 Length = 42" + NL + 
            "16 Authenticator" + NL + 
            "Attributes:" + NL + 
            "    18 Message Authenticator" + NL + 
            "    4 Eap-Message" + NL);
    // clang-format on
}

TEST_CASE("Print EapPacket") {
    EapPacket packet;
    std::string foo("foo");

    EapIdentity eapId;
    eapId.setIdentity(foo);

    packet.setIdentifier(1);
    packet.setType(EapPacket::SUCCESS);

    std::ostringstream stream;
    stream << packet;

    // clang-format off
    REQUIRE(stream.str() ==
            "1 Type = 3(Success)" + NL + 
            "1 ID = 1" + NL + 
            "2 Length = 4" + NL +
            "Type-data:" + NL + 
            "    None" + NL);
    // clang-format on
    packet.setType(EapPacket::REQUEST);
    packet.setData(eapId);

    stream.str("");
    stream.clear();

    stream << packet;
    // clang-format off
    REQUIRE(stream.str() ==
            "1 Type = 1(Request)" + NL + 
            "1 ID = 1" + NL + 
            "2 Length = 8" + NL +
            "Type-data:" + NL + 
            "    4 Identity: foo" + NL);
    // clang-format on
}
}
}
