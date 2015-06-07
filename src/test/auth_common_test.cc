#include "auth_common.h"
#include "packets/radius_packet.h"
#include "packets/eap_packet.h"
#include "crypto.h"
#include "catch.hpp"
#include <string>
#include <array>

namespace radius {
using packets::RadiusPacket;
using packets::MessageAuthenticator;
using packets::RadiusAVP;

namespace {
const std::vector<byte> RADIUS_BASE_BUF = {0x01,       // code
                                           0x01,       // identifier
                                           0x00, 0x14, // length
                                           0x00, 0x01, 0x02, 0x03, 0x04, 0x05,
                                           0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b,
                                           0x0c, 0x0d, 0x0e, 0x0f};

const std::array<byte, 16> EMPTY_MD5{};
const std::string secret = "secret";
}

TEST_CASE("Testing MessageAuthenticator checking",
          "[checkMessageAuthenticator]") {
    RadiusPacket packet(RADIUS_BASE_BUF);
    MessageAuthenticator ma;
    ma.setMd5(EMPTY_MD5);
    packet.addAVP(static_cast<RadiusAVP>(ma));

    std::array<byte, 16> md5 = crypto::md5HmacBin(packet.getBuffer(), secret);
    MessageAuthenticator oma = ma;

    REQUIRE(oma.getMd5() == EMPTY_MD5);
    ma.setMd5(md5);

    // successful hmac check
    packet.replaceAVP(static_cast<RadiusAVP>(oma), static_cast<RadiusAVP>(ma));
    bool success = checkMessageAuthenticator(packet, secret);
    REQUIRE(success == true);

    // unsuccessful hmac check
    packet.replaceAVP(static_cast<RadiusAVP>(ma), static_cast<RadiusAVP>(oma));
    success = checkMessageAuthenticator(packet, secret);
    REQUIRE(success == false);
}
}
