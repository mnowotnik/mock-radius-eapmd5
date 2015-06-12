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
using packets::EapPacket;
using packets::EapData;
using packets::EapMd5Challenge;

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
    packet.addAVP(static_cast<const RadiusAVP &>(ma));

    std::array<byte, 16> md5 = md5HmacBin(packet.getBuffer(), secret);
    MessageAuthenticator oma = ma;

    REQUIRE(oma.getMd5() == EMPTY_MD5);
    ma.setMd5(md5);

    // successful hmac check
    packet.replaceAVP(static_cast<const RadiusAVP &>(oma),
                      static_cast<const RadiusAVP &>(ma));
    REQUIRE(checkMessageAuthenticator(packet, secret));

    // unsuccessful hmac check
    packet.replaceAVP(static_cast<const RadiusAVP &>(ma),
                      static_cast<const RadiusAVP &>(oma));
    REQUIRE_FALSE(checkMessageAuthenticator(packet, secret));
}

TEST_CASE("Testing ResponseAuthenticator checking", "[checkAuthenticator]") {

    RadiusPacket packet(RADIUS_BASE_BUF);
    packet.setCode(RadiusPacket::ACCESS_CHALLENGE);
    std::array<byte, 16> authen = packet.getAuthenticator();
    std::array<byte, 16> md5 = md5Bin(packet.getBuffer());
    packet.setAuthenticator(md5);

    REQUIRE(checkAuthenticator(packet, authen));

    authen[0] = 0xFF;
    REQUIRE_FALSE(checkAuthenticator(packet, authen));
}
TEST_CASE("Testing Authenticator generation", "[calcAndSetAuth]") {

    RadiusPacket packet(RADIUS_BASE_BUF);
    packet.setCode(RadiusPacket::ACCESS_CHALLENGE);
    std::array<byte, 16> md5 = calcAuthenticatorChecksum(packet);
    calcAndSetAuth(packet);

    REQUIRE(md5 == packet.getAuthenticator());
}
TEST_CASE("Testing MessageAuthenticator generation", "[calcAndSetAuth]") {
    RadiusPacket packet(RADIUS_BASE_BUF);
    packet.setCode(RadiusPacket::ACCESS_CHALLENGE);
    MessageAuthenticator ma;
    ma.setMd5(EMPTY_MD5);
    packet.addAVP(ma);
    MessageAuthenticator nMa;
    std::array<byte, 16> md5 = md5HmacBin(packet.getBuffer(), secret);
    calcAndSetMsgAuth(packet, secret);

    std::unique_ptr<MessageAuthenticator> pMa(findMessageAuthenticator(packet));
    REQUIRE(md5 == pMa->getMd5());
}
TEST_CASE("Testing MessageAuthenticator generation(with init)",
          "[calcAndSetAuth]") {
    RadiusPacket packet(RADIUS_BASE_BUF);
    packet.setCode(RadiusPacket::ACCESS_CHALLENGE);
    MessageAuthenticator ma;
    ma.setMd5(EMPTY_MD5);
    packet.addAVP(ma);
    MessageAuthenticator nMa;
    std::array<byte, 16> md5 = md5HmacBin(packet.getBuffer(), secret);
    packet.removeAVP(ma);
    calcAndSetMsgAuth(packet, secret);

    std::unique_ptr<MessageAuthenticator> pMa(findMessageAuthenticator(packet));
    REQUIRE(md5 == pMa->getMd5());
}
TEST_CASE("Testing generate random bytes", "[generateRandomBytes]") {
    int i;
    for (i = 0; i < 15; i++) {
        std::vector<byte> gen1 =
            generateRandomBytes((unsigned int)5, (unsigned int)5);
        std::vector<byte> gen2 =
            generateRandomBytes((unsigned int)5, (unsigned int)5);
        REQUIRE(gen1.size() == 20);
        REQUIRE_FALSE(gen1 == gen2);
    }
}

TEST_CASE("Testing min max", "[generateRandomBytes]") {
    int i;
    for (i = 0; i < 26; i++) {
        std::vector<byte> gen1 =
            generateRandomBytes((unsigned int)6, (unsigned int)9);

        REQUIRE(gen1.size() >= 6 * 4);
        REQUIRE(gen1.size() <= 9 * 4);
    }
}

TEST_CASE("Calculate challenge value", "[calcChalVal]") {
    std::vector<byte> buffer;
    const byte ident = 1;
    buffer.push_back(ident);
    buffer.insert(buffer.end(), secret.begin(), secret.end());
    buffer.insert(buffer.end(), EMPTY_MD5.begin(), EMPTY_MD5.end());

    EapPacket packet;
    packet.setIdentifier(ident);
    EapMd5Challenge md5Chal;
    md5Chal.setValue(std::vector<byte>(EMPTY_MD5.begin(), EMPTY_MD5.end()));
    packet.setData(dynamic_cast<const EapData &>(md5Chal));
    REQUIRE(md5Bin(buffer) == calcChalVal(packet, secret));
}
}
