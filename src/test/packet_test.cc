#include "packets/common.h"
#include "packets/packet.h"
#include "packets/radius_packet.h"
#include "packets/eap_packet.h"
#include "packets/utils.h"
#include "catch.hpp"
#include <array>
#include <memory>

namespace radius {
namespace packets {

namespace {
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
}

TEST_CASE("Conversion of network bytes to short", "[networkBytes2Short]") {
    std::array<byte, 2> bytes = {0x00, 0x38};
    unsigned short s = networkBytes2Short(bytes);
    REQUIRE(s == 56);
}

TEST_CASE("Conversion of short to network bytes", "[short2NetworkBytes]") {
    std::array<byte, 2> bytes;
    unsigned short s = 56;
    bytes = short2NetworkBytes(s);
    REQUIRE(bytes[0] == 0x00);
    REQUIRE(bytes[1] == 0x38);
}

TEST_CASE("Create basic RadiusPacket", "[RadiusPacket]") {
    RadiusPacket packet;
    packet.setCode(RadiusPacket::ACCESS_REQUEST);
    packet.setIdentifier(0x01);
    REQUIRE(packet.getLength() == 20);

    packet.setAuthenticator(RADIUS_BASE_AUTH);
    std::vector<byte> buffer = packet.getBuffer();

    REQUIRE(buffer.size() == 20);
    REQUIRE(buffer == RADIUS_BASE_BUF);
}

TEST_CASE("Read basic RadiusPacket", "[RadiusPacket]") {

    std::vector<byte> buffer(RADIUS_BASE_BUF);

    RadiusPacket packet(buffer);

    REQUIRE(packet.getBuffer().size() == 20);
    REQUIRE(packet.getCode() == 0x01);
    REQUIRE(packet.getIdentifier() == 0x01);
    REQUIRE(packet.getLength() == 20);
    REQUIRE(packet.getAuthenticator() == RADIUS_BASE_AUTH);
}

TEST_CASE("Check AVP types", "[RadiusAVP]") {

    NasIdentifier n;
    MessageAuthenticator m;
    NasIpAddr na;
    EapMessage em;

    REQUIRE(n.getType() == 32);
    REQUIRE(m.getType() == 80);
    REQUIRE(na.getType() == 4);
    REQUIRE(em.getType() == 79);
}

TEST_CASE("Create basic AVP and add to RadiusPacket", "[RadiusAVP]") {

    RadiusPacket packet;
    MessageAuthenticator avp = MessageAuthenticator();
    avp.setMd5(MD5_0);

    REQUIRE(avp.getValue().size() == 16);
    REQUIRE(avp.getBuffer().size() == 18);

    packet.addAVP(static_cast<const RadiusAVP &>(avp));

    REQUIRE(packet.getBuffer().size() == 38);
    REQUIRE(packet.getLength() == 38);

    std::vector<std::unique_ptr<RadiusAVP>> avpList = packet.getAVPList();
    REQUIRE(avpList.size() == 1);
    MessageAuthenticator m =
        static_cast<const MessageAuthenticator &>(*avpList[0]);
    std::array<byte, 16> rMd5 = m.getMd5();
    REQUIRE(rMd5 == MD5_0);
}

TEST_CASE("Add 3 AVP to RadiusPacket", "[RadiusAVP]") {

    RadiusPacket packet;
    MessageAuthenticator ma = MessageAuthenticator();
    ma.setMd5(MD5_0);

    packet.addAVP(static_cast<const RadiusAVP &>(ma));
    packet.addAVP(static_cast<const RadiusAVP &>(ma));

    NasIdentifier ni;
    ni.setIdentifier("foo");

    packet.addAVP(static_cast<const RadiusAVP &>(ni));

    REQUIRE(packet.getBuffer().size() == (20 + 2 * 18 + 5));
    REQUIRE(packet.getLength() == (20 + 2 * 18 + 5));

    std::vector<std::unique_ptr<RadiusAVP>> avpList = packet.getAVPList();
    REQUIRE(avpList.size() == 3);
    MessageAuthenticator m =
        static_cast<const MessageAuthenticator &>(*avpList[0]);
    MessageAuthenticator m2 =
        static_cast<const MessageAuthenticator &>(*avpList[1]);
    NasIdentifier n = static_cast<const NasIdentifier &>(*avpList[2]);

    REQUIRE(m.getMd5() == m2.getMd5());
    REQUIRE(n.getIdentifier() == "foo");
}
TEST_CASE("replacing,removing AVP", "[RadiusPacket]") {

    RadiusPacket packet(RADIUS_BASE_BUF);
    MessageAuthenticator ma = MessageAuthenticator();
    ma.setMd5(MD5_0);
    packet.addAVP(static_cast<const RadiusAVP &>(ma));

    MessageAuthenticator oMa = MessageAuthenticator(ma.getBuffer());
    oMa.setMd5(std::array<byte, 16>{});

    std::vector<byte> bufref(packet.getBufferWoAVP());
    std::vector<byte> oMaVec = oMa.getBuffer();
    bufref.insert(bufref.end(), oMaVec.begin(), oMaVec.end());
    REQUIRE(bufref.size() == 38);

    bool success = packet.replaceAVP(ma, oMa);
    REQUIRE(success == true);
    REQUIRE(bufref == packet.getBuffer());

    success = packet.removeAVP(oMa);
    REQUIRE(success == true);
    RadiusPacket op(RADIUS_BASE_BUF);
    REQUIRE(packet == op);
}

TEST_CASE("Initalize RadiusPacket with AVP byte array") {

    std::vector<byte> buffer(RADIUS_BASE_BUF);

    std::array<byte, 2> nasIpHeader = {0x04, 0x06};
    buffer.insert(buffer.end(), nasIpHeader.begin(), nasIpHeader.end());
    std::vector<byte> ip{127, 0, 0, 1};
    buffer.insert(buffer.end(), ip.begin(), ip.end());

    std::array<byte, 2> md5Header = {0x50, 0x12};
    buffer.insert(buffer.end(), md5Header.begin(), md5Header.end());
    buffer.insert(buffer.end(), MD5_0.begin(), MD5_0.end());

    std::array<byte, 2> identHeader = {0x20, 0x05};
    buffer.insert(buffer.end(), identHeader.begin(), identHeader.end());
    buffer.insert(buffer.end(), TXT_BYTES.begin(), TXT_BYTES.end());

    unsigned short size = buffer.size();
    std::array<byte, 2> sizeBytes = short2NetworkBytes(size);
    buffer[2] = sizeBytes[0];
    buffer[3] = sizeBytes[1];
    RadiusPacket packet(buffer);

    REQUIRE(packet.getBufferWoAVP().size() == 20);
    REQUIRE(packet.getBufferWoAVP() ==
            std::vector<byte>(buffer.begin(), buffer.begin() + 20));

    std::vector<std::unique_ptr<RadiusAVP>> avpList = packet.getAVPList();
    REQUIRE(avpList.size() == 3);
    NasIpAddr nasAddr = static_cast<const NasIpAddr &>(*avpList[0]);
    MessageAuthenticator ma =
        static_cast<const MessageAuthenticator &>(*avpList[1]);
    NasIdentifier ni = static_cast<const NasIdentifier &>(*avpList[2]);

    REQUIRE(nasAddr.getType() == 4);
    REQUIRE(nasAddr.getBuffer().size() == 6);
    REQUIRE(nasAddr.getLength() == 6);
    in_addr nasAddrIn;
    inet_pton(AF_INET, "127.0.0.1", &nasAddrIn);
    REQUIRE(nasAddrIn.s_addr == nasAddr.getIp().s_addr);

    REQUIRE(ni.getType() == 32);
    REQUIRE(ni.getBuffer().size() == 5);
    REQUIRE(ni.getLength() == 5);
    REQUIRE(ni.getIdentifier() == TXT);

    REQUIRE(ma.getType() == 80);
    REQUIRE(ma.getBuffer().size() == 18);
    REQUIRE(ma.getLength() == 18);
    REQUIRE(ma.getMd5() == MD5_0);
}

TEST_CASE("EapPacket integrity", "[EapPacket]") {

    std::vector<byte> buffer{0x01, 0x01, 0x00, 0x08, 0x01};
    buffer.insert(buffer.end(), TXT_BYTES.begin(), TXT_BYTES.end());

    EapIdentity eapId;
    eapId.setIdentity(TXT);

    EapPacket packet;
    packet.setData(eapId);
    packet.setIdentifier(1);
    packet.setType(EapPacket::REQUEST);

    REQUIRE(packet.getType() == EapPacket::REQUEST);
    REQUIRE(packet.getLength() == 8);
    REQUIRE(packet.getBuffer().size() == 8);
    REQUIRE(buffer == packet.getBuffer());

    EapPacket desPacket(buffer);
    REQUIRE(desPacket.getType() == EapPacket::REQUEST);
    REQUIRE(desPacket.getLength() == 8);
    REQUIRE(desPacket.getBuffer().size() == 8);
    REQUIRE(buffer == desPacket.getBuffer());
}

TEST_CASE("EapPacket extraction integrity", "[extractEapPacket]") {
    std::string longString(200, '-');

    EapPacket eapPacket;
    EapIdentity eapId;
    eapId.setIdentity(longString);
    eapPacket.setData(eapId);
    eapPacket.setIdentifier(1);
    eapPacket.setType(EapPacket::REQUEST);

    REQUIRE(eapPacket.getLength() == longString.length() + 5);

    std::vector<byte> bytes = eapPacket.getBuffer();

    std::vector<byte> bytes1(bytes.begin(), bytes.begin() + 100);
    std::vector<byte> bytes2(bytes.begin() + 100, bytes.end());
    REQUIRE((bytes1.size() + bytes2.size()) == bytes.size());

    EapMessage msg1;
    msg1.setValue(bytes1);
    EapMessage msg2;
    msg2.setValue(bytes2);

    RadiusPacket radiusPacket(RADIUS_BASE_BUF);
    REQUIRE_THROWS(extractEapPacket(radiusPacket));
    radiusPacket.addAVP(static_cast<const RadiusAVP &>(msg1));
    REQUIRE(radiusPacket.getBuffer().size() == 122);
    radiusPacket.addAVP(static_cast<const RadiusAVP &>(msg2));
    REQUIRE(radiusPacket.getBuffer().size() == 229);
    REQUIRE(radiusPacket.getAVPList().size() == 2);
    EapPacket refPacket = extractEapPacket(radiusPacket);
    REQUIRE(refPacket.getBuffer() == eapPacket.getBuffer());
}

TEST_CASE("Check EapData types", "[EapData]") {

    EapMd5Challenge ch;
    EapNak nak;
    EapIdentity id;

    REQUIRE(ch.getType() == 4);
    REQUIRE(nak.getType() == 3);
    REQUIRE(id.getType() == 1);
}
TEST_CASE("EapMd5Challenge integrity", "[EapData]") {

    std::vector<byte> md5(MD5_0.begin(), MD5_0.end());
    std::vector<byte> buffer(md5);
    std::vector<byte> eapMd5Header{0x04, 0x10};
    buffer.insert(buffer.begin(), eapMd5Header.begin(), eapMd5Header.end());

    EapMd5Challenge ch(buffer);
    REQUIRE(ch.getValueSize() == 16);
    REQUIRE(ch.getValue().size() == 16);
    REQUIRE(ch.getValue() == md5);
    REQUIRE(ch.getBuffer().size() == 18);
    REQUIRE(ch.getBuffer() == buffer);
    REQUIRE(ch.getType() == 4);

    EapMd5Challenge ch2;
    ch2.setValue(md5);
    REQUIRE(ch2.getValueSize() == 16);
    REQUIRE(ch2.getValue().size() == 16);
    REQUIRE(ch2.getValue() == md5);
    REQUIRE(ch2.getBuffer().size() == 18);
    REQUIRE(ch2.getBuffer() == buffer);
    REQUIRE(ch2.getType() == 4);
}

TEST_CASE("Invalid RadiusPacket Exception", "[RadiusPacket]") {

    // Radius packet length field value is too big
    std::vector<byte> buffer(RADIUS_BASE_BUF);
    buffer[3] = 255;
    buffer[4] = 255;
    REQUIRE_THROWS(RadiusPacket packet(buffer));

    // Radius packet length field value is too small
    buffer[3] = 0;
    buffer[4] = 1;
    REQUIRE_THROWS(RadiusPacket packet(buffer));

    // AVP "length" field value is too big
    std::array<byte, 2> inAvpH = {0x04, 0xFF};
    buffer.insert(buffer.end(), inAvpH.begin(), inAvpH.end());
    REQUIRE_THROWS(RadiusPacket packet(buffer));
}
}
}
