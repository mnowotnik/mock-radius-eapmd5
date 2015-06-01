#include "packets/packet.h"
#include "packets/radius_packet.h"
#include "packets/eap_packet.h"
#include <array>

TEST_CASE( "Conversion of network bytes to short", "[networkBytes2Short]" ) {
    std::array<byte,2> bytes = {0x00,0x38};
    unsigned short s = radius::internal::networkBytes2Short(bytes);
    REQUIRE( s == 56 );
}

TEST_CASE( "Conversion of short to network bytes", "[short2NetworkBytes]" ) {
    std::array<byte,2> bytes;
    unsigned short s = 56;
    bytes = radius::internal::short2NetworkBytes(s);
    REQUIRE( bytes[0] == 0x00 );
    REQUIRE( bytes[1] == 0x38 );
}

TEST_CASE( "Create basic RadiusPacket","[RadiusPacket]") {
    RadiusPacket packet;
    packet.setCode(RadiusPacket::ACCESS_REQUEST);
    packet.setIdentifier(0x01);
    packet.setLength(20);

    packet.setAuthenticator(std::array<byte,16>({{
                0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f,
                }}));

    std::vector<byte>buffer = packet.getBuffer();

    REQUIRE(buffer.size() == 20);

    REQUIRE(buffer[0] == 0x01); //code

    REQUIRE(buffer[1] == 0x01); //identifier

    REQUIRE(buffer[2] == 0x00); //length
    REQUIRE(buffer[3] == 0x14);

    REQUIRE(buffer[4] == 0x00); //authenticator
    REQUIRE(buffer[5] == 0x01);
    REQUIRE(buffer[9] == 0x05);
    REQUIRE(buffer[18] == 0x0e);
    REQUIRE(buffer[19] == 0x0f);
}


TEST_CASE( "Read basic RadiusPacket","[RadiusPacket]"){

    std::array<byte,16> authenticator = {
        0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f
    };
    std::vector<byte>buffer = {
        0x01, //code
        0x01, //identifier
        0x00,0x14 //length
    };

    //authenticator
    buffer.insert(buffer.end(),authenticator.begin(),authenticator.end());
    RadiusPacket packet(&buffer[0],20);

    REQUIRE(packet.getBuffer().size()==20);
    REQUIRE(packet.getCode() == 0x01);
    REQUIRE(packet.getIdentifier() == 0x01);
    REQUIRE(packet.getLength() == 20);
    REQUIRE(packet.getAuthenticator() == authenticator);
}

TEST_CASE( "Create basic AVP and add to RadiusPacket", "[RadiusAVP]"){

    RadiusPacket packet;
    //md5 of char '0'
    std::array<byte,16>md5 = {
        0xcf,0xcd,0x20,0x84,0x95,0xd5,0x65,0xef,0x66,0xe7,0xdf,0xf9,0xf9,0x87,0x64,0xda
    };
    MessageAuthenticator avp = MessageAuthenticator();
    avp.setMd5(md5);

    REQUIRE(avp.getValue().size()==16);
    REQUIRE(avp.getBuffer().size()==18);

    packet.addAVP(static_cast<RadiusAVP>(avp));

    REQUIRE(packet.getBuffer().size()==38);

    std::vector<RadiusAVP>avpList = packet.getAVPList();
    REQUIRE(avpList.size()==1);
    MessageAuthenticator m = static_cast<const MessageAuthenticator&>(avpList[0]);
    std::array<byte,16>rMd5 = m.getMd5();
    REQUIRE(rMd5==md5);
}

