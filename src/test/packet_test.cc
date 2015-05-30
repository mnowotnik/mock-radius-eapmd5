#include "packet.h"
#include <array>


typedef unsigned char byte;

TEST_CASE( "Conversion of network bytes to short", "[networkBytes2Short]" ) {
    std::array<byte,2> bytes = {0x00,0x38};
    short s = radius::internal::networkBytes2Short(bytes);
    REQUIRE( s == 56 );
}

TEST_CASE( "Conversion of short to network bytes", "[short2NetworkBytes]" ) {
    std::array<byte,2> bytes;
    unsigned short s = 56;
    bytes = radius::internal::short2NetworkBytes(s);
    REQUIRE( bytes[0] == 0x00 );
    REQUIRE( bytes[1] == 0x38 );
}
