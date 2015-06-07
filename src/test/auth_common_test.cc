#include "auth_common.h"
#include "packets/radius_packet.h"
#include "packets/eap_packet.h"
#include "catch.hpp"

namespace radius {
    
    namespace{
        const std::vector<byte> RADIUS_BASE_BUF = {0x01,       // code
            0x01,       // identifier
            0x00, 0x14, // length
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05,
            0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b,
            0x0c, 0x0d, 0x0e, 0x0f};
    
    }

    TEST_CASE("auth test"){
    
    }

}
