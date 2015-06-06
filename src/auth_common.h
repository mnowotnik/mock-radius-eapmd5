#include <string>
#include <vector>
#include "packets/radius_packet.h"
#include "packets/eap_packet.h"
#include "typedefs.h"

namespace radius{


    bool checkIntegrity(const packets::RadiusPacket &packet,
            const std::string &secret,
            const std::vector<byte>&authenticator);
}
