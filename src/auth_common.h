#include <string>
#include <vector>
#include <array>
#include "packets/radius_packet.h"
#include "packets/eap_packet.h"
#include "crypto.h"
#include "typedefs.h"

namespace radius{


    bool checkMessageAuthenticator(const packets::RadiusPacket &packet,const std::string &secret);
    bool checkIntegrity(const packets::RadiusPacket &packet,
            const std::string &secret,
            const std::vector<byte>&authenticator=std::vector<byte>());
}
