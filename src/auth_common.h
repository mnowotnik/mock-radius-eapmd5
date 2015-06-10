#include <string>
#include <vector>
#include <array>
#include "packets/radius_packet.h"
#include "packets/eap_packet.h"
#include "crypto.h"
#include "typedefs.h"

namespace radius {

bool checkMessageAuthenticator(const packets::RadiusPacket &packet,
                               const std::string &secret);
bool checkAuthenticator(const packets::RadiusPacket &packet,
        const std::array<byte,16>& authenticator);
                               
bool checkIntegrity(const packets::RadiusPacket &packet, const std::string &secret,
        const std::array<byte,16> &authenticator = std::array<byte,16>{});
}
