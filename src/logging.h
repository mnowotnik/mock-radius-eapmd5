#include "packets/radius_packet.h"
#include "packets/eap_packet.h"
#include <string>
namespace radius {
std::string packet2Log(const packets::RadiusPacket &packet);
std::string packet2LogBytes(const packets::RadiusPacket &packet);
}
