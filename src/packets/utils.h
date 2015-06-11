#include "packets/eap_packet.h"
#include "packets/radius_packet.h"
#include "packets/common.h"
namespace radius{
    namespace packets{
EapPacket extractEapPacket(const RadiusPacket &radiusPacket);
    }}
