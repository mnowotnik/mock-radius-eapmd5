#include "logging.h"
using radius::packets::RadiusPacket;

namespace radius {
std::string packet2Log(const RadiusPacket &packet) {
    std::string log = "";

    log += "1 Code = " + std::to_string(packet.getCode()) + '\n';
    log += "1 ID = " + std::to_string(packet.getIdentifier()) + '\n';
    log += "2 Length = " + std::to_string(packet.getLength()) + '\n';
    /* log += "16 Request Authenticator = " + */
    /*        std::string(packet.getAuthenticator().begin(), */
    /*                    packet.getAuthenticator().end()) + */
           '\n';
    log += "Attributes: \n";
    for (const auto &attribute : packet.getAVPList()) {
        log += std::to_string(attribute->getLength()) + " ";
        log += std::to_string(attribute->getType()) + " ";
        log += '\n';
        /* log += "= " + std::string(attribute->getValue().begin(), */
        /*                           attribute->getValue().end()) + */
    }

    return log;
}
std::string packet2LogBytes(const RadiusPacket &packet) {
    std::string log =
        std::string(packet.getBuffer().begin(), packet.getBuffer().end());
    return log;
}
}
