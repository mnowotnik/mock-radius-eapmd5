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
    std::string log ="";
	for(int i =0;i<(packet.getBuffer()).size();i++) {
		log+= byte2hex(packet.getBuffer()[i]);
	}
    return log;
}
std::string byte2hex(const byte &byte){
	char buf[5];
	sprintf(buf,"%02X ",byte);
	std::string out =buf;
	return out;
}
}
