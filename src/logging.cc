#include "logging.h"

using radius::packets::RadiusPacket;

namespace radius {
    namespace{

std::string byte2hex(const byte &byte){
	char buf[5];
	sprintf(buf,"%02X ",byte);
	std::string out =buf;
	return out;
}
}

std::string packet2LogBytes(const RadiusPacket &packet) {
    std::string log ="";
	for(int i =0;i<(packet.getBuffer()).size();i++) {
		log+= byte2hex(packet.getBuffer()[i]);
	}
    return log;
}

void initLoggers(){

}
}
