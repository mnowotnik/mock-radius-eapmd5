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
std::string code2string(int code){
	switch (code)
	{
		case 1:
		return "Access-Request";
		case 2:
		return "Access-Accept";
		case 3:
		return "Access-Reject";
		case 4:
		return "Accounting-Request";
		case 5:
		return "Accounting-Response";
		case 11:
		return "Access-Challenge";
		case 12:
		return "Status-Server (experimental)";
		case 13:
		return "Status-Client (experimental";
		default:
		return "reserved";
		
	}
}
}



std::string packet2Log(const RadiusPacket &packet) {
    std::string log = "";

    log += "1 Code = " + std::to_string(packet.getCode()) + '('+code2string(packet.getCode())+')'+'\n';
    log += "1 ID = " + std::to_string(packet.getIdentifier()) + '\n';
    log += "2 Length = " + std::to_string(packet.getLength()) + '\n'+'\n';
    log += "16 Request Authenticator\n";
    /*        std::string(packet.getAuthenticator().begin(), */
    /*                    packet.getAuthenticator().end()) + */
           '\n';
    log += "Attributes: \n";
	//log +=	"8  User-Name (1) =" + packet.getValue();

    return log;
}
std::string packet2LogBytes(const RadiusPacket &packet) {
    std::string log ="";
	for(int i =0;i<(packet.getBuffer()).size();i++) {
		log+= byte2hex(packet.getBuffer()[i]);
	}
    return log;
}
}
