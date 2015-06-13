#include "client_net.h"
#include "interactive.h"
#include "crc32.h"
#include "md5.h"
#include "sha1.h"
#include "sha256.h"
#include "sha3.h"
#include "spdlog/spdlog.h"
#include "logging.h"
#include "auth_common.h"
#include "packets/radius_packet.h"
#include "packets/eap_packet.h"
#include "packets/packet.h"
#include "packets/utils.h"

using namespace std;
const std::vector<byte> temp = {0xe0, 0xbd, 0x18, 0xdb, 0x4c, 0xc2, 0xf8, 0x5c,
                                0xed, 0xef, 0x65, 0x4f, 0xcc, 0xc4, 0xa4, 0xd8};

const std::string LOGGER_NAME = "client";
std::string hashString(std::string input, std::string hash);
int main(int argc, char **argv) {
    using namespace TCLAP;
    try {

        CmdLine cmd("NAS Test Client", ' ');

        ValueArg<string> logpathArg("l", "log",
                                    "The path where log file shall be written",
                                    false, "client.log", "string");
        cmd.add(logpathArg);

        ValueArg<string> loginArg(
            "u", "username", "The name of a user that wishes to authenticate",
            false, "Basia", "string");
        cmd.add(loginArg);

        ValueArg<string> passArg("", "password", "The password of a user",
                                 false, "password", "string");
        cmd.add(passArg);

        /*         SwitchArg interSwitch("i", "interactive", */
        /*                               "Run in the interactive mode", false);
         */
        /*         cmd.add(interSwitch); */

        SwitchArg verboseSwitch("v", "verbose", "Run in the verbose mode",
                                false);
        cmd.add(verboseSwitch);

        ValueArg<string> secretArg("s", "secret", "The secret shared with NAS",
                                   true, "", "string");
        cmd.add(secretArg);

        ValueArg<int> portArg("p", "port", "Binded port", false, 0, "number");
        cmd.add(portArg);

        ValueArg<string> bindIpArg("b", "bind-ip", "Binded IP address", false,
                                   "0.0.0.0", "IP");

        cmd.add(bindIpArg);

        ValueArg<string> ipArg("a", "address", "Server IP address", true, "",
                               "IP");

        cmd.add(ipArg);

        ValueArg<string> hashArg(
            "", "hash", "Type of hashing function (crc32 md5 sha1 sha256 sha3)",
            false, "sha256", "string");
        cmd.add(hashArg);

        cmd.parse(argc, argv);

        int port = portArg.getValue();
        string ip = ipArg.getValue();
        string bindIp = ipArg.getValue();
        string secret = secretArg.getValue();
        string logpath = logpathArg.getValue();
        radius::initLogger(logpath, LOGGER_NAME);

        bool verbose = verboseSwitch.getValue();
        if (verbose) {
            spdlog::set_level(spdlog::level::trace);
        }

        auto logger = spdlog::get(LOGGER_NAME);

        string hash = hashArg.getValue();

        string login = loginArg.getValue();
        string pas = passArg.getValue();
        /* bool inter = interSwitch.getValue(); */
        // setup address structure //adres serwera
        struct sockaddr_in server_addr;
        memset((char *)&server_addr, 0, sizeof(server_addr));
        server_addr.sin_family = AF_INET;
        server_addr.sin_addr.s_addr = INADDR_ANY;
        server_addr.sin_port = htons(port);

        /* if (inter) { */
        /*     login = radius::getUsername(); */
        /*     pas = radius::getPassword("Enter password:\n"); */
        /* } */
        pas = hashString(pas, hash);

        // radius::packets::Packet newPack(temp, server_addr);

        radius::startClient(ip.c_str(), port);
        // 1.access-request
        using namespace radius;
        using namespace radius::packets;
			EapPacket eapIdentity;
			eapIdentity = makeIdentity(login);
			eapIdentity.setType(EapPacket::RESPONSE);
			eapIdentity.setIdentifier(1);

			EapMessage eapMessage;
			eapMessage.setValue(eapIdentity.getBuffer());

			RadiusPacket arPacket;
			arPacket.setIdentifier(1);
			arPacket.setCode(RadiusPacket::ACCESS_REQUEST);
			std::array<radius::byte, 16> authTable = generateRandom16();
			arPacket.setAuthenticator(authTable);
			arPacket.addAVP(static_cast<const RadiusAVP &>(eapMessage));
			calcAndSetMsgAuth(arPacket, secret);

        radius::packets::Packet newPack(arPacket.getBuffer(), server_addr);
		
        logger->info() <<"[Packet:]\n" << packet2LogBytes(newPack.bytes);
		logger->info() <<"[RadiusPacket:]\n"<< arPacket;
		logger->info() <<"[EapPacket:]\n"<< eapIdentity;
			
        radius::sendPack(newPack);
        // 2.otrzymuj odpowiedz od Radius server
        newPack = radius::receivePack();
		
			RadiusPacket recArPacket(newPack.bytes);
            logger->info() <<"[Packet:]\n" <<packet2LogBytes(recArPacket.getBuffer());
				
		logger->info() <<"[RadiusPacket:]\n"<< recArPacket;
		EapPacket recEapIdentity = extractEapPacket(recArPacket);
		logger->info() <<"[EapPacket:]\n"<< recEapIdentity;
			
		//make response
		EapPacket eapIdentity2;
		eapIdentity2.setType(EapPacket::RESPONSE);
		eapIdentity2.setIdentifier(2);
			
			EapMessage eapMessage2;
			eapMessage2.setValue(eapIdentity2.getBuffer());
			
		RadiusPacket responsePacket;
		responsePacket.setIdentifier(2);
		responsePacket.setCode(RadiusPacket::ACCESS_REQUEST);
		authTable = generateRandom16();
		responsePacket.setAuthenticator(authTable);
			
			responsePacket.addAVP(static_cast<const RadiusAVP &>(eapMessage2));

			

				
		        /* radius::packets::Packet responsePack(responsePacket.getBuffer() , server_addr); */
		

        /* radius::sendPack(responsePack); */
        // 4.success or failure
        /* newPack = radius::receivePack(); */

        radius::stopClient();

    } catch (ArgException &e) {
        cerr << "error: " << e.error() << " for arg " << e.argId() << endl;
    }
}

std::string hashString(std::string input, std::string hash) {
    std::string output;

    if (hash == "sha256") {
        SHA256 sha256;
        output = sha256(input);
    } else if (hash == "sha1") {
        SHA1 sha1;
        output = sha1(input);
    } else if (hash == "sha3") {
        SHA3 sha3;
        output = sha3(input);
    } else if (hash == "md5") {
        MD5 md5;
        output = md5(input);
    } else if (hash == "crc32") {
        CRC32 crc32;
        output = crc32(input);
    } else {
        output = input;
    }
    return output;
}
