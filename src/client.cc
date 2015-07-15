#include "connection.h"
#include "spdlog/spdlog.h"
#include "logging.h"
#include "auth_common.h"
#include "crypto.h"
#include "tclap/CmdLine.h"
#include "packets/radius_packet.h"
#include "packets/eap_packet.h"
#include "packets/packet.h"
#include "packets/utils.h"


const std::map<std::string, radius::HashAlg> HASHES_MAP = {
    {"sha256", radius::SHA256}, {"sha3", radius::SHA3}, {"md5", radius::MD5}};

const std::string LOGGER_NAME = "client";
std::string hashString(std::string input, std::string hash);
int main(int argc, char **argv) {
    using namespace std;
    using namespace TCLAP;
    typedef unsigned short ushort;
    try {

        CmdLine cmd("NAS Test Client", ' ');

        ValueArg<string> logpathArg("l", "log",
                                    "The path where log file shall be written",
                                    false, "client.log", "string");
        cmd.add(logpathArg);

        ValueArg<string> loginArg(
            "u", "username", "The name of a user that wishes to authenticate",
            true, "", "string");
        cmd.add(loginArg);

        ValueArg<string> passArg("d", "password", "The password of a user",
                                 true, "password", "string");
        cmd.add(passArg);

        SwitchArg verboseSwitch("v", "verbose", "Run in the verbose mode",
                                false);
        cmd.add(verboseSwitch);

        ValueArg<string> secretArg("s", "secret", "The secret shared with NAS",
                                   true, "", "string");
        cmd.add(secretArg);

        ValueArg<ushort> bindPortArg("", "bind-port", "Binded port", false, 0, "number");
        cmd.add(bindPortArg);

        ValueArg<string> bindIpArg("", "bind-ip", "Binded IP address", false,
                                   "0.0.0.0", "IP");
        cmd.add(bindIpArg);

        ValueArg<ushort> portArg("p", "port", "Server port", true, 0, "number");
        cmd.add(portArg);

        ValueArg<string> ipArg("a", "address", "Server IP address", true, "",
                               "IP");
        cmd.add(ipArg);

        ValueArg<string> hashArg(
            "", "hash", "Type of password hashing function (md5 sha256 sha3 plain)."
                        "Default: plain text.",
            false, "plain", "string");
        cmd.add(hashArg);

        cmd.parse(argc, argv);

        ushort port = portArg.getValue();
        ushort bindPort = bindPortArg.getValue();
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
        if (hash != "plain" && HASHES_MAP.find(hash) == HASHES_MAP.end()) {
            logger->error()  << "Unrecognized hash: " << hash;
            return 1;
        }

        string login = loginArg.getValue();
        string pass = passArg.getValue();
        pass = hashString(pass, hash);

        // set up address 
        struct sockaddr_in server_addr;
        memset((char *)&server_addr, 0, sizeof(server_addr));
        server_addr.sin_family = AF_INET;
        server_addr.sin_addr.s_addr = INADDR_ANY;
        server_addr.sin_port = htons(port);

        radius::initBind(bindIp.c_str(), bindPort);
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
         
        logger->info() <<"Send Packet";
        logger->info() <<"[Packet:]\n" << packet2LogBytes(newPack.bytes);
        logger->info() <<"[RadiusPacket:]\n"<< arPacket;
        logger->info() <<"[EapPacket:]\n"<< eapIdentity;

        radius::sendPacket(newPack);
        // 2.otrzymuj odpowiedz od Radius server
        newPack = radius::recvPacket();

        RadiusPacket recArPacket(newPack.bytes);
        logger->info() <<"Received Packet";
        logger->info() <<"[Packet:]\n" <<packet2LogBytes(recArPacket.getBuffer());
        logger->info() <<"[RadiusPacket:]\n"<< recArPacket;
        EapPacket recEapIdentity = extractEapPacket(recArPacket);
        logger->info() <<"[EapPacket:]\n"<< recEapIdentity;

        std::array<radius::byte,16> chalArray=calcChalVal(recEapIdentity,pass);

        /* //make response */
        EapPacket eapMd5Chal;
        eapMd5Chal = makeChallengeResp(chalArray);
        eapMd5Chal.setType(EapPacket::RESPONSE);
        eapMd5Chal.setIdentifier(2);

        EapMessage eapMessage2;
        eapMessage2.setValue(eapMd5Chal.getBuffer());

        RadiusPacket responsePacket;
        responsePacket.setIdentifier(2);
        responsePacket.setCode(RadiusPacket::ACCESS_REQUEST);
        authTable = generateRandom16();
        responsePacket.setAuthenticator(authTable);
        responsePacket.addAVP(static_cast<const RadiusAVP &>(eapMessage2));
        calcAndSetMsgAuth(responsePacket, secret);

         radius::packets::Packet responsePack(responsePacket.getBuffer() ,
         server_addr);

        logger->info() <<"Send Packet";
        logger->info() <<"[Packet:]\n" <<
            packet2LogBytes(responsePack.bytes);
        logger->info() <<"[RadiusPacket:]\n"<< responsePacket;
        logger->info() <<"[EapPacket:]\n"<< eapMd5Chal;

        radius::sendPacket(responsePack);
        /* // 4.success or failure */
        newPack = radius::recvPacket();

        RadiusPacket sucArPacket(newPack.bytes);
        logger->info() <<"Received Packet";
        logger->info() <<"[Packet:]\n" <<
          packet2LogBytes(sucArPacket.getBuffer());
        logger->info() <<"[RadiusPacket:]\n"<< sucArPacket;
        EapPacket sucEapIdentity = extractEapPacket(recArPacket);
        logger->info() <<"[EapPacket:]\n"<< sucEapIdentity;
        if (newPack.bytes[0]==0x02)
        {
        logger->info() <<"ACCEPT";
        }
        else if (newPack.bytes[0]==0x03	)
        {
        logger->error() <<"REJECT";
        }

        radius::unbind();

    } catch (ArgException &e) {
        cerr << "error: " << e.error() << " for arg " << e.argId() << endl;
    }
}

std::string hashString(std::string input, std::string hash) {
    if(hash=="plain"){
        return input;
    }
    const auto &it = HASHES_MAP.find(hash);
    if (it == HASHES_MAP.end()) {
        return input;
    }
    return radius::hashStr(input, it->second);
}
