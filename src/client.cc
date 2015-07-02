#include "client_net.h"
#include "interactive.h"
#include "spdlog/spdlog.h"
#include "logging.h"
#include "auth_common.h"
#include "crypto.h"
#include "packets/radius_packet.h"
#include "packets/eap_packet.h"
#include "packets/packet.h"
#include "packets/utils.h"

using namespace std;

const std::map<std::string, radius::HashAlg> HASHES_MAP = {
    {"sha256", radius::SHA256}, {"sha3", radius::SHA3}, {"md5", radius::MD5}};

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
            "", "hash", "Type of password hashing function (md5 sha256 sha3)."
                        "Defaults to plain text.",
            false, "", "string");
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
        if (hash != "" && HASHES_MAP.find(hash) == HASHES_MAP.end()) {
            std::cout << "Unrecognized hash: " << hash << std::endl;
            return 1;
        }

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

        radius::startClient(ip.c_str(), port);
        // 1.access-request
        using namespace radius;
        using namespace radius::packets;

        std::vector<radius::byte> buffer = {
            0x01, 0x01, 0x00, 0x81, 0xcd, 0x57, 0x59, 0x14, 0x7f, 0x74, 0xd4,
            0x85, 0xb4, 0x93, 0xdd, 0xd7, 0x81, 0x96, 0x4b, 0x88, 0x01, 0x09,
            0x73, 0x74, 0x65, 0x66, 0x61, 0x6e, 0x31, 0x06, 0x06, 0x00, 0x00,
            0x00, 0x02, 0x0c, 0x06, 0x00, 0x00, 0x05, 0xdc, 0x1e, 0x13, 0x30,
            0x30, 0x2d, 0x32, 0x34, 0x2d, 0x43, 0x33, 0x2d, 0x31, 0x41, 0x2d,
            0x41, 0x32, 0x2d, 0x30, 0x33, 0x1f, 0x13, 0x31, 0x30, 0x2d, 0x31,
            0x46, 0x2d, 0x37, 0x34, 0x2d, 0x46, 0x38, 0x2d, 0x45, 0x45, 0x2d,
            0x32, 0x37, 0x4f, 0x0e, 0x02, 0x02, 0x00, 0x0c, 0x01, 0x73, 0x74,
            0x65, 0x66, 0x61, 0x6e, 0x31, 0x50, 0x12, 0x3a, 0xca, 0x54, 0x12,
            0xa9, 0xec, 0xc6, 0xb3, 0x5c, 0xae, 0xac, 0x58, 0x11, 0xed, 0x69,
            0x27, 0x3d, 0x06, 0x00, 0x00, 0x00, 0x0f, 0x05, 0x06, 0x00, 0x00,
            0xc3, 0x51, 0x04, 0x06, 0xc0, 0xa8, 0x0a, 0x01};
        Packet newPack(buffer, server_addr);
        /* EapPacket eapIdentity; */
        /* eapIdentity = makeIdentity(login); */
        /* eapIdentity.setType(EapPacket::RESPONSE); */
        /* eapIdentity.setIdentifier(1); */

        /* EapMessage eapMessage; */
        /* eapMessage.setValue(eapIdentity.getBuffer()); */

        /* RadiusPacket arPacket; */
        /* arPacket.setIdentifier(1); */
        /* arPacket.setCode(RadiusPacket::ACCESS_REQUEST); */
        /* std::array<radius::byte, 16> authTable = generateRandom16(); */
        /* arPacket.setAuthenticator(authTable); */
        /* arPacket.addAVP(static_cast<const RadiusAVP &>(eapMessage)); */
        /* calcAndSetMsgAuth(arPacket, secret); */

        /* radius::packets::Packet newPack(arPacket.getBuffer(), server_addr);
         */
        /* logger->info() <<"Send Packet"; */
        /* logger->info() <<"[Packet:]\n" << packet2LogBytes(newPack.bytes); */
        /* logger->info() <<"[RadiusPacket:]\n"<< arPacket; */
        /* logger->info() <<"[EapPacket:]\n"<< eapIdentity; */

        radius::sendPacket(newPack);
        // 2.otrzymuj odpowiedz od Radius server
        /* newPack = radius::receivePack(); */

        /* RadiusPacket recArPacket(newPack.bytes); */
        /* logger->info() <<"Received Packet"; */
        /* logger->info() <<"[Packet:]\n"
         * <<packet2LogBytes(recArPacket.getBuffer()); */
        /* logger->info() <<"[RadiusPacket:]\n"<< recArPacket; */
        /* EapPacket recEapIdentity = extractEapPacket(recArPacket); */
        /* logger->info() <<"[EapPacket:]\n"<< recEapIdentity; */

        /* std::array<radius::byte,16> chalArray
         * =calcChalVal(recEapIdentity,pas); */

        /* //make response */
        /* EapPacket eapMd5Chal; */
        /* eapMd5Chal = makeChallengeResp(chalArray); */
        /* eapMd5Chal.setType(EapPacket::RESPONSE); */
        /* eapMd5Chal.setIdentifier(2); */

        /* EapMessage eapMessage2; */
        /* eapMessage2.setValue(eapMd5Chal.getBuffer()); */

        /* RadiusPacket responsePacket; */
        /* responsePacket.setIdentifier(2); */
        /* responsePacket.setCode(RadiusPacket::ACCESS_REQUEST); */
        /* authTable = generateRandom16(); */
        /* responsePacket.setAuthenticator(authTable); */
        /* responsePacket.addAVP(static_cast<const RadiusAVP &>(eapMessage2));
         */
        /* calcAndSetMsgAuth(responsePacket, secret); */

        /* radius::packets::Packet responsePack(responsePacket.getBuffer() ,
         * server_addr); */

        /* logger->info() <<"Send Packet"; */
        /* logger->info() <<"[Packet:]\n" <<
         * packet2LogBytes(responsePack.bytes); */
        /* logger->info() <<"[RadiusPacket:]\n"<< responsePacket; */
        /* logger->info() <<"[EapPacket:]\n"<< eapMd5Chal; */

        /* radius::sendPack(responsePack); */
        /* // 4.success or failure */
        /* newPack = radius::receivePack(); */

        /* RadiusPacket sucArPacket(newPack.bytes); */
        /* logger->info() <<"Received Packet"; */
        /* logger->info() <<"[Packet:]\n" <<
         * packet2LogBytes(sucArPacket.getBuffer()); */
        /* logger->info() <<"[RadiusPacket:]\n"<< sucArPacket; */
        /* EapPacket sucEapIdentity = extractEapPacket(recArPacket); */
        /* logger->info() <<"[EapPacket:]\n"<< sucEapIdentity; */
        /* if (newPack.bytes[0]==0x02) */
        /* { */
        /* logger->info() <<"ACCEPT"; */
        /* } */
        /* else if (newPack.bytes[0]==0x03	) */
        /* { */
        /* logger->error() <<"REJECT"; */
        /* } */

        radius::stopClient();

    } catch (ArgException &e) {
        cerr << "error: " << e.error() << " for arg " << e.argId() << endl;
    }
}

std::string hashString(std::string input, std::string hash) {
    const auto &it = HASHES_MAP.find(hash);
    if (it == HASHES_MAP.end()) {
        return input;
    }
    return radius::hashStr(input, it->second);
}
