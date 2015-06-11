#include "client_net.h"
#include "interactive.h"
#include "crc32.h"
#include "md5.h"
#include "sha1.h"
#include "sha256.h"
#include "sha3.h"
#include "spdlog/spdlog.h"
#include "logging.h"
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
            false, "", "string");
        cmd.add(loginArg);

        ValueArg<string> passArg("p", "password", "The password of a user",
                                 false, "", "string");
        cmd.add(passArg);

        SwitchArg interSwitch("i", "interactive",
                              "Run the client in the interactive mode", false);
        cmd.add(interSwitch);

        ValueArg<string> secretArg("s", "secret", "The secret shared with NAS",
                                   true, "", "string");
        cmd.add(secretArg);

        ValueArg<int> portArg("", "port", "Binded port", false, 8080, "number");
        cmd.add(portArg);

        ValueArg<string> ipArg("a", "address", "Binded IP address", false,
                               "127.0.0.1", "IP");
        cmd.add(ipArg);

        ValueArg<string> hashArg(
            "", "hash", "Type of hashing function (crc32 md5 sha1 sha256 sha3)",
            false, "", "string");
        cmd.add(hashArg);

        cmd.parse(argc, argv);

        int port = portArg.getValue();
        string ip = ipArg.getValue();
        string secret = secretArg.getValue();
        string logpath = logpathArg.getValue();
        radius::initLogger(logpath, LOGGER_NAME);

        auto logger = spdlog::get(LOGGER_NAME);

        string hash = hashArg.getValue();

        string login = loginArg.getValue();
        string pas = passArg.getValue();
        bool inter = interSwitch.getValue();
        // setup address structure //adres serwera
        struct sockaddr_in server_addr;
        memset((char *)&server_addr, 0, sizeof(server_addr));
        server_addr.sin_family = AF_INET;
        server_addr.sin_addr.s_addr = INADDR_ANY;
        server_addr.sin_port = htons(port);

        if (inter) {
            login = radius::getUsername();
            pas = radius::getPassword("Enter password:\n");
        }
        pas = hashString(pas, hash);

        radius::packets::Packet newPack(temp, server_addr);
        // printf("send data:\n");
        // printf("%d\n",newPack.bytes[0]);
        radius::startClient(ip.c_str(), port);
        // 1.access-request
        radius::sendPack(newPack);
        // 2.otrzymuj odpowiedz od Radius server
        newPack = radius::receivePack();
        // 3.access-request z hashem
        radius::sendPack(newPack);
        // 4.success or failure
        newPack = radius::receivePack();
        printf("recieve data:\n");
        printf("%d", newPack.bytes[0]);
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
