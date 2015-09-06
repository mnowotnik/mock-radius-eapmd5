#include <iostream>
#include "connection.h"
#include "tclap/CmdLine.h"
#include "logging.h"
#include "users.h"
#include "exception.h"
#include "radius_server.h"

const std::string LOGGER_NAME = "server";

using radius::RadiusServer;
using radius::packets::Packet;

void serverLoop(RadiusServer &radiusServer) {

    while (1) {
        Packet packet = radius::recvPacket(); //TODO add timeout
        std::vector<Packet> packets = radiusServer.processPacket(packet);
        for (std::vector<Packet>::size_type i = 0; i < packets.size(); i++) {
            radius::sendPacket(packets[i]);
        }
    }
}

int main(int argc, char **argv) {
    using namespace TCLAP;
    using namespace std;
    typedef unsigned short ushort;
    try {

        CmdLine cmd("RADIUS Server with EAP-MD5", ' ');

        ValueArg<string> logpathArg(
            "l", "log", "The path where the log file shall be written. "
                        "Default: ./server.log",
            false, "server.log", "path/to/log.log");
        cmd.add(logpathArg);

        ValueArg<string> dbArg(
            "d", "database", "The path to the plain text file with user data. "
                             "Default: ./users.txt",
            false, "users.txt", "path/to/users.txt");
        cmd.add(dbArg);

        ValueArg<string> secretArg("s", "secret", "The secret shared with NAS",
                                   true, "", "string");
        cmd.add(secretArg);

        ValueArg<ushort> portArg("p", "port", "Binded port", true, 0, "number");
        cmd.add(portArg);

        ValueArg<string> ipArg("a", "address", "Binded IP address", true, "",
                               "IP");

        cmd.add(ipArg);

        MultiSwitchArg verboseSwitch("v", "verbose", "Run in the verbose mode",
                                false);
        cmd.add(verboseSwitch);

        cmd.parse(argc, argv);

        ushort port = portArg.getValue();
        string ip = ipArg.getValue();
        string secret = secretArg.getValue();
        string logpath = logpathArg.getValue();
        radius::initLogger(logpath, LOGGER_NAME);

        int verbose = verboseSwitch.getValue();

        if (verbose==1) {
            spdlog::set_level(spdlog::level::debug);
        }else if(verbose==2){
            spdlog::set_level(spdlog::level::trace);
        }

        auto logger = spdlog::get(LOGGER_NAME);

        string dbpath = dbArg.getValue();

        radius::initBind(ip.c_str(), port);

        try{
            radius::RadiusServer radiusServer(radius::readUsersDb(dbpath), secret,
                    logger,radius::AuthMode::EAP_MD5);
            logger->info() << "Started server";
            serverLoop(radiusServer);
        }catch(radius::FileNotFound &e){
            logger->error() << "error: "<<e.what();
            return 1;
        }


    } catch (CmdLineParseException &ce) {
        std::cerr << "error: " << ce.error() << ce.argId() << endl;
    }
}
