#include <iostream>
#include "connection.h"
#include "tclap/CmdLine.h"
#include "logging.h"
#include "csv_reader.h"
#include "radius_server.h"

const std::string LOGGER_NAME = "server";

using radius::RadiusServer;
using radius::packets::Packet;

void serverLoop(RadiusServer &radiusServer) {

    while (1) {
        Packet iPacket = radius::recvPacket();
        std::vector<Packet> packets = radiusServer.processPacket(iPacket);
        for (std::vector<Packet>::size_type i = 0; i < packets.size(); i++) {
            radius::sendPacket(packets[i]);
        }
    }
}

int main(int argc, char **argv) {
    using namespace TCLAP;
    using namespace std;
    try {

        CmdLine cmd("RADIUS Server with EAP-MD5", ' ');

        ValueArg<string> logpathArg(
            "l", "log", "The path where the log file shall be written. "
                        "Default: server.log",
            false, "server.log", "path\\to\\log.log");
        cmd.add(logpathArg);

        ValueArg<string> dbArg(
            "d", "database", "The path to the plain text file with user data. "
                             "Default: users.txt",
            false, ".\\users.txt", "path\\to\\db.csv");
        cmd.add(dbArg);

        ValueArg<string> secretArg("s", "secret", "The secret shared with NAS",
                                   true, "", "string");
        cmd.add(secretArg);

        ValueArg<int> portArg("p", "port", "Binded port", true, -1, "number");
        cmd.add(portArg);

        ValueArg<string> ipArg("a", "address", "Binded IP address", true, "",
                               "IP");

        cmd.add(ipArg);

        SwitchArg verboseSwitch("v", "verbose", "Run in the verbose mode",
                                false);
        cmd.add(verboseSwitch);

        cmd.parse(argc, argv);

        int port = portArg.getValue();
        string ip = ipArg.getValue();
        string secret = secretArg.getValue();
        string logpath = logpathArg.getValue();
        radius::initLogger(logpath, LOGGER_NAME);

        bool verbose = verboseSwitch.getValue();

        if (verbose) {
            spdlog::set_level(spdlog::level::trace);
        }

        auto logger = spdlog::get(LOGGER_NAME);

        string dbpath = dbArg.getValue();

        radius::initBind(ip.c_str(), port);
        radius::RadiusServer radiusServer(radius::readCsvFile(dbpath), secret,
                                          logger);

        logger->info() << "Started server";
        serverLoop(radiusServer);

    } catch (CmdLineParseException &ce) {
        cerr << "error: " << ce.error() << ce.argId() << endl;
    }
}
