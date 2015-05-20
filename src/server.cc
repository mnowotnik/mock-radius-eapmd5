#include <iostream>
#include "tclap/CmdLine.h"

using namespace TCLAP;
using namespace std;

int main(int argc, char **argv) {
  try {

    CmdLine cmd("RADIUS Server with EAP-MD5", ' ');

    ValueArg<string> logpathArg("l", "log",
                                "The path where log file shall be written",
                                false, "server.log", "string");
    cmd.add(logpathArg);

    ValueArg<string> dbArg("d", "database",
                           "The path to the plain text file with user data",
                           false, "users.txt", "string");
    cmd.add(dbArg);

    ValueArg<string> secretArg("s", "secret", "The secret shared with NAS",
                               true, "", "string");
    cmd.add(secretArg);

    ValueArg<int> portArg("p", "port", "Binded port", true, -1, "number");
    cmd.add(portArg);

    ValueArg<string> ipArg("a", "address", "Binded IP address", true, "", "IP");

    cmd.add(ipArg);

    cmd.parse(argc, argv);

    int port = portArg.getValue();
    string ip = ipArg.getValue();
    string secret = secretArg.getValue();
    string logpath = logpathArg.getValue();
    string dbpath = dbArg.getValue();
  } catch (ArgException &e) {
    cerr << "error: " << e.error() << " for arg " << e.argId() << endl;
  }
}
