#include <iostream>
#include "tclap/CmdLine.h"
#include "crypto.h"

using namespace TCLAP;
using namespace std;

int main(int argc, char **argv) {
  try {

    CmdLine cmd("NAS Test Client", ' ');

    ValueArg<string> logpathArg("l", "log",
                                "The path where log file shall be written",
                                false, "server.log", "string");
    cmd.add(logpathArg);

    ValueArg<string> loginArg("u", "username",
            "The name of a user that wishes to authenticate",
                           false, "", "string");
    cmd.add(loginArg);

    ValueArg<string> passArg("p", "password",
            "The password of a user",
                           false, "", "string");
    cmd.add(passArg);

    SwitchArg interSwitch("i","interactive","Run the client in the interactive mode",false);
    cmd.add(interSwitch);

    ValueArg<string> secretArg("s", "secret", "The secret shared with NAS",
                               true, "", "string");
    cmd.add(secretArg);

    ValueArg<int> portArg("", "port", "Binded port", false, -1, "number");
    cmd.add(portArg);

    ValueArg<string> ipArg("a", "address", "Binded IP address", true, "", "IP");

    cmd.add(ipArg);

    cmd.parse(argc, argv);

    int port = portArg.getValue();
    string ip = ipArg.getValue();
    string secret = secretArg.getValue();
    string logpath = logpathArg.getValue();

    string login = loginArg.getValue();
    string pas = passArg.getValue();
    bool inter = interSwitch.getValue();
  } catch (ArgException &e) {
    cerr << "error: " << e.error() << " for arg " << e.argId() << endl;
  }
}
