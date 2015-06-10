#include "client_net.h"
#include "interactive.h"

using namespace TCLAP;
using namespace std;
        const std::vector<byte> temp = 
        {0xe0,0xbd,0x18,0xdb,0x4c,0xc2,0xf8,0x5c,
            0xed,0xef,0x65,0x4f,0xcc,0xc4,0xa4,0xd8};
int main(int argc, char **argv) {
    try {

        CmdLine cmd("NAS Test Client", ' ');

        ValueArg<string> logpathArg("l", "log",
                                    "The path where log file shall be written",
                                    false, "server.log", "string");
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

        ValueArg<string> ipArg("a", "address", "Binded IP address", false, "127.0.0.1","IP");

        cmd.add(ipArg);

        cmd.parse(argc, argv);

        int port = portArg.getValue();
        string ip = ipArg.getValue();
        string secret = secretArg.getValue();
        string logpath = logpathArg.getValue();

        string login = loginArg.getValue();
        string pas = passArg.getValue();
        bool inter = interSwitch.getValue();
				// setup address structure //adres serwera
		struct sockaddr_in server_addr;
		memset((char *)&server_addr, 0, sizeof(server_addr));
		server_addr.sin_family = AF_INET;
		server_addr.sin_addr.s_addr = INADDR_ANY;
		server_addr.sin_port = htons(port);
	
		if (inter){
			login=radius::getUsername();
			pas=radius::getPassword("Enter password:\n");
		}
		
		radius::packets::Packet newPack(temp,server_addr);
		//printf("send data:\n");
		//printf("%d\n",newPack.bytes[0]);
        radius::startClient(ip.c_str(),port);
		radius::sendPack(newPack);
		newPack = radius::receivePack();
		printf("recieve data:\n");
		printf("%d",newPack.bytes[0]);
		radius::stopClient();

    } catch (ArgException &e) {
        cerr << "error: " << e.error() << " for arg " << e.argId() << endl;
    }
	

}


