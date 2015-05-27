#include "client.h"
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

    ValueArg<string> passArg("p", "password", "The password of a user", false,
                             "", "string");
    cmd.add(passArg);

    SwitchArg interSwitch("i", "interactive",
                          "Run the client in the interactive mode", false);
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
    start(ip.c_str());
  } catch (ArgException &e) {
    cerr << "error: " << e.error() << " for arg " << e.argId() << endl;
  }
}

void start(const char *addr) {
    const int BUFLEN = 1000;
    const int PORT = 32000;
    struct sockaddr_in dest_addr;
    int s, slen=sizeof(dest_addr);
    char buf[BUFLEN];
    char message[BUFLEN];
    WSADATA wsa;
 
    //Initialise winsock
    printf("\nInitialising Winsock...");
    if (WSAStartup(MAKEWORD(2,2),&wsa) != 0)
    {
        printf("Failed. Error Code : %d",WSAGetLastError());
        exit(EXIT_FAILURE);
    }
    printf("Initialised.\n");
     
    //create socket
    if ( (s=socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) == SOCKET_ERROR)
    {
        printf("socket() failed with error code : %d" , WSAGetLastError());
        exit(EXIT_FAILURE);
    }
     
    //setup address structure
    memset((char *) &dest_addr, 0, sizeof(dest_addr));
    dest_addr.sin_family = AF_INET;
    dest_addr.sin_port = htons(PORT);
    dest_addr.sin_addr.S_un.S_addr = inet_addr(addr);
     
    //start communication
    while(1)
    {
        printf("Enter message : ");
        gets(message);
         
        //send the message
        if (sendto(s, message, strlen(message) , 0 , (struct sockaddr *) &dest_addr, slen) == SOCKET_ERROR)
        {
            printf("sendto() failed with error code : %d" , WSAGetLastError());
            exit(EXIT_FAILURE);
        }
         
        //receive a reply and print it
        //clear the buffer by filling null, it might have previously received data
        memset(buf,'\0', BUFLEN);
        //try to receive some data, this is a blocking call
        if (recvfrom(s, buf, BUFLEN, 0, (struct sockaddr *) &dest_addr, &slen) == SOCKET_ERROR)
        {
            printf("recvfrom() failed with error code : %d" , WSAGetLastError());
            exit(EXIT_FAILURE);
        }
         
        puts(buf);
    }
 
    closesocket(s);
    WSACleanup();
}
