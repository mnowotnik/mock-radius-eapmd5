#include "client_net.h"
#include <vector>
namespace radius{
	const int BUFLEN = 1000;
    int PORT = 32000;
    static struct sockaddr_in dest_addr;
    int s, slen = sizeof(dest_addr);
	bool isRunning;
	
	

void startClient(const char *addr,const int port){
	PORT=port;
	if (isRunning)
	{
		return;
	}
    //char buf[BUFLEN];
    //char message[BUFLEN];
	
    WSADATA wsa;

    // Initialise winsock
   // printf("\nInitialising Winsock...");
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
        printf("Failed. Error Code : %d", WSAGetLastError());
        exit(EXIT_FAILURE);
    }
   // printf("Initialised.\n");

    // create socket
    if ((s = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) == SOCKET_ERROR) {
        printf("socket() failed with error code : %d", WSAGetLastError());
        exit(EXIT_FAILURE);
    }
	
	// setup address structure
    memset((char *)&dest_addr, 0, sizeof(dest_addr));
    dest_addr.sin_family = AF_INET;
    dest_addr.sin_port = htons(PORT);
    dest_addr.sin_addr.S_un.S_addr = inet_addr(addr);
	
	//Client is running
	isRunning=true;
}

void stopClient(){
    closesocket(s);
    WSACleanup();
	isRunning=false;
	}

void sendPack(packets::Packet sen_pack){
	if (!isRunning)
	{
		exit(EXIT_FAILURE);
	}
			//sockaddr_in dest_addr =sen_pack.addr;
			std::vector<char> buf(&(sen_pack.bytes[0]),&(sen_pack.bytes[sen_pack.bytes.size()-1]));
	        if (sendto(s, &buf[0], 8, 0,
                   (struct sockaddr *)&dest_addr, slen) == SOCKET_ERROR){
            printf("sendto() failed with error code : %d", WSAGetLastError());
            exit(EXIT_FAILURE);
        }
		// receive a reply and print it
}

packets::Packet receivePack(){
		if (!isRunning)
	{
		exit(EXIT_FAILURE);
	}
        // data
		std::vector<char> buf(BUFLEN,'\0');
        // try to receive some data, this is a blocking call
        if (recvfrom(s, &buf[0], BUFLEN, 0, (struct sockaddr *)&dest_addr, &slen) ==
            SOCKET_ERROR) {
            printf("recvfrom() failed with error code : %d", WSAGetLastError());
            exit(EXIT_FAILURE);
        }
		
		std::vector<byte> buffr(&buf[0],&buf[BUFLEN]);
        radius::packets::Packet rec_pack(buffr,dest_addr);
		return rec_pack;
}



}//radius