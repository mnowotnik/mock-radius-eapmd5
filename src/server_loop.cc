#include <iostream>
#include "server_loop.h"
#include <vector>
#include "packets/Packet.h"

void start(const char *addr) {
    using std::vector;
SOCKET s;
    const int BUFLEN = 1000;
    const int PORT = 32000;
    struct sockaddr_in server, dest_addr;
    int slen , recv_len;
    vector<char> buf(BUFLEN,'\0');

    WSADATA wsa;
 
    slen = sizeof(dest_addr) ;
     
    //Initialise winsock
    printf("\nInitialising Winsock...");
    if (WSAStartup(MAKEWORD(2,2),&wsa) != 0)
    {
        printf("Failed. Error Code : %d",WSAGetLastError());
        exit(EXIT_FAILURE);
    }
    printf("Initialised.\n");
     
    //Create a socket
    if((s = socket(AF_INET , SOCK_DGRAM , 0 )) == INVALID_SOCKET)
    {
        printf("Could not create socket : %d" , WSAGetLastError());
    }
    printf("Socket created.\n");
     
    //Prepare the sockaddr_in structure
    server.sin_family = AF_INET;
    server.sin_addr.s_addr = INADDR_ANY;
    server.sin_port = htons( PORT );
     
    //Bind
    if( bind(s ,(struct sockaddr *)&server , sizeof(server)) == SOCKET_ERROR)
    {
        printf("Bind failed with error code : %d" , WSAGetLastError());
        exit(EXIT_FAILURE);
    }
    puts("Bind done");
 
    //keep listening for data
    while(1)
    {
        printf("Waiting for data...");
        fflush(stdout);
         
        //clear the buffer by filling null, it might have previously received data
        //memset(buf,'\0', BUFLEN);
         buf.clear();
		 buf.resize(BUFLEN,'/0');
        //try to receive some data, this is a blocking call
        if ((recv_len = recvfrom(s, &buf[0], BUFLEN, 0, (struct sockaddr *) &dest_addr, &slen)) == SOCKET_ERROR)
        {
            printf("recvfrom() failed with error code : %d" , WSAGetLastError());
            exit(EXIT_FAILURE);
        }
		//vector<byte> buffr(&buf[0],&buf[BUFLEN]);
         radius::packets::Packet rec_pack(buf,dest_addr);
        //print details of the client/peer and the data received
        printf("Received packet from %s:%d\n", inet_ntoa(dest_addr.sin_addr), ntohs(dest_addr.sin_port));
        printf("Data: %s\n" , buf);
         
        //now reply the client with the same data
        if (sendto(s, &buf[0], recv_len, 0, (struct sockaddr*) &dest_addr, slen) == SOCKET_ERROR)

        {
            printf("sendto() failed with error code : %d" , WSAGetLastError());
            exit(EXIT_FAILURE);
        }
    }
 
    closesocket(s);
    WSACleanup();
}

