#include <iostream>
#include "server_net.h"
#include <vector>
#include "packets/packet.h"
using std::vector;

namespace radius {
namespace {

const int BUFLEN = 1000;
int s;
bool isRunning;
}
void startServer(const char *addr, const int port = 0) {

    if (isRunning) {
        printf("Server is running");
        return;
    }
    struct sockaddr_in server;

    // Create a socket
    if ((s = socket(AF_INET, SOCK_DGRAM, 0)) == -1) {
        perror("Could not create socket");
        exit(EXIT_FAILURE);
    }
    // printf("Socket created.\n");

    // Prepare the sockaddr_in structure
    server.sin_family = AF_INET;

    if ((std::string)addr == "") {
        server.sin_addr.s_addr = INADDR_ANY;
    } else {
        server.sin_addr.s_addr = inet_addr(addr);
    }
    server.sin_port = htons(port);

    // Bind
    if (bind(s, (struct sockaddr *)&server, sizeof(server)) == -1) {
        perror("Bind failed");
        exit(EXIT_FAILURE);
    }
    isRunning = true;
    // puts("Bind done");
}

void stopServer() {
    close(s);
    isRunning = false;
}

packets::Packet receiveData() {
    if (!isRunning) {
        printf("Server is not running");
        exit(EXIT_FAILURE);
    }
    // printf("Waiting for data...");
    //  fflush(stdout);
    socklen_t slen;
    int recv_len;
    vector<char> buf(BUFLEN, '\0');
    struct sockaddr_in dest_addr;
    slen = sizeof(dest_addr);
    // try to receive some data, this is a blocking call
    if ((recv_len = recvfrom(s, &buf[0], BUFLEN, 0,(struct sockaddr *)&dest_addr, &slen)) == -1) {
        if (errno == EINTR) {
            std::cout << "Stopping server..";
        } else {
            printf("recvfrom() failed with errno code : %d", errno);
        }
        stopServer();
        exit(EXIT_FAILURE);
    }
    // vector<byte> buffr(&buf[0],&buf[BUFLEN]);
    vector<byte> buffr(&buf[0], &buf[BUFLEN]);
    radius::packets::Packet rec_pack(buffr, dest_addr);
    return rec_pack;
}
void sendData(packets::Packet sen_pack) {
    if (!isRunning) {
        printf("Server is not running");
        exit(EXIT_FAILURE);
    }
    int slen, recv_len;
    sockaddr_in dest_addr = sen_pack.addr;
    slen = sizeof(dest_addr);
    vector<char> buf(&(sen_pack.bytes[0]), &(sen_pack.bytes[BUFLEN]));
    recv_len = BUFLEN * sizeof(byte);
    // now reply the client with the same data
    if (sendto(s, &buf[0], recv_len, 0, (struct sockaddr *)&dest_addr, slen) ==
        -1) {
        printf("sendto() failed with errno code : %d", errno);
        exit(EXIT_FAILURE);
    }
}
}
