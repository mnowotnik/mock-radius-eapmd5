#include <iostream>
#include "server_net.h"
#include <vector>
#include "packets/packet.h"
using std::vector;

namespace radius {
namespace {

BOOL WINAPI consoleHandler(DWORD signal) {

    if (signal == CTRL_C_EVENT)
        radius::stopServer();

    return TRUE;
}

const int BUFLEN = 1000;
SOCKET s;
bool isRunning;
const unsigned int INT_ERR_CODE = 10004;
} //namespace
void startServer(const char *addr, const int port = 0) {
    PORT = port;

    if (isRunning) {
        printf("Server is running");
        return;
    }
    struct sockaddr_in server;

    WSADATA wsa;

    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
        printf("Failed. Error Code : %d", WSAGetLastError());

        exit(EXIT_FAILURE);
    }

    s = createSocket();
    initAddr(dest_addr,std::string(addr),port);
    bindSocket(s,server);

    isRunning = true;
    if (!SetConsoleCtrlHandler(consoleHandler, TRUE)) {
        logger->error() << "Could not set control handler!";
        radius::stopServer();
        return 1;
    }
}

void stopServer() {
    closesocket(s);
    WSACleanup();
    isRunning = false;
}

packets::Packet recvData() {
    if (!isRunning) {
        printf("Server is not running");
        exit(EXIT_FAILURE);
    }

    int slen, recv_len;
    vector<char> buf(BUFLEN, '\0');
    struct sockaddr_in dest_addr;
    slen = sizeof(dest_addr);

    if ((recv_len = recvfrom(s, &buf[0], BUFLEN, 0,
                             (struct sockaddr *)&dest_addr, &slen)) ==
        SOCKET_ERROR) {
        unsigned int err = WSAGetLastError();
        if (err == INT_ERR_CODE) {
            std::cout << "Stopping server..";
        } else {
            printf("recvfrom() failed with error code : %d", err);
        }
        stopServer();
        exit(EXIT_FAILURE);
    }
    return packets::Packet(buf, dest_addr);
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
    if (sendto(s, &buf[0], recv_len, 0, (struct sockaddr *)&dest_addr, slen) ==
        SOCKET_ERROR) {
        printf("sendto() failed with error code : %d", WSAGetLastError());
        exit(EXIT_FAILURE);
    }
}
}
