#include "connection.h"

namespace radius {
namespace {

BOOL WINAPI consoleHandler(DWORD signal) {

    if (signal == CTRL_C_EVENT)
        unbind();

    return TRUE;
}

const int BUFLEN = 1000;
SOCKET s;
bool isRunning;
const unsigned int INT_ERR_CODE = 10004;
} //namespace
void initBind(const char *addr, const int port = 0) {
    PORT = port;

    if (isRunning) {
        std::cerr<<"initBind() ran twice";
        return;
    }
    struct sockaddr_in server;

    WSADATA wsa;

    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
        std::cerr<<"Failed. Error Code : "<<WSAGetLastError()<<std::endl;
        exit(EXIT_FAILURE);
    }

    s = createSocket();
    initAddr(dest_addr,std::string(addr),port);
    bindSocket(s,server);

    isRunning = true;
    if (!SetConsoleCtrlHandler(consoleHandler, TRUE)) {
        std::cerr<< "Could not set control handler!";
        unbind();
        exit(EXIT_FAILURE);
    }
}

void unbind() {
    closesocket(s);
    WSACleanup();
    isRunning = false;
}

packets::Packet recvPacket() {
    if (!isRunning) {
        std::cerr<<"You have to call initBind() first"<<std::endl;
        exit(EXIT_FAILURE);
    }

    int slen, recv_len;
    std::vector<char> buf(BUFLEN, '\0');
    struct sockaddr_in dest_addr;
    slen = sizeof(dest_addr);

    if ((recv_len = recvfrom(s, &buf[0], BUFLEN, 0,
                             (struct sockaddr *)&dest_addr, &slen)) ==
        SOCKET_ERROR) {
        unsigned int err = WSAGetLastError();
        if (err == INT_ERR_CODE) {
            std::cout << "Stopping server..";
        } else {
            std::cerr<<"recvfrom() failed with error code : "<<err<<std::endl;
        }
        unbind();
        exit(EXIT_FAILURE);
    }
    return packets::Packet(buf, dest_addr);
}
void sendData(packets::Packet sen_pack) {
    if (!isRunning) {
        std::cerr<<"You have to call initBind() first"<<std::endl;
        exit(EXIT_FAILURE);
    }
    int slen, recv_len;
    sockaddr_in dest_addr = sen_pack.addr;
    slen = sizeof(dest_addr);
    std::vector<char> buf(&(sen_pack.bytes[0]), &(sen_pack.bytes[BUFLEN]));
    recv_len = BUFLEN * sizeof(byte);
    if (sendto(s, &buf[0], recv_len, 0, (struct sockaddr *)&dest_addr, slen) ==
        SOCKET_ERROR) {
        std::cerr<<"sendto() failed with error code : "<<WSAGetLastError()<<std::endl;
        exit(EXIT_FAILURE);
    }
}
}
