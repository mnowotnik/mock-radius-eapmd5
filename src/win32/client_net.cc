#include "client_net.h"
#include <vector>
namespace radius {
namespace{

const int BUFLEN = 1000;
static struct sockaddr_in dest_addr;
int s, slen = sizeof(dest_addr);
bool isRunning;
}

void startClient(const char *addr, const int port) {
    if (isRunning) {
        return;
    }
    WSADATA wsa;

    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
        printf("Failed. Error Code : %d", WSAGetLastError());
        exit(EXIT_FAILURE);
    }

    s = createSocket();
    initAddr(dest_addr,std::string(addr),port);

    // Client is running
    isRunning = true;
}

void stopClient() {
    closesocket(s);
    WSACleanup();
    isRunning = false;
}

void sendPacket(packets::Packet sen_pack) {
    if (!isRunning) {
        exit(EXIT_FAILURE);
    }

    std::vector<char> buf(sen_pack.bytes.begin(), sen_pack.bytes.end());
    if (sendto(s, &buf[0], buf.size(), 0, (struct sockaddr *)&dest_addr,
               slen) == SOCKET_ERROR) {
        printf("sendto() failed with error code : %d", WSAGetLastError());
        exit(EXIT_FAILURE);
    }
}

packets::Packet recvPacket() {
    if (!isRunning) {
        exit(EXIT_FAILURE);
    }
    // data
    std::vector<char> buf(BUFLEN, '\0');
    if (recvfrom(s, &buf[0], BUFLEN, 0, (struct sockaddr *)&dest_addr, &slen) ==
        SOCKET_ERROR) {
        printf("recvfrom() failed with error code : %d", WSAGetLastError());
        exit(EXIT_FAILURE);
    }

    return packets::Packet(buf, dest_addr);
}

} // radius
