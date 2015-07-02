#include "server_net.h"
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

    s = createSocket();
    initAddr(server,std::string(addr),port);
    bindSocket(s,server);

    isRunning = true;
}

void stopServer() {
    close(s);
    isRunning = false;
}

packets::Packet recvData() {
    if (!isRunning) {
        printf("Server is not running");
        exit(EXIT_FAILURE);
    }
    socklen_t slen;
    int recv_len;
    vector<byte> buf(BUFLEN, '\0');
    struct sockaddr_in src_addr;
    slen = sizeof(src_addr);

    if ((recv_len = recvfrom(s, &buf[0], BUFLEN, 0,(struct sockaddr *)&src_addr, &slen)) == -1) {
        if (errno == EINTR) {
            std::cout << "Stopping server..";
        } else {
            printf("recvfrom() failed with errno code : %d", errno);
        }
        stopServer();
        exit(EXIT_FAILURE);
    }
    return packets::Packet(buf, src_addr);
}
void sendData(packets::Packet sen_pack) {
    if (!isRunning) {
        printf("Server is not running");
        exit(EXIT_FAILURE);
    }
    int slen, recv_len;
    sockaddr_in dest_addr = sen_pack.addr;
    slen = sizeof(dest_addr);
    vector<byte> buf(&(sen_pack.bytes[0]), &(sen_pack.bytes[BUFLEN]));
    recv_len = BUFLEN * sizeof(byte);

    if (sendto(s, &buf[0], recv_len, 0, (struct sockaddr *)&dest_addr, slen) ==
        -1) {
        printf("sendto() failed with errno code : %d", errno);
        exit(EXIT_FAILURE);
    }
}
}
