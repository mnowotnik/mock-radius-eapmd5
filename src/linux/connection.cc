#include "connection.h"

namespace radius {
namespace {

const int BUFLEN = 1000;
int s;
bool isRunning;
}
void initBind(const char *addr, const int port = 0) {

    if (isRunning) {
        std::cerr<<"initBind() ran twice";
        return;
    }
    struct sockaddr_in server;

    s = createSocket();
    initAddr(server,std::string(addr),port);
    bindSocket(s,server);

    isRunning = true;
}

void unbind() {
    close(s);
    isRunning = false;
}

packets::Packet recvPacket() {
    if (!isRunning) {
        std::cerr<<"You have to call initBind() first"<<std::endl;
        exit(EXIT_FAILURE);
    }
    socklen_t slen;
    int recv_len;
    std::vector<byte> buf(BUFLEN, '\0');
    struct sockaddr_in src_addr;

    if ((recv_len = recvfrom(s, &buf[0], BUFLEN, 0,(struct sockaddr *)&src_addr, &slen)) == -1) {
        if (errno == EINTR) {
            std::cout << "Stopping server..";
        } else {
            printf("recvfrom() failed with errno code : %d", errno);
        }
        unbind();
        exit(EXIT_FAILURE);
    }
    return packets::Packet(buf, src_addr);
}
void sendPacket(packets::Packet sen_pack) {
    if (!isRunning) {
        std::cerr<<"You have to call initBind() first"<<std::endl;
        exit(EXIT_FAILURE);
    }
    int slen, recv_len;
    sockaddr_in dest_addr = sen_pack.addr;
    slen = sizeof(dest_addr);
    std::vector<byte> buf(&(sen_pack.bytes[0]), &(sen_pack.bytes[BUFLEN]));
    recv_len = BUFLEN * sizeof(byte);

    if (sendto(s, &buf[0], recv_len, 0, (struct sockaddr *)&dest_addr, slen) ==
        -1) {
        std::cerr<<"sendto() failed with errno code : "<<errno<<std::endl;
        exit(EXIT_FAILURE);
    }
}
}
