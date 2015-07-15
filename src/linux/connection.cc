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
    socklen_t slen = sizeof(sockaddr_in);
    int recv_len;
    std::vector<byte> buf(BUFLEN, '\0');
    struct sockaddr_in src_addr;

    if ((recv_len = recvfrom(s, &buf[0], buf.size(), 0,(struct sockaddr *)&src_addr, &slen)) == -1) {
        if (errno == EINTR) {
            std::cout << "Stopping server.."<<std::endl;
        } else {
            std::cerr<<"recvfrom() failed with errno code : "<< errno<<std::endl;
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
    sockaddr_in dest_addr = sen_pack.addr;
    std::vector<byte> buf(sen_pack.bytes.begin(), sen_pack.bytes.end());

    if (sendto(s, &buf[0], buf.size(), 0, (struct sockaddr *)&dest_addr, sizeof(dest_addr)) ==
        -1) {
        std::cerr<<"sendto() failed with errno code : "<<errno<<std::endl;
        exit(EXIT_FAILURE);
    }
}
}
