#include "client_net.h"
#include <vector>
namespace radius {
namespace{
static struct sockaddr_in dest_addr;
int dest_len = sizeof(dest_addr);
int s;
const int BUFLEN = 1000;
bool isRunning;
}

void startClient(const char *addr, const int port) {
    if (isRunning) {
        return;
    }

    s=createSocket();
    initAddr(dest_addr,std::string(addr),port);

    // Client is running
    isRunning = true;
}

void stopClient() {
    close(s);
    isRunning = false;
}

void sendPacket(packets::Packet sen_pack) {
    if (!isRunning) {
        exit(EXIT_FAILURE);
    }
    // sockaddr_in dest_addr =sen_pack.addr;
    std::vector<char> buf(sen_pack.bytes.begin(), sen_pack.bytes.end());
    if (sendto(s, &buf[0], buf.size(), 0, (struct sockaddr *)&dest_addr, dest_len) ==
        -1) {
        printf("sendto() failed with errno code : %d", errno);
        exit(EXIT_FAILURE);
    }
}

packets::Packet recvPacket() {
    if (!isRunning) {
        exit(EXIT_FAILURE);
    }
    // data
    std::vector<byte> buf(BUFLEN, '\0');
    socklen_t slen;
    int recv_len;

    if ((recv_len = recvfrom(s, &buf[0], BUFLEN, 0,(struct sockaddr *)&dest_addr, &slen)) == -1) {
        printf("recvfrom() failed with errno code : %d", errno);
        exit(EXIT_FAILURE);
    }
    return packets::Packet(buf, dest_addr);
}

} // radius
