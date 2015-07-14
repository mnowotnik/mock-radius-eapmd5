#include "utils_net.h"
namespace radius{
void initAddr(sockaddr_in &addr,const std::string &ip,const int port){
    std::memset((byte *)&addr, 0, sizeof(addr));

    addr.sin_family = AF_INET;

    if (ip == "") {
        addr.sin_addr.s_addr = INADDR_ANY;
    } else {
        addr.sin_addr.s_addr = inet_addr(ip.c_str());
    }
    addr.sin_port = htons(port);
}
}

