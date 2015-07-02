#include "sockets.h"

int createSocket(){
    int s;
    if ((s = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) == -1) {
        std::cerr<<"Could not create socket"<<std::endl;
        exit(EXIT_FAILURE);
    }
    return s;
}
void bindSocket(int sock,const sockaddr_in &addr){
    if (bind(sock, (struct sockaddr *)&addr, sizeof(addr)) == -1) {
        std::cerr<<"Bind failed"<<std::endl;
        exit(EXIT_FAILURE);
    }
}

