#ifndef SERVER_NET_H_WCZRN4Y6
#define SERVER_NET_H_WCZRN4Y6

#include <stdio.h>
#include <iostream>
#include <vector>
#include "sockets.h"
#include "utils_net.h"
#include "packets/packet.h"
#include "radius_server.h"
namespace radius {
void startServer(const char *addr, const int port);
void stopServer();
radius::packets::Packet recvData();
void sendData(radius::packets::Packet sen_pack);
}

#endif /* end of include guard: SERVER_NET_H_WCZRN4Y6 */
