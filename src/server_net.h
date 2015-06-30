#ifndef SERVER_NET_H_WCZRN4Y6
#define SERVER_NET_H_WCZRN4Y6

#include "sockets.h"
#include <stdio.h>
#include "radius_server.h"
namespace radius {
void startServer(const char *addr, const int port);
void stopServer();
radius::packets::Packet receiveData();
void sendData(radius::packets::Packet sen_pack);
}

#endif /* end of include guard: SERVER_NET_H_WCZRN4Y6 */
