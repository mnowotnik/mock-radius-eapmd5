#ifndef CONNECTION_H_3HUPRL9W
#define CONNECTION_H_3HUPRL9W

#include <iostream>
#include <vector>
#include "sockets.h"
#include "utils_net.h"
#include "packets/packet.h"
#include "radius_server.h"
namespace radius {
void initBind(const char *addr, const int port);
void unbind();
radius::packets::Packet recvPacket();
void sendPacket(radius::packets::Packet sen_pack);
}

#endif /* end of include guard: CONNECTION_H_3HUPRL9W */
