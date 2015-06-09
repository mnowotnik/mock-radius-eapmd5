#include <winsock2.h>
#pragma comment(lib, "ws2_32.lib")
#include <WS2tcpip.h>
#include <stdio.h>
#include "radius_server.h"
namespace radius {
void startServer(const char *addr);
void stopServer();
radius::packets::Packet receiveData();
void sendData(radius::packets::Packet sen_pack);
}