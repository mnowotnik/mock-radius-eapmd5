#include <winsock2.h>
/* #include <netinet/in.h> */
#pragma comment(lib, "ws2_32.lib")
#include <WS2tcpip.h>
#include <stdio.h>
#include "tclap/CmdLine.h"
#include <iostream>
#include "packets/Packet.h"
namespace radius{

void startClient(const char *addr,const int port);
void stopClient();
void sendPack(packets::Packet sen_pack);
packets::Packet receivePack();
}