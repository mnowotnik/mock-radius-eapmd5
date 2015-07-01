#include "sockets.h"
#include "tclap/CmdLine.h"
#include <iostream>
#include "packets/packet.h"
namespace radius {

void startClient(const char *addr, const int port);
void stopClient();
void sendPack(packets::Packet sen_pack);
packets::Packet receivePack();
}
