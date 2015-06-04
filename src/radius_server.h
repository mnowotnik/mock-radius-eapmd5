#pragma once
#include <string>
#include <map>
#include "packets/packet.h"
#include "typedefs.h"

namespace{
    using std::map;
    using std::string;
    using std::vector;
}

namespace radius{
class RadiusServer {
    /**
     * @param usersAuth user credentials login x password
     * @param secret the secret shared with client (NAS)
     **/
    Server(map<string,string>usersAuth,string secret);

    void recvPacket(Packet packet);
    vector<Packet> sendPackets();
}
}
