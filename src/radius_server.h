#pragma once
#include <string>
#include <map>
#include "packets/packet.h"
#include "typedefs.h"

namespace radius{
class RadiusServer {
    typedef std::map<std::string,std::string> UserPassMap;
    typedef packets::Packet Packet;

    public:
    /**
     * @param userPassMap user credentials login x password
     * @param secret the secret shared with client (NAS)
     **/
    RadiusServer(const UserPassMap &userPassMap,const std::string &secret);

    std::vector<Packet> recvPacket(const Packet &packet);
};
}
