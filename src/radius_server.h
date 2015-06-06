#pragma once
#include <string>
#include <map>
#include "packets/packet.h"
#include "typedefs.h"

namespace radius {
class RadiusServer {
    typedef std::map<std::string, std::string> UserPassMap;
    typedef packets::Packet Packet;

    const int PENDING_LIMIT=5;
    // pending EAP-Request with a counter
    struct PendingPacket {
        int counter= 0;
        Packet packet;
        PendingPacket(const Packet &p) : packet(p) {}
    };

    // list of pending EAP-Requests
    std::vector<PendingPacket> pendingPackets;

    const UserPassMap userPassMap;
    const std::string secret;

    void updatePending();

  public:
    /**
     * @param userPassMap user credentials login x password
     * @param secret the secret shared with client (NAS)
     **/
    RadiusServer(const UserPassMap &userPassMap, const std::string &secret);

    std::vector<const Packet> recvPacket(const Packet &packet);
};
}
