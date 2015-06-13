#pragma once
#include <string>
#include <map>
#include <vector>
#include <random>
/* #include <climits> */
#include <algorithm>
#include <functional>
#include "packets/packet.h"
#include "packets/radius_packet.h"
#include "packets/eap_packet.h"
#include "logging.h"
#include "typedefs.h"
#include "spdlog/spdlog.h"
#include "auth_common.h"
#include "packets/utils.h"

namespace radius {
class RadiusServer {
    typedef std::map<std::string, std::string> UserPassMap;
    typedef packets::Packet Packet;
    typedef std::shared_ptr<spdlog::logger> Logger;

    const int PENDING_LIMIT = 5;
    // pending EAP-Request with a counter
    struct PendingPacket {
        int counter = 0;
        Packet packet;
        PendingPacket(const Packet &p) : packet(p) {}
    };


    struct AuthRequestId {
        std::string userName;
        sockaddr_in nasAddr;
        byte eapMsgId;
    };
    struct AuthRequestIdCompare {
        bool operator()(const AuthRequestId &lhs, const AuthRequestId &rhs)const {
            return lhs.userName < rhs.userName &&
                   lhs.nasAddr.sin_addr.s_addr < rhs.nasAddr.sin_addr.s_addr &&
                   lhs.nasAddr.sin_port < lhs.nasAddr.sin_port &&
                   lhs.eapMsgId < lhs.eapMsgId;
        }
    };
    struct AuthData {
        std::vector<byte> challenge;
    };
    std::unique_ptr<AuthData> persistChal;

    std::map<AuthRequestId, AuthData, AuthRequestIdCompare> authProcMap;

    // list of pending EAP-Requests
    std::vector<PendingPacket> pendingPackets;

    Logger logger;

    const UserPassMap userPassMap;
    const std::string secret;

    void updatePending();
    const std::vector<Packet>
    addPendingPackets(std::vector<Packet> packetsTosend);

  public:
    /**
     * @param userPassMap user credentials login x password
     * @param secret the secret shared with client (NAS)
     **/
    RadiusServer(const UserPassMap &userPassMap, const std::string &secret,
                 const Logger &logger);

    const std::vector<Packet> recvPacket(const Packet &packet);
};
}
