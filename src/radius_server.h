#pragma once
#include <string>
#include <map>
#include "packets/packet.h"
#include "typedefs.h"
#include "spdlog/spdlog.h"

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
        sockaddr_in addr;
        byte eapMsgId;
    };
    struct AuthRequestIdCompare {
        bool operator()(const AuthRequestId &lhs, const AuthRequestId &rhs) {
            return lhs.userName < rhs.userName &&
                   lhs.addr.sin_addr.s_addr < rhs.addr.sin_addr.s_addr &&
                   lhs.addr.sin_port < lhs.addr.sin_port &&
                   lhs.eapMsgId < lhs.eapMsgId;
        }
    };
    struct AuthData {
        std::vector<byte> challenge;
    };

    std::map<AuthRequestId, AuthData, AuthRequestIdCompare> authProcMap;

    // list of pending EAP-Requests
    std::vector<PendingPacket> pendingPackets;

    Logger logger;

    const UserPassMap userPassMap;
    const std::string secret;

    void updatePending();

  public:
    /**
     * @param userPassMap user credentials login x password
     * @param secret the secret shared with client (NAS)
     **/
    RadiusServer(const UserPassMap &userPassMap, const std::string &secret,
                 const Logger &logger);

    std::vector<const Packet> recvPacket(const Packet &packet);
};
}
