#include "radius_server.h"
using std::map;
using std::string;
using std::vector;
using radius::packets::Packet;
using radius::packets::RadiusPacket;
using radius::packets::EapPacket;
using radius::packets::EapIdentity;
using radius::packets::EapData;

namespace radius {

    namespace{
        const std::string nl ("\r\n");
    }

RadiusServer::RadiusServer(const map<string, string> &userPassMap,
                           const string &secret, const Logger &logger)
    : userPassMap(userPassMap), secret(secret), logger(logger) {}

const vector<Packet> RadiusServer::recvPacket(const Packet &packet) {
    logger -> info() << "Incoming RADIUS packet";

    vector<Packet> packetsToSend;

    try {
        RadiusPacket radiusPacket(packet.bytes);
        logger -> info() << nl << radiusPacket;

        if(!isValid(radiusPacket)){
            logger -> warn() << "Input packet has invaild structure. Requires only one Message Authenticator and "<<nl
                << "at least one EAP-Message";
            return addPendingPackets(packetsToSend);
        }

        if(!isRequest(radiusPacket)){
            logger -> warn() << "Packet has wrong type. Is not an Access-Request";
            return addPendingPackets(packetsToSend);
        }

        if (!checkIntegrity(radiusPacket, secret)) {
            logger -> warn() << "Message Authenticator checksum does not match the packet";
            return addPendingPackets(packetsToSend);
        }

        EapPacket eapPacket(extractEapPacket(radiusPacket));
        logger -> info() << "Encapsulated EAP packet:" << nl << eapPacket;

        std::unique_ptr<EapData> eapDataPtr(eapPacket.getData());
        byte eapDataT = eapDataPtr->getType();

        if(eapDataT == EapData::IDENTITY){
            EapIdentity * eapIden = static_cast<EapIdentity*>(eapDataPtr.get());
            std::string userName = eapIden->getIdentity();
            const auto passPtr = userPassMap.find(userName);
            if(passPtr == userPassMap.end()){
                return addPendingPackets(packetsToSend);
            }

        }
    } catch (const packets::InvalidPacket &e) {
        logger -> error() << "Packet invalid. Reason :" << e.what();
        logger -> error() << "Packet dump:"<<nl << packet2LogBytes(packet.bytes);
        return addPendingPackets(packetsToSend);
    }
    return addPendingPackets(packetsToSend);
}
const vector<Packet>
RadiusServer::addPendingPackets(vector<Packet> packetsToSend) {
    std::transform(pendingPackets.begin(), pendingPackets.end(),
                   std::back_inserter(packetsToSend),
                   [](const PendingPacket &p) { return p.packet; });
    return packetsToSend;
}


void RadiusServer::updatePending() {
    std::for_each(pendingPackets.begin(), pendingPackets.end(),
                  [](PendingPacket &p) { p.counter++; });

    for (auto it = pendingPackets.begin(); it != pendingPackets.end();) {
        if (it->counter > PENDING_LIMIT) {
            it = pendingPackets.erase(it);
        } else {
            ++it;
        }
    }
}
}
