#include "radius_server.h"
using std::map;
using std::string;
using std::vector;
using radius::packets::Packet;
using radius::packets::RadiusPacket;

namespace radius {

RadiusServer::RadiusServer(const map<string, string> &userPassMap,
                           const string &secret, const Logger &logger)
    : userPassMap(userPassMap), secret(secret), logger(logger) {}

const vector<Packet> RadiusServer::recvPacket(const Packet &packet) {
    /* Packet sendPacket; */
    vector<Packet> packetsToSend;

    try{
        RadiusPacket radiusPacket(packet.bytes);
    
        if(!checkIntegrity(radiusPacket,secret)){
            return addPendingPackets(packetsToSend);
        }
    }catch(const packets::InvalidPacket& e){
        return addPendingPackets(packetsToSend);
    }



}
const vector<Packet> RadiusServer::addPendingPackets(vector<Packet>packetsToSend){
    std::transform(pendingPackets.begin(), pendingPackets.end(),
                   std::back_inserter(packetsToSend),
                   [](const PendingPacket &p) { return p.packet; });
    return packetsTosend;
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
