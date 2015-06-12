#include "radius_server.h"
using std::map;
using std::string;
using std::vector;
using radius::packets::Packet;
using radius::packets::RadiusPacket;
using radius::packets::EapPacket;

namespace radius {

    namespace{
        std::mt19937 seedGen(std::random_device{}());
        typedef std::uniform_int_distribution<unsigned int> IntGenerator;
        typedef std::independent_bits_engine<std::mt19937,4,unsigned int> UniBiIntGenerator;

        IntGenerator genLen{5,25};
        UniBiIntGenerator genBytes(seedGen);

        std::vector<byte> generateRandomBytes(){
            unsigned int len = genLen(seedGen);
            std::vector<byte> randInts(len);
            std::generate(randInts.begin(),randInts.end(),[&]{return genBytes();});

            byte*castInts = static_cast<byte*>(&randInts[0]);
            std::vector<byte> bytes(&castInts[0],&castInts[randInts.size()*4]);
            return bytes;
        }
        const std::string nl ("\n");
    }

RadiusServer::RadiusServer(const map<string, string> &userPassMap,
                           const string &secret, const Logger &logger)
    : userPassMap(userPassMap), secret(secret), logger(logger) {}

const vector<Packet> RadiusServer::recvPacket(const Packet &packet) {
    logger -> info() << "Incoming RADIUS packet:";

    vector<Packet> packetsToSend;

    try {
        RadiusPacket radiusPacket(packet.bytes);
        logger -> debug() << nl << packet2LogBytes(radiusPacket);
        logger -> info() << nl << radiusPacket;

        if(!isValid(radiusPacket)){
            logger -> warn() << "Packet has invaild structure";
            return addPendingPackets(packetsToSend);
        }

        if(!isRequest(radiusPacket)){
            logger -> warn() << "Packet has wrong type";
            return addPendingPackets(packetsToSend);
        }

        if (!checkIntegrity(radiusPacket, secret)) {
            logger -> warn() << "Message Authenticator checksum does not match the packet";
            return addPendingPackets(packetsToSend);
        }

        EapPacket eapPacket(extractEapPacket(radiusPacket));

        logger -> info() << "encapsulated EAP packet:" << nl << eapPacket;
    } catch (const packets::InvalidPacket &e) {
        logger -> error() << "Packet invalid. Reason :" << e.what();
        return addPendingPackets(packetsToSend);
    }
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
