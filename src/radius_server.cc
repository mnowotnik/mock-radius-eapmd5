#include "radius_server.h"
using std::map;
using std::string;
using std::vector;
using radius::packets::Packet;
using radius::packets::RadiusPacket;
using radius::packets::EapPacket;
using radius::packets::EapIdentity;
using radius::packets::EapData;
using radius::packets::EapMd5Challenge;
using radius::packets::RadiusAVP;
using radius::packets::EapMessage;
using radius::AuthMode;

namespace radius {

namespace {
const int MIN_CHAL_VAL = 12;
const int MAX_CHAL_VAL = 24;

std::unique_ptr<packets::RadiusPacket>
prepareAccessChal(RadiusPacket &req, EapMessage &eapM,
                  const std::string secret) {
    std::unique_ptr<packets::RadiusPacket> accessChal(new RadiusPacket);
    accessChal->setCode(RadiusPacket::ACCESS_CHALLENGE);
    accessChal->setIdentifier(req.getIdentifier() + 1);
    accessChal->addAVP(dynamic_cast<const RadiusAVP &>(eapM));
    accessChal->setAuthenticator(req.getAuthenticator());
    calcAndSetMsgAuth(*accessChal, secret);
    calcAndSetAuth(*accessChal);
    return accessChal;
}
}

RadiusServer::RadiusServer(const map<string, string> &userPassMap,
                           const string &secret, const Logger &logger,
                           AuthMode authMode)
    : userPassMap(userPassMap), secret(secret), logger(logger),
      authMode(authMode) {}

const vector<Packet> RadiusServer::processPacket(const Packet &packet) {
    logger->info() << "Received RADIUS packet";

    vector<Packet> packetsToSend;

    try {
        RadiusPacket radiusPacket(packet.bytes);
        logger->debug() << NL << radiusPacket;

        if (!isValid(radiusPacket)) {
            logger->trace() << "Input packet has invaild structure. Requires "
                               "only one Message Authenticator and " << NL
                            << "at least one EAP-Message";
            return packetsToSend;
        }

        if (!isRequest(radiusPacket)) {
            logger->trace()
                << "Packet has wrong type. Is not an Access-Request";
            return packetsToSend;
        }

        if (!checkIntegrity(radiusPacket, secret)) {
            logger->trace()
                << "Message Authenticator checksum does not match the packet";
            return packetsToSend;
        }

        EapPacket eapPacket(extractEapPacket(radiusPacket));
        logger->debug() << "Encapsulated EAP packet:" << NL << eapPacket;

        std::unique_ptr<EapData> eapDataPtr(eapPacket.getData());
        byte eapDataT = eapDataPtr->getType();

        std::string userName = getUserName(radiusPacket);
        if(userName==""){
            return packetsToSend;
        }

        if (eapDataT == EapData::IDENTITY) {
            EapIdentity &eapIden =
                *dynamic_cast<EapIdentity *>(eapDataPtr.get());
            RadiusPacketPtr radiusPacketPtr =
                recvEapId(radiusPacket, eapIden, packet.addr,eapPacket.getIdentifier()+1);
            if (radiusPacketPtr.get()) {
                packetsToSend.push_back(
                    Packet(radiusPacketPtr->getBuffer(), packet.addr));
            }
        } else if (eapDataT == EapData::MD5_CHALLENGE) {
            AuthRequestId authId(userName,packet.addr,eapPacket.getIdentifier());
            auto authDataIt = authProcMap.find(authId);
            if(authDataIt == authProcMap.end()){
                return packetsToSend;
            }

            auto passIt = userPassMap.find(userName);
            if(passIt == userPassMap.end()){
                logger->debug() << "Unknown user: "+userName;
                return packetsToSend;
            }
            std::array<byte, 16> refHash =
                calcChalVal(authId.msgId, authDataIt->second.challenge,
                        passIt->second);
            RadiusPacketPtr rPtr = recvEapMd5Chal(
                    radiusPacket,
                    *dynamic_cast<EapMd5Challenge*>(eapDataPtr.get()),
                    refHash);
            Packet packetToSend(rPtr->getBuffer(), packet.addr);
            packetsToSend.push_back(packetToSend);
        }
    } catch (const packets::InvalidPacket &e) {
        logger->trace() << "Packet invalid. Reason : " << NL << e.what();
        logger->trace() << "Packet dump: " << NL
                        << packet2LogBytes(packet.bytes);
        return packetsToSend;
    }
    return packetsToSend;
}

RadiusServer::RadiusPacketPtr RadiusServer::recvEapMd5Chal(RadiusPacket &radiusPacket,
        EapMd5Challenge &eapMd5, std::array<byte,16> &refHash){

    std::vector<byte> md5RespVec = eapMd5.getValue();
    std::array<byte, 16> md5RespArr;
    std::copy(md5RespVec.begin(), md5RespVec.end(), md5RespArr.begin());

    EapPacket eapPacket(extractEapPacket(radiusPacket));

    EapPacket respEapPacket;
    RadiusPacketPtr respPacket(new RadiusPacket);
    if (refHash == md5RespArr) {
        respEapPacket.setType(EapPacket::SUCCESS);
        respPacket->setCode(RadiusPacket::ACCESS_ACCEPT);
    } else {
        respEapPacket.setType(EapPacket::FAILURE);
        respPacket->setCode(RadiusPacket::ACCESS_REJECT);
    }
    respEapPacket.setIdentifier(eapPacket.getIdentifier());
    respPacket->setIdentifier(radiusPacket.getIdentifier());

    EapMessage eapM;
    eapM.setValue(respEapPacket.getBuffer());
    respPacket->addAVP(dynamic_cast<const RadiusAVP &>(eapM));
    respPacket->setAuthenticator(radiusPacket.getAuthenticator());
    calcAndSetMsgAuth(*respPacket, secret);
    calcAndSetAuth(*respPacket);

    return respPacket;
}

RadiusServer::RadiusPacketPtr
RadiusServer::recvEapId(RadiusPacket &radiusPacket, EapIdentity &eapIden,
                        const sockaddr_in &inAddr,byte eapId) {
    std::string userName = eapIden.getIdentity();
    const auto passIt = userPassMap.find(userName);
    if (passIt == userPassMap.end()) {
        logger->debug() << "Username " + userName + " not found";
        return RadiusPacketPtr(nullptr);
    }

    // prepare EAP packet
    EapPacket eapReq;
    eapReq.setType(EapPacket::REQUEST);
    // initial identifier is the same as in the radius packet
    // arbitrary decision
    eapReq.setIdentifier(eapId);

    // prepare MD5 challenge
    std::vector<byte> challenge =
        generateRandomBytes(MIN_CHAL_VAL, MAX_CHAL_VAL);
    EapMd5Challenge md5Chal;
    md5Chal.setValue(challenge);
    eapReq.setData(dynamic_cast<const EapData &>(md5Chal));
    EapMessage eapM;
    eapM.setValue(eapReq.getBuffer());

    // add unique challenge to map and await reponse
    persistChallenge(getUserName(radiusPacket),
            inAddr, eapReq.getIdentifier(), challenge);

    // prepare RADIUS Acess-Challenge packet
    return prepareAccessChal(radiusPacket, eapM, secret);
}

void RadiusServer::persistChallenge(const std::string &user,
                        const sockaddr_in &inAddr, byte msgId,
                                    std::vector<byte> &challenge) {
    authProcMap[AuthRequestId(user,inAddr,msgId)] = AuthData(challenge);
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
